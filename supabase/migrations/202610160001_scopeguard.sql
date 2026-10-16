-- Project membership and every write are enforced in PostgreSQL, not in the UI.
create table public.sg_projects (
 id uuid primary key default gen_random_uuid(),
 manager_id uuid not null references auth.users(id),
 client_email text not null check (length(client_email) between 3 and 254),
 data jsonb not null,
 revision bigint not null default 1,
 created_at timestamptz not null default now()
);
create index sg_projects_manager_idx on public.sg_projects(manager_id);
create index sg_projects_client_idx on public.sg_projects(lower(client_email));
alter table public.sg_projects enable row level security;

-- Check the confirmed Auth record; user-editable metadata cannot grant membership.
create function public.sg_is_client(p_email text) returns boolean
language sql stable security definer set search_path = '' as $$
 select exists(select 1 from auth.users u where u.id=auth.uid()
  and u.email_confirmed_at is not null and lower(u.email)=lower(p_email));
$$;
revoke all on function public.sg_is_client(text) from public, anon;
grant execute on function public.sg_is_client(text) to authenticated;
create policy sg_members_read on public.sg_projects for select to authenticated
 using(manager_id=(select auth.uid()) or public.sg_is_client(client_email));
revoke all on public.sg_projects from anon, authenticated;
grant select on public.sg_projects to authenticated;

create function public.sg_create_project(p_data jsonb) returns public.sg_projects
language plpgsql security definer set search_path = '' as $$
declare
 v_id uuid:=gen_random_uuid(); v_budget numeric; v_deadline date; v_email text;
 v_doc jsonb; v_row public.sg_projects;
begin
 if auth.uid() is null then raise exception 'signInRequired'; end if;
 v_email:=lower(trim(p_data->>'clientEmail'));
 if p_data->>'name' is null or p_data->>'client' is null or length(trim(p_data->>'name')) not between 1 and 120
  or length(trim(p_data->>'client')) not between 1 and 120
  or v_email is null or v_email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'
  or length(v_email)>254 then raise exception 'invalidProject'; end if;
 if jsonb_typeof(p_data->'budget') is distinct from 'number' then raise exception 'invalidProject'; end if;
 v_budget:=(p_data->>'budget')::numeric;
 if v_budget<1 or v_budget>1000000000000 or v_budget<>trunc(v_budget) then raise exception 'invalidProject'; end if;
 v_deadline:=(p_data->>'deadline')::date;
 if v_deadline is null or v_deadline not between date '2000-01-01' and date '2100-12-31' then raise exception 'invalidProject'; end if;
 if jsonb_typeof(p_data->'requirements') is distinct from 'array' then raise exception 'invalidProject'; end if;
 if jsonb_array_length(p_data->'requirements') not between 1 and 100
  or exists(select 1 from jsonb_array_elements(p_data->'requirements') x where jsonb_typeof(x)<>'string' or length(trim(x#>>'{}')) not between 1 and 1000)
  then raise exception 'invalidProject'; end if;
 v_doc:=jsonb_build_object('id',v_id,'name',trim(p_data->>'name'),'client',trim(p_data->>'client'),
  'budget',v_budget,'deadline',v_deadline,'requirements',p_data->'requirements','requests','[]'::jsonb,
  'events',jsonb_build_array(jsonb_build_object('id',gen_random_uuid(),'key','eventProject',
   'values',jsonb_build_object('name',trim(p_data->>'name'),'amount',v_budget::text||' ₸'),
   'actor','Менеджер','at',now())));
 insert into public.sg_projects(id,manager_id,client_email,data) values(v_id,auth.uid(),v_email,v_doc) returning * into v_row;
 return v_row;
end $$;
revoke all on function public.sg_create_project(jsonb) from public, anon;
grant execute on function public.sg_create_project(jsonb) to authenticated;

create function public.sg_mutate(p_project_id uuid,p_revision bigint,p_action text,p_args jsonb)
returns public.sg_projects language plpgsql security definer set search_path = '' as $$
declare
 v_row public.sg_projects; v_doc jsonb; v_requests jsonb; v_request jsonb;
 v_index int; v_role text; v_event_key text; v_values jsonb; v_options jsonb:='[]';
 v_option jsonb; v_clean jsonb; v_history jsonb; v_version int; v_chosen jsonb;
 v_hours numeric; v_rate numeric; v_days numeric; v_text text; v_number int;
begin
 if auth.uid() is null then raise exception 'signInRequired'; end if;
 select * into v_row from public.sg_projects where id=p_project_id for update;
 if not found then raise exception 'notAllowed'; end if;
 if v_row.manager_id=auth.uid() then v_role:='manager';
 elsif public.sg_is_client(v_row.client_email) then v_role:='client';
 else raise exception 'notAllowed'; end if;
 if p_revision is null or p_revision<>v_row.revision then raise exception 'staleVersion'; end if;
 v_doc:=v_row.data; v_requests:=v_doc->'requests';
 if p_action='request' then
  if length(trim(p_args->>'title')) not between 1 and 120
   or length(trim(p_args->>'description')) not between 1 and 3000
   or length(trim(p_args->>'reason')) not between 1 and 2000
   or p_args->>'title' is null or p_args->>'description' is null or p_args->>'reason' is null
   then raise exception 'requiredFields'; end if;
  v_number:=jsonb_array_length(v_requests)+1;
  v_request:=jsonb_build_object('id',gen_random_uuid(),'number',v_number,'title',trim(p_args->>'title'),
   'description',trim(p_args->>'description'),'reason',trim(p_args->>'reason'),'status','new','created',now());
  v_requests:=v_requests||jsonb_build_array(v_request);v_event_key:='eventRequest';
  v_values:=jsonb_build_object('title',v_request->>'title');
 else
  select (ordinality-1)::int,value into v_index,v_request
   from jsonb_array_elements(v_requests) with ordinality where value->>'id'=p_args->>'requestId';
  if v_index is null then raise exception 'notAllowed'; end if;
  if p_action='estimate' then
   if v_role<>'manager' then raise exception 'notAllowed'; end if;
   if v_request->>'status' not in ('new','assessed','revision_requested') then raise exception 'alreadyDecided'; end if;
   if jsonb_typeof(p_args->'options') is distinct from 'array' then raise exception 'invalidOptions'; end if;
   if jsonb_array_length(p_args->'options') not between 1 and 3 then raise exception 'invalidOptions'; end if;
   for v_option in select * from jsonb_array_elements(p_args->'options') loop
    if length(trim(v_option->>'name')) not between 1 and 100 or v_option->>'name' is null then raise exception 'optionNameRequired'; end if;
    if jsonb_typeof(v_option->'hours') is distinct from 'number' or jsonb_typeof(v_option->'rate') is distinct from 'number'
     or jsonb_typeof(v_option->'days') is distinct from 'number' then raise exception 'invalidEstimate'; end if;
    v_hours:=(v_option->>'hours')::numeric;v_rate:=(v_option->>'rate')::numeric;v_days:=(v_option->>'days')::numeric;
    if v_hours not between 1 and 100000 or v_rate not between 1 and 10000000 or v_days not between 0 and 3650
     or v_hours<>trunc(v_hours) or v_rate<>trunc(v_rate) or v_days<>trunc(v_days) then raise exception 'invalidEstimate'; end if;
    v_clean:=jsonb_build_object('id',gen_random_uuid(),'name',trim(v_option->>'name'),'hours',v_hours,'rate',v_rate,
     'days',v_days,'note',left(coalesce(v_option->>'note',''),2000));
    v_options:=v_options||jsonb_build_array(v_clean);
   end loop;
   v_history:=coalesce(v_request->'estimateHistory','[]'::jsonb);
   v_version:=coalesce((v_request->>'estimateVersion')::int,0)+1;
   v_history:=v_history||jsonb_build_array(jsonb_build_object('version',v_version,'at',now(),'options',v_options));
   v_request:=v_request||jsonb_build_object('status','assessed','options',v_options,'estimateVersion',v_version,
    'estimateHistory',v_history,'hours',v_options->0->'hours','rate',v_options->0->'rate','days',v_options->0->'days');
   v_event_key:='eventOptions';v_values:=jsonb_build_object('title',v_request->>'title','version',v_version,'n',jsonb_array_length(v_options));
  elsif p_action='revision' then
   if v_role<>'client' then raise exception 'notAllowed'; end if;
   if v_request->>'status'<>'assessed' then raise exception 'assessFirst'; end if;
   v_text:=trim(p_args->>'reason');if v_text is null or length(v_text) not between 1 and 2000 then raise exception 'feedbackRequired'; end if;
   v_request:=v_request||jsonb_build_object('status','revision_requested','feedback',
    coalesce(v_request->'feedback','[]'::jsonb)||jsonb_build_array(jsonb_build_object('text',v_text,'at',now(),'version',v_request->'estimateVersion')));
   v_event_key:='eventRevision';v_values:=jsonb_build_object('title',v_request->>'title','reason',v_text);
  elsif p_action in ('approve','reject') then
   if v_role<>'client' then raise exception 'notAllowed'; end if;
   if v_request->>'status'<>'assessed' then raise exception 'alreadyDecided'; end if;
   if p_action='approve' then
    select value into v_chosen from jsonb_array_elements(v_request->'options') where value->>'id'=p_args->>'optionId';
    if v_chosen is null then raise exception 'chooseOption'; end if;
    v_request:=v_request||jsonb_build_object('status','approved','approvedEstimate',v_chosen,
     'selectedOptionId',v_chosen->'id','hours',v_chosen->'hours','rate',v_chosen->'rate','days',v_chosen->'days');
    v_event_key:='eventApproved';v_values:=jsonb_build_object('title',v_request->>'title',
     'amount',(((v_chosen->>'hours')::numeric*(v_chosen->>'rate')::numeric)::text)||' ₸','days',v_chosen->'days');
   else
    v_request:=v_request||jsonb_build_object('status','rejected');v_event_key:='eventRejectedSimple';
    v_values:=jsonb_build_object('title',v_request->>'title');
   end if;
  else raise exception 'invalidDecision';
  end if;
  v_requests:=jsonb_set(v_requests,array[v_index::text],v_request);
 end if;
 v_doc:=jsonb_set(v_doc,'{requests}',v_requests);
 v_doc:=jsonb_set(v_doc,'{events}',(v_doc->'events')||jsonb_build_array(jsonb_build_object('id',gen_random_uuid(),
  'key',v_event_key,'values',v_values,'actor',case when v_role='manager' then 'Менеджер' else 'Клиент' end,'at',now())));
 update public.sg_projects set data=v_doc,revision=revision+1 where id=p_project_id returning * into v_row;
 return v_row;
end $$;
revoke all on function public.sg_mutate(uuid,bigint,text,jsonb) from public, anon;
grant execute on function public.sg_mutate(uuid,bigint,text,jsonb) to authenticated;
