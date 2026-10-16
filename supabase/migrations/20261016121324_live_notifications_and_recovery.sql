-- Notifications are generated in the same transaction as a project change.
create schema if not exists sg_private;
revoke all on schema sg_private from public, anon, authenticated;
create table public.sg_notifications (
 id uuid primary key default gen_random_uuid(),
 recipient_id uuid not null references auth.users(id) on delete cascade,
 project_id uuid not null references public.sg_projects(id) on delete cascade,
 revision bigint not null, project_name text not null, event jsonb not null,
 created_at timestamptz not null default now(), read_at timestamptz,
 unique(project_id,revision,recipient_id)
);
create index sg_notifications_inbox_idx on public.sg_notifications(recipient_id,created_at desc);
alter table public.sg_notifications enable row level security;
revoke all on public.sg_notifications from public,anon,authenticated;
grant select,update(read_at) on public.sg_notifications to authenticated;
create policy sg_notification_read on public.sg_notifications for select to authenticated using(recipient_id=(select auth.uid()));
create policy sg_notification_seen on public.sg_notifications for update to authenticated
 using(recipient_id=(select auth.uid())) with check(recipient_id=(select auth.uid()));
create function sg_private.notify_project_change() returns trigger
language plpgsql security definer set search_path='' as $$
declare v_event jsonb; v_client uuid;
begin
 v_event:=new.data->'events'->-1;
 select id into v_client from auth.users where lower(email)=lower(new.client_email) and email_confirmed_at is not null;
 insert into public.sg_notifications(recipient_id,project_id,revision,project_name,event)
 select distinct recipient,new.id,new.revision,new.data->>'name',v_event
 from unnest(array[new.manager_id,v_client]) recipient
 where recipient is not null and recipient is distinct from auth.uid()
 on conflict do nothing;
 return new;
end $$;
revoke all on function sg_private.notify_project_change() from public,anon,authenticated;
create trigger sg_project_notification after insert or update on public.sg_projects
 for each row execute function sg_private.notify_project_change();

-- Recovery secrets are readable only by service code. A claim prevents replay/races.
create table public.sg_recovery_secrets (
 user_id uuid primary key references auth.users(id) on delete cascade,
 code_hash text not null check(code_hash ~ '^[a-f0-9]{64}$'),
 claim_id uuid, claimed_at timestamptz, updated_at timestamptz not null default now()
);
alter table public.sg_recovery_secrets enable row level security;
revoke all on public.sg_recovery_secrets from public,anon,authenticated;
create function public.sg_set_recovery(p_user uuid,p_hash text) returns void
language sql security definer set search_path='' as $$
 insert into public.sg_recovery_secrets(user_id,code_hash) values(p_user,p_hash)
 on conflict(user_id) do update set code_hash=excluded.code_hash,claim_id=null,claimed_at=null,updated_at=now();
$$;
create function public.sg_claim_recovery(p_email text,p_hash text,p_claim uuid) returns uuid
language plpgsql security definer set search_path='' as $$
declare v_user uuid;
begin
 if p_claim is null then return null; end if;
 update public.sg_recovery_secrets r set claim_id=p_claim,claimed_at=now()
 from auth.users u where u.id=r.user_id and lower(u.email)=lower(p_email)
 and u.email_confirmed_at is not null and r.code_hash=p_hash
 and (r.claim_id is null or r.claimed_at<now()-interval '5 minutes') returning r.user_id into v_user;
 return v_user;
end $$;
create function public.sg_finish_recovery(p_user uuid,p_claim uuid,p_new_hash text) returns boolean
language plpgsql security definer set search_path='' as $$
begin
 update public.sg_recovery_secrets set code_hash=coalesce(p_new_hash,code_hash),claim_id=null,claimed_at=null,updated_at=now()
 where user_id=p_user and claim_id=p_claim;
 return found;
end $$;
revoke all on function public.sg_set_recovery(uuid,text),public.sg_claim_recovery(text,text,uuid),public.sg_finish_recovery(uuid,uuid,text) from public,anon,authenticated;
grant execute on function public.sg_set_recovery(uuid,text),public.sg_claim_recovery(text,text,uuid),public.sg_finish_recovery(uuid,uuid,text) to service_role;

-- RLS still filters each Realtime subscriber; no DELETE payloads are subscribed to.
do $$ begin
 if exists(select 1 from pg_publication where pubname='supabase_realtime') then
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='sg_projects') then
   alter publication supabase_realtime add table public.sg_projects;
  end if;
  if not exists(select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='sg_notifications') then
   alter publication supabase_realtime add table public.sg_notifications;
  end if;
 end if;
end $$;
