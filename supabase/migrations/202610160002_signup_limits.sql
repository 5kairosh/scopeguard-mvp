create table public.sg_signup_limits (
 bucket text not null, day date not null, attempts int not null,
 primary key(bucket,day)
);
alter table public.sg_signup_limits enable row level security;
revoke all on public.sg_signup_limits from public,anon,authenticated;
create function public.sg_claim_signup(p_bucket text,p_limit int) returns boolean
language plpgsql security definer set search_path = '' as $$
declare v_count int;
begin
 if p_bucket is null or length(p_bucket)>100 or p_limit not between 1 and 100 then return false; end if;
 insert into public.sg_signup_limits(bucket,day,attempts) values(p_bucket,current_date,1)
 on conflict(bucket,day) do update set attempts=public.sg_signup_limits.attempts+1 returning attempts into v_count;
 return v_count<=p_limit;
end $$;
revoke all on function public.sg_claim_signup(text,int) from public,anon,authenticated;
grant execute on function public.sg_claim_signup(text,int) to service_role;
