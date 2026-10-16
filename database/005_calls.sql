-- Release-U migration 005: voice calls. Run AFTER 001-004.

-- Settings (change the demo length for testing; production must stay at 300)
create table public.app_settings (key text primary key, value text not null);
alter table public.app_settings enable row level security;   -- no policies: only SQL editor / functions
insert into public.app_settings values ('demo_seconds', '300');

create or replace function public.demo_limit() returns int
language sql stable security definer set search_path = public as $$
  select least(300, greatest(10, coalesce((select value::int from public.app_settings where key = 'demo_seconds'), 300)));
$$;

create table public.call_sessions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  listener_id uuid references auth.users(id),
  call_type text not null check (call_type in ('DEMO','PAID')),
  status text not null default 'ringing' check (status in ('ringing','active','ended','declined','missed')),
  selected_gender text not null default 'any',
  channel text not null unique default ('call_' || replace(gen_random_uuid()::text, '-', '')),
  created_at timestamptz not null default now(),
  started_at timestamptz, ended_at timestamptz,
  billable_seconds int, termination_reason text
);
alter table public.call_sessions enable row level security;
create policy "participants read calls" on public.call_sessions for select to authenticated
  using (user_id = auth.uid() or listener_id = auth.uid() or public.is_admin());
grant select on public.call_sessions to authenticated;

-- User asks to talk: picks an approved, online, idle listener matching the preference
create or replace function public.request_call(p_gender text) returns uuid
language plpgsql security definer set search_path = public as $$
declare v_type text; v_bal bigint; v_listener uuid; v_id uuid; v_demo text;
begin
  if p_gender not in ('any','male','female') then raise exception 'invalid preference'; end if;
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text));
  if not exists (select 1 from public.profiles where id = auth.uid() and status = 'active' and account_role = 'user')
    then raise exception 'not allowed'; end if;

  update public.call_sessions set status = 'ended', ended_at = now(), termination_reason = 'stale', billable_seconds = 0
    where status = 'active' and started_at < now() - interval '3 hours';
  update public.call_sessions set status = 'missed', ended_at = now(), termination_reason = 'no_answer', billable_seconds = 0
    where status = 'ringing' and created_at < now() - interval '45 seconds';
  update public.demo_entitlements d set status = 'available', claimed_session_id = null
    where d.status = 'in_progress' and not exists
      (select 1 from public.call_sessions c where c.id = d.claimed_session_id and c.status in ('ringing','active'));

  if exists (select 1 from public.call_sessions where user_id = auth.uid() and status in ('ringing','active'))
    then raise exception 'call_in_progress'; end if;

  select status into v_demo from public.demo_entitlements where user_id = auth.uid() for update;
  if v_demo = 'available' then v_type := 'DEMO';
  else
    select coalesce(sum(amount_paise), 0) into v_bal from public.wallet_ledger where user_id = auth.uid() and account = 'wallet';
    if v_bal < 500 then raise exception 'insufficient_balance'; end if;   -- at least one minute (Rs 5)
    v_type := 'PAID';
  end if;

  select p.id into v_listener from public.profiles p
    join public.listener_applications a on a.user_id = p.id
   where p.account_role = 'listener' and p.status = 'active' and p.listener_online
     and (p_gender = 'any' or lower(coalesce(a.gender_category, '')) = p_gender)
     and not exists (select 1 from public.call_sessions c where c.listener_id = p.id and c.status in ('ringing','active'))
   order by random() limit 1 for update of p skip locked;
  if v_listener is null then raise exception 'no_listener_available'; end if;

  insert into public.call_sessions (user_id, listener_id, call_type, selected_gender)
  values (auth.uid(), v_listener, v_type, p_gender) returning id into v_id;
  if v_type = 'DEMO' then
    update public.demo_entitlements set status = 'in_progress', claimed_session_id = v_id where user_id = auth.uid();
  end if;
  return v_id;
end $$;

-- Listener accepts or declines (45-second window)
create or replace function public.respond_call(p_call_id uuid, p_accept boolean) returns text
language plpgsql security definer set search_path = public as $$
declare c public.call_sessions;
begin
  select * into c from public.call_sessions where id = p_call_id and listener_id = auth.uid() and status = 'ringing' for update;
  if not found then return 'unavailable'; end if;
  if c.created_at < now() - interval '45 seconds' or not p_accept then
    update public.call_sessions set status = case when p_accept then 'missed' else 'declined' end,
      ended_at = now(), billable_seconds = 0, termination_reason = case when p_accept then 'no_answer' else 'declined' end
      where id = c.id;
    if c.call_type = 'DEMO' then
      update public.demo_entitlements set status = 'available', claimed_session_id = null where user_id = c.user_id and status = 'in_progress';
    end if;
    return case when p_accept then 'expired' else 'declined' end;
  end if;
  update public.call_sessions set status = 'active', started_at = now() where id = c.id;
  return 'accepted';
end $$;

-- How many seconds this call may still run, and the channel (used by the token function)
create or replace function public.call_token_info(p_call_id uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare c public.call_sessions; elapsed numeric; rem numeric; bal bigint;
begin
  select * into c from public.call_sessions where id = p_call_id and status = 'active';
  if not found or auth.uid() not in (c.user_id, c.listener_id) then return null; end if;
  elapsed := extract(epoch from now() - c.started_at);
  if c.call_type = 'DEMO' then rem := public.demo_limit() - elapsed;
  else
    select coalesce(sum(amount_paise), 0) into bal from public.wallet_ledger where user_id = c.user_id and account = 'wallet';
    rem := (bal / 500) * 60 - elapsed;
  end if;
  if rem < 5 then return null; end if;
  return jsonb_build_object('channel', c.channel, 'uid', case when auth.uid() = c.user_id then 1 else 2 end, 'remaining', floor(rem));
end $$;

-- Ends a call and settles it exactly once, using SERVER time
create or replace function public.end_call(p_call_id uuid, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
declare c public.call_sessions; secs int; mins int; bal bigint; why text := left(coalesce(p_reason, 'ended'), 60);
begin
  select * into c from public.call_sessions where id = p_call_id for update;
  if not found or auth.uid() not in (c.user_id, c.listener_id) then raise exception 'not allowed'; end if;
  if c.status in ('ended','declined','missed') then return; end if;
  if c.status = 'ringing' then
    update public.call_sessions set status = 'missed', ended_at = now(), termination_reason = why, billable_seconds = 0 where id = c.id;
    if c.call_type = 'DEMO' then
      update public.demo_entitlements set status = 'available', claimed_session_id = null where user_id = c.user_id and status = 'in_progress';
    end if;
    return;
  end if;
  secs := greatest(0, floor(extract(epoch from now() - c.started_at)))::int;
  if c.call_type = 'DEMO' then
    secs := least(secs, public.demo_limit());
    update public.demo_entitlements set status = 'used', consumed_at = now() where user_id = c.user_id;
  else
    select coalesce(sum(amount_paise), 0) into bal from public.wallet_ledger where user_id = c.user_id and account = 'wallet';
    mins := least(ceil(secs / 60.0)::int, (bal / 500)::int);          -- billed per started minute, never more than the balance
    if mins > 0 then
      insert into public.wallet_ledger (user_id, account, amount_paise, entry_type, idempotency_key, note)
        values (c.user_id, 'wallet', -mins * 500, 'call_debit', 'call_debit:' || c.id, mins || ' min at Rs 5/min');
      insert into public.wallet_ledger (user_id, account, amount_paise, entry_type, idempotency_key, note)
        values (c.listener_id, 'earnings', mins * 200, 'call_earning', 'call_earning:' || c.id, mins || ' min at Rs 2/min');
    end if;
    secs := least(secs, (bal / 500)::int * 60);
  end if;
  update public.call_sessions set status = 'ended', ended_at = now(), billable_seconds = secs, termination_reason = why where id = c.id;
end $$;

revoke all on function public.request_call(text), public.respond_call(uuid, boolean), public.call_token_info(uuid), public.end_call(uuid, text) from public, anon;
grant execute on function public.request_call(text), public.respond_call(uuid, boolean), public.call_token_info(uuid), public.end_call(uuid, text) to authenticated;
