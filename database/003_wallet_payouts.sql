-- Release-U migration 003. Run AFTER 001 and 002 (Supabase > SQL Editor > Run).

-- 1. Preferences
alter table public.profiles
  add column preferred_listener_gender text not null default 'any'
    check (preferred_listener_gender in ('any','male','female')),
  add column listener_online boolean not null default false;
grant update (preferred_listener_gender) on public.profiles to authenticated;

create table public.voice_preferences (
  user_id uuid primary key references auth.users(id) on delete cascade,
  effect_preset text not null default 'natural'
    check (effect_preset in ('natural','deeper','higher','neutral')),
  updated_at timestamptz not null default now()
);
alter table public.voice_preferences enable row level security;
create policy "own voice prefs" on public.voice_preferences for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());
grant select, insert, update on public.voice_preferences to authenticated;

-- 2. Money ledger: append-only, integer paise. Users can only READ their own rows.
create table public.wallet_ledger (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  account text not null check (account in ('wallet','earnings')),
  amount_paise bigint not null check (amount_paise <> 0),
  entry_type text not null check (entry_type in
    ('topup','call_debit','call_earning','payout_hold','payout_release','adjustment')),
  idempotency_key text not null unique,
  note text,
  created_at timestamptz not null default now()
);
alter table public.wallet_ledger enable row level security;
create policy "read own ledger" on public.wallet_ledger for select to authenticated
  using (user_id = auth.uid());
grant select on public.wallet_ledger to authenticated;
revoke insert, update, delete on public.wallet_ledger from anon, authenticated;

create or replace function public.my_balance(p_account text) returns bigint
language sql stable as $$
  select coalesce(sum(amount_paise), 0)::bigint from public.wallet_ledger
  where user_id = auth.uid() and account = p_account;
$$;

-- 3. Admin credits a wallet AFTER you confirm the payment in the Razorpay dashboard.
--    The same payment ID can never be credited twice.
create or replace function public.admin_credit_wallet(
  p_alias text, p_amount_paise bigint, p_payment_ref text, p_reason text) returns void
language plpgsql security definer set search_path = public as $$
declare uid uuid;
begin
  if not exists (select 1 from public.admin_users
                 where user_id = auth.uid() and role in ('finance','admin','super_admin'))
    then raise exception 'not authorized' using errcode = '42501'; end if;
  if p_amount_paise <= 0 or p_amount_paise > 1000000 then raise exception 'amount out of range'; end if;
  if coalesce(trim(p_payment_ref),'') = '' or coalesce(trim(p_reason),'') = ''
    then raise exception 'payment reference and reason required'; end if;
  select id into uid from public.profiles where public_alias = p_alias;
  if not found then raise exception 'alias not found'; end if;
  insert into public.wallet_ledger (user_id, account, amount_paise, entry_type, idempotency_key, note)
  values (uid, 'wallet', p_amount_paise, 'topup', 'topup:' || trim(p_payment_ref), p_reason);
  insert into public.audit_logs (actor_id, action, target_type, target_id, reason, new_value)
  values (auth.uid(), 'wallet_credit', 'user', uid, p_reason,
          jsonb_build_object('amount_paise', p_amount_paise, 'payment_ref', trim(p_payment_ref)));
end $$;
revoke all on function public.admin_credit_wallet(text, bigint, text, text) from public, anon;
grant execute on function public.admin_credit_wallet(text, bigint, text, text) to authenticated;

-- 4. Listener payouts: minimum Rs 100, one open request at a time
create table public.payout_requests (
  id uuid primary key default gen_random_uuid(),
  listener_id uuid not null references auth.users(id),
  amount_paise bigint not null check (amount_paise >= 10000),
  upi_id text not null check (length(upi_id) between 5 and 100),
  status text not null default 'requested' check (status in ('requested','paid','rejected')),
  requested_at timestamptz not null default now(),
  reviewed_by uuid, reviewed_at timestamptz,
  provider_reference text, decision_reason text
);
alter table public.payout_requests enable row level security;
create policy "read own or admin payouts" on public.payout_requests for select to authenticated
  using (listener_id = auth.uid() or public.is_admin());
grant select on public.payout_requests to authenticated;

create or replace function public.request_payout(p_amount_paise bigint, p_upi text) returns void
language plpgsql security definer set search_path = public as $$
declare pid uuid;
begin
  perform pg_advisory_xact_lock(hashtext(auth.uid()::text));
  if not exists (select 1 from public.profiles
                 where id = auth.uid() and account_role = 'listener' and status = 'active')
    then raise exception 'only approved listeners can request payouts'; end if;
  if p_amount_paise < 10000 then raise exception 'minimum payout is Rs 100'; end if;
  if exists (select 1 from public.payout_requests where listener_id = auth.uid() and status = 'requested')
    then raise exception 'you already have a payout request in progress'; end if;
  if (select coalesce(sum(amount_paise),0) from public.wallet_ledger
      where user_id = auth.uid() and account = 'earnings') < p_amount_paise
    then raise exception 'not enough earnings'; end if;
  insert into public.payout_requests (listener_id, amount_paise, upi_id)
  values (auth.uid(), p_amount_paise, trim(p_upi)) returning id into pid;
  insert into public.wallet_ledger (user_id, account, amount_paise, entry_type, idempotency_key, note)
  values (auth.uid(), 'earnings', -p_amount_paise, 'payout_hold', 'payout:' || pid, 'Payout requested');
end $$;
revoke all on function public.request_payout(bigint, text) from public, anon;
grant execute on function public.request_payout(bigint, text) to authenticated;

create or replace function public.decide_payout(p_id uuid, p_decision text, p_note text) returns void
language plpgsql security definer set search_path = public as $$
declare r public.payout_requests;
begin
  if not exists (select 1 from public.admin_users
                 where user_id = auth.uid() and role in ('finance','admin','super_admin'))
    then raise exception 'not authorized' using errcode = '42501'; end if;
  if p_decision not in ('paid','rejected') then raise exception 'invalid decision'; end if;
  if coalesce(trim(p_note),'') = '' then raise exception 'note required (UPI reference or reason)'; end if;
  select * into r from public.payout_requests where id = p_id and status = 'requested' for update;
  if not found then raise exception 'request not found or already decided'; end if;
  update public.payout_requests
  set status = p_decision, reviewed_by = auth.uid(), reviewed_at = now(),
      provider_reference = case when p_decision = 'paid' then trim(p_note) end,
      decision_reason = case when p_decision = 'rejected' then trim(p_note) end
  where id = p_id;
  if p_decision = 'rejected' then
    insert into public.wallet_ledger (user_id, account, amount_paise, entry_type, idempotency_key, note)
    values (r.listener_id, 'earnings', r.amount_paise, 'payout_release', 'payout_release:' || p_id, 'Payout rejected');
  end if;
  insert into public.audit_logs (actor_id, action, target_type, target_id, reason, new_value)
  values (auth.uid(), 'payout_' || p_decision, 'payout_request', p_id, p_note,
          jsonb_build_object('amount_paise', r.amount_paise));
end $$;
revoke all on function public.decide_payout(uuid, text, text) from public, anon;
grant execute on function public.decide_payout(uuid, text, text) to authenticated;

-- 5. Only approved listeners can switch online
create or replace function public.set_listener_online(p_online boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set listener_online = p_online
  where id = auth.uid() and account_role = 'listener' and status = 'active';
  if not found then raise exception 'only approved listeners can go online'; end if;
end $$;
revoke all on function public.set_listener_online(boolean) from public, anon;
grant execute on function public.set_listener_online(boolean) to authenticated;
