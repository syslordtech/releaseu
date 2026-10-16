-- Release-U migration 004. Run AFTER 001-003. Gives admins the dashboard numbers.
create or replace function public.admin_stats() returns jsonb
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not authorized' using errcode = '42501'; end if;
  return jsonb_build_object(
    'users',               (select count(*) from public.profiles where account_role = 'user'),
    'listeners',           (select count(*) from public.profiles where account_role = 'listener'),
    'online_listeners',    (select count(*) from public.profiles where account_role = 'listener' and listener_online),
    'pending_applications',(select count(*) from public.listener_applications where status in ('pending','more_info')),
    'demos_used',          (select count(*) from public.demo_entitlements where status = 'used'),
    'topups_paise',        (select coalesce(sum(amount_paise), 0) from public.wallet_ledger where entry_type = 'topup'),
    'pending_payouts',     (select count(*) from public.payout_requests where status = 'requested'),
    'pending_payout_paise',(select coalesce(sum(amount_paise), 0) from public.payout_requests where status = 'requested'),
    'signups_7d',          (select coalesce(jsonb_agg(c order by d), '[]'::jsonb) from (
                              select g::date as d,
                                     (select count(*) from public.profiles p where p.created_at::date = g::date) as c
                              from generate_series(current_date - 6, current_date, interval '1 day') g) t));
end $$;
revoke all on function public.admin_stats() from public, anon;
grant execute on function public.admin_stats() to authenticated;
