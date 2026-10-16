-- Release-U migration 002. Run AFTER 001_init.sql (Supabase > SQL Editor > Run).

-- 1. No waitlist any more
drop table if exists public.waitlist;

-- 2. Free demo status (users can read it; only the server can change it)
create table public.demo_entitlements (
  user_id uuid primary key references auth.users(id) on delete cascade,
  status text not null default 'available'
    check (status in ('available','in_progress','used')),
  claimed_session_id uuid,
  consumed_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.demo_entitlements enable row level security;
create policy "read own demo status" on public.demo_entitlements for select to authenticated
  using (user_id = auth.uid());
grant select on public.demo_entitlements to authenticated;

-- accounts that already exist (for example yours)
insert into public.demo_entitlements (user_id)
  select id from auth.users on conflict do nothing;

-- new accounts get a profile AND one demo entitlement
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, public_alias)
  values (new.id, 'user_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
  insert into public.demo_entitlements (user_id) values (new.id);
  return new;
end $$;

-- 3. Admins can see applicant aliases
create policy "admins read profiles" on public.profiles for select to authenticated
  using (public.is_admin());

-- 4. Private storage for identity documents (5 MB, images or PDF)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('kyc', 'kyc', false, 5242880, array['image/jpeg','image/png','application/pdf'])
on conflict (id) do nothing;

create policy "upload own kyc" on storage.objects for insert to authenticated
  with check (bucket_id = 'kyc' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "read own or admin kyc" on storage.objects for select to authenticated
  using (bucket_id = 'kyc'
         and ((storage.foldername(name))[1] = auth.uid()::text or public.is_admin()));

-- 5. Every time an admin opens an ID document, it is written to the audit log
create or replace function public.log_kyc_access(p_application_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not authorized' using errcode = '42501'; end if;
  insert into public.audit_logs (actor_id, action, target_type, target_id, reason)
  values (auth.uid(), 'kyc_view', 'listener_application', p_application_id, 'document opened by admin');
end $$;
revoke all on function public.log_kyc_access(uuid) from public, anon;
grant execute on function public.log_kyc_access(uuid) to authenticated;
