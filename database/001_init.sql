-- Release-U: initial schema. Paste into Supabase > SQL Editor > Run.
-- Safe to run once on a fresh project.

create extension if not exists pgcrypto;

-- ============ WAITLIST (public can only ADD an email, never read) ============
create table public.waitlist (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  role text not null check (role in ('user','listener')),
  created_at timestamptz not null default now(),
  constraint waitlist_email_format
    check (email ~* '^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$' and length(email) <= 254)
);
create unique index waitlist_email_role_key on public.waitlist (lower(email), role);
alter table public.waitlist enable row level security;
create policy "anyone can join waitlist" on public.waitlist
  for insert to anon, authenticated with check (true);
grant insert on public.waitlist to anon, authenticated;
-- No select policy: only you (in the Supabase dashboard) can read the list.

-- ============ ADMINS ============
create table public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'reviewer'
    check (role in ('support','reviewer','finance','admin','super_admin')),
  created_at timestamptz not null default now()
);
alter table public.admin_users enable row level security;  -- no policies: API cannot touch it

create or replace function public.is_admin() returns boolean
language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.admin_users where user_id = auth.uid());
$$;

-- ============ PROFILES (anonymous alias; users see only their own) ============
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  public_alias text not null unique,
  account_role text not null default 'user' check (account_role in ('user','listener')),
  status text not null default 'active' check (status in ('active','suspended','deleted')),
  preferred_language text not null default 'en',
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "read own profile" on public.profiles for select to authenticated
  using (id = auth.uid());
create policy "update own profile" on public.profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
grant select on public.profiles to authenticated;
revoke update on public.profiles from anon, authenticated;
grant update (public_alias, preferred_language) on public.profiles to authenticated;
-- Users can NOT change their own role or status.

create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, public_alias)
  values (new.id, 'user_' || substr(replace(gen_random_uuid()::text, '-', ''), 1, 8));
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ============ CONSENTS (append-only record of what was accepted) ============
create table public.consents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  consent_type text not null
    check (consent_type in ('user_terms','listener_terms','privacy','disclaimer')),
  document_version text not null,
  locale text not null default 'en',
  accepted_at timestamptz not null default now()
);
alter table public.consents enable row level security;
create policy "add own consent" on public.consents for insert to authenticated
  with check (user_id = auth.uid());
create policy "read own consent" on public.consents for select to authenticated
  using (user_id = auth.uid());
grant select, insert on public.consents to authenticated;

-- ============ LISTENER APPLICATIONS ============
create table public.listener_applications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null unique references auth.users(id) on delete cascade,
  languages text[] not null default '{}',
  bio text check (length(bio) <= 500),
  gender_category text,                 -- voluntary, never inferred
  kyc_object_key text,                  -- path in a PRIVATE storage bucket
  status text not null default 'pending'
    check (status in ('pending','approved','rejected','more_info')),
  reviewer_id uuid,
  reviewed_at timestamptz,
  decision_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.listener_applications enable row level security;
create policy "apply as self" on public.listener_applications for insert to authenticated
  with check (user_id = auth.uid() and status = 'pending');
create policy "read own or admin" on public.listener_applications for select to authenticated
  using (user_id = auth.uid() or public.is_admin());
grant select, insert on public.listener_applications to authenticated;
-- No update policy: status can only change through decide_listener() below.

-- ============ AUDIT LOG (append-only) ============
create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  actor_id uuid,
  action text not null,
  target_type text,
  target_id uuid,
  reason text,
  old_value jsonb,
  new_value jsonb,
  created_at timestamptz not null default now()
);
alter table public.audit_logs enable row level security;
create policy "admins read audit" on public.audit_logs for select to authenticated
  using (public.is_admin());
grant select on public.audit_logs to authenticated;
revoke update, delete on public.audit_logs from anon, authenticated;

-- ============ ADMIN DECISION (reason required, audited) ============
create or replace function public.decide_listener(p_application_id uuid, p_decision text, p_reason text)
returns void language plpgsql security definer set search_path = public as $$
declare old_status text; app_user uuid;
begin
  if not public.is_admin() then raise exception 'not authorized' using errcode = '42501'; end if;
  if p_decision not in ('approved','rejected','more_info') then raise exception 'invalid decision'; end if;
  if coalesce(trim(p_reason), '') = '' then raise exception 'reason required'; end if;

  select status, user_id into old_status, app_user
  from public.listener_applications where id = p_application_id for update;
  if not found then raise exception 'application not found'; end if;

  update public.listener_applications
  set status = p_decision, reviewer_id = auth.uid(), reviewed_at = now(),
      decision_reason = p_reason, updated_at = now()
  where id = p_application_id;

  if p_decision = 'approved' then
    update public.profiles set account_role = 'listener' where id = app_user;
  end if;

  insert into public.audit_logs (actor_id, action, target_type, target_id, reason, old_value, new_value)
  values (auth.uid(), 'listener_decision', 'listener_application', p_application_id, p_reason,
          jsonb_build_object('status', old_status), jsonb_build_object('status', p_decision));
end $$;
revoke all on function public.decide_listener(uuid, text, text) from public, anon;
grant execute on function public.decide_listener(uuid, text, text) to authenticated;

-- ============ AFTER YOU SIGN UP ONCE, MAKE YOURSELF SUPER-ADMIN ============
-- Replace the email, then run this line separately:
-- insert into public.admin_users (user_id, role)
--   select id, 'super_admin' from auth.users where email = 'you@example.com';
