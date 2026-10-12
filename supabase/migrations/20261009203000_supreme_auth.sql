alter table public.admin_users
  add column auth_user_id uuid unique references auth.users(id) on delete cascade,
  add column role text not null default 'admin' check (role in ('admin', 'supreme'));

alter table public.admin_users drop constraint admin_users_username_check;
alter table public.admin_users add constraint admin_users_username_check
  check (username ~ '^[A-Za-z0-9_.@+-]{3,254}$');
alter table public.admin_users add constraint admin_users_supreme_auth_check
  check ((role = 'supreme') = (auth_user_id is not null));
create unique index admin_users_one_supreme_idx on public.admin_users (role) where role = 'supreme';

insert into public.admin_users (username, password_hash, active, auth_user_id, role)
select 'admin@novabet.com', 'supabase-auth-only', true, id, 'supreme'
from auth.users
where lower(email) = 'admin@novabet.com' and email_confirmed_at is not null;

do $$
begin
  if not exists (select 1 from public.admin_users where role = 'supreme') then
    raise exception 'Confirmed Supabase Auth administrator is missing';
  end if;
end $$;
