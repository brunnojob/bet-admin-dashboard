create table public.admin_users (
  id bigint generated always as identity primary key,
  username text not null unique check (username ~ '^[A-Za-z0-9_.-]{3,64}$'),
  password_hash text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create table public.admin_sessions (
  id bigint generated always as identity primary key,
  user_id bigint not null references public.admin_users(id) on delete cascade,
  token_hash text not null unique,
  csrf text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);
create index admin_sessions_user_id_idx on public.admin_sessions(user_id);
create index admin_sessions_expires_at_idx on public.admin_sessions(expires_at);
create table public.login_attempts (
  id bigint generated always as identity primary key,
  username text not null,
  success boolean not null,
  attempted_at timestamptz not null default now()
);
create index login_attempts_throttle_idx on public.login_attempts(username, attempted_at desc) where success = false;
create table public.sites (
  id bigint generated always as identity primary key,
  name text not null check (length(name) between 1 and 240),
  url text not null check (url ~ '^https?://'),
  status text not null default 'ativo' check (status in ('ativo','inativo')),
  created_at timestamptz not null default now()
);
create table public.domains (
  id bigint generated always as identity primary key,
  name text not null unique,
  site_id bigint references public.sites(id) on delete set null,
  status text not null default 'ativo' check (status in ('ativo','inativo')),
  created_at timestamptz not null default now()
);
create index domains_site_id_idx on public.domains(site_id);
create table public.transactions (
  id bigint generated always as identity primary key,
  kind text not null check (kind in ('deposito','saque')),
  customer text not null check (length(customer) between 1 and 240),
  amount bigint not null check (amount > 0 and amount <= 10000000000),
  status text not null default 'pendente' check (status in ('pendente','concluido','cancelado')),
  site_id bigint references public.sites(id) on delete set null,
  provider text not null default 'manual' check (provider in ('manual','mercado_pago')),
  provider_payment_id text unique,
  external_reference text unique,
  payment_method text,
  payer_email text,
  payer_document text,
  live_mode boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint completed_deposit_requires_provider check (kind <> 'deposito' or status <> 'concluido' or (provider = 'mercado_pago' and provider_payment_id is not null)),
  constraint withdrawals_require_payout check (kind <> 'saque' or status <> 'concluido')
);
create index transactions_site_id_idx on public.transactions(site_id);
create index transactions_created_at_idx on public.transactions(created_at);
create table public.audit (
  id bigint generated always as identity primary key,
  actor text not null,
  action text not null,
  created_at timestamptz not null default now()
);

do $$
declare t text;
begin
  foreach t in array array['admin_users','admin_sessions','login_attempts','sites','domains','transactions','audit'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('revoke all on table public.%I from public, anon, authenticated', t);
    execute format('grant select, insert, update, delete on table public.%I to service_role', t);
    execute format('revoke all on sequence public.%I from public, anon, authenticated', t || '_id_seq');
    execute format('grant usage, select on sequence public.%I to service_role', t || '_id_seq');
  end loop;
end $$;
revoke update, delete on public.audit from service_role;
