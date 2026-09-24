-- Área de Membros — ReativaZap
-- Auth simples própria (sem Supabase Auth), senha com hash bcrypt.

create extension if not exists pgcrypto;

create table if not exists alunas (
  id uuid primary key default gen_random_uuid(),
  nome text not null,
  email text unique,
  whatsapp text unique not null,
  senha_hash text not null,
  precisa_trocar_senha boolean not null default true,
  criado_em timestamptz not null default now()
);

create table if not exists produtos (
  id uuid primary key default gen_random_uuid(),
  nome text not null,
  slug text unique not null,
  descricao text,
  cakto_offer_id text unique,
  checkout_url text not null,
  ativo boolean not null default true,
  criado_em timestamptz not null default now()
);

create table if not exists cursos (
  id uuid primary key default gen_random_uuid(),
  produto_id uuid not null references produtos(id) on delete cascade,
  titulo text not null,
  descricao text,
  ordem int not null default 0,
  criado_em timestamptz not null default now()
);

create table if not exists aulas (
  id uuid primary key default gen_random_uuid(),
  curso_id uuid not null references cursos(id) on delete cascade,
  titulo text not null,
  descricao text,
  youtube_video_id text not null,
  ordem int not null default 0,
  criado_em timestamptz not null default now()
);

-- Liberação: aluna comprou o produto X, ganha acesso a todos os cursos dele
create table if not exists acessos (
  id uuid primary key default gen_random_uuid(),
  aluna_id uuid not null references alunas(id) on delete cascade,
  produto_id uuid not null references produtos(id) on delete cascade,
  origem text not null default 'cakto',
  cakto_order_id text,
  status text not null default 'ativo' check (status in ('ativo','pausado','cancelado')),
  criado_em timestamptz not null default now(),
  unique (aluna_id, produto_id)
);

create table if not exists sessoes (
  token text primary key,
  aluna_id uuid not null references alunas(id) on delete cascade,
  criado_em timestamptz not null default now(),
  expira_em timestamptz not null
);

create index if not exists idx_aulas_curso on aulas(curso_id, ordem);
create index if not exists idx_cursos_produto on cursos(produto_id, ordem);
create index if not exists idx_acessos_aluna on acessos(aluna_id);
create index if not exists idx_sessoes_aluna on sessoes(aluna_id);
