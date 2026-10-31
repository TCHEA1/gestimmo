-- =====================================================================
-- GestImmo — base de données en ligne (Supabase / PostgreSQL)
-- Comptes, agences, données synchronisées, audit anti-fraude côté serveur
-- =====================================================================
create extension if not exists pgcrypto;

-- ---------- Tables ----------
create table if not exists public.plateforme(
  id int primary key default 1 check (id = 1),
  whatsapp text not null default '',
  message text not null default ''
);
insert into public.plateforme(id) values (1) on conflict do nothing;

create table if not exists public.organisations(
  id uuid primary key default gen_random_uuid(),
  nom text not null,
  tel text not null default '',
  statut text not null default 'en_attente' check (statut in ('en_attente','active','suspendue')),
  expire_le date,
  note text not null default '',
  code_invitation text unique not null default upper(substr(md5(gen_random_uuid()::text),1,8)),
  created_at timestamptz not null default now()
);

create table if not exists public.profiles(
  id uuid primary key references auth.users(id) on delete cascade,
  username text unique not null,
  nom text not null,
  tel text not null default '',
  role text not null check (role in ('plateforme','admin','gestionnaire')),
  org_id uuid not null references public.organisations(id) on delete cascade,
  actif boolean not null default true,
  created_at timestamptz not null default now()
);

create table if not exists public.org_data(
  org_id uuid primary key references public.organisations(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  version int not null default 0,
  updated_at timestamptz not null default now(),
  updated_by uuid
);

create table if not exists public.audit(
  id bigserial primary key,
  org_id uuid not null references public.organisations(id) on delete cascade,
  at timestamptz not null default now(),
  user_id uuid,
  kind text not null,
  ref text, num text, montant numeric, detail text
);
create index if not exists audit_org_at on public.audit(org_id, at desc);

create table if not exists public.org_backups(
  id bigserial primary key,
  org_id uuid not null references public.organisations(id) on delete cascade,
  jour date not null default current_date,
  version int, data jsonb,
  unique(org_id, jour)
);

create table if not exists public.pieces(
  id text primary key,
  org_id uuid not null references public.organisations(id) on delete cascade,
  data text not null,
  created_by uuid default auth.uid(),
  created_at timestamptz not null default now()
);

-- ---------- Fonctions utilitaires ----------
create or replace function public.my_org() returns uuid
language sql stable security definer set search_path = public as $$
  select org_id from profiles where id = auth.uid() and actif
$$;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from profiles where id = auth.uid() and actif
$$;

create or replace function public.is_platform() returns boolean
language sql stable security definer set search_path = public as $$
  select coalesce((select role = 'plateforme' from profiles where id = auth.uid() and actif), false)
$$;

create or replace function public.org_ok(o uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists(select 1 from organisations where id = o and statut = 'active'
                and (expire_le is null or expire_le >= current_date))
$$;

-- ---------- Sécurité des lignes (RLS) ----------
alter table public.plateforme    enable row level security;
alter table public.organisations enable row level security;
alter table public.profiles      enable row level security;
alter table public.org_data      enable row level security;
alter table public.audit         enable row level security;
alter table public.org_backups   enable row level security;
alter table public.pieces        enable row level security;

drop policy if exists plat_read on public.plateforme;
create policy plat_read on public.plateforme for select using (true);

drop policy if exists org_read on public.organisations;
create policy org_read on public.organisations for select using (id = public.my_org() or public.is_platform());

drop policy if exists prof_read on public.profiles;
create policy prof_read on public.profiles for select using (id = auth.uid() or org_id = public.my_org() or public.is_platform());

drop policy if exists data_read on public.org_data;
create policy data_read on public.org_data for select using (org_id = public.my_org() and public.org_ok(org_id));

drop policy if exists audit_read on public.audit;
create policy audit_read on public.audit for select using (org_id = public.my_org() and public.my_role() in ('admin','plateforme'));

drop policy if exists pieces_read on public.pieces;
create policy pieces_read on public.pieces for select using (org_id = public.my_org() and public.org_ok(org_id));
drop policy if exists pieces_ins on public.pieces;
create policy pieces_ins on public.pieces for insert with check (org_id = public.my_org() and public.org_ok(org_id));

-- Le code d'invitation n'est lisible que via les fonctions (réservé à l'admin)
revoke all on public.organisations from anon, authenticated;
grant select (id, nom, tel, statut, expire_le, created_at) on public.organisations to authenticated;
revoke insert, update, delete on public.profiles, public.org_data, public.audit, public.org_backups, public.plateforme from anon, authenticated;
revoke update, delete on public.pieces from anon, authenticated;
revoke all on public.org_backups from anon, authenticated;

-- ---------- Inscription ----------
create or replace function public.register_owner(p_username text, p_nom text, p_tel text, p_agence text)
returns json language plpgsql security definer set search_path = public as $$
declare o uuid; premier boolean; r text;
begin
  if auth.uid() is null then raise exception 'Non connecté'; end if;
  if exists(select 1 from profiles where id = auth.uid()) then raise exception 'Ce compte existe déjà'; end if;
  premier := not exists(select 1 from profiles where role = 'plateforme');
  insert into organisations(nom, tel, statut)
    values (coalesce(nullif(trim(p_agence), ''), trim(p_nom)), coalesce(p_tel, ''), case when premier then 'active' else 'en_attente' end)
    returning id into o;
  r := case when premier then 'plateforme' else 'admin' end;
  insert into profiles(id, username, nom, tel, role, org_id)
    values (auth.uid(), lower(trim(p_username)), trim(p_nom), coalesce(p_tel, ''), r, o);
  insert into org_data(org_id) values (o);
  insert into audit(org_id, user_id, kind, detail) values (o, auth.uid(), 'inscription', r || ' : ' || trim(p_nom));
  return json_build_object('role', r, 'org', o);
end $$;

create or replace function public.join_org(p_code text, p_username text, p_nom text, p_tel text)
returns json language plpgsql security definer set search_path = public as $$
declare o uuid;
begin
  if auth.uid() is null then raise exception 'Non connecté'; end if;
  if exists(select 1 from profiles where id = auth.uid()) then raise exception 'Ce compte existe déjà'; end if;
  select id into o from organisations where code_invitation = upper(trim(p_code)) and statut = 'active';
  if o is null then raise exception 'Code d''invitation invalide'; end if;
  insert into profiles(id, username, nom, tel, role, org_id)
    values (auth.uid(), lower(trim(p_username)), trim(p_nom), coalesce(p_tel, ''), 'gestionnaire', o);
  insert into audit(org_id, user_id, kind, detail) values (o, auth.uid(), 'membre', 'Nouveau gestionnaire : ' || trim(p_nom));
  return json_build_object('role', 'gestionnaire', 'org', o);
end $$;

create or replace function public.username_libre(p_username text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists(select 1 from profiles where username = lower(trim(p_username)))
$$;

-- ---------- Session ----------
create or replace function public.me() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object(
    'profile', json_build_object('id', p.id, 'username', p.username, 'nom', p.nom, 'tel', p.tel, 'role', p.role, 'actif', p.actif),
    'org', json_build_object('id', o.id, 'nom', o.nom, 'statut', o.statut, 'expire_le', o.expire_le,
                             'code', case when p.role in ('admin','plateforme') then o.code_invitation end),
    'ok', public.org_ok(o.id) and p.actif,
    'plateforme', (select json_build_object('whatsapp', whatsapp, 'message', message) from plateforme where id = 1))
  from profiles p join organisations o on o.id = p.org_id
  where p.id = auth.uid()
$$;

create or replace function public.contact_plateforme() returns json
language sql stable security definer set search_path = public as $$
  select json_build_object('whatsapp', whatsapp, 'message', message) from plateforme where id = 1
$$;

-- ---------- Données ----------
create or replace function public.get_data() returns json
language plpgsql stable security definer set search_path = public as $$
declare o uuid := public.my_org(); d org_data;
begin
  if o is null or not public.org_ok(o) then raise exception 'Accès refusé'; end if;
  select * into d from org_data where org_id = o;
  return json_build_object('data', d.data, 'version', d.version, 'updated_at', d.updated_at);
end $$;

create or replace function public.get_version() returns int
language sql stable security definer set search_path = public as $$
  select version from org_data where org_id = public.my_org() and public.org_ok(public.my_org())
$$;

create or replace function public.save_data(p_data jsonb, p_version int)
returns int language plpgsql security definer set search_path = public as $$
declare pr profiles; cur org_data; nv int;
begin
  select * into pr from profiles where id = auth.uid() and actif;
  if not found then raise exception 'Accès refusé'; end if;
  if not public.org_ok(pr.org_id) then raise exception 'Abonnement inactif'; end if;
  select * into cur from org_data where org_id = pr.org_id for update;
  if cur.version <> p_version then raise exception 'conflit'; end if;

  -- Règles anti-fraude imposées par le serveur pour les gestionnaires
  if pr.role = 'gestionnaire' then
    if exists(
      with o as (select x->>'id' id, x->>'montant' m from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
           n as (select x->>'id' id, x->>'montant' m from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x)
      select 1 from o left join n using (id) where n.id is null or n.m is distinct from o.m)
    then raise exception 'Interdit : un gestionnaire ne peut ni supprimer ni modifier un paiement'; end if;
    if exists(
      with o as (select x->>'id' id from jsonb_array_elements(coalesce(cur.data->'depenses','[]')) x),
           n as (select x->>'id' id from jsonb_array_elements(coalesce(p_data->'depenses','[]')) x)
      select 1 from o left join n using (id) where n.id is null)
    then raise exception 'Interdit : un gestionnaire ne peut pas supprimer une dépense'; end if;
    if exists(
      with o as (select x->>'id' id, x->'loyer' l, x->'charges' c, x->'revisions' r from jsonb_array_elements(coalesce(cur.data->'baux','[]')) x),
           n as (select x->>'id' id, x->'loyer' l, x->'charges' c, x->'revisions' r from jsonb_array_elements(coalesce(p_data->'baux','[]')) x)
      select 1 from o join n using (id) where n.l is distinct from o.l or n.c is distinct from o.c or n.r is distinct from o.r)
    then raise exception 'Interdit : un gestionnaire ne peut pas modifier un loyer'; end if;
  end if;

  -- Journal serveur (impossible à effacer depuis l'application)
  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x),
       a as (select x->>'id' id from jsonb_array_elements(coalesce(p_data->'annules','[]')) x)
  select pr.org_id, auth.uid(), case when a.id is not null then 'annulation' else 'suppression' end,
         o.x->>'recu', o.x->>'num', (o.x->>'montant')::numeric, 'Loyer ' || coalesce(o.x->>'mois', '')
  from o left join n using (id) left join a using (id) where n.id is null;

  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x)
  select pr.org_id, auth.uid(), 'modification', o.x->>'recu', o.x->>'num', (n.x->>'montant')::numeric,
         'Montant ' || (o.x->>'montant') || ' → ' || (n.x->>'montant')
  from o join n using (id) where (o.x->>'montant') is distinct from (n.x->>'montant');

  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x)
  select pr.org_id, auth.uid(), 'paiement', n.x->>'recu', min(n.x->>'num'), sum((n.x->>'montant')::numeric), min(n.x->>'mode')
  from n left join o using (id) where o.id is null group by n.x->>'recu';

  insert into audit(org_id, user_id, kind, ref, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'depenses','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'depenses','[]')) x)
  select pr.org_id, auth.uid(),
         case when n.id is null then 'depense_suppr' when o.id is null then 'depense' else 'depense_modif' end,
         coalesce(n.id, o.id), coalesce((n.x->>'montant')::numeric, (o.x->>'montant')::numeric),
         coalesce(n.x->>'libelle', o.x->>'libelle')
  from o full join n using (id)
  where n.id is null or o.id is null or (o.x->>'montant') is distinct from (n.x->>'montant');

  nv := cur.version + 1;
  update org_data set data = p_data, version = nv, updated_at = now(), updated_by = auth.uid() where org_id = pr.org_id;

  -- Sauvegarde automatique quotidienne (30 derniers jours)
  insert into org_backups(org_id, jour, version, data) values (pr.org_id, current_date, nv, p_data)
    on conflict (org_id, jour) do update set version = excluded.version, data = excluded.data;
  delete from org_backups where org_id = pr.org_id and jour < current_date - 30;
  return nv;
end $$;

-- ---------- Équipe (admin de l'agence) ----------
create or replace function public.team() returns json
language plpgsql stable security definer set search_path = public as $$
declare o uuid := public.my_org();
begin
  if o is null then raise exception 'Accès refusé'; end if;
  return (select coalesce(json_agg(json_build_object('id', id, 'username', username, 'nom', nom, 'tel', tel, 'role', role, 'actif', actif, 'created_at', created_at) order by created_at), '[]'::json)
          from profiles where org_id = o);
end $$;

create or replace function public.set_member(p_user uuid, p_actif boolean) returns void
language plpgsql security definer set search_path = public as $$
declare o uuid := public.my_org();
begin
  if public.my_role() not in ('admin','plateforme') then raise exception 'Réservé au Super admin'; end if;
  update profiles set actif = p_actif where id = p_user and org_id = o and role = 'gestionnaire';
  insert into audit(org_id, user_id, kind, ref, detail) values (o, auth.uid(), 'membre', p_user::text, case when p_actif then 'Gestionnaire réactivé' else 'Gestionnaire désactivé' end);
end $$;

create or replace function public.regen_code() returns text
language plpgsql security definer set search_path = public as $$
declare o uuid := public.my_org(); c text := upper(substr(md5(gen_random_uuid()::text), 1, 8));
begin
  if public.my_role() not in ('admin','plateforme') then raise exception 'Réservé au Super admin'; end if;
  update organisations set code_invitation = c where id = o;
  return c;
end $$;

create or replace function public.rename_org(p_nom text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if public.my_role() not in ('admin','plateforme') then raise exception 'Réservé au Super admin'; end if;
  update organisations set nom = trim(p_nom) where id = public.my_org();
end $$;

create or replace function public.audit_list(p_limit int default 300) returns json
language plpgsql stable security definer set search_path = public as $$
declare o uuid := public.my_org();
begin
  if public.my_role() not in ('admin','plateforme') then raise exception 'Réservé au Super admin'; end if;
  return (select coalesce(json_agg(r), '[]'::json) from (
    select a.at, a.kind, a.ref, a.num, a.montant, a.detail, p.nom as qui, p.role
    from audit a left join profiles p on p.id = a.user_id
    where a.org_id = o order by a.at desc limit p_limit) r);
end $$;

-- ---------- Console du propriétaire de la plateforme ----------
create or replace function public.platform_orgs() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return (select coalesce(json_agg(r order by r.created_at desc), '[]'::json) from (
    select o.id, o.nom, o.tel, o.statut, o.expire_le, o.note, o.created_at,
           (select json_build_object('nom', p.nom, 'username', p.username, 'tel', p.tel, 'role', p.role)
              from profiles p where p.org_id = o.id and p.role in ('admin','plateforme') order by p.created_at limit 1) as proprietaire,
           (select count(*) from profiles p where p.org_id = o.id) as membres,
           coalesce(jsonb_array_length(d.data->'immeubles'), 0) as immeubles,
           coalesce(jsonb_array_length(d.data->'logements'), 0) as logements,
           coalesce(jsonb_array_length(d.data->'locataires'), 0) as locataires,
           d.updated_at
    from organisations o left join org_data d on d.org_id = o.id) r);
end $$;

create or replace function public.platform_set(p_org uuid, p_statut text, p_expire date, p_note text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  update organisations set statut = p_statut, expire_le = p_expire, note = coalesce(p_note, '') where id = p_org;
  insert into audit(org_id, user_id, kind, detail) values (p_org, auth.uid(), 'abonnement',
    'Statut : ' || p_statut || coalesce(' — expire le ' || to_char(p_expire, 'DD/MM/YYYY'), ' — sans limite'));
end $$;

create or replace function public.platform_settings(p_whatsapp text, p_message text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  update plateforme set whatsapp = coalesce(p_whatsapp, ''), message = coalesce(p_message, '') where id = 1;
end $$;

-- ---------- Droits d'exécution ----------
revoke execute on all functions in schema public from public, anon;
grant execute on function public.register_owner(text,text,text,text), public.join_org(text,text,text,text),
  public.me(), public.get_data(), public.get_version(), public.save_data(jsonb,int), public.team(),
  public.set_member(uuid,boolean), public.regen_code(), public.rename_org(text), public.audit_list(int),
  public.platform_orgs(), public.platform_set(uuid,text,date,text), public.platform_settings(text,text),
  public.my_org(), public.my_role(), public.is_platform(), public.org_ok(uuid) to authenticated;
grant execute on function public.username_libre(text), public.contact_plateforme() to anon, authenticated;

-- ---------- Réinitialisation de mot de passe (sans e-mail) ----------
create or replace function public.reset_password(p_user uuid, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare moi profiles; cible profiles;
begin
  select * into moi from profiles where id = auth.uid() and actif;
  select * into cible from profiles where id = p_user;
  if moi.id is null or cible.id is null then raise exception 'Accès refusé'; end if;
  if length(coalesce(p_new, '')) < 6 then raise exception 'Mot de passe : 6 caractères minimum'; end if;
  if not ((moi.role in ('admin','plateforme') and cible.org_id = moi.org_id and cible.role = 'gestionnaire')
       or (moi.role = 'plateforme' and cible.role = 'admin')) then raise exception 'Accès refusé'; end if;
  update auth.users set encrypted_password = crypt(p_new, gen_salt('bf')), updated_at = now() where id = p_user;
  insert into audit(org_id, user_id, kind, ref, detail) values (cible.org_id, auth.uid(), 'membre', p_user::text, 'Mot de passe réinitialisé pour ' || cible.nom);
end $$;
grant execute on function public.reset_password(uuid, text) to authenticated;
