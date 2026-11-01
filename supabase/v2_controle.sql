-- =====================================================================
-- GestImmo v2 — suppression de comptes et contrôle total du propriétaire
-- (à exécuter après schema.sql ; peut être relancé sans risque)
-- =====================================================================

-- Archive des comptes supprimés (pour garder les noms dans l'historique)
create table if not exists public.anciens_membres(
  id uuid primary key,
  org_id uuid references public.organisations(id) on delete cascade,
  nom text, username text, role text,
  supprime_le timestamptz not null default now(),
  supprime_par uuid
);
alter table public.anciens_membres enable row level security;
revoke all on public.anciens_membres from anon, authenticated;

-- Le propriétaire de la plateforme peut lire / ajouter les photos de toutes les agences
drop policy if exists pieces_read on public.pieces;
create policy pieces_read on public.pieces for select using ((org_id = public.my_org() and public.org_ok(org_id)) or public.is_platform());
drop policy if exists pieces_ins on public.pieces;
create policy pieces_ins on public.pieces for insert with check ((org_id = public.my_org() and public.org_ok(org_id)) or public.is_platform());

-- ---------- Enregistrement des données (logique commune) ----------
create or replace function public._apply_save(p_org uuid, p_role text, p_data jsonb, p_version int)
returns int language plpgsql security definer set search_path = public as $$
declare cur org_data; nv int;
begin
  select * into cur from org_data where org_id = p_org for update;
  if not found then raise exception 'Agence introuvable'; end if;
  if cur.version <> p_version then raise exception 'conflit'; end if;

  if p_role = 'gestionnaire' then
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

  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x),
       a as (select x->>'id' id from jsonb_array_elements(coalesce(p_data->'annules','[]')) x)
  select p_org, auth.uid(), case when a.id is not null then 'annulation' else 'suppression' end,
         o.x->>'recu', o.x->>'num', (o.x->>'montant')::numeric, 'Loyer ' || coalesce(o.x->>'mois', '')
  from o left join n using (id) left join a using (id) where n.id is null;

  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x)
  select p_org, auth.uid(), 'modification', o.x->>'recu', o.x->>'num', (n.x->>'montant')::numeric,
         'Montant ' || (o.x->>'montant') || ' → ' || (n.x->>'montant')
  from o join n using (id) where (o.x->>'montant') is distinct from (n.x->>'montant');

  insert into audit(org_id, user_id, kind, ref, num, montant, detail)
  with o as (select x->>'id' id from jsonb_array_elements(coalesce(cur.data->'paiements','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'paiements','[]')) x)
  select p_org, auth.uid(), 'paiement', n.x->>'recu', min(n.x->>'num'), sum((n.x->>'montant')::numeric), min(n.x->>'mode')
  from n left join o using (id) where o.id is null group by n.x->>'recu';

  insert into audit(org_id, user_id, kind, ref, montant, detail)
  with o as (select x->>'id' id, x from jsonb_array_elements(coalesce(cur.data->'depenses','[]')) x),
       n as (select x->>'id' id, x from jsonb_array_elements(coalesce(p_data->'depenses','[]')) x)
  select p_org, auth.uid(),
         case when n.id is null then 'depense_suppr' when o.id is null then 'depense' else 'depense_modif' end,
         coalesce(n.id, o.id), coalesce((n.x->>'montant')::numeric, (o.x->>'montant')::numeric),
         coalesce(n.x->>'libelle', o.x->>'libelle')
  from o full join n using (id)
  where n.id is null or o.id is null or (o.x->>'montant') is distinct from (n.x->>'montant');

  nv := cur.version + 1;
  update org_data set data = p_data, version = nv, updated_at = now(), updated_by = auth.uid() where org_id = p_org;
  insert into org_backups(org_id, jour, version, data) values (p_org, current_date, nv, p_data)
    on conflict (org_id, jour) do update set version = excluded.version, data = excluded.data;
  delete from org_backups where org_id = p_org and jour < current_date - 30;
  return nv;
end $$;
revoke all on function public._apply_save(uuid, text, jsonb, int) from public, anon, authenticated;

create or replace function public.save_data(p_data jsonb, p_version int)
returns int language plpgsql security definer set search_path = public as $$
declare pr profiles;
begin
  select * into pr from profiles where id = auth.uid() and actif;
  if not found then raise exception 'Accès refusé'; end if;
  if not public.org_ok(pr.org_id) then raise exception 'Abonnement inactif'; end if;
  return public._apply_save(pr.org_id, pr.role, p_data, p_version);
end $$;

-- ---------- Équipe : inclut les comptes supprimés (pour les noms) ----------
create or replace function public.team() returns json
language plpgsql stable security definer set search_path = public as $$
declare o uuid := public.my_org();
begin
  if o is null then raise exception 'Accès refusé'; end if;
  return public._team(o);
end $$;

create or replace function public._team(o uuid) returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(x order by x.created_at), '[]'::json) from (
    select id, username, nom, tel, role, actif, false as supprime, created_at from profiles where org_id = o
    union all
    select id, username, nom, '' as tel, role, false, true, supprime_le from anciens_membres where org_id = o) x
$$;
revoke all on function public._team(uuid) from public, anon, authenticated;

create or replace function public.audit_list(p_limit int default 300) returns json
language plpgsql stable security definer set search_path = public as $$
declare o uuid := public.my_org();
begin
  if public.my_role() not in ('admin','plateforme') then raise exception 'Réservé au Super admin'; end if;
  return public._audit(o, p_limit);
end $$;

create or replace function public._audit(o uuid, p_limit int) returns json
language sql stable security definer set search_path = public as $$
  select coalesce(json_agg(r), '[]'::json) from (
    select a.at, a.kind, a.ref, a.num, a.montant, a.detail, coalesce(p.nom, am.nom) as qui, coalesce(p.role, am.role) as role
    from audit a left join profiles p on p.id = a.user_id left join anciens_membres am on am.id = a.user_id
    where a.org_id = o order by a.at desc limit p_limit) r
$$;
revoke all on function public._audit(uuid, int) from public, anon, authenticated;

-- ---------- Suppression d'un compte ----------
create or replace function public.delete_member(p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
declare moi profiles; cible profiles;
begin
  select * into moi from profiles where id = auth.uid() and actif;
  select * into cible from profiles where id = p_user;
  if moi.id is null then raise exception 'Accès refusé'; end if;
  if cible.id is null then raise exception 'Compte introuvable'; end if;
  if cible.id = moi.id then raise exception 'Vous ne pouvez pas supprimer votre propre compte'; end if;
  if cible.role = 'plateforme' then raise exception 'Le compte du propriétaire de la plateforme ne peut pas être supprimé'; end if;
  if not ((moi.role = 'admin' and cible.org_id = moi.org_id and cible.role = 'gestionnaire') or moi.role = 'plateforme') then
    raise exception 'Accès refusé'; end if;
  insert into anciens_membres(id, org_id, nom, username, role, supprime_par)
    values (cible.id, cible.org_id, cible.nom, cible.username, cible.role, moi.id) on conflict (id) do nothing;
  insert into audit(org_id, user_id, kind, ref, detail)
    values (cible.org_id, moi.id, 'membre', cible.id::text, 'Compte supprimé : ' || cible.nom || ' (' || cible.username || ', ' || cible.role || ')');
  delete from auth.users where id = p_user;
end $$;

-- ---------- Mot de passe : le propriétaire peut réinitialiser tout compte ----------
create or replace function public.reset_password(p_user uuid, p_new text) returns void
language plpgsql security definer set search_path = public, extensions as $$
declare moi profiles; cible profiles;
begin
  select * into moi from profiles where id = auth.uid() and actif;
  select * into cible from profiles where id = p_user;
  if moi.id is null or cible.id is null then raise exception 'Accès refusé'; end if;
  if length(coalesce(p_new, '')) < 6 then raise exception 'Mot de passe : 6 caractères minimum'; end if;
  if not ((moi.role in ('admin','plateforme') and cible.org_id = moi.org_id and cible.role = 'gestionnaire')
       or (moi.role = 'plateforme' and cible.role <> 'plateforme')) then raise exception 'Accès refusé'; end if;
  update auth.users set encrypted_password = crypt(p_new, gen_salt('bf')), updated_at = now() where id = p_user;
  insert into audit(org_id, user_id, kind, ref, detail) values (cible.org_id, auth.uid(), 'membre', p_user::text, 'Mot de passe réinitialisé pour ' || cible.nom);
end $$;

-- ---------- Contrôle total du propriétaire de la plateforme ----------
create or replace function public.platform_team(p_org uuid) returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return public._team(p_org);
end $$;

create or replace function public.platform_set_member(p_user uuid, p_actif boolean) returns void
language plpgsql security definer set search_path = public as $$
declare c profiles;
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  select * into c from profiles where id = p_user;
  if c.id is null or c.role = 'plateforme' then raise exception 'Compte introuvable'; end if;
  update profiles set actif = p_actif where id = p_user;
  insert into audit(org_id, user_id, kind, ref, detail) values (c.org_id, auth.uid(), 'membre', p_user::text,
    case when p_actif then 'Compte réactivé par GestImmo : ' else 'Compte désactivé par GestImmo : ' end || c.nom);
end $$;

create or replace function public.platform_get_data(p_org uuid) returns json
language plpgsql stable security definer set search_path = public as $$
declare d org_data;
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  select * into d from org_data where org_id = p_org;
  if not found then raise exception 'Agence introuvable'; end if;
  return json_build_object('data', d.data, 'version', d.version, 'updated_at', d.updated_at);
end $$;

create or replace function public.platform_get_version(p_org uuid) returns int
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return (select version from org_data where org_id = p_org);
end $$;

create or replace function public.platform_save_data(p_org uuid, p_data jsonb, p_version int) returns int
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return public._apply_save(p_org, 'plateforme', p_data, p_version);
end $$;

create or replace function public.platform_audit(p_org uuid, p_limit int default 300) returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return public._audit(p_org, p_limit);
end $$;

create or replace function public.delete_org(p_org uuid, p_confirm text) returns void
language plpgsql security definer set search_path = public as $$
declare o organisations;
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  select * into o from organisations where id = p_org;
  if o.id is null then raise exception 'Agence introuvable'; end if;
  if p_org = public.my_org() then raise exception 'Vous ne pouvez pas supprimer votre propre agence'; end if;
  if upper(trim(p_confirm)) <> upper(trim(o.nom)) then raise exception 'Le nom saisi ne correspond pas'; end if;
  if exists(select 1 from profiles where org_id = p_org and role = 'plateforme') then raise exception 'Impossible : agence du propriétaire de la plateforme'; end if;
  delete from auth.users where id in (select id from profiles where org_id = p_org);
  delete from organisations where id = p_org;
end $$;

revoke execute on function public.delete_member(uuid), public.platform_team(uuid), public.platform_set_member(uuid,boolean),
  public.platform_get_data(uuid), public.platform_get_version(uuid), public.platform_save_data(uuid,jsonb,int),
  public.platform_audit(uuid,int), public.delete_org(uuid,text) from public, anon;
grant execute on function public.save_data(jsonb,int), public.team(), public.audit_list(int), public.reset_password(uuid,text),
  public.delete_member(uuid), public.platform_team(uuid), public.platform_set_member(uuid,boolean),
  public.platform_get_data(uuid), public.platform_get_version(uuid), public.platform_save_data(uuid,jsonb,int),
  public.platform_audit(uuid,int), public.delete_org(uuid,text) to authenticated;

-- Console : ajoute l'identifiant du propriétaire de chaque agence
create or replace function public.platform_orgs() returns json
language plpgsql stable security definer set search_path = public as $$
begin
  if not public.is_platform() then raise exception 'Réservé au propriétaire de la plateforme'; end if;
  return (select coalesce(json_agg(r order by r.created_at desc), '[]'::json) from (
    select o.id, o.nom, o.tel, o.statut, o.expire_le, o.note, o.created_at,
           (select json_build_object('id', p.id, 'nom', p.nom, 'username', p.username, 'tel', p.tel, 'role', p.role)
              from profiles p where p.org_id = o.id and p.role in ('admin','plateforme') order by p.created_at limit 1) as proprietaire,
           (select count(*) from profiles p where p.org_id = o.id) as membres,
           coalesce(jsonb_array_length(d.data->'immeubles'), 0) as immeubles,
           coalesce(jsonb_array_length(d.data->'logements'), 0) as logements,
           coalesce(jsonb_array_length(d.data->'locataires'), 0) as locataires,
           d.updated_at
    from organisations o left join org_data d on d.org_id = o.id) r);
end $$;
