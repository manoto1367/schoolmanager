-- مدیریت کلاس: ادمین اصلی + مدیر مدرسه (جدول‌ها و توابع cm_*)
-- جدول‌ها RLS دارند و policy ندارند؛ فقط از طریق توابع زیر قابل دسترسی‌اند.
create table if not exists public.cm_admin(id int primary key default 1 check (id=1), username text not null, pass_hash text not null, created_at timestamptz not null default now());
create table if not exists public.cm_schools(
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 2 and 120),
  username text not null unique, pass_hash text not null,
  slug text not null unique default encode(extensions.gen_random_bytes(9),'hex'),
  tabs int[] not null default '{0,1,2,3,4,5,6,7,8,9,10,11,12,13}',
  active boolean not null default true, data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table if not exists public.cm_sessions(token text primary key, role text not null check (role in ('admin','school')), school_id uuid references public.cm_schools(id) on delete cascade, expires_at timestamptz not null);
create table if not exists public.cm_attempts(id bigint generated always as identity primary key, k text not null, at timestamptz not null default now());
alter table public.cm_admin enable row level security; alter table public.cm_schools enable row level security;
alter table public.cm_sessions enable row level security; alter table public.cm_attempts enable row level security;
revoke all on public.cm_admin, public.cm_schools, public.cm_sessions, public.cm_attempts from public, anon, authenticated;

create or replace function public.cm_session(p_token text) returns public.cm_sessions language sql stable security definer set search_path=public,extensions as $$
  select s.* from public.cm_sessions s left join public.cm_schools c on c.id=s.school_id
  where s.token=p_token and s.expires_at>now() and (s.role='admin' or c.active) limit 1 $$;
create or replace function public.cm_has_admin() returns boolean language sql stable security definer set search_path=public as $$ select exists(select 1 from public.cm_admin) $$;
create or replace function public.cm_setup_admin(p_user text, p_pass text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
begin
  if exists(select 1 from public.cm_admin) then return jsonb_build_object('ok',false,'err','exists'); end if;
  if char_length(btrim(coalesce(p_user,'')))<3 or char_length(coalesce(p_pass,''))<8 then return jsonb_build_object('ok',false,'err','weak'); end if;
  insert into public.cm_admin(username,pass_hash) values(btrim(p_user), extensions.crypt(p_pass, extensions.gen_salt('bf')));
  return jsonb_build_object('ok',true);
end $$;
create or replace function public.cm_login(p_user text, p_pass text, p_slug text default null) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v_k text := lower(btrim(coalesce(p_user,''))); a public.cm_admin; s public.cm_schools; t text;
begin
  delete from public.cm_sessions where expires_at<now();
  delete from public.cm_attempts where at<now()-interval '1 day';
  if v_k='' or coalesce(p_pass,'')='' then return jsonb_build_object('ok',false,'err','bad'); end if;
  if (select count(*) from public.cm_attempts x where x.k=v_k and x.at>now()-interval '15 minutes')>=8 then return jsonb_build_object('ok',false,'err','locked'); end if;
  t := encode(extensions.gen_random_bytes(24),'hex');
  select * into a from public.cm_admin where lower(username)=v_k and pass_hash=extensions.crypt(p_pass,pass_hash);
  if found and coalesce(p_slug,'')='' then
    insert into public.cm_sessions(token,role,expires_at) values(t,'admin',now()+interval '30 days');
    delete from public.cm_attempts x where x.k=v_k;
    return jsonb_build_object('ok',true,'token',t,'role','admin');
  end if;
  select * into s from public.cm_schools where lower(username)=v_k and active and pass_hash=extensions.crypt(p_pass,pass_hash) and (coalesce(p_slug,'')='' or slug=p_slug);
  if found then
    insert into public.cm_sessions(token,role,school_id,expires_at) values(t,'school',s.id,now()+interval '30 days');
    delete from public.cm_attempts x where x.k=v_k;
    return jsonb_build_object('ok',true,'token',t,'role','school','school',jsonb_build_object('id',s.id,'name',s.name,'tabs',to_jsonb(s.tabs)));
  end if;
  insert into public.cm_attempts(k) values(v_k);
  return jsonb_build_object('ok',false,'err','bad');
end $$;
create or replace function public.cm_me(p_token text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions; s public.cm_schools;
begin
  v := public.cm_session(p_token);
  if v.token is null then return jsonb_build_object('ok',false,'err','auth'); end if;
  if v.role='admin' then return jsonb_build_object('ok',true,'role','admin'); end if;
  select * into s from public.cm_schools where id=v.school_id;
  return jsonb_build_object('ok',true,'role','school','school',jsonb_build_object('id',s.id,'name',s.name,'tabs',to_jsonb(s.tabs)));
end $$;
create or replace function public.cm_school_info(p_slug text) returns jsonb language sql stable security definer set search_path=public as $$
  select coalesce((select jsonb_build_object('ok',true,'name',name) from public.cm_schools where slug=p_slug and active), jsonb_build_object('ok',false)) $$;
create or replace function public.cm_list_schools(p_token text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions;
begin
  v := public.cm_session(p_token);
  if v.token is null or v.role<>'admin' then return jsonb_build_object('ok',false,'err','auth'); end if;
  return jsonb_build_object('ok',true,'schools',coalesce((select jsonb_agg(jsonb_build_object('id',id,'name',name,'username',username,'slug',slug,'tabs',to_jsonb(tabs),'active',active,'updated_at',updated_at) order by created_at) from public.cm_schools),'[]'::jsonb));
end $$;
create or replace function public.cm_save_school(p_token text, p_id uuid, p_name text, p_user text, p_pass text, p_tabs int[], p_active boolean) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions; v_u text := btrim(coalesce(p_user,'')); r public.cm_schools;
begin
  v := public.cm_session(p_token);
  if v.token is null or v.role<>'admin' then return jsonb_build_object('ok',false,'err','auth'); end if;
  if char_length(btrim(coalesce(p_name,'')))<2 or char_length(v_u)<3 then return jsonb_build_object('ok',false,'err','bad'); end if;
  if exists(select 1 from public.cm_admin where lower(username)=lower(v_u)) then return jsonb_build_object('ok',false,'err','taken'); end if;
  begin
    if p_id is null then
      if char_length(coalesce(p_pass,''))<6 then return jsonb_build_object('ok',false,'err','weak'); end if;
      insert into public.cm_schools(name,username,pass_hash,tabs,active) values(btrim(p_name),v_u,extensions.crypt(p_pass,extensions.gen_salt('bf')),coalesce(p_tabs,'{}'),coalesce(p_active,true)) returning * into r;
    else
      update public.cm_schools set name=btrim(p_name), username=v_u, tabs=coalesce(p_tabs,'{}'), active=coalesce(p_active,true),
        pass_hash=case when coalesce(p_pass,'')<>'' then extensions.crypt(p_pass,extensions.gen_salt('bf')) else pass_hash end
      where id=p_id returning * into r;
      if r.id is null then return jsonb_build_object('ok',false,'err','nf'); end if;
      if coalesce(p_pass,'')<>'' or not r.active then delete from public.cm_sessions where school_id=r.id; end if;
    end if;
  exception when unique_violation then return jsonb_build_object('ok',false,'err','taken');
  end;
  return jsonb_build_object('ok',true,'id',r.id,'slug',r.slug);
end $$;
create or replace function public.cm_delete_school(p_token text, p_id uuid) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions;
begin
  v := public.cm_session(p_token);
  if v.token is null or v.role<>'admin' then return jsonb_build_object('ok',false,'err','auth'); end if;
  delete from public.cm_schools where id=p_id;
  return jsonb_build_object('ok',true);
end $$;
create or replace function public.cm_get_data(p_token text, p_school uuid default null) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions; s public.cm_schools;
begin
  v := public.cm_session(p_token);
  if v.token is null then return jsonb_build_object('ok',false,'err','auth'); end if;
  select * into s from public.cm_schools where id=case when v.role='admin' then p_school else v.school_id end;
  if s.id is null then return jsonb_build_object('ok',false,'err','nf'); end if;
  return jsonb_build_object('ok',true,'id',s.id,'name',s.name,'tabs',to_jsonb(s.tabs),'data',s.data,'updated_at',s.updated_at);
end $$;
create or replace function public.cm_put_data(p_token text, p_school uuid, p_data jsonb, p_base timestamptz default null) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions; s public.cm_schools; n timestamptz := clock_timestamp();
begin
  v := public.cm_session(p_token);
  if v.token is null then return jsonb_build_object('ok',false,'err','auth'); end if;
  select * into s from public.cm_schools where id=case when v.role='admin' then p_school else v.school_id end for update;
  if s.id is null then return jsonb_build_object('ok',false,'err','nf'); end if;
  if p_base is not null and p_base<>s.updated_at then return jsonb_build_object('ok',false,'err','conflict'); end if;
  if octet_length(p_data::text)>9000000 then return jsonb_build_object('ok',false,'err','big'); end if;
  update public.cm_schools set data=p_data, updated_at=n where id=s.id;
  return jsonb_build_object('ok',true,'updated_at',n);
end $$;
create or replace function public.cm_admin_set(p_token text, p_user text, p_pass text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions;
begin
  v := public.cm_session(p_token);
  if v.token is null or v.role<>'admin' then return jsonb_build_object('ok',false,'err','auth'); end if;
  if char_length(btrim(coalesce(p_user,'')))<3 or char_length(coalesce(p_pass,''))<8 then return jsonb_build_object('ok',false,'err','weak'); end if;
  if exists(select 1 from public.cm_schools where lower(username)=lower(btrim(p_user))) then return jsonb_build_object('ok',false,'err','taken'); end if;
  update public.cm_admin set username=btrim(p_user), pass_hash=extensions.crypt(p_pass,extensions.gen_salt('bf'));
  return jsonb_build_object('ok',true);
end $$;
create or replace function public.cm_logout(p_token text) returns void language sql security definer set search_path=public as $$ delete from public.cm_sessions where token=p_token $$;

-- دسترسی: فقط توابع API برای کلاینت؛ cm_session داخلی است. (فقط روی توابع cm_* اعمال می‌شود)
revoke execute on function public.cm_session(text) from public, anon, authenticated;
do $$ declare r record; begin
  for r in select p.oid::regprocedure f from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public' and p.proname like 'cm\_%' and p.proname<>'cm_session' loop
    execute format('revoke execute on function %s from public', r.f);
    execute format('grant execute on function %s to anon, authenticated', r.f);
  end loop;
end $$;
