-- بازیابی نام کاربری و رمز ادمین اصلی با «کد بازیابی»
-- روی دیتابیسی که cm_roles.sql را قبلاً اجرا کرده، یک‌بار در Supabase > SQL Editor اجرا کنید.
-- کد بازیابی فقط به‌صورت هش (bcrypt) ذخیره می‌شود و در هر بازیابی موفق، کد جدید ساخته می‌شود.
-- ورود ناموفق به بازیابی: پس از ۵ تلاش، ۱۵ دقیقه قفل.

alter table public.cm_admin add column if not exists recovery_hash text;

create or replace function public.cm_norm_code(p text) returns text language sql immutable as $$
  select upper(regexp_replace(coalesce(p,''),'[^0-9A-Za-z]','','g')) $$;

create or replace function public.cm_new_code() returns text language sql volatile set search_path=public,extensions as $$
  select regexp_replace(upper(encode(extensions.gen_random_bytes(10),'hex')),'(.{4})(?=.)','\1-','g') $$;

-- ساخت ادمین (جایگزین نسخهٔ قبلی): حالا کد بازیابی هم برمی‌گرداند
create or replace function public.cm_setup_admin(p_user text, p_pass text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v_code text;
begin
  if exists(select 1 from public.cm_admin) then return jsonb_build_object('ok',false,'err','exists'); end if;
  if char_length(btrim(coalesce(p_user,'')))<3 or char_length(coalesce(p_pass,''))<8 then return jsonb_build_object('ok',false,'err','weak'); end if;
  v_code := public.cm_new_code();
  insert into public.cm_admin(username,pass_hash,recovery_hash)
    values(btrim(p_user), extensions.crypt(p_pass, extensions.gen_salt('bf')), extensions.crypt(public.cm_norm_code(v_code), extensions.gen_salt('bf')));
  return jsonb_build_object('ok',true,'recovery',v_code);
end $$;

-- ادمینِ واردشده کد بازیابی جدید می‌سازد (کد قبلی باطل می‌شود)
create or replace function public.cm_admin_make_recovery(p_token text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v public.cm_sessions; v_code text;
begin
  v := public.cm_session(p_token);
  if v.token is null or v.role<>'admin' then return jsonb_build_object('ok',false,'err','auth'); end if;
  v_code := public.cm_new_code();
  update public.cm_admin set recovery_hash=extensions.crypt(public.cm_norm_code(v_code), extensions.gen_salt('bf'));
  return jsonb_build_object('ok',true,'recovery',v_code);
end $$;

-- مرحلهٔ ۱ (قبل از ورود): بررسی کد و نمایش نام کاربری فعلی
create or replace function public.cm_recover_check(p_code text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v_c text := public.cm_norm_code(p_code); v_user text;
begin
  delete from public.cm_attempts where at<now()-interval '1 day';
  if (select count(*) from public.cm_attempts x where x.k='#recover#' and x.at>now()-interval '15 minutes')>=5 then return jsonb_build_object('ok',false,'err','locked'); end if;
  select username into v_user from public.cm_admin where v_c<>'' and recovery_hash is not null and recovery_hash=extensions.crypt(v_c,recovery_hash);
  if v_user is null then insert into public.cm_attempts(k) values('#recover#'); return jsonb_build_object('ok',false,'err','bad'); end if;
  return jsonb_build_object('ok',true,'username',v_user);
end $$;

-- مرحلهٔ ۲ (قبل از ورود): تعیین نام کاربری و رمز جدید؛ کد جدید برمی‌گردد و همهٔ نشست‌های ادمین بسته می‌شود
create or replace function public.cm_recover(p_code text, p_user text, p_pass text) returns jsonb language plpgsql security definer set search_path=public,extensions as $$
declare v_c text := public.cm_norm_code(p_code); v_u text := btrim(coalesce(p_user,'')); v_new text;
begin
  delete from public.cm_attempts where at<now()-interval '1 day';
  if (select count(*) from public.cm_attempts x where x.k='#recover#' and x.at>now()-interval '15 minutes')>=5 then return jsonb_build_object('ok',false,'err','locked'); end if;
  if v_c='' or not exists(select 1 from public.cm_admin where recovery_hash is not null and recovery_hash=extensions.crypt(v_c,recovery_hash)) then
    insert into public.cm_attempts(k) values('#recover#'); return jsonb_build_object('ok',false,'err','bad');
  end if;
  if char_length(v_u)<3 or char_length(coalesce(p_pass,''))<8 then return jsonb_build_object('ok',false,'err','weak'); end if;
  if exists(select 1 from public.cm_schools where lower(username)=lower(v_u)) then return jsonb_build_object('ok',false,'err','taken'); end if;
  v_new := public.cm_new_code();
  update public.cm_admin set username=v_u, pass_hash=extensions.crypt(p_pass, extensions.gen_salt('bf')),
    recovery_hash=extensions.crypt(public.cm_norm_code(v_new), extensions.gen_salt('bf'));
  delete from public.cm_sessions where role='admin';
  delete from public.cm_attempts where k='#recover#';
  return jsonb_build_object('ok',true,'recovery',v_new);
end $$;

-- دسترسی: توابع کمکی داخلی‌اند؛ فقط توابع API برای کلاینت باز می‌شوند
revoke execute on function public.cm_norm_code(text), public.cm_new_code() from public, anon, authenticated;
revoke execute on function public.cm_admin_make_recovery(text), public.cm_recover_check(text), public.cm_recover(text,text,text) from public;
grant execute on function public.cm_admin_make_recovery(text), public.cm_recover_check(text), public.cm_recover(text,text,text), public.cm_setup_admin(text,text) to anon, authenticated;

-- ─────────────────────────────────────────────────────────────
-- اضطراری (اگر ادمین فعلی هم رمز را فراموش کرده و هم کد بازیابی ندارد):
-- در SQL Editor خودِ Supabase (دسترسی مالک پروژه) این را با مقدار دلخواه اجرا کنید، بعد وارد شوید و کد بازیابی بسازید:
--   update public.cm_admin set username='NEWUSER', pass_hash=extensions.crypt('NEW-PASSWORD-8+', extensions.gen_salt('bf'));
--   delete from public.cm_sessions where role='admin';
