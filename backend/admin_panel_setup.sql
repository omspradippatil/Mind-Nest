-- Admin panel RPC setup for Mind Nest
-- Run this in Supabase SQL Editor.

-- This setup is for the HTML admin panel login:
-- user id: sanika
-- password: om

create or replace function public.panel_admin_authorized(
  p_user text,
  p_password text
)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select
    lower(trim(coalesce(p_user, ''))) = 'sanika'
    and coalesce(p_password, '') = 'om';
$$;

revoke all on function public.panel_admin_authorized(text, text) from public;
grant execute on function public.panel_admin_authorized(text, text) to anon, authenticated;

create or replace function public.panel_admin_list_tables(
  p_user text,
  p_password text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  output jsonb;
begin
  if not public.panel_admin_authorized(p_user, p_password) then
    raise exception 'Admin access denied';
  end if;

  select coalesce(
    jsonb_agg(
      jsonb_build_object(
        'table', t.table_name,
        'columns', (
          select coalesce(
            jsonb_agg(
              jsonb_build_object(
                'name', c.column_name,
                'type', c.data_type,
                'nullable', c.is_nullable = 'YES'
              )
              order by c.ordinal_position
            ),
            '[]'::jsonb
          )
          from information_schema.columns c
          where c.table_schema = 'public'
            and c.table_name = t.table_name
        ),
        'rowEstimate', (
          select greatest(pc.reltuples::bigint, 0)
          from pg_class pc
          join pg_namespace pn on pn.oid = pc.relnamespace
          where pn.nspname = 'public'
            and pc.relname = t.table_name
          limit 1
        )
      )
      order by t.table_name
    ),
    '[]'::jsonb
  )
  into output
  from information_schema.tables t
  where t.table_schema = 'public'
    and t.table_type = 'BASE TABLE';

  return output;
end;
$$;

revoke all on function public.panel_admin_list_tables(text, text) from public;
grant execute on function public.panel_admin_list_tables(text, text) to anon, authenticated;

create or replace function public.panel_admin_table_rows(
  p_user text,
  p_password text,
  p_table text,
  p_limit int default 100,
  p_offset int default 0
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  rows_json jsonb;
  total_rows bigint;
  safe_limit int := least(greatest(coalesce(p_limit, 100), 1), 500);
  safe_offset int := greatest(coalesce(p_offset, 0), 0);
begin
  if not public.panel_admin_authorized(p_user, p_password) then
    raise exception 'Admin access denied';
  end if;

  if p_table is null or trim(p_table) = '' then
    raise exception 'Table name is required';
  end if;

  if not exists (
    select 1
    from information_schema.tables
    where table_schema = 'public'
      and table_name = p_table
      and table_type = 'BASE TABLE'
  ) then
    raise exception 'Unknown table: %', p_table;
  end if;

  execute format(
    'select coalesce(jsonb_agg(row_to_json(t)), ''[]''::jsonb) from (select * from %I limit %s offset %s) t',
    p_table,
    safe_limit,
    safe_offset
  )
  into rows_json;

  execute format('select count(*) from %I', p_table)
  into total_rows;

  return jsonb_build_object(
    'table', p_table,
    'limit', safe_limit,
    'offset', safe_offset,
    'total', total_rows,
    'rows', coalesce(rows_json, '[]'::jsonb)
  );
end;
$$;

revoke all on function public.panel_admin_table_rows(text, text, text, int, int) from public;
grant execute on function public.panel_admin_table_rows(text, text, text, int, int) to anon, authenticated;

create or replace function public.panel_admin_run_sql(
  p_user text,
  p_password text,
  p_sql text
)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  cleaned_sql text;
  first_keyword text;
  rows_json jsonb;
  affected bigint;
begin
  if not public.panel_admin_authorized(p_user, p_password) then
    raise exception 'Admin access denied';
  end if;

  cleaned_sql := trim(coalesce(p_sql, ''));
  if cleaned_sql = '' then
    raise exception 'SQL text cannot be empty';
  end if;

  cleaned_sql := regexp_replace(cleaned_sql, ';+[[:space:]]*$', '', 'g');
  first_keyword := lower(coalesce((regexp_match(cleaned_sql, '^[[:space:]]*([a-z]+)'))[1], ''));

  if first_keyword in ('select', 'with', 'values', 'explain') then
    execute format(
      'select coalesce(jsonb_agg(row_to_json(t)), ''[]''::jsonb) from (%s) t',
      cleaned_sql
    )
    into rows_json;

    return jsonb_build_object(
      'kind', 'rows',
      'rows', coalesce(rows_json, '[]'::jsonb)
    );
  end if;

  if first_keyword in ('insert', 'update', 'delete', 'create', 'alter', 'drop', 'truncate') then
    execute cleaned_sql;
    get diagnostics affected = row_count;

    return jsonb_build_object(
      'kind', 'command',
      'affectedRows', affected,
      'message', 'SQL command executed'
    );
  end if;

  raise exception 'Unsupported SQL command: %', coalesce(first_keyword, 'unknown');
end;
$$;

revoke all on function public.panel_admin_run_sql(text, text, text) from public;
grant execute on function public.panel_admin_run_sql(text, text, text) to anon, authenticated;
