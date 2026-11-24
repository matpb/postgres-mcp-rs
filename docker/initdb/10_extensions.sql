\set ON_ERROR_STOP on
-- Extensions present on every target server; optional ones are gated by catalog checks.
CREATE EXTENSION IF NOT EXISTS hstore;
CREATE EXTENSION IF NOT EXISTS ltree;
CREATE EXTENSION IF NOT EXISTS citext;

DO $do$
DECLARE
  v_preloaded text[] := string_to_array(replace(current_setting('shared_preload_libraries'), ' ', ''), ',');
BEGIN
  IF 'pg_stat_statements' = ANY (v_preloaded)
     AND EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pg_stat_statements') THEN
    CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
  END IF;
  IF 'pgaudit' = ANY (v_preloaded)
     AND EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = 'pgaudit') THEN
    CREATE EXTENSION IF NOT EXISTS pgaudit;
  END IF;
END
$do$;

DO $do$
DECLARE
  v_ext text;
BEGIN
  FOREACH v_ext IN ARRAY ARRAY['timescaledb', 'postgis', 'vector', 'postgres_fdw'] LOOP
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = v_ext) THEN
      EXECUTE format('CREATE EXTENSION IF NOT EXISTS %I', v_ext);
    END IF;
  END LOOP;
END
$do$;
