\set ON_ERROR_STOP on
-- pageinspect and pg_walinspect let the gate tests prove that their functions are refused. A server that
-- does not ship an extension skips it with a notice.
DO $do$
DECLARE
  v_ext text;
BEGIN
  FOREACH v_ext IN ARRAY ARRAY['pageinspect', 'pg_walinspect'] LOOP
    IF EXISTS (SELECT 1 FROM pg_available_extensions WHERE name = v_ext) THEN
      EXECUTE format('CREATE EXTENSION IF NOT EXISTS %I', v_ext);
    ELSE
      RAISE NOTICE 'extension % is not shipped on this server; skipped', v_ext;
    END IF;
  END LOOP;
END
$do$;
