\set ON_ERROR_STOP on
-- Creates pgmcp.read_log_file and pgmcp.list_log_files for reading the server log. Run as a superuser.
-- Idempotent. Grants no application role; see the commented examples at the end.

DO $do$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'pgmcp_log_reader') THEN
    CREATE ROLE pgmcp_log_reader NOLOGIN;
  END IF;
END
$do$;

CREATE SCHEMA IF NOT EXISTS pgmcp AUTHORIZATION CURRENT_USER;
REVOKE ALL ON SCHEMA pgmcp FROM PUBLIC;
GRANT USAGE ON SCHEMA pgmcp TO pgmcp_log_reader;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_read_binary_file(text, bigint, bigint, boolean) TO pgmcp_log_reader;
GRANT EXECUTE ON FUNCTION pg_catalog.pg_ls_logdir() TO pgmcp_log_reader;
-- log_directory is a superuser-only setting; the definer needs this to read it.
GRANT pg_read_all_settings TO pgmcp_log_reader;

CREATE OR REPLACE FUNCTION pgmcp.read_log_file(p_name text, p_offset bigint, p_length integer)
RETURNS bytea
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
DECLARE
  v_data bytea;
BEGIN
  IF p_name IS NULL OR p_name !~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
     OR p_offset IS NULL OR p_offset < 0
     OR p_length IS NULL OR p_length NOT BETWEEN 1 AND 1048576
     OR NOT EXISTS (SELECT 1 FROM pg_catalog.pg_ls_logdir() AS l WHERE l.name = p_name) THEN
    RAISE EXCEPTION 'invalid log file request' USING ERRCODE = '22023';
  END IF;
  v_data := pg_catalog.pg_read_binary_file(
    pg_catalog.current_setting('log_directory') || '/' || p_name, p_offset, p_length, true);
  RETURN COALESCE(v_data, ''::bytea);
END
$fn$;

CREATE OR REPLACE FUNCTION pgmcp.list_log_files()
RETURNS TABLE(name text, size bigint, modification timestamptz)
LANGUAGE sql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $fn$
  SELECT l.name, l.size, l.modification FROM pg_catalog.pg_ls_logdir() AS l
$fn$;

ALTER FUNCTION pgmcp.read_log_file(text, bigint, integer) OWNER TO pgmcp_log_reader;
ALTER FUNCTION pgmcp.list_log_files() OWNER TO pgmcp_log_reader;
REVOKE ALL ON FUNCTION pgmcp.read_log_file(text, bigint, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION pgmcp.list_log_files() FROM PUBLIC;

-- GRANT USAGE ON SCHEMA pgmcp TO your_mcp_role;
-- GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO your_mcp_role;
