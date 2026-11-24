\set ON_ERROR_STOP on
-- Hostile public functions: they win unqualified calls with a matching argument type. Only mcp_strict's
-- role search_path reaches them; the server's internal SQL must not. Every body raises the marker.
CREATE OR REPLACE FUNCTION public.starts_with(name, text) RETURNS boolean LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$;
CREATE OR REPLACE FUNCTION public.lower(name) RETURNS text LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$;
CREATE OR REPLACE FUNCTION public.strpos(name, text) RETURNS int LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$;
CREATE OR REPLACE FUNCTION public.format_type(oid, int) RETURNS text LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$;
CREATE OR REPLACE FUNCTION public.pg_get_expr(pg_node_tree, oid) RETURNS text LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$;
ALTER ROLE mcp_strict IN DATABASE appdb SET search_path = public, pg_catalog;

-- Decoy log reader on PostgreSQL 19 only: not SECURITY DEFINER and not owned by pgmcp_log_reader.
SELECT current_setting('server_version_num')::int >= 190000 AS is19 \gset
\if :is19
\connect postgres
CREATE SCHEMA IF NOT EXISTS pgmcp AUTHORIZATION mcp_strict;
CREATE OR REPLACE FUNCTION pgmcp.read_log_file(p_name text, p_offset bigint, p_length integer)
RETURNS bytea LANGUAGE sql AS $$ SELECT NULL::bytea $$;
CREATE OR REPLACE FUNCTION pgmcp.list_log_files()
RETURNS TABLE(name text, size bigint, modification timestamptz)
LANGUAGE sql AS $$ SELECT NULL::text, NULL::bigint, NULL::timestamptz WHERE false $$;
ALTER FUNCTION pgmcp.read_log_file(text, bigint, integer) OWNER TO mcp_strict;
ALTER FUNCTION pgmcp.list_log_files() OWNER TO mcp_strict;
GRANT USAGE ON SCHEMA pgmcp TO mcp_ro;
GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_ro;
\connect appdb
\endif
