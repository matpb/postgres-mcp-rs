\set ON_ERROR_STOP on
-- Test roles may read the server log through the pgmcp functions from sql/log_reader.sql.
GRANT USAGE ON SCHEMA pgmcp TO mcp_ro, mcp_strict;
GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_ro, mcp_strict;
