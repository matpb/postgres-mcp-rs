\set ON_ERROR_STOP on
-- A broad role whose search_path starts with a schema that defines an operator <> for name that always
-- returns true. The statistics-view filter must use pg_catalog's operator, whatever the search_path says.
CREATE ROLE mcp_path LOGIN PASSWORD 'test-only-path' CONNECTION LIMIT 5;
ALTER ROLE mcp_path SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE appdb TO mcp_path;
GRANT pg_read_all_data TO mcp_path;
CREATE SCHEMA trap;
CREATE FUNCTION trap.name_not_equal(a name, b name) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT true';
CREATE OPERATOR trap.<> (LEFTARG = name, RIGHTARG = name, FUNCTION = trap.name_not_equal);
ALTER ROLE mcp_path SET search_path = trap, public;
