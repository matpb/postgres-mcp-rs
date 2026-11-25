\set ON_ERROR_STOP on
-- The README recipe for a read-only role, with the test substitutions.
-- tests/docs.rs checks that these statements equal the README block.
CREATE ROLE mcp_recipe LOGIN PASSWORD 'test-only-recipe' CONNECTION LIMIT 10;
ALTER ROLE mcp_recipe SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE appdb TO mcp_recipe;
GRANT USAGE ON SCHEMA app TO mcp_recipe;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO mcp_recipe;
ALTER DEFAULT PRIVILEGES FOR ROLE postgres IN SCHEMA app GRANT SELECT ON TABLES TO mcp_recipe;
-- optional: monitoring tools (other sessions' queries, statement statistics, settings)
GRANT pg_monitor TO mcp_recipe;
