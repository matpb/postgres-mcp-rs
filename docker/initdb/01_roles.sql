-- Test-only roles. Never reuse these passwords.
CREATE ROLE mcp_ro LOGIN PASSWORD 'test-only-ro' CONNECTION LIMIT 20;
GRANT pg_read_all_data, pg_monitor TO mcp_ro;
ALTER ROLE mcp_ro SET default_transaction_read_only = on;

CREATE ROLE mcp_strict LOGIN PASSWORD 'test-only-strict' CONNECTION LIMIT 20;
GRANT CONNECT ON DATABASE appdb TO mcp_strict;
GRANT pg_read_all_stats TO mcp_strict;
ALTER ROLE mcp_strict SET default_transaction_read_only = on;

CREATE SCHEMA app;
GRANT USAGE ON SCHEMA app TO mcp_strict;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO mcp_strict;

CREATE TABLE app.items (id int PRIMARY KEY, name text NOT NULL, qty bigint, price numeric(12,2));
COMMENT ON TABLE app.items IS 'Demo inventory items';
INSERT INTO app.items SELECT g, 'item ' || g, g * 1000000000000, g * 1.5 FROM generate_series(1, 5000) g;
CREATE SEQUENCE app.item_seq;
