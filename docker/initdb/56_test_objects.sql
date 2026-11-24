\set ON_ERROR_STOP on
-- Objects the integration tests rely on, created before any test runs. Valid on every test server.
CREATE SCHEMA sess_test;
CREATE TYPE sess_test.mood AS ENUM ('sad', 'ok');
CREATE DOMAIN sess_test.posint AS int;
CREATE TYPE sess_test.pair AS (a int, b text);
CREATE TABLE sess_test.typed (mood sess_test.mood, dom sess_test.posint, pr sess_test.pair,
  moods sess_test.mood[], r int4range, mr int4multirange, iv int2vector, boxes box[],
  hs hstore, ct citext);
CREATE DOMAIN sess_test.dchain1 AS int;
CREATE DOMAIN sess_test.dchain2 AS sess_test.dchain1;
CREATE DOMAIN sess_test.dchain3 AS sess_test.dchain2;
CREATE DOMAIN sess_test.dchain4 AS sess_test.dchain3;
CREATE DOMAIN sess_test.dchain5 AS sess_test.dchain4;
CREATE DOMAIN sess_test.dchain6 AS sess_test.dchain5;
CREATE DOMAIN sess_test.dchain7 AS sess_test.dchain6;
CREATE DOMAIN sess_test.dchain8 AS sess_test.dchain7;
CREATE DOMAIN sess_test.dchain9 AS sess_test.dchain8;
CREATE DOMAIN sess_test.dchain10 AS sess_test.dchain9;
GRANT USAGE ON SCHEMA sess_test TO mcp_ro;
GRANT SELECT ON sess_test.typed TO mcp_ro;

-- Tries each session-level change a read-only transaction may still make; returns how many succeeded.
CREATE FUNCTION sess_test.leave_state() RETURNS int LANGUAGE plpgsql AS $fn$
DECLARE
  steps int := 0;
BEGIN
  BEGIN
    EXECUTE 'PREPARE pgmcp_leak AS SELECT 1';
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    EXECUTE 'DECLARE pgmcp_cur CURSOR WITH HOLD FOR SELECT 1';
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    EXECUTE 'LISTEN pgmcp_chan';
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    EXECUTE 'CREATE TEMP TABLE pgmcp_tmp(x int)';
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    EXECUTE 'SET SESSION work_mem = ''9MB''';
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    PERFORM set_config('work_mem', '9MB', false);
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  BEGIN
    PERFORM pg_advisory_lock(424242);
    steps := steps + 1;
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
  RETURN steps;
END
$fn$;
REVOKE EXECUTE ON FUNCTION sess_test.leave_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sess_test.leave_state() TO mcp_ro;

-- Role with CONNECT, USAGE on app and SELECT on app.items only.
CREATE ROLE mcp_min LOGIN PASSWORD 'test-only-min' CONNECTION LIMIT 20;
GRANT CONNECT ON DATABASE appdb TO mcp_min;
GRANT USAGE ON SCHEMA app TO mcp_min;
GRANT SELECT ON app.items TO mcp_min;

-- A table name that also exists in another schema (shop.orders).
CREATE TABLE app.orders (id int);

-- Partitioned table with 201 partitions, kept in shop_parts so that shop lists stay short.
CREATE SCHEMA shop_parts;
CREATE TABLE shop.many_parts (id int NOT NULL, note text) PARTITION BY RANGE (id);
DO $do$
BEGIN
  FOR i IN 0..200 LOOP
    EXECUTE format('CREATE TABLE shop_parts.many_parts_%s PARTITION OF shop.many_parts FOR VALUES FROM (%s) TO (%s)',
                   i, i * 10, i * 10 + 10);
  END LOOP;
END
$do$;
INSERT INTO shop.many_parts VALUES (5, 'first'), (1995, 'last');

-- Table with a dot and an uppercase letter in its name, and a column named like a keyword.
CREATE TABLE shop."Odd.Name" ("Select" int PRIMARY KEY, val text);
INSERT INTO shop."Odd.Name" VALUES (1, 'odd');

GRANT SELECT ON ALL TABLES IN SCHEMA shop TO mcp_strict;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO mcp_strict;
GRANT USAGE ON SCHEMA shop_parts TO mcp_strict;
GRANT SELECT ON ALL TABLES IN SCHEMA shop_parts TO mcp_strict;

-- Publications for the replication tests: one per kind of membership, the partition root and the leaves.
CREATE PUBLICATION pub_schema FOR TABLES IN SCHEMA app;
CREATE PUBLICATION pub_one FOR TABLE shop.customers;
CREATE PUBLICATION pub_root FOR TABLE shop.events WITH (publish_via_partition_root = true);
CREATE PUBLICATION pub_leaves FOR TABLE shop.events;
CREATE PUBLICATION pub_all FOR ALL TABLES;
