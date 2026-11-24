\set ON_ERROR_STOP on
-- Schema for introspection: keys, indexes, partitions, inheritance, views, triggers, functions, RLS, LOs, FDW.
CREATE SCHEMA shop;

CREATE TABLE shop.customers (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  email citext UNIQUE NOT NULL,
  full_name text NOT NULL,
  tier text NOT NULL DEFAULT 'free' CHECK (tier IN ('free', 'pro')),
  created_at timestamptz NOT NULL DEFAULT '2024-01-01 00:00:00+00',
  name_upper text GENERATED ALWAYS AS (upper(full_name)) STORED
);
INSERT INTO shop.customers (email, full_name, tier)
SELECT 'user' || g || '@example.com', 'Customer ' || g, CASE WHEN g % 3 = 0 THEN 'pro' ELSE 'free' END
FROM generate_series(1, 100) AS g;
COMMENT ON TABLE shop.customers IS 'Customer accounts';
COMMENT ON COLUMN shop.customers.email IS 'Case-insensitive login email';

CREATE TABLE shop.orders (
  id bigserial PRIMARY KEY,
  customer_id bigint NOT NULL REFERENCES shop.customers (id) ON DELETE CASCADE,
  status text NOT NULL,
  total numeric(12, 2) NOT NULL,
  placed_at timestamptz NOT NULL,
  notes text COLLATE "C"
);
INSERT INTO shop.orders (customer_id, status, total, placed_at, notes)
SELECT ((g - 1) % 100) + 1,
       CASE g % 3 WHEN 0 THEN 'open' WHEN 1 THEN 'shipped' ELSE 'closed' END,
       (g * 37 % 100000) / 100.0,
       '2024-01-01 00:00:00+00'::timestamptz + g * interval '1 hour',
       CASE WHEN g % 5 = 0 THEN NULL ELSE 'note ' || g END
FROM generate_series(1, 1000) AS g;
CREATE INDEX orders_customer_placed_idx ON shop.orders (customer_id, placed_at DESC);
CREATE INDEX orders_open_placed_idx ON shop.orders (placed_at) WHERE status = 'open';
CREATE INDEX orders_lower_status_idx ON shop.orders (lower(status));
COMMENT ON TABLE shop.orders IS 'Orders placed by customers';
COMMENT ON COLUMN shop.orders.total IS 'Order total, two decimals';

CREATE TABLE shop.order_items (
  order_id bigint NOT NULL REFERENCES shop.orders (id) ON DELETE CASCADE,
  line_no int NOT NULL,
  customer_id bigint NOT NULL REFERENCES shop.customers (id),
  sku text NOT NULL,
  qty int NOT NULL,
  PRIMARY KEY (order_id, line_no)
);
INSERT INTO shop.order_items (order_id, line_no, customer_id, sku, qty)
SELECT o.id, l.n, o.customer_id, 'SKU-' || lpad((o.id * 3 + l.n)::text, 5, '0'), l.n
FROM shop.orders AS o CROSS JOIN generate_series(1, 3) AS l (n);
COMMENT ON TABLE shop.order_items IS 'Lines of an order';
COMMENT ON COLUMN shop.order_items.qty IS 'Quantity ordered';

CREATE TABLE shop.events (
  id bigint,
  happened_at timestamptz NOT NULL,
  kind text,
  payload jsonb
) PARTITION BY RANGE (happened_at);
CREATE TABLE shop.events_2024_q1 PARTITION OF shop.events
  FOR VALUES FROM ('2024-01-01 00:00:00+00') TO ('2024-04-01 00:00:00+00');
CREATE TABLE shop.events_2024_q2 PARTITION OF shop.events
  FOR VALUES FROM ('2024-04-01 00:00:00+00') TO ('2024-07-01 00:00:00+00');
CREATE TABLE shop.events_default PARTITION OF shop.events DEFAULT;
INSERT INTO shop.events (id, happened_at, kind, payload)
SELECT g, '2023-10-01 00:00:00+00'::timestamptz + g * interval '1 day',
       CASE g % 2 WHEN 0 THEN 'click' ELSE 'view' END,
       jsonb_build_object('n', g)
FROM generate_series(1, 300) AS g;
COMMENT ON TABLE shop.events IS 'Range-partitioned event log';
COMMENT ON TABLE shop.events_2024_q1 IS 'Events in 2024 Q1';
COMMENT ON TABLE shop.events_2024_q2 IS 'Events in 2024 Q2';
COMMENT ON TABLE shop.events_default IS 'Events outside 2024 Q1 and Q2';
COMMENT ON COLUMN shop.events.kind IS 'Event kind';
COMMENT ON COLUMN shop.events_2024_q1.id IS 'Event id, Q1 partition';
COMMENT ON COLUMN shop.events_2024_q2.id IS 'Event id, Q2 partition';
COMMENT ON COLUMN shop.events_default.id IS 'Event id, default partition';

CREATE TABLE shop.audit_base (id bigint, note text);
CREATE TABLE shop.audit_child (extra text) INHERITS (shop.audit_base);
INSERT INTO shop.audit_base (id, note) VALUES (1, 'base row');
INSERT INTO shop.audit_child (id, note, extra) VALUES (2, 'child row', 'extra');
COMMENT ON TABLE shop.audit_base IS 'Audit records (parent)';
COMMENT ON TABLE shop.audit_child IS 'Audit records with extra data (child)';
COMMENT ON COLUMN shop.audit_base.note IS 'Free-text note';
COMMENT ON COLUMN shop.audit_child.extra IS 'Extra child-only data';

CREATE VIEW shop.open_orders AS
  SELECT id, customer_id, total, placed_at FROM shop.orders WHERE status = 'open';
COMMENT ON VIEW shop.open_orders IS 'Orders with status open';

CREATE MATERIALIZED VIEW shop.customer_totals AS
  SELECT customer_id, count(*) AS order_count, sum(total) AS total_amount
  FROM shop.orders GROUP BY customer_id WITH DATA;
CREATE UNIQUE INDEX customer_totals_customer_idx ON shop.customer_totals (customer_id);
COMMENT ON MATERIALIZED VIEW shop.customer_totals IS 'Per-customer order totals';

CREATE FUNCTION shop.touch_order() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  RETURN NEW;
END
$fn$;
CREATE TRIGGER orders_touch BEFORE UPDATE ON shop.orders
  FOR EACH ROW EXECUTE FUNCTION shop.touch_order();

CREATE FUNCTION shop.order_total(bigint) RETURNS numeric LANGUAGE sql STABLE AS $fn$
  SELECT COALESCE(sum(total), 0) FROM shop.orders WHERE customer_id = $1
$fn$;
COMMENT ON FUNCTION shop.order_total(bigint) IS 'Sum of order totals for one customer';

CREATE FUNCTION shop.secret_fn() RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $fn$
BEGIN
  RETURN 'pgmcp secret';
END
$fn$;

CREATE PROCEDURE shop.noop() LANGUAGE plpgsql AS $fn$
BEGIN
  NULL;
END
$fn$;

CREATE FUNCTION shop.fmt(int) RETURNS text LANGUAGE sql IMMUTABLE AS $fn$
  SELECT 'int:' || $1::text
$fn$;
CREATE FUNCTION shop.fmt(text) RETURNS text LANGUAGE sql IMMUTABLE AS $fn$
  SELECT 'text:' || $1
$fn$;

CREATE TABLE shop.tenant_data (tenant text, v int);
ALTER TABLE shop.tenant_data ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON shop.tenant_data USING (tenant = current_user);
INSERT INTO shop.tenant_data (tenant, v) VALUES ('mcp_ro', 1), ('mcp_ro', 2), ('mcp_strict', 3), ('other', 4);
COMMENT ON TABLE shop.tenant_data IS 'Row-level security demo';
COMMENT ON COLUMN shop.tenant_data.tenant IS 'Matched against current_user by the policy';

CREATE SEQUENCE shop.invoice_seq;
COMMENT ON SEQUENCE shop.invoice_seq IS 'Invoice numbers';

CREATE TABLE shop.blobs (id int PRIMARY KEY, lo oid);
INSERT INTO shop.blobs (id, lo) VALUES (1, lo_from_bytea(0, 'pgmcp large object'));
COMMENT ON TABLE shop.blobs IS 'Large object references';
COMMENT ON COLUMN shop.blobs.lo IS 'OID of a large object';

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgres_fdw') THEN
    CREATE SERVER loopback FOREIGN DATA WRAPPER postgres_fdw
      OPTIONS (host '127.0.0.1', dbname 'appdb', port '5432');
    CREATE USER MAPPING FOR postgres SERVER loopback
      OPTIONS (user 'postgres', password 'test-only-superuser');
    CREATE USER MAPPING FOR mcp_ro SERVER loopback
      OPTIONS (user 'mcp_ro', password 'test-only-ro', password_required 'false');
    CREATE FOREIGN TABLE shop.items_remote (id int, name text, qty bigint, price numeric(12, 2))
      SERVER loopback OPTIONS (schema_name 'app', table_name 'items');
    COMMENT ON FOREIGN TABLE shop.items_remote IS 'app.items over a loopback connection';
    COMMENT ON COLUMN shop.items_remote.name IS 'Item name';
  END IF;
END
$do$;

CREATE FUNCTION shop.pgmcp_noop_evt_fn() RETURNS event_trigger LANGUAGE plpgsql AS $fn$
BEGIN
  NULL;
END
$fn$;
CREATE EVENT TRIGGER pgmcp_noop_evt ON ddl_command_end
  EXECUTE FUNCTION shop.pgmcp_noop_evt_fn();

GRANT USAGE ON SCHEMA shop, types TO mcp_strict;
GRANT SELECT ON ALL TABLES IN SCHEMA shop, types TO mcp_strict;
