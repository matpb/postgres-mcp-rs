\set ON_ERROR_STOP on
-- Statement activity for pg_stat_statements; the caught error is handled inside the DO block.
SELECT count(*) FROM app.items;
SELECT max(price) FROM app.items;
SELECT count(*) FROM shop.customers;
SELECT 1 AS one;

DO $do$
BEGIN
  PERFORM 1 / 0;
EXCEPTION WHEN division_by_zero THEN
  NULL;
END
$do$;
