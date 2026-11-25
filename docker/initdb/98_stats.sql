\set ON_ERROR_STOP on
-- Statistics for the statistics-view tests: a legitimate extended statistics object and analyzed catalogs.
-- CREATE STATISTICS on pg_authid needs allow_system_table_mods, so the catalogs are analyzed only.
CREATE STATISTICS app.items_stx (dependencies, mcv) ON name, qty FROM app.items;
ANALYZE app.items;
ANALYZE pg_catalog.pg_authid;
ANALYZE pg_catalog.pg_user_mapping;
ANALYZE pg_catalog.pg_subscription;
ANALYZE pg_catalog.pg_db_role_setting;
ANALYZE pg_catalog.pg_statistic;
ANALYZE pg_catalog.pg_statistic_ext_data;
ANALYZE pg_catalog.pg_largeobject;
