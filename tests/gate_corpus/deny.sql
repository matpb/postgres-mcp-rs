-- code: statement_not_allowed
INSERT INTO t (a) VALUES (1);
--;;
-- code: statement_not_allowed
UPDATE t SET a = 1 WHERE b = 2;
--;;
-- code: statement_not_allowed
DELETE FROM t WHERE a = 1;
--;;
-- code: statement_not_allowed
MERGE INTO t USING s ON t.a = s.a WHEN MATCHED THEN DELETE;
--;;
-- code: statement_not_allowed
TRUNCATE t;
--;;
-- code: statement_not_allowed
CREATE TABLE t (a int);
--;;
-- code: statement_not_allowed
CREATE TABLE t2 AS SELECT 1 AS a;
--;;
-- code: statement_not_allowed
DROP TABLE t;
--;;
-- code: statement_not_allowed
ALTER TABLE t ADD COLUMN c int;
--;;
-- code: statement_not_allowed
GRANT SELECT ON t TO some_role;
--;;
-- code: statement_not_allowed
COMMENT ON TABLE t IS 'x';
--;;
-- code: statement_not_allowed
SET search_path = public;
--;;
-- code: statement_not_allowed
RESET ALL;
--;;
-- code: statement_not_allowed
SET TRANSACTION READ WRITE;
--;;
-- code: statement_not_allowed
BEGIN;
--;;
-- code: statement_not_allowed
COMMIT;
--;;
-- code: statement_not_allowed
ROLLBACK AND CHAIN;
--;;
-- code: statement_not_allowed
PREPARE TRANSACTION 'tx1';
--;;
-- code: statement_not_allowed
SAVEPOINT sp1;
--;;
-- code: statement_not_allowed
DO $$ BEGIN PERFORM 1; END $$;
--;;
-- code: statement_not_allowed
CALL some_proc(1);
--;;
-- code: statement_not_allowed
COPY t TO STDOUT;
--;;
-- code: statement_not_allowed
COPY t FROM '/tmp/x.csv';
--;;
-- code: statement_not_allowed
LISTEN chan;
--;;
-- code: statement_not_allowed
NOTIFY chan, 'payload';
--;;
-- code: statement_not_allowed
UNLISTEN *;
--;;
-- code: statement_not_allowed
PREPARE p AS SELECT 1;
--;;
-- code: statement_not_allowed
EXECUTE p;
--;;
-- code: statement_not_allowed
DEALLOCATE p;
--;;
-- code: statement_not_allowed
DECLARE c CURSOR FOR SELECT 1;
--;;
-- code: statement_not_allowed
FETCH NEXT FROM c;
--;;
-- code: statement_not_allowed
LOCK TABLE t IN ACCESS EXCLUSIVE MODE;
--;;
-- code: statement_not_allowed
DISCARD ALL;
--;;
-- code: statement_not_allowed
VACUUM t;
--;;
-- code: statement_not_allowed
ANALYZE t;
--;;
-- code: statement_not_allowed
REFRESH MATERIALIZED VIEW mv;
--;;
-- code: statement_not_allowed
REINDEX TABLE t;
--;;
-- code: statement_not_allowed
CLUSTER t;
--;;
-- code: statement_not_allowed
CHECKPOINT;
--;;
-- code: statement_not_allowed
LOAD 'auto_explain';
--;;
-- code: statement_not_allowed
SECURITY LABEL FOR selinux ON TABLE t IS 'x';
--;;
-- code: statement_not_allowed
EXPLAIN ANALYZE INSERT INTO t VALUES (1);
--;;
-- code: statement_not_allowed
EXPLAIN DELETE FROM t;
--;;
-- code: statement_not_allowed
EXPLAIN (ANALYZE) CREATE TABLE t2 AS SELECT 1;
--;;
-- code: multiple_statements
SELECT 1; SELECT 2;
--;;
-- code: multiple_statements
SELECT 1; DROP TABLE x;
--;;
-- code: select_into
SELECT 1 INTO x;
--;;
-- code: select_into
SELECT * INTO TEMP t FROM y;
--;;
-- code: row_locking
SELECT * FROM t FOR UPDATE;
--;;
-- code: row_locking
SELECT * FROM (SELECT * FROM t FOR SHARE) s;
--;;
-- code: data_modifying_cte
WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d;
--;;
-- code: data_modifying_cte
SELECT * FROM (WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d) s;
--;;
-- code: data_modifying_cte
EXPLAIN WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i;
--;;
-- code: placeholder
SELECT $1;
--;;
-- code: function_denied
SELECT pg_terminate_backend(1);
--;;
-- code: function_denied
SELECT pg_catalog.pg_terminate_backend(1);
--;;
-- code: function_denied
SELECT pg_reload_conf();
--;;
-- code: function_denied
SELECT * FROM t WHERE pg_cancel_backend(pid) IS NOT NULL;
--;;
-- code: function_denied
SELECT pg_wal_replay_pause();
--;;
-- code: function_denied
SELECT pg_backup_start('x');
--;;
-- code: function_denied
SELECT pg_stat_reset();
--;;
-- code: function_denied
SELECT pg_stat_statements_reset();
--;;
-- code: function_denied
SELECT pg_restore_relation_stats('t'::regclass);
--;;
-- code: function_denied
SELECT pg_clear_attribute_stats('t'::regclass, 'a', false);
--;;
-- code: function_denied
SELECT pg_advisory_lock(1);
--;;
-- code: function_denied
SELECT "pg_advisory_lock"(1);
--;;
-- code: function_denied
SELECT pg_try_advisory_lock(1);
--;;
-- code: function_denied
SELECT set_config('statement_timeout', '0', false);
--;;
-- code: function_denied
SELECT pg_catalog.set_config('work_mem', '1GB', false);
--;;
-- code: function_denied
SELECT pg_notify('chan', 'x');
--;;
-- code: function_denied
SELECT setseed(0.5);
--;;
-- code: function_denied
SELECT pg_export_snapshot();
--;;
-- code: function_denied
SELECT nextval('s');
--;;
-- code: function_denied
SELECT setval('s', 1);
--;;
-- code: function_denied
SELECT txid_current();
--;;
-- code: function_denied
SELECT pg_current_xact_id();
--;;
-- code: function_denied
SELECT lo_import('/etc/passwd');
--;;
-- code: function_denied
SELECT lo_create(0);
--;;
-- code: function_denied
SELECT lo_unlink(1);
--;;
-- code: function_denied
SELECT * FROM dblink('x', 'y') AS t(a int);
--;;
-- code: function_denied
SELECT ts_stat('select * from pg_authid');
--;;
-- code: function_denied
SELECT query_to_xml('select 1', true, false, '');
--;;
-- code: function_denied
SELECT pg_logical_emit_message(true, 'p', 'x');
--;;
-- code: function_denied
SELECT pg_create_physical_replication_slot('s');
--;;
-- code: function_denied
SELECT pg_drop_replication_slot('s');
--;;
-- code: function_denied
SELECT pg_read_file('/etc/passwd');
--;;
-- code: function_denied
SELECT pg_ls_dir('/');
--;;
-- code: function_denied
SELECT pg_stat_file('/etc/passwd');
--;;
-- code: function_denied
SELECT pg_file_write('x', 'y', false);
--;;
-- code: function_denied
SELECT pg_prewarm('t');
--;;
-- code: function_denied
SELECT brin_summarize_new_values('i');
--;;
-- code: function_denied
SELECT gin_clean_pending_list('i');
--;;
-- code: function_denied
SELECT * FROM pg_show_all_settings();
--;;
-- code: function_denied
SELECT * FROM pg_hba_file_rules();
--;;
-- code: function_denied
SELECT add_retention_policy('t', INTERVAL '1 day');
--;;
-- code: function_denied
SELECT drop_chunks('t', INTERVAL '1 day');
--;;
-- code: function_denied
SELECT run_job(1);
--;;
-- code: function_denied
SELECT create_hypertable('t', 'ts');
--;;
-- code: function_denied
SELECT cron.schedule('* * * * *', 'select 1');
--;;
-- code: function_denied
SELECT cron.unschedule(1);
--;;
-- code: function_denied
SELECT * FROM t WHERE x = ANY (ARRAY(SELECT set_config('a', 'b', false)::text));
--;;
-- code: function_denied
SELECT array_agg(a) FILTER (WHERE nextval('s') > 0) FROM t;
--;;
-- code: function_denied
SELECT * FROM t JOIN LATERAL (SELECT pg_terminate_backend(p.pid)) s ON true, (SELECT 1) p;
--;;
-- code: function_denied
SELECT ARRAY(SELECT pg_read_file('/etc/passwd'));
--;;
-- code: function_denied
SELECT rank() OVER (PARTITION BY pg_advisory_lock(1)) FROM t;
--;;
-- code: function_denied
WITH c AS (SELECT pg_reload_conf()) SELECT * FROM c;
--;;
-- code: function_denied
SELECT * FROM JSON_TABLE(pg_read_file('/etc/passwd')::jsonb, '$' COLUMNS (a int PATH '$.a')) jt;
--;;
-- code: function_denied
SELECT * FROM dblink_exec('x', 'y');
--;;
-- code: function_denied
SELECT lo_import('x') FROM t LIMIT 1;
--;;
-- code: function_denied
SELECT brin_desummarize_range('i', 1);
--;;
-- code: function_denied
SELECT pg_buffercache_evict(1);
--;;
-- code: function_denied
SELECT * FROM pg_ident_file_mappings();
--;;
-- code: function_denied
SELECT pg_show_all_file_settings();
--;;
-- code: function_denied
SELECT * FROM pg_logical_slot_get_changes('s', NULL, NULL);
--;;
-- code: function_denied
SELECT cursor_to_xml('c', true, false, '');
--;;
-- code: function_denied
WITH x AS (SELECT setval('s', 5)) SELECT * FROM x;
--;;
-- code: function_denied
SELECT txid_current() FROM t;
--;;
-- code: relation_denied
SELECT * FROM pg_authid;
--;;
-- code: relation_denied
SELECT * FROM pg_catalog.pg_shadow;
--;;
-- code: relation_denied
SELECT * FROM pg_settings;
--;;
-- code: relation_denied
SELECT * FROM pg_hba_file_rules;
--;;
-- code: relation_denied
SELECT (SELECT rolpassword FROM pg_authid LIMIT 1);
--;;
-- code: setting_denied
SHOW primary_conninfo;
--;;
-- code: setting_denied
SELECT current_setting('ssl_key_file');
--;;
-- code: empty
-- comment only
--;;
-- code: parse_error
SELECT FROM WHERE;
--;;
-- code: setting_denied
SELECT current_setting('primary_conninfo'::text);
--;;
-- code: setting_denied
SELECT current_setting('primary_' || 'conninfo');
--;;
-- code: setting_denied
SELECT current_setting(lower('X'));
--;;
-- code: setting_denied
SELECT current_setting(n) FROM unnest(ARRAY['primary_conninfo']) AS n;
--;;
-- code: setting_denied
SELECT pg_catalog.current_setting('archive_command'::text);
--;;
-- code: setting_denied
SELECT current_setting((SELECT 'primary_conninfo'));
--;;
-- code: setting_denied
SELECT current_setting(VARIADIC ARRAY['primary_conninfo']);
--;;
-- code: setting_denied
SELECT "current_setting"('ssl_passphrase_command'::name);
--;;
-- code: setting_denied
SELECT current_setting('primary_conninfo', true);
--;;
-- code: setting_denied
SELECT current_setting('work_mem', current_setting('work_mem'));
--;;
-- code: setting_denied
SELECT current_setting();
--;;
-- code: relation_denied
SELECT * FROM pg_config;
--;;
-- code: relation_denied
SELECT * FROM pg_db_role_setting;
--;;
-- code: function_denied
SELECT * FROM pg_show_all_settings();
--;;
-- code: relation_denied
SELECT * FROM pg_file_settings;
--;;
-- code: relation_denied
SELECT * FROM pg_hba_file_rules;
--;;
-- code: relation_denied
SELECT * FROM pg_ident_file_mappings;
--;;
-- code: function_denied
SELECT heap_force_kill('t'::regclass, NULL);
--;;
-- code: function_denied
SELECT heap_force_freeze('t'::regclass, NULL);
--;;
-- code: function_denied
SELECT pg_truncate_visibility_map('t'::regclass);
--;;
-- code: function_denied
SELECT autoprewarm_dump_now();
--;;
-- code: function_denied
SELECT pg_prewarm('t'::regclass);
--;;
-- code: function_denied
SELECT pg_logdir_ls();
--;;
-- code: function_denied
SELECT add_policies('t', false, 'ts', INTERVAL '1 day');
--;;
-- code: function_denied
SELECT enable_chunk_skipping('t', 'ts');
--;;
-- code: function_denied
SELECT pg_background_launch('SELECT 1');
--;;
-- code: function_denied
SELECT http_get('https://example.com/');
--;;
-- code: function_denied
SELECT postgres_fdw_disconnect_all();
--;;
-- code: function_denied
SELECT hypopg_create_index('CREATE INDEX ON t (a)');
--;;
-- code: function_denied
SELECT get_raw_page('t', 0);
--;;
-- code: function_denied
SELECT pg_stat_kcache_reset();
--;;
-- code: function_denied
SELECT pgr_dijkstra('SELECT 1', 1, 2);
--;;
-- code: function_denied
SELECT _timescaledb_functions.hypertable_size('t');
--;;
-- code: function_denied
SELECT _timescaledb_internal.hypertable_size('t');
--;;
-- code: function_denied
SELECT _timescaledb_catalog.hypertable_size('t');
--;;
-- code: function_denied
SELECT attach_chunk('h', 'c', '{}'::jsonb);
--;;
-- code: function_denied
SELECT "pg_catalog"."heap_force_kill"('t'::regclass, NULL);
--;;
-- code: function_denied
SELECT remove_compaction_policy('t');
--;;
-- code: function_denied
SELECT set_partitioning_interval('t');
--;;
-- code: function_denied
SELECT merge_chunks_concurrently('t');
--;;
-- code: function_denied
SELECT add_job('t');
--;;
-- code: function_denied
SELECT drop_chunks('t');
--;;
-- code: function_denied
SELECT compress_chunk('t');
--;;
-- code: function_denied
SELECT create_hypertable('t');
--;;
-- code: function_denied
SELECT refresh_continuous_aggregate('t');
--;;
-- code: function_denied
SELECT run_job('t');
--;;
-- code: function_denied
SELECT move_chunk('t');
--;;
-- code: function_denied
SELECT enable_chunk_skipping('t');
--;;
-- code: function_denied
SELECT pg_rotate_logfile();
--;;
-- code: function_denied
SELECT pg_catalog.pg_rotate_logfile();
--;;
-- code: function_denied
SELECT pg_switch_wal();
--;;
-- code: function_denied
SELECT pg_catalog.pg_switch_wal();
--;;
-- code: function_denied
SELECT pg_create_restore_point('x');
--;;
-- code: function_denied
SELECT pg_catalog.pg_create_restore_point('x');
--;;
-- code: function_denied
SELECT pg_promote();
--;;
-- code: function_denied
SELECT pg_catalog.pg_promote();
--;;
-- code: function_denied
SELECT pg_stat_reset();
--;;
-- code: function_denied
SELECT pg_catalog.pg_stat_reset();
--;;
-- code: function_denied
SELECT pg_stat_reset_shared('bgwriter');
--;;
-- code: function_denied
SELECT pg_catalog.pg_stat_reset_shared('bgwriter');
--;;
-- code: function_denied
SELECT lo_put(1, 0, 'x');
--;;
-- code: function_denied
SELECT pg_catalog.lo_put(1, 0, 'x');
--;;
-- code: function_denied
SELECT lo_from_bytea(0, 'x');
--;;
-- code: function_denied
SELECT pg_catalog.lo_from_bytea(0, 'x');
--;;
-- code: function_denied
SELECT lowrite(1, 'x');
--;;
-- code: function_denied
SELECT pg_catalog.lowrite(1, 'x');
--;;
-- code: function_denied
SELECT lo_export(1, '/tmp/x');
--;;
-- code: function_denied
SELECT pg_catalog.lo_export(1, '/tmp/x');
--;;
-- code: function_denied
SELECT pg_export_snapshot();
--;;
-- code: function_denied
SELECT pg_catalog.pg_export_snapshot();
--;;
-- code: function_denied
SELECT table_to_xml('t', true, false, '');
--;;
-- code: function_denied
SELECT pg_catalog.table_to_xml('t', true, false, '');
--;;
-- code: function_denied
SELECT schema_to_xml('s', true, false, '');
--;;
-- code: function_denied
SELECT pg_catalog.schema_to_xml('s', true, false, '');
--;;
-- code: function_denied
SELECT database_to_xml(true, false, '');
--;;
-- code: function_denied
SELECT pg_catalog.database_to_xml(true, false, '');
--;;
-- code: function_denied
SELECT query_to_xmlschema('SELECT 1', true, false, '');
--;;
-- code: function_denied
SELECT pg_catalog.query_to_xmlschema('SELECT 1', true, false, '');
--;;
-- code: function_denied
SELECT cursor_to_xml('c', 1, true, false, '');
--;;
-- code: function_denied
SELECT pg_catalog.cursor_to_xml('c', 1, true, false, '');
--;;
-- code: function_denied
SELECT pg_advisory_xact_lock(1);
--;;
-- code: function_denied
SELECT pg_catalog.pg_advisory_xact_lock(1);
--;;
-- code: function_denied
SELECT pg_try_advisory_lock(1);
--;;
-- code: function_denied
SELECT pg_catalog.pg_try_advisory_lock(1);
--;;
-- code: function_denied
SELECT txid_current();
--;;
-- code: function_denied
SELECT pg_catalog.txid_current();
--;;
-- code: function_denied
SELECT pg_replication_slot_advance('s', '0/0');
--;;
-- code: function_denied
SELECT pg_catalog.pg_replication_slot_advance('s', '0/0');
--;;
-- code: function_denied
SELECT pg_create_logical_replication_slot('s', 'test_decoding');
--;;
-- code: function_denied
SELECT pg_catalog.pg_create_logical_replication_slot('s', 'test_decoding');
--;;
-- code: function_denied
SELECT pg_drop_replication_slot('s');
--;;
-- code: function_denied
SELECT pg_catalog.pg_drop_replication_slot('s');
--;;
-- code: function_denied
SELECT dblink_exec('x', 'y');
--;;
-- code: function_denied
SELECT pg_catalog.dblink_exec('x', 'y');
--;;
-- code: function_denied
SELECT dblink_connect('x');
--;;
-- code: function_denied
SELECT pg_catalog.dblink_connect('x');
--;;
-- code: setting_denied
SELECT ('ssl_key_file'::text).current_setting;
--;;
-- code: setting_denied
SELECT (x).current_setting FROM (VALUES ('ssl_key_file')) v(x);
--;;
-- code: function_denied
SELECT (pid).pg_terminate_backend FROM pg_stat_activity;
--;;
-- code: function_denied
SELECT (pid).pg_cancel_backend FROM pg_stat_activity;
--;;
-- code: function_denied
SELECT (x).ts_stat FROM (VALUES ('select 1')) v(x);
--;;
-- code: function_denied
SELECT (0.5::float8).setseed;
--;;
-- code: function_denied
SELECT (12345::bigint).pg_advisory_lock;
--;;
-- code: function_denied
SELECT (ARRAY['x'])[1].pg_read_file;
--;;
-- code: function_denied
SELECT (v).x.pg_read_file FROM (VALUES ('a')) v(x);
--;;
-- code: function_denied
SELECT s.pg_restore_relation_stats FROM (SELECT 1) s;
--;;
-- code: function_denied
SELECT v.x.nextval FROM (VALUES ('s'::regclass)) v(x);
--;;
-- code: function_denied
SELECT ('s'::regclass).nextval;
--;;
-- code: function_denied
SELECT (x)."pg_terminate_backend" FROM (VALUES (1)) v(x);
--;;
-- code: function_denied
SELECT (x).query_to_xml FROM (VALUES ('select 1')) v(x);
--;;
-- code: function_denied
SELECT ts_rewrite('foo'::tsquery, 'select ''foo''::tsquery, ''bar''::tsquery');
--;;
-- code: function_denied
SELECT (x).ts_rewrite FROM (VALUES ('select 1')) v(x);
--;;
-- code: function_denied
SELECT (x).pg_terminate_backend.y FROM (VALUES (1)) v(x);
--;;
-- code: function_denied
SELECT pgmcp.read_log_file('postgresql.log', 0, 10);
--;;
-- code: function_denied
SELECT pgmcp.list_log_files();
--;;
-- code: function_denied
SELECT read_log_file('postgresql.log', 0, 10);
--;;
-- code: function_denied
SELECT * FROM list_log_files();
--;;
-- code: function_denied
SELECT (x).read_log_file FROM (VALUES (1)) v(x);
--;;
-- code: relation_denied
SELECT * FROM pg_statistic;
--;;
-- code: relation_denied
SELECT * FROM pg_catalog.pg_statistic;
--;;
-- code: relation_denied
SELECT * FROM "pg_catalog"."pg_statistic";
--;;
-- code: relation_denied
SELECT * FROM "PG_STATISTIC";
--;;
-- code: relation_denied
TABLE pg_statistic;
--;;
-- code: relation_denied
SELECT s.staop FROM pg_statistic s;
--;;
-- code: relation_denied
SELECT * FROM pg_statistic_ext_data;
--;;
-- code: relation_denied
SELECT * FROM pg_catalog.pg_statistic_ext_data;
--;;
-- code: relation_denied
SELECT * FROM information_schema.user_mapping_options;
--;;
-- code: relation_denied
SELECT * FROM user_mapping_options;
--;;
-- code: relation_denied
SELECT * FROM "information_schema"."user_mapping_options";
--;;
-- code: relation_denied
SELECT (u).umoptions FROM (SELECT * FROM information_schema.user_mapping_options) u;
--;;
-- code: relation_denied
SELECT (u).umoptions FROM (SELECT * FROM pg_catalog.pg_statistic) u;
