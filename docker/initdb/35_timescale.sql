\set ON_ERROR_STOP on
-- TimescaleDB objects in schema metrics. Each block is a no-op unless the timescaledb extension is installed.
-- ALTER SYSTEM cannot run inside a function, so this one statement is guarded by psql \if instead.
SELECT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') AS has_timescaledb \gset
\if :has_timescaledb
ALTER SYSTEM SET timescaledb.enable_job_execution_logging = on;
SELECT pg_reload_conf();
\endif

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    EXECUTE 'CREATE SCHEMA metrics';
    EXECUTE $q$CREATE TABLE metrics.readings (
      ts timestamptz NOT NULL,
      device_id int NOT NULL,
      temperature double precision,
      humidity double precision
    ) WITH (tsdb.hypertable, tsdb.partition_column = 'ts', tsdb.chunk_interval = '1 day',
            tsdb.segmentby = 'device_id', tsdb.orderby = 'ts DESC')$q$;
    EXECUTE $q$INSERT INTO metrics.readings
      SELECT ts, d,
             15 + d + ((extract(epoch FROM ts)::bigint / 600) % 50) * 0.1,
             30 + 2 * d + ((extract(epoch FROM ts)::bigint / 600) % 40) * 0.5
      FROM generate_series('2024-01-01 00:00:00+00'::timestamptz, '2024-01-07 23:50:00+00', '10 min') AS ts,
           generate_series(1, 5) AS d$q$;
    EXECUTE $q$CREATE MATERIALIZED VIEW metrics.readings_hourly WITH (timescaledb.continuous) AS
      SELECT time_bucket('1 hour', ts) AS bucket, device_id,
             avg(temperature) AS avg_temperature, max(humidity) AS max_humidity
      FROM metrics.readings GROUP BY 1, 2 WITH NO DATA$q$;
    EXECUTE 'COMMENT ON TABLE metrics.readings IS ''Hypertable of device readings, one row per 10 minutes''';
    EXECUTE 'COMMENT ON COLUMN metrics.readings.device_id IS ''Device segment key''';
    EXECUTE 'COMMENT ON VIEW metrics.readings_hourly IS ''Hourly continuous aggregate of readings''';
  END IF;
END
$do$;

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    CALL refresh_continuous_aggregate('metrics.readings_hourly', '2024-01-01 00:00:00+00', '2024-01-08 00:00:00+00');
  END IF;
END
$do$;

DO $do$
DECLARE
  v_chunk text;
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    FOR v_chunk IN
      SELECT format('%I.%I', chunk_schema, chunk_name)
      FROM timescaledb_information.chunks
      WHERE hypertable_schema = 'metrics' AND hypertable_name = 'readings'
      ORDER BY range_start
      LIMIT 3
    LOOP
      EXECUTE format('CALL convert_to_columnstore(%L)', v_chunk);
    END LOOP;
  END IF;
END
$do$;

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    EXECUTE 'CALL remove_columnstore_policy(''metrics.readings'', if_exists => true)';
    EXECUTE 'CALL add_columnstore_policy(''metrics.readings'', after => INTERVAL ''7 days'')';
    EXECUTE 'SELECT add_retention_policy(''metrics.readings'', drop_after => INTERVAL ''3650 days'')';
    EXECUTE 'SELECT add_continuous_aggregate_policy(''metrics.readings_hourly'', start_offset => NULL, end_offset => INTERVAL ''1 hour'', schedule_interval => INTERVAL ''1 hour'')';
  END IF;
END
$do$;

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    EXECUTE $q$CREATE PROCEDURE metrics.failing_job(job_id int, config jsonb) LANGUAGE plpgsql AS $p$
      BEGIN RAISE EXCEPTION 'pgmcp intentional job failure'; END $p$$q$;
    EXECUTE $q$CREATE PROCEDURE metrics.ok_job(job_id int, config jsonb) LANGUAGE plpgsql AS $p$
      BEGIN NULL; END $p$$q$;
    -- Jobs are owned by mcp_ro, the only role the job views must show to the test reader.
    EXECUTE 'SET LOCAL ROLE mcp_ro';
    EXECUTE $q$SELECT add_job('metrics.failing_job', INTERVAL '1 hour', config => '{}'::jsonb, initial_start => now())$q$;
    EXECUTE $q$SELECT add_job('metrics.ok_job', INTERVAL '1 hour', config => '{}'::jsonb, initial_start => now())$q$;
    EXECUTE 'RESET ROLE';
  END IF;
END
$do$;

DO $do$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
    EXECUTE 'GRANT USAGE ON SCHEMA metrics TO mcp_strict';
    EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA metrics TO mcp_strict';
  END IF;
END
$do$;
