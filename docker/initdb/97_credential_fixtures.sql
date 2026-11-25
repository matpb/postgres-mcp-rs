\set ON_ERROR_STOP on
-- Seed-only NOLOGIN roles with dummy passwords. Their hashes fill pg_authid so that pg_stats has sample values.
CREATE ROLE seed_role_1 NOLOGIN PASSWORD 'test-only-seed-1';
CREATE ROLE seed_role_2 NOLOGIN PASSWORD 'test-only-seed-2';
CREATE ROLE seed_role_3 NOLOGIN PASSWORD 'test-only-seed-3';
CREATE ROLE seed_role_4 NOLOGIN PASSWORD 'test-only-seed-4';
CREATE ROLE seed_role_5 NOLOGIN PASSWORD 'test-only-seed-5';
CREATE ROLE seed_role_6 NOLOGIN PASSWORD 'test-only-seed-6';
CREATE ROLE seed_role_7 NOLOGIN PASSWORD 'test-only-seed-7';
CREATE ROLE seed_role_8 NOLOGIN PASSWORD 'test-only-seed-8';
CREATE ROLE seed_role_9 NOLOGIN PASSWORD 'test-only-seed-9';
CREATE ROLE seed_role_10 NOLOGIN PASSWORD 'test-only-seed-10';
CREATE ROLE seed_role_11 NOLOGIN PASSWORD 'test-only-seed-11';
CREATE ROLE seed_role_12 NOLOGIN PASSWORD 'test-only-seed-12';
CREATE ROLE seed_role_13 NOLOGIN PASSWORD 'test-only-seed-13';
CREATE ROLE seed_role_14 NOLOGIN PASSWORD 'test-only-seed-14';
CREATE ROLE seed_role_15 NOLOGIN PASSWORD 'test-only-seed-15';
CREATE ROLE seed_role_16 NOLOGIN PASSWORD 'test-only-seed-16';
CREATE ROLE seed_role_17 NOLOGIN PASSWORD 'test-only-seed-17';
CREATE ROLE seed_role_18 NOLOGIN PASSWORD 'test-only-seed-18';
CREATE ROLE seed_role_19 NOLOGIN PASSWORD 'test-only-seed-19';
CREATE ROLE seed_role_20 NOLOGIN PASSWORD 'test-only-seed-20';
CREATE ROLE seed_role_21 NOLOGIN PASSWORD 'test-only-seed-21';
CREATE ROLE seed_role_22 NOLOGIN PASSWORD 'test-only-seed-22';
CREATE ROLE seed_role_23 NOLOGIN PASSWORD 'test-only-seed-23';
CREATE ROLE seed_role_24 NOLOGIN PASSWORD 'test-only-seed-24';
CREATE ROLE seed_role_25 NOLOGIN PASSWORD 'test-only-seed-25';
CREATE ROLE seed_role_26 NOLOGIN PASSWORD 'test-only-seed-26';
CREATE ROLE seed_role_27 NOLOGIN PASSWORD 'test-only-seed-27';
CREATE ROLE seed_role_28 NOLOGIN PASSWORD 'test-only-seed-28';
CREATE ROLE seed_role_29 NOLOGIN PASSWORD 'test-only-seed-29';
CREATE ROLE seed_role_30 NOLOGIN PASSWORD 'test-only-seed-30';
CREATE ROLE seed_role_31 NOLOGIN PASSWORD 'test-only-seed-31';
CREATE ROLE seed_role_32 NOLOGIN PASSWORD 'test-only-seed-32';
CREATE ROLE seed_role_33 NOLOGIN PASSWORD 'test-only-seed-33';
CREATE ROLE seed_role_34 NOLOGIN PASSWORD 'test-only-seed-34';
CREATE ROLE seed_role_35 NOLOGIN PASSWORD 'test-only-seed-35';
CREATE ROLE seed_role_36 NOLOGIN PASSWORD 'test-only-seed-36';
CREATE ROLE seed_role_37 NOLOGIN PASSWORD 'test-only-seed-37';
CREATE ROLE seed_role_38 NOLOGIN PASSWORD 'test-only-seed-38';
CREATE ROLE seed_role_39 NOLOGIN PASSWORD 'test-only-seed-39';
CREATE ROLE seed_role_40 NOLOGIN PASSWORD 'test-only-seed-40';

-- An ordinary table holding one SCRAM hash and one md5 hash in each column, built from a seed-only password.
CREATE TABLE app.leaky (id int PRIMARY KEY, note text, tags text[], doc jsonb);
INSERT INTO app.leaky
SELECT 1,
  'scram ' || s.scram || ' md5 ' || m.md5,
  ARRAY[s.scram, m.md5],
  jsonb_build_object('scram', s.scram, 'md5', m.md5)
FROM (SELECT rolpassword AS scram FROM pg_catalog.pg_authid WHERE rolname = 'seed_role_1') AS s,
     (SELECT 'md5' || md5('test-only-seed-1' || 'seed_role_1') AS md5) AS m;
-- Autovacuum stays off so that no analyzed sample of the planted hashes reaches pg_stats.
ALTER TABLE app.leaky SET (autovacuum_enabled = false);
COMMENT ON TABLE app.leaky IS 'Hashes planted in an ordinary table for the scrubber tests';
