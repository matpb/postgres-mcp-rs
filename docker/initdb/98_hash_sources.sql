CREATE SCHEMA hashes;
\set ON_ERROR_STOP on
-- Planted password hashes in each place a tool can show text from: a comment, a column name, a view, a
-- function body and a row value. The every-tool test reads all of them.
CREATE TABLE hashes.hash_sources (
  id int PRIMARY KEY,
  label text,
  "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5" int
);
INSERT INTO hashes.hash_sources VALUES (1, 'SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5', 1);
COMMENT ON TABLE hashes.hash_sources IS 'SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5';
CREATE VIEW hashes.hash_view AS SELECT 'md5d41d8cd98f00b204e9800998ecf8427e'::text AS v;
CREATE FUNCTION hashes.hash_body() RETURNS text LANGUAGE sql AS $body$ SELECT 'SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5'::text $body$;
-- A typed password in statement text, recorded by pg_stat_statements where it is preloaded.
ALTER ROLE seed_role_1 PASSWORD 'plain-test-secret';
-- A table whose name is hash-shaped: schema and table completion return it.
CREATE TABLE hashes."SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5" (id int);
