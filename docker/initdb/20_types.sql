\set ON_ERROR_STOP on
-- One table with a column per type, three literal rows (typical, edge, all-null).
CREATE SCHEMA types;
CREATE TYPE types.mood AS ENUM ('sad', 'ok', 'happy');
CREATE TYPE types.pair AS (a int, b text);
CREATE DOMAIN types.posint AS int CHECK (VALUE > 0);
CREATE TYPE types.floatrange AS RANGE (subtype = float8);

CREATE TABLE types.all_types (
  id int PRIMARY KEY,
  c_bool bool, c_int2 int2, c_int4 int4, c_int8 int8, c_float4 float4, c_float8 float8,
  c_numeric numeric, c_money money, c_text text, c_varchar varchar(20), c_bpchar char(5),
  c_name name, c_char "char", c_bytea bytea, c_uuid uuid, c_date date, c_time time,
  c_timetz timetz, c_timestamp timestamp, c_timestamptz timestamptz, c_interval interval,
  c_json json, c_jsonb jsonb, c_xml xml, c_bit bit(4), c_varbit varbit, c_inet inet,
  c_cidr cidr, c_macaddr macaddr, c_macaddr8 macaddr8, c_point point, c_line line,
  c_lseg lseg, c_box box, c_path path, c_polygon polygon, c_circle circle,
  c_tsvector tsvector, c_tsquery tsquery, c_jsonpath jsonpath, c_pg_lsn pg_lsn,
  c_xid8 xid8, c_oid oid, c_regclass regclass, c_regtype regtype,
  c_int4range int4range, c_int8range int8range, c_numrange numrange, c_tsrange tsrange,
  c_tstzrange tstzrange, c_daterange daterange, c_int4multirange int4multirange,
  c_datemultirange datemultirange, c_floatrange types.floatrange, c_mood types.mood,
  c_pair types.pair, c_posint types.posint, c_hstore hstore, c_ltree ltree, c_citext citext,
  c_int4_arr int4[], c_text_arr text[], c_numeric_arr numeric[], c_jsonb_arr jsonb[],
  c_mood_arr types.mood[], c_int4range_arr int4range[], c_timestamptz_arr timestamptz[],
  c_box_arr box[], c_int2vector int2vector, c_pg_snapshot pg_snapshot
);

INSERT INTO types.all_types VALUES
(1, true, 7, 1000, 42, 1.5, 0.1,
 12345.6789, '12.34', 'hello', 'varchar', 'abc',
 'name1', 'a', '\xdeadbeef', 'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11', '2024-02-29', '13:00:00.5',
 '13:00:00+05:30', '2024-02-29 13:00:00.123456', '2024-02-29 13:00:00.123456+05:30', '1 year 2 mons 3 days 04:05:06.789',
 '{"a":1,"b":[1,2,{"c":null}]}', '{"a":1,"b":[1,2,{"c":null}]}', '<a>1</a>', '1010', '101', '192.168.1.5/24',
 '10.0.0.0/8', '08:00:2b:01:02:03', '08:00:2b:01:02:03:04:05', '(1,2)', '{1,-1,0}',
 '[(0,0),(1,1)]', '((1,1),(0,0))', '((0,0),(1,0),(1,1))', '((0,0),(1,0),(0,1))', '<(1,2),3>',
 'fat:2 cat:3', 'fat & rat', '$.a[*] ? (@ > 1)', '16/B374D848',
 '42', 42, 'pg_class', 'integer',
 '[1,5)', '[1,9)', '(1.5,2.5]', '[2024-01-01 00:00:00,2024-01-02 00:00:00)',
 '[2024-01-01 00:00:00+00,2024-01-02 00:00:00+00)', '[2024-01-01,2024-02-01)', '{[1,3),[5,8)}',
 '{[2024-01-01,2024-02-01)}', '[0.5,1.5)', 'happy',
 '(1,"x, y")', 5, 'a=>1,b=>NULL', 'a.b.c', 'AbC',
 '{1,2,3}', '{"a b","c"}', '{1.5,2}', '{"{\"x\": 1}","[3]"}',
 '{happy,ok}', '{"[1,3)","[5,8)"}', '{"2024-01-01 00:00:00+00","2024-06-01 12:00:00+00"}', '{(1,1),(0,0)}',
 '1 2 3', '10:20:10,14,15'),
(2, false, -32768, 2147483647, 9223372036854775807, 'NaN', '-Infinity',
 'NaN', '-92233720368547758.08', '', 'héllo wörld ✓', 'ab',
 'x', '', '\x', '00000000-0000-0000-0000-000000000000', 'infinity', '24:00:00',
 '00:00:00+14', '0044-03-15 12:00:00 BC', '-infinity', '-1 mon +2 days -03:00:00',
 '{"a":1,"a":2, "big":1e400}', '{"n":12345678901234567890.123456789}', '<r/>', '0000', '', '::1',
 '::/0', 'ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00:00:00', '(0,0)', '{0,1,-0.5}',
 '((1,1),(0,0))', '((2,2),(3,3))', '[(0,0),(1,1)]', '((0,0),(1,1),(1,0))', '<(0,0),0>',
 '', 'a <-> b', '$', '0/0',
 '18446744073709551615', 4294967295, 'pg_type', 'text[]',
 'empty', '(,)', '[1.5,)', '(,2024-01-01 00:00:00]',
 '[2024-01-01 00:00:00+00,2024-12-31 23:59:59+00]', '(,2024-01-01]', '{}',
 '{}', '[1.5,2.5]', 'sad',
 '(,)', 2147483647, '"k"=>""', 'top_1.Sci_2', 'ÄÖ',
 '[2:3][0:1]={{1,NULL},{3,4}}', '{"NULL",NULL,"c\"d","e\\f",""}', '{1.50,NaN,Infinity}', '{"{\"a\": 1}","[1, 2]"}',
 '{sad,NULL,happy}', '{"[1,2)","empty"}', '{"2024-01-01 00:00:00+00",infinity}', '{(1,1),(0,0);(3,3),(2,2)}',
 '-1 0 32767', '1:1:');
INSERT INTO types.all_types (id) VALUES (3);

COMMENT ON TABLE types.all_types IS 'One column per type; rows 1 and 2 are fully populated, row 3 is all NULL';
COMMENT ON COLUMN types.all_types.c_int8 IS 'Plain bigint';
COMMENT ON COLUMN types.all_types.c_numeric IS 'Arbitrary-precision numeric, including NaN in row 2';
COMMENT ON COLUMN types.all_types.c_json IS 'Json text kept verbatim, duplicate keys included';

DO $do$
BEGIN
  IF to_regtype('oid8') IS NOT NULL THEN
    EXECUTE 'CREATE TABLE types.ext_types (id int PRIMARY KEY, c_oid8 oid8)';
    EXECUTE $q$INSERT INTO types.ext_types VALUES (1, '18446744073709551615')$q$;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'vector') THEN
    EXECUTE 'CREATE TABLE types.vec_types (id int PRIMARY KEY, c_vector vector(3), c_halfvec halfvec(3), c_sparsevec sparsevec(5))';
    EXECUTE $q$INSERT INTO types.vec_types VALUES (1, '[1,2,3]', '[1,2,3]', '{1:1,3:2}/5')$q$;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'postgis') THEN
    EXECUTE 'CREATE TABLE types.geo_types (id int PRIMARY KEY, c_geometry geometry(Point,4326), c_geography geography(Point,4326))';
    EXECUTE $q$INSERT INTO types.geo_types VALUES (1, 'SRID=4326;POINT(-71.9 45.4)', 'SRID=4326;POINT(-71.9 45.4)')$q$;
  END IF;
END
$do$;
