\set ON_ERROR_STOP on
-- Ordinary SQL text that holds the word password: the PASSWORD mask must return it byte for byte.
CREATE SCHEMA masks;
CREATE TABLE masks.kinds (
  id int PRIMARY KEY,
  kind text CHECK (kind IN ('password', 'token', 'key'))
);
CREATE TABLE masks.creds (kind text, v text);
CREATE VIEW masks.password_rows AS SELECT kind, v FROM masks.creds WHERE kind = 'password' AND v = 'x';
CREATE FUNCTION masks.check_password(ok boolean) RETURNS integer LANGUAGE plpgsql AS $body$
BEGIN
  IF NOT ok THEN RAISE EXCEPTION 'wrong password'; END IF;
  RETURN 1;
END
$body$;
