#!/usr/bin/env bash
# Test-only TLS for the pgtls service: a private CA, server and client certificates, and the roles that use them.
# Runs on the first start of an empty data directory. No key or certificate is committed; they are made here.
set -Eeuo pipefail

DAYS=3650
TLS_DIR="$PGDATA/tls"
umask 077
mkdir -p "$TLS_DIR"
cd "$TLS_DIR"

# Signs $1.csr with the CA named by $2 (prefix), serial $3, extension file $4; writes $1.crt.
sign() {
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -set_serial "$3" -days "$DAYS" \
        -extfile "$4" -out "$1.crt" 2>/dev/null
}

printf '%s\n' \
    "basicConstraints=CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:localhost,DNS:pgtls.test.example" >server.ext
printf '%s\n' \
    "basicConstraints=CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=clientAuth" >client.ext

# The test CA and the unrelated CA.
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -keyout ca.key -out ca.crt \
    -subj "/CN=pgmcp test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" -keyout bad_ca.key -out bad_ca.crt \
    -subj "/CN=pgmcp unrelated CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"

# Server certificate: names localhost and pgtls.test.example, no IP address.
openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=pgtls.test.example"
sign server ca 16 server.ext

# Client certificates for CN=mcp_cert: RSA in PKCS#8, the same key in PKCS#1, EC in SEC1, and one from the unrelated CA.
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=mcp_cert"
sign client ca 17 client.ext
openssl rsa -in client.key -traditional -out client_pkcs1.key 2>/dev/null
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out client_ec_pkcs8.key 2>/dev/null
openssl ec -in client_ec_pkcs8.key -out client_ec.key 2>/dev/null
rm -f client_ec_pkcs8.key
openssl req -new -key client_ec.key -out client_ec.csr -subj "/CN=mcp_cert"
sign client_ec ca 18 client.ext
openssl req -new -newkey rsa:2048 -nodes -keyout bad_client.key -out bad_client.csr -subj "/CN=mcp_cert"
sign bad_client bad_ca 19 client.ext

rm -f ./*.csr ./*.ext
chmod 600 ./*.key
chmod 644 ./*.crt

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
ALTER SYSTEM SET ssl = on;
ALTER SYSTEM SET ssl_cert_file = 'tls/server.crt';
ALTER SYSTEM SET ssl_key_file = 'tls/server.key';
ALTER SYSTEM SET ssl_ca_file = 'tls/ca.crt';
ALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.2';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SET password_encryption = 'scram-sha-256';
CREATE ROLE mcp_ro LOGIN PASSWORD 'test-only-ro';
GRANT pg_read_all_data TO mcp_ro;
CREATE ROLE mcp_cert LOGIN PASSWORD 'test-only-cert';
GRANT pg_read_all_data TO mcp_cert;
SQL

# Socket trust for the entrypoint and health check; TCP needs TLS, mcp_cert also needs a verified client certificate.
cat >"$PGDATA/pg_hba.conf" <<'HBA'
local all all trust
hostssl all mcp_cert all scram-sha-256 clientcert=verify-full
hostssl all all all scram-sha-256
hostnossl all all all reject
HBA

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname appdb <<'SQL'
CREATE SCHEMA app;
GRANT USAGE ON SCHEMA app TO mcp_ro, mcp_cert;
CREATE TABLE app.items (id int PRIMARY KEY, name text NOT NULL);
INSERT INTO app.items VALUES (1, 'alpha'), (2, 'beta'), (3, 'gamma');
CREATE TABLE pgmcp_seed_done AS SELECT 1 AS ok;
SQL
