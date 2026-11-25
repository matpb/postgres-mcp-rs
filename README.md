# postgres-mcp-rs

postgres-mcp-rs is a read-only [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for PostgreSQL and TimescaleDB, written in Rust. It gives an AI client schema browsing, monitoring, server log access and read-only SQL against one or more databases. Nothing it accepts can write data or change session state: the SQL gate refuses anything that is not a single read-only statement, and PostgreSQL runs every statement in a read-only transaction. The crate and binary are both named `postgres-mcp`. The project is MIT licensed.

<p align="center"><img src="assets/logo.svg" width="96" alt="postgres-mcp-rs logo"></p>

## Why

- **Read-only in several independent layers.** The SQL gate accepts one read-only statement. Every call runs in a `READ ONLY` transaction that is rolled back. The session is checked before use and reset afterwards. The recommended database role holds only read privileges. No single layer is relied on alone (see [SECURITY.md](SECURITY.md)).
- **Typed results with exact numbers.** Booleans, small integers and floats are JSON numbers. Integers beyond 2^53-1, every `numeric` value and the NaN and Infinity floats are strings, so no precision is lost. Dates and times are ISO text, timestamptz is always UTC, and types the server does not decode arrive as PostgreSQL's own text.
- **Tools that replace catalog SQL.** `describe_table` returns columns, keys, foreign keys in both directions, indexes, policies and statistics in one call. Monitoring tools show sessions, lock waits, statement statistics and replication. Log and TimescaleDB tools cover server logs, hypertables, continuous aggregates and jobs. The model does not have to write `pg_catalog` queries to find its way around.
- **One binary, a small non-root container.** The server is a single executable. The Dockerfile builds it into a distroless image that runs as a non-root user. The example compose file adds a read-only root filesystem, all capabilities dropped and `no-new-privileges`.
- **One optional API key.** Set `API_KEY` to require a key on the HTTP endpoint. Leave it unset for a loopback-only server that only you use.
- **Several databases behind one server.** One process serves any number of configured databases. Every tool that reads a database takes a `database` argument, which may be omitted when only one is configured.
- **stdio and Streamable HTTP.** Run it as a process that one client starts for itself, or serve it over HTTP to clients on the same machine or your network.

## Quick start

There are three ways to run the server. Each one needs a PostgreSQL role for the server to use. Create the read-only role in [Create a read-only role](#create-a-read-only-role) first.

### a) Docker

Images for `linux/amd64` are published as `ghcr.io/matpb/postgres-mcp-rs` and `matpb/postgres-mcp-rs` on Docker Hub, tagged with the version and `latest`. Pull one and use its name in place of `postgres-mcp:local` below, or build the image from this repository. Then run it with the database URL and an API key:

```bash
docker build -t postgres-mcp:local .   # or: docker pull ghcr.io/matpb/postgres-mcp-rs:0.1.6
docker run -d --name postgres-mcp \
  -p 127.0.0.1:8432:8432 \
  -e 'DATABASE_URL=postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full' \
  -e 'API_KEY=change-me-to-a-random-key-of-16-plus-chars' \
  postgres-mcp:local
```

The health check answers with plain text:

```bash
curl -sS http://127.0.0.1:8432/health
```

```
ok
```

The port is published on `127.0.0.1` only. Inside the container the server listens on `0.0.0.0`, so that Docker's port mapping can reach it.

### b) From source

Building needs Rust 1.88 or newer and libclang (the SQL parser is built with bindgen). [CONTRIBUTING.md](CONTRIBUTING.md) lists the prerequisites.

```bash
cargo build --release
export DATABASE_URL='postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full'
export API_KEY='change-me-to-a-random-key-of-16-plus-chars'
./target/release/postgres-mcp
```

With no argument the binary serves Streamable HTTP, the same as `postgres-mcp http`. It binds to `127.0.0.1:8432` unless `MCP_HOST` or `MCP_PORT` say otherwise. The health check works the same way as in the Docker example:

```bash
curl -sS http://127.0.0.1:8432/health
```

### c) stdio

stdio mode serves one session over stdin and stdout. The client starts the process itself, so no port is opened and no API key is needed. Logs go to stderr.

```bash
DATABASE_URL='postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full' \
  ./target/release/postgres-mcp stdio
```

Stdout carries only JSON-RPC messages, so a wrapper script must not print anything to it.

## Connect a client

### Claude Code

Over HTTP, with the key sent as a header:

```bash
claude mcp add --transport http postgres http://127.0.0.1:8432/mcp --header "X-API-Key: change-me-to-a-random-key-of-16-plus-chars"
```

Over stdio, with the binary on `PATH` and the database in the environment:

```bash
claude mcp add postgres --env 'DATABASE_URL=postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full' -- postgres-mcp stdio
```

### Any MCP client

Clients that read an `mcpServers` map take one of these two entries. The HTTP form:

```json
{
  "mcpServers": {
    "postgres": {
      "type": "http",
      "url": "http://127.0.0.1:8432/mcp",
      "headers": {
        "X-API-Key": "change-me-to-a-random-key-of-16-plus-chars"
      }
    }
  }
}
```

The stdio form, with the absolute path to the binary:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "/path/to/postgres-mcp",
      "args": ["stdio"],
      "env": {
        "DATABASE_URL": "postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full"
      }
    }
  }
}
```

### Claude Desktop

Claude Desktop starts the server itself over stdio with the entry below. Add it to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "/path/to/postgres-mcp",
      "args": ["stdio"],
      "env": {
        "DATABASE_URL": "postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full"
      }
    }
  }
}
```

## Create a read-only role

Give the server its own database role and grant it read access only. Run this as an administrator, replacing `appdb`, `app_owner`, the schema and the password:

```sql
CREATE ROLE mcp_reader LOGIN PASSWORD 'change-me' CONNECTION LIMIT 10;
ALTER ROLE mcp_reader SET default_transaction_read_only = on;
GRANT CONNECT ON DATABASE appdb TO mcp_reader;
GRANT USAGE ON SCHEMA public TO mcp_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_reader;
ALTER DEFAULT PRIVILEGES FOR ROLE app_owner IN SCHEMA public GRANT SELECT ON TABLES TO mcp_reader;
-- optional: monitoring tools (other sessions' queries, statement statistics, settings)
GRANT pg_monitor TO mcp_reader;
```

This is the recommended setup. It reads the tables it is granted and nothing else. Replace `app_owner` with the role that creates the tables; default privileges apply only to objects that role creates. Tables that role creates in `public` later are readable too. For each further schema the server should see, repeat the `GRANT USAGE` and `GRANT SELECT` pair.

Do not grant `pg_read_all_data` and do not connect as a superuser. `pg_read_all_data` reads every table in every schema, present and future, including the system catalogs that hold password hashes and stored connection passwords. The server refuses to read those catalogs and their TOAST tables, removes their rows from the statistics views, and replaces text shaped like a stored password hash in every result. These are safeguards built into the server, whatever the role may do; a narrow role is still the better setup, because a role that was never granted the data has nothing to leak. If only monitoring is missing, `pg_monitor` is enough; it grants no table data, but it shows other sessions' statement text.

The server works with any role and never needs write privileges. `get_privileges` reports what the connected role can do and flags anything beyond read access, such as the ability to write, create or act as superuser.

## Configuration

The server reads only environment variables. It reads them when it starts in `http` or `stdio` mode, and an invalid value stops startup in both. A variable of a database form that is not in use is not checked: with `DATABASE_URL` set, for example, a bad `PGPORT` is ignored. An empty value counts as unset. A configuration error is printed as `configuration error: ...` on stderr and the process exits with status 2.

### Databases

| Variable | Default | Meaning |
|----------|---------|---------|
| `PG_DATABASES` | unset | JSON array of database objects. The most complete form, and the only one that holds several databases. See below. |
| `PG_DATABASES_FILE` | unset | Path to a file with the same JSON array. Cannot be combined with `PG_DATABASES`. |
| `DATABASE_URL` | unset | One `postgres://` or `postgresql://` URL, whose query may hold only `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `require_auth`, `application_name` and `connect_timeout`. Takes precedence over the `PG*` variables. Inline PEM for this form comes from `PGSSLROOTCERT_PEM`, `PGSSLCERT_PEM` and `PGSSLKEY_PEM`. |
| `PG_NAME` | database name | Connection name for the `DATABASE_URL` or `PGDATABASE` form. Required when the database name has characters outside A-Z, a-z, 0-9, `_` and `-`. |
| `PGHOST` | `127.0.0.1` | Host for the `PG*` form. This is not libpq's socket default. |
| `PGPORT` | `5432` | Port for the `PG*` form. |
| `PGDATABASE` | unset | Database name for the `PG*` form. Setting it selects that form. |
| `PGUSER` | unset | Role name for the `PG*` form. Required with `PGDATABASE`. |
| `PGPASSWORD` | unset | Password for the `PG*` form. |
| `PGSSLMODE` | `prefer` | TLS mode for the `PG*` form. See [TLS](#tls). |
| `PGSSLROOTCERT` | bundled roots | PEM file of trusted CA certificates for the `PG*` form. |
| `PGSSLCERT` | unset | Client certificate, a PEM file, for the `PG*` form. Needs `PGSSLKEY`. See [TLS with a private certificate authority](#tls-with-a-private-certificate-authority). |
| `PGSSLKEY` | unset | Unencrypted private key, a PEM file, for `PGSSLCERT`. |
| `PGSSLROOTCERT_PEM` | unset | Trusted CA certificates as inline PEM, for the `DATABASE_URL` and `PG*` forms. Cannot be combined with `PGSSLROOTCERT`. A literal `\n` is read as a newline. |
| `PGSSLCERT_PEM` | unset | Client certificate as inline PEM, with `PGSSLKEY_PEM`, for the `DATABASE_URL` and `PG*` forms. Cannot be combined with `PGSSLCERT`. |
| `PGSSLKEY_PEM` | unset | Unencrypted private key as inline PEM, with `PGSSLCERT_PEM`, for the `DATABASE_URL` and `PG*` forms. Cannot be combined with `PGSSLKEY`. |
| `PGREQUIREAUTH` | `scram-sha-256,none` | Authentication methods the server may use for the `PG*` form. See [Authentication to PostgreSQL](#authentication-to-postgresql). |
| `PGAPPNAME` | `postgres-mcp` | `application_name` for every connection. Overrides an `application_name` in a URL. |

The three ways to name databases, in the order the server checks them, are:

1. `PG_DATABASES` or `PG_DATABASES_FILE`, a JSON array. Setting both is an error.
2. `DATABASE_URL`, one database named after the URL's database name (or `PG_NAME`).
3. `PGDATABASE` with `PGUSER` and the other `PG*` variables, one database.

If none of them is set, startup fails with a configuration error that begins `no database configured`. When `PG_DATABASES` is set, `DATABASE_URL` and the `PG*` variables are ignored without a warning.

One database from a URL:

```bash
export DATABASE_URL='postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full'
```

The same database from the libpq variables:

```bash
export PGHOST=db.example.com PGPORT=5432 PGDATABASE=appdb PGUSER=mcp_reader PGPASSWORD=change-me-reader-password PGSSLMODE=verify-full
```

Several databases, from a JSON array. Each entry needs `name`, and either a `url` or `database` and `user`. It may set `password` or `password_file`:

```bash
export PG_DATABASES='[
  {"name": "appdb", "url": "postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full"},
  {"name": "analytics", "host": "analytics.example.com", "port": 5432, "database": "warehouse", "user": "mcp_reader",
   "password_file": "/run/secrets/analytics_password", "sslmode": "verify-full", "sslrootcert": "/etc/ssl/certs/corp-ca.pem",
   "max_connections": 4, "statement_timeout_ms": 15000}
]'
```

A JSON entry takes these fields. An unknown field, or a field of the wrong type, is an error:

| Field | Meaning |
|-------|---------|
| `name` | Required. The connection name, 1 to 63 characters of A-Z, a-z, 0-9, `_` or `-`. Names must be unique. |
| `url` | A `postgres://` URL. Its query may hold only `sslmode`, `sslrootcert`, `sslcert`, `sslkey`, `require_auth`, `application_name` and `connect_timeout` (1 to 3600 seconds). Cannot be combined with `host`, `port`, `database`, `user`, `password`, `sslmode`, `sslrootcert`, `sslcert`, `sslkey` or `require_auth`. The inline PEM fields below may accompany it. |
| `host`, `port` | Host (default `127.0.0.1`) and port (default 5432, 1 to 65535). |
| `database`, `user` | Required in the discrete form. |
| `password`, `password_file` | At most one. `password_file` is read at startup, and its trailing line break is dropped. An empty file means no password. With `url`, `password_file` replaces the password in the URL. |
| `sslmode`, `sslrootcert` | As for the `PG*` variables. |
| `sslcert`, `sslkey` | Client certificate and its unencrypted key, PEM files, as for `PGSSLCERT` and `PGSSLKEY`. Cannot be combined with `url`. |
| `sslrootcert_pem`, `sslcert_pem`, `sslkey_pem` | The same items as inline PEM text, as for the `PGSSL*_PEM` variables. A JSON string holds real newlines or `\n` escapes. Each may be used with `url` or with the discrete fields. |
| `require_auth` | The authentication methods the server may use, as for `PGREQUIREAUTH`. Cannot be combined with `url`. |
| `max_connections` | Pooled connections for this database, 1 to 64. Default 4. |
| `statement_timeout_ms`, `lock_timeout_ms` | Per-database timeouts, with the same bounds as the global variables below. |

The `*_FILE` variants keep secrets out of the environment. `API_KEY_FILE` reads the whole file and trims whitespace at both ends. `PG_DATABASES_FILE` reads the JSON array from a file, and a `password_file` inside an entry reads that entry's password. Setting a value and its `_FILE` variant together is an error.

### TLS

`sslmode` (or `PGSSLMODE`, or the `sslmode` parameter of a URL, or the `sslmode` field of a JSON entry) takes one of five values. The default is `prefer`.

| Value | Behaviour |
|-------|-----------|
| `disable` | No TLS. |
| `prefer` | Use TLS when the server offers it, and accept any certificate. Otherwise connect without TLS. |
| `require` | TLS is required, and any certificate is accepted. The connection fails if the server refuses TLS. |
| `verify-ca` | TLS, and the certificate must chain to a trusted root. The host name is not checked. |
| `verify-full` | TLS, and the certificate must chain to a trusted root and match the host name. |

The trusted roots are the PEM file named by `sslrootcert` (or `PGSSLROOTCERT`), or the inline PEM named by `sslrootcert_pem` (or `PGSSLROOTCERT_PEM`), when one is set, and otherwise the bundled Mozilla root set (webpki-roots), not the operating system store. A private certificate authority therefore needs `sslrootcert` or its inline form. `verify-ca` needs one of them: without it the configuration fails with an error that ends `sslmode=verify-ca needs sslrootcert`. `verify-full` without a root checks against the bundled roots. Files and inline PEM are read once, when the server starts. A file that cannot be read, or PEM that holds no certificate, stops startup with a configuration error. Use `verify-full` for any database that is reached over a network.

Unlike libpq, the server does not turn sslmode=require into certificate verification when a root certificate is given: it refuses that combination, so a configuration never looks verified when it is not.

### TLS with a private certificate authority

A server whose certificate is signed by your own CA is verified with that CA certificate, given as `sslrootcert`, with `sslmode=verify-full`:

```bash
export DATABASE_URL='postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full&sslrootcert=/etc/ssl/private-ca.pem'
```

- The host name in the URL must be one of the names in the server certificate. An IP address fails unless the certificate lists that address. `verify-ca` checks the chain without the name, and only where that is acceptable.
- The server certificate must carry the host name in its subject alternative names. A certificate that has the name only in its common name (CN) is refused, even though libpq accepts it.
- The inline alternative avoids a mounted file. In a JSON entry use `sslrootcert_pem`. For the `DATABASE_URL` and `PG*` forms use `PGSSLROOTCERT_PEM`, where a literal `\n` is read as a newline. Give one form of an item, never both.
- A server that requires a client certificate, with `hostssl ... clientcert=verify-full` in `pg_hba.conf` or with `cert` authentication, needs `sslcert` and `sslkey`, or `PGSSLCERT` and `PGSSLKEY`, or the `_PEM` forms. The key must be an unencrypted PEM key: PKCS#8, PKCS#1 (RSA) or SEC1 (EC). An encrypted key stops startup. The certificate file holds the leaf certificate first, and may be followed by intermediate certificates. It must match the key. The certificate is offered whenever the server asks for one. Client certificates need a `sslmode` other than `disable`. With `sslmode=prefer`, a server that refuses TLS gets a plain connection, and no certificate is sent.
- All these settings are read once at startup. Keys are never written to the log or to an error text.

Run the server in a container with the CA file mounted read-only:

```bash
docker run -d --name postgres-mcp \
  -p 127.0.0.1:8432:8432 \
  -v /path/to/ca.pem:/etc/postgres-mcp/ca.pem:ro \
  -e 'DATABASE_URL=postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full&sslrootcert=/etc/postgres-mcp/ca.pem' \
  -e 'API_KEY=change-me-to-a-random-key-of-16-plus-chars' \
  postgres-mcp:local
```

The container runs as user 65532, so a mounted certificate or key file must be readable by that user.

The same with a Compose `secrets:` entry, which mounts the file at `/run/secrets/db_ca`:

```yaml
services:
  postgres-mcp:
    image: postgres-mcp:local
    environment:
      DATABASE_URL: postgres://mcp_reader:change-me-reader-password@db.example.com:5432/appdb?sslmode=verify-full&sslrootcert=/run/secrets/db_ca
    secrets:
      - db_ca
secrets:
  db_ca:
    file: ./ca.pem
```

### Authentication to PostgreSQL

`require_auth` lists the authentication methods the server may use. It takes a comma list of `scram-sha-256`, `md5`, `password` (cleartext) and `none` (trust, no password). It is set by `PGREQUIREAUTH`, by the `require_auth` query parameter of a URL, or by the `require_auth` field of a JSON entry. When it is unset the list is `scram-sha-256,none`.

A method that the server asks for and the list does not name is refused, and no password is sent for it. `md5` and `password` are refused unless they are listed. `password` also needs TLS: a server that asks for a cleartext password on an unencrypted connection is refused, whatever the list says. An unknown name, or a list with no name in it, is a configuration error.

The client also refuses a SCRAM server that ends authentication without proving that it knows the password. SCRAM-SHA-256-PLUS (channel binding) is not implemented.

### Connection errors

A failed connection reaches the client as one short text that names the database, for example `Database "appdb" is unavailable: authentication failed`. The text is one of `authentication failed`, `the database does not exist`, `too many connections`, `the server refused the connection (SQLSTATE code)`, `cannot connect to the server`, `TLS negotiation failed`, `connection timed out` or `unexpected reply from the server`. When every pooled connection of a database is in use, the text is `all connections are busy, retry shortly`. The PostgreSQL message and its SQLSTATE, or the TLS or socket error, are written to the server log only, with the role name in the message replaced by `<user>`.

### HTTP and authentication

| Variable | Default | Meaning |
|----------|---------|---------|
| `MCP_HOST` | `127.0.0.1` | IP address to bind, as an IP literal such as `127.0.0.1` or `::1`. The container image sets `0.0.0.0`. |
| `MCP_PORT` | `8432` | TCP port for the HTTP server. Also used by `postgres-mcp healthcheck`. |
| `API_KEY` | unset | Required key for `/mcp`, at least 16 characters. Unset means no key is checked. |
| `API_KEY_FILE` | unset | Path to a file that holds the key. Cannot be combined with `API_KEY`. |
| `ALLOWED_ORIGINS` | none | Comma-separated extra browser origins such as `https://app.example.com`. Loopback origins are always allowed. |
| `ALLOWED_HOSTS` | none | Comma-separated extra `Host` header names, such as `mcp.example.com`. `localhost`, `127.0.0.1` and `::1` are always allowed. |

When `MCP_HOST` is not a loopback address and no `API_KEY` is set, the server logs a warning at startup. A request to `/mcp` is checked in this order: the Origin header, then the API key, then the Host header. The key is accepted in an `X-API-Key` or an `Authorization: Bearer` header. An `X-API-Key` header that is present but empty wins over a Bearer token. See [Security model](#security-model).

### Limits and timeouts

| Variable | Default | Bounds | Meaning |
|----------|---------|--------|---------|
| `MAX_ROWS` | `1000` | 1 to 100000 | Most rows one `execute_query` call returns. |
| `MAX_VALUE_BYTES` | `4096` | 64 to 1048576 | Longest text or JSON value returned before it is cut. An array is cut only when its text is more than 16 times this. |
| `MAX_BINARY_PREVIEW_BYTES` | `256` | 16 to 65536 | Bytes of a `bytea` value shown as hex before it is cut. |
| `MAX_RESPONSE_BYTES` | `48000` | 1024 to 16777216 | Budget for the raw bytes of values in one result. |
| `MAX_REQUEST_BYTES` | `1048576` | 1024 to 16777216 | Largest HTTP request body accepted. A larger body gets 413 with a JSON body, whether it is sent with a length or chunked. A body that cannot be read gets 400. |
| `MAX_SQL_BYTES` | `102400` | 256 to 1048576 | Longest SQL text accepted by the gate. |
| `MAX_CONCURRENT_REQUESTS` | `16` | 1 to 1024 | Requests to `/mcp` handled at once. Further requests wait for a slot. |
| `STATEMENT_TIMEOUT_MS` | `30000` | 100 to 3600000 | Server-side limit for each statement. A per-database value overrides it. |
| `LOCK_TIMEOUT_MS` | `5000` | 10 to 600000 | Server-side limit for waiting on a lock. A per-database value overrides it. |
| Request time limit | largest statement timeout plus 30 s | Not set by a variable. A `/mcp` request, body included, that is not complete in time gets 408 with `request_timeout`. |

A database configured through the `DATABASE_URL` or `PG*` forms holds at most 4 pooled connections. The JSON form sets its own `max_connections`. A tool call waits up to 10 seconds for a free connection before it reports that all connections are busy.

### Toolsets and logging

| Variable | Default | Meaning |
|----------|---------|---------|
| `TOOLSETS` | `schema,monitor,logs,timescale` | Tool groups to enable, comma-separated: `schema`, `monitor`, `logs`, `timescale`, `core` or `all`. The core tools are always enabled. See [Tools](#tools). |
| `AUDIT_LOG` | `on` | One audit line per tool call. Accepts `on`, `off`, `true`, `false`, `1` or `0`. See [Security model](#security-model). |
| `LOG_FORMAT` | `text` | Format of log lines on stderr: `text` or `json`. |
| `LOG_LEVEL` | `info` | Log level, used when `RUST_LOG` is unset. The filter is `info,rmcp=warn`: `LOG_LEVEL=x` gives `x,rmcp=warn`, except `debug` and `trace`, which apply to `rmcp` too. |
| `RUST_LOG` | unset | Log filter in `tracing` syntax, used verbatim. Takes precedence over `LOG_LEVEL`. |

At debug and trace level the MCP library logs whole requests and responses, which include SQL text and result rows: use those levels only for troubleshooting.

## Tools

The server exposes 20 tools in five toolsets. `core` is always on. Every tool except `list_databases` takes an optional `database` argument, which is required only when several databases are configured. Every tool carries the MCP `readOnlyHint` annotation.

### Core

| Tool | What it does |
|------|--------------|
| `list_databases` | Lists the configured connections with reachability, the PostgreSQL version and the TimescaleDB version. Never returns credentials. |
| `server_info` | Describes one server as this connection sees it: version, uptime, replica status, the role and its memberships, extensions and settings relevant to reading data. |
| `execute_query` | Runs one read-only SQL statement and returns typed columns, rows and truncation flags. |
| `explain_query` | Returns the execution plan of one read-only statement. With `analyze` it really runs the statement, inside the same read-only transaction. |

### Schema (`schema`)

| Tool | What it does |
|------|--------------|
| `list_schemas` | Lists schemas with owner, comment and counts of tables, views and functions. System schemas are left out unless asked for. |
| `list_objects` | Lists tables, views, materialized views, sequences, functions, procedures and types, with estimated row counts and sizes. Paged. |
| `describe_table` | Full definition of a table or view: columns, primary and unique keys, checks, foreign keys in both directions, indexes, triggers, policies and statistics. Sizes: `tableBytes` is `pg_table_size` (heap, TOAST heap and maps), `indexBytes` the indexes and `totalBytes` everything; `toastBytes` is the TOAST table with its indexes and overlaps `tableBytes`. A bare name that several schemas hold is an error that lists them. A partitioned table lists at most 200 partitions, and `partitionsTruncated` is true when there are more. |
| `describe_function` | Argument and return types, language, volatility, parallel safety, strictness, `SECURITY DEFINER`, owner and source text where readable. |
| `search_schema` | Finds tables, views, columns and functions whose name or comment contains the text, case-insensitively. |
| `get_privileges` | Reports what the connected role may read, its predefined roles, its database privileges (`databasePrivileges`), the monitoring features that work, and anything beyond read access. |

### Monitor (`monitor`)

| Tool | What it does |
|------|--------------|
| `list_activity` | Sessions from `pg_stat_activity` with state, wait event, durations, query text and the PIDs that block each session. Passwords in the query text are masked on a best-effort basis. |
| `query_stats` | Top statements from `pg_stat_statements`, ranked by total time, mean time, calls, rows or I/O. Passwords in the statement text are masked on a best-effort basis. |
| `database_stats` | Cumulative database, I/O, WAL, checkpointer, progress and wait-event statistics, one section or several per call. On PostgreSQL 17 and newer each wait event carries its description. |
| `table_stats` | Per-table scan, write and vacuum activity with sizes, plus each index's scan count, so unused indexes show up. |
| `replication_status` | Recovery state, standbys with lag, replication slots and the WAL they retain, and logical subscriptions and publications. |

### Logs (`logs`)

| Tool | What it does |
|------|--------------|
| `read_server_log` | Reads PostgreSQL server log entries, newest first, with time, severity, text and user filters, or lists the log files and logging settings. See [Server log access](#server-log-access). |

### TimescaleDB (`timescale`)

| Tool | What it does |
|------|--------------|
| `list_hypertables` | Hypertables with time dimension, chunk interval, chunk count, columnstore state, size and approximate row count. |
| `describe_hypertable` | One hypertable in detail: dimensions, columnstore settings, attached policies and its chunks, newest first. Its `tableBytes` is the heap and TOAST, `indexBytes` the indexes and `totalBytes` everything. |
| `list_continuous_aggregates` | Continuous aggregates with their source hypertable, defining query, real-time setting, refresh policy and watermark. |
| `list_jobs` | TimescaleDB jobs and policies with schedule and last run, and optionally recent runs and failures. |

The hypertable and job list tools report `timescaledb: false` with a note when the extension is not installed in the database. The monitoring and TimescaleDB tools report what is missing, such as a grant, an extension or a server version, rather than failing silently.

### Resources

Clients that support MCP resources can read three read-only views, which need the `schema` toolset (on by default). Each configured database is listed as `postgres://<database>`, and reading it returns a summary: the PostgreSQL version, the TimescaleDB version when installed, the schemas with their object counts, and the installed extensions. `postgres://<database>/<schema>` returns the `list_objects` result for one schema, its first page, with `nextCursor` when more objects follow. `postgres://<database>/<schema>/<table>` returns the `describe_table` result for one table or view. A name that contains `/` is written with `%2F`, and other names are percent-decoded as usual. The `database`, `schema` and `table` arguments of the two templates have completion, and schemas and tables are listed only where the role may use the schema. With `TOOLSETS=core` the server offers neither resources nor completions.

### Switching toolsets

`TOOLSETS` takes a comma-separated list. Only the listed groups are enabled, plus `core`:

```bash
TOOLSETS=core                  # the four core tools only
TOOLSETS=core,schema,monitor   # core, schema and monitoring
TOOLSETS=all                   # every group, the same as the default
```

A disabled tool is not listed to the client, and calling it returns an `unknown tool` error.

### Calling a tool

Tools are called with JSON arguments. A call to `execute_query` looks like this:

```json
{"name": "execute_query", "arguments": {"database": "appdb", "sql": "SELECT id, name FROM app.items ORDER BY id LIMIT 3"}}
```

Successful results come back as structured JSON, and also as the same JSON in one text block. A database or gate error is a tool result with `isError` set to true, and its text gives the reason. Invalid arguments and unknown tool names are JSON-RPC errors instead.

### Examples

One call per tool, as the JSON a client sends in `tools/call`. The examples use the `appdb` database, and the names are those of the test stack. Each row says what the call returns.

**Core**

| Call | Returns |
|------|---------|
| `{"name": "list_databases", "arguments": {}}` | The configured connections, with reachability and versions. |
| `{"name": "execute_query", "arguments": {"database": "appdb", "sql": "SELECT status, count(*) AS orders FROM shop.orders GROUP BY status ORDER BY status"}}` | Typed columns and rows of the query. |
| `{"name": "explain_query", "arguments": {"database": "appdb", "sql": "SELECT * FROM shop.orders WHERE customer_id = 7", "format": "json"}}` | The plan of the statement as JSON, without running it. |
| `{"name": "server_info", "arguments": {"database": "appdb"}}` | The server version, uptime, role, extensions and settings. |

**Schema**

| Call | Returns |
|------|---------|
| `{"name": "list_schemas", "arguments": {"database": "appdb"}}` | The non-system schemas with owner and object counts. |
| `{"name": "list_objects", "arguments": {"database": "appdb", "schema": "shop", "kinds": ["table", "view"], "limit": 50}}` | One page of tables and views in `shop`. |
| `{"name": "describe_table", "arguments": {"database": "appdb", "table": "orders", "schema": "shop"}}` | Columns, keys, indexes and policies of `shop.orders`. |
| `{"name": "describe_function", "arguments": {"database": "appdb", "function": "order_total", "schema": "shop"}}` | The signature, volatility and source of `shop.order_total`. |
| `{"name": "search_schema", "arguments": {"database": "appdb", "query": "order", "kinds": ["table", "column"]}}` | Tables and columns whose name or comment contains "order". |
| `{"name": "get_privileges", "arguments": {"database": "appdb"}}` | What the connected role may read, and which monitoring features work. |

**Monitor**

| Call | Returns |
|------|---------|
| `{"name": "list_activity", "arguments": {"database": "appdb", "state": "active", "min_duration_ms": 1000}}` | Sessions that have been active for at least one second. |
| `{"name": "query_stats", "arguments": {"database": "appdb", "order_by": "total_time", "limit": 10}}` | The ten statements with the most total time. |
| `{"name": "database_stats", "arguments": {"database": "appdb", "sections": ["database", "wal"]}}` | Database counters and WAL statistics. |
| `{"name": "table_stats", "arguments": {"database": "appdb", "schema": "shop", "order_by": "dead_rows", "limit": 10}}` | The ten tables in `shop` with the most dead rows. |
| `{"name": "replication_status", "arguments": {"database": "appdb"}}` | Recovery state, standbys with their lag, and replication slots. |

**Logs**

| Call | Returns |
|------|---------|
| `{"name": "read_server_log", "arguments": {"database": "appdb", "min_severity": "ERROR", "contains": "deadlock", "limit": 50}}` | Up to 50 ERROR entries that mention "deadlock", newest first. |

**TimescaleDB**

| Call | Returns |
|------|---------|
| `{"name": "list_hypertables", "arguments": {"database": "appdb", "schema": "metrics"}}` | The hypertables in `metrics`, with chunk counts and sizes. |
| `{"name": "describe_hypertable", "arguments": {"database": "appdb", "hypertable": "readings", "schema": "metrics"}}` | Dimensions, policies and the newest chunks of `metrics.readings`. |
| `{"name": "list_continuous_aggregates", "arguments": {"database": "appdb", "schema": "metrics"}}` | Continuous aggregates with their source and refresh policy. |
| `{"name": "list_jobs", "arguments": {"database": "appdb", "history": true, "only_failures": true, "limit": 20}}` | Recent failed job runs. |

## What queries are accepted

`execute_query` and `explain_query` accept exactly one statement per call. The gate parses it with PostgreSQL's own parser and walks the parse tree. Only a statement it can prove read-only is run.

Accepted: `SELECT` in all its forms (`WITH`, set operations, window functions, `LATERAL`, `GROUPING SETS`, `JSON_TABLE`), `VALUES`, `TABLE`, `EXPLAIN` of a `SELECT` (with `ANALYZE` and other options from an allow-list), and `SHOW`. One trailing `;` is fine.

| Accepted | Rejected |
|----------|----------|
| `SELECT id, name FROM users WHERE id > 10 ORDER BY name LIMIT 5;` | `INSERT INTO t (a) VALUES (1);` |
| `WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 10) SELECT n FROM r;` | `UPDATE t SET a = 1 WHERE b = 2;` and `DELETE FROM t WHERE a = 1;` |
| `VALUES (1, 'a'), (2, 'b');` and `TABLE t;` | `CREATE TABLE t (a int);`, `DROP TABLE t;` and `ALTER TABLE t ADD COLUMN c int;` |
| `(SELECT a FROM t1) UNION (SELECT a FROM t2);` | `SET search_path = public;`, `BEGIN;`, `COMMIT;` and `CALL some_proc(1);` |
| `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) SELECT * FROM t;` | `DO $$ BEGIN PERFORM 1; END $$;`, `COPY t TO STDOUT;` and `LISTEN chan;` |
| `SHOW server_version;` | `PREPARE p AS SELECT 1;` and `VACUUM t;` |
| `SELECT "delete", "update" FROM "t";` (keywords as quoted names) | `EXPLAIN ANALYZE INSERT INTO t VALUES (1);` (EXPLAIN takes only a SELECT) |
| `SELECT time_bucket('1 hour', ts) AS h, avg(v) FROM metrics GROUP BY h;` | `SELECT 1; SELECT 2;` (more than one statement) |
| `SELECT pg_sleep(1);` (allowed, and still limited by the time limit) | `SELECT 1 INTO x;` and `SELECT * FROM t FOR UPDATE;` |
| `SELECT lo_get(123);` (reads one large object) | `WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d;` (data-modifying CTE) |
| `SELECT * FROM pg_stat_activity;` and `SELECT * FROM pg_roles;` | `SELECT $1;` (a placeholder is rejected; inline the value) |
| | `SELECT pg_terminate_backend(1);`, `SELECT nextval('s');` and `SELECT pg_read_file('/etc/passwd');` |
| | `SELECT (pid).pg_terminate_backend FROM pg_stat_activity;` (a dotted name that would call a denied function) |
| | `SELECT * FROM dblink('x', 'y') AS t(a int);` (remote SQL functions are denied by name) |
| | `SELECT * FROM pg_authid;` and `SELECT * FROM pg_settings;` (credential catalogs and settings) |
| | `SHOW primary_conninfo;` and `SELECT current_setting('ssl_key_file');` (settings that name credentials or paths) |

The examples are shortened from [`tests/gate_corpus/allow.sql`](tests/gate_corpus/allow.sql) and [`tests/gate_corpus/deny.sql`](tests/gate_corpus/deny.sql), which hold the full set and are checked by the test suite. Keywords and semicolons inside string literals do not count as statements, so `SELECT 'INSERT INTO t; DROP TABLE x';` is a plain read.

A rejected statement comes back as `Query rejected:` followed by the reason, which names the construct. For example, `SELECT $1;` returns `Query rejected: Parameter placeholders ($1) are not supported. Inline the value.`

Three things happen in order. The gate runs first and rejects the statement before the database sees it. The statement then runs in a `READ ONLY` transaction, which PostgreSQL enforces on its own, and that transaction is always rolled back. Finally the connection is reset with `ROLLBACK` and `DISCARD ALL` before it returns to the pool. A statement the gate misses still cannot write, because PostgreSQL refuses writes in a read-only transaction.

The gate accepts only a fixed set of node types, so a statement with a construct it does not recognise is refused. It checks the functions a statement calls by name against a deny-list of side-effect, file and network functions of PostgreSQL and common extensions, and it refuses calls into TimescaleDB internal schemas. A deny-list cannot name every extension function, so the read-only transaction and the role's privileges are the real barrier. It also checks the catalogs and settings a statement reads. `current_setting()` takes only a literal setting name, such as `current_setting('work_mem')`. `current_setting('work_mem'::text)` and a computed name are refused, and so is a setting that can expose credentials. [SECURITY.md](SECURITY.md) lists what the gate cannot stop.

### Placeholders and generic plans

`execute_query` refuses `$1` placeholders: `Query rejected: Parameter placeholders ($1) are not supported. Inline the value.`

`explain_query` with `generic_plan` set plans the statement as a generic plan, so the statement may contain `$1` placeholders. The tool binds no values and does not run the statement, so the plan shows the placeholders as they are. `generic_plan` needs PostgreSQL 16 or newer, and it cannot be combined with `analyze`. An older server answers `Option generic_plan needs PostgreSQL 16 or newer; this server is PostgreSQL` followed by its own version.

For this option only, the statement is sent with the simple query protocol, and only after the server has parsed the identical text through the extended protocol as a single statement. The reply must be exactly one EXPLAIN result. A reply of any other shape is refused as an internal error, and its connection is closed. A database error is returned as usual.

## Result format and value encoding

`execute_query` returns one envelope per call:

```json
{
  "database": "appdb",
  "columns": [{"name": "id", "type": "int4", "typeOid": 23}, {"name": "name", "type": "text", "typeOid": 25}],
  "rows": [{"id": 1, "name": "item 1"}],
  "rowCount": 1,
  "truncated": false,
  "truncatedValues": 0,
  "rawFallbacks": 0,
  "executionTimeMs": 2,
  "redactedHashes": 0
}
```

`redactedHashes` is the number of `[redacted password hash]` markers in the result, as text and as the hex of their bytes, in column names, row keys and values.

`columns` lists every result column in SELECT order, even when there are no rows. Each column's `type` is the PostgreSQL type name, such as `int4` or `text`. An array column is named `<element>[]`, such as `int4[]` or `text[]`, for built-in and custom element types alike. A custom type outside the `public` and `pg_catalog` schemas is schema-qualified, such as `types.mood`. A domain column reports its base type. A column has `originalName` only when its name was changed. Duplicate names become `id__2`, `id__3` and so on, with `originalName` set to the name the query used. `rows` holds one object per row, keyed by column name. `truncatedReason` appears only when `truncated` is true. `truncatedValues` counts values that were cut, and `rawFallbacks` counts values that were returned as PostgreSQL text because they did not parse as their type.

The server sets the session's DateStyle to ISO, MDY, IntervalStyle to `iso_8601`, TimeZone to UTC and `bytea_output` to hex. Every result is formatted under those settings.

| PostgreSQL type | JSON value |
|-----------------|------------|
| `boolean` | `true` or `false` |
| `smallint`, `integer`, `oid`, `xid`, `cid` | number |
| `bigint`, `xid8`, `oid8`, `count(*)` | number while the value is between -(2^53-1) and 2^53-1, otherwise an exact decimal string |
| `numeric`, `decimal` | string with the exact digits and scale, such as `"1.50"`, or `"NaN"`, `"Infinity"`, `"-Infinity"` |
| `real`, `double precision` | number, or the strings `"NaN"`, `"Infinity"`, `"-Infinity"` |
| `date`, `time`, `timetz`, `timestamp`, `timestamptz` | ISO text such as `"2024-02-29 13:00:00.123456"`. timestamptz is in UTC and ends in `+00`. `infinity`, `-infinity` and a ` BC` suffix can appear. |
| `interval` | ISO 8601 duration such as `"P1Y2M3DT4H5M6.789S"`. Parts can be negative, as in `"P-1M2DT-3H"`. |
| `json`, `jsonb` | inline JSON, with numbers kept exact. A `json` value with duplicate keys comes back as its original text. |
| arrays | nested JSON arrays, with elements encoded by the same rules and SQL NULL as `null`. An array with non-default lower bounds is `{"lowerBounds": [...], "elements": [...]}`. |
| ranges | `{"lower": ..., "upper": ..., "lowerInc": true, "upperInc": false}`, where an unbounded bound is `null`, or `{"empty": true}` |
| multiranges | an array of range objects |
| `bytea` | `"\x"` followed by hex. A value of up to `(MAX_VALUE_BYTES - 2) / 2` bytes shows its first `MAX_BINARY_PREVIEW_BYTES` bytes when it is longer than that, then `…[truncated: X of Y bytes]`. A longer value shows the `(MAX_VALUE_BYTES - 2) / 2` bytes the wire kept, then `…[truncated: X of Y bytes]`. |
| `text`, `varchar`, `char`, `name`, `uuid`, `inet`, `cidr`, `macaddr`, `money`, `bit`, `xml`, geometric types, `tsvector`, `tsquery` | PostgreSQL's own text |
| enum, composite and extension types (`hstore`, `vector`, PostGIS geometry and so on) | PostgreSQL's own text. Use `to_jsonb(col)`, `ST_AsGeoJSON(col)` or `col::text` for another shape. |
| domain | the encoding of its base type, so a domain over `integer` is a number |
| SQL NULL | `null` |

Text values longer than `MAX_VALUE_BYTES` are cut on a character boundary and end with `…[truncated: X of Y bytes]`. The cut value is counted in `truncatedValues`. Re-query with `substr()` to get the rest. A wide value is cut while it is read: the rest of it is discarded without being held in memory, and the row is still returned.

Size caps apply in this order:

- **Rows.** At most `MAX_ROWS` rows (default 1000) are returned. If another row exists, `truncated` is true and `truncatedReason` is `row_limit`.
- **Response budget.** The raw bytes of the kept values are summed. When the next row would take the total past `MAX_RESPONSE_BYTES` (default 48000), the result stops there with `truncatedReason` set to `response_size`. The first row is always returned, even when it alone exceeds the budget. The JSON text can be somewhat larger than the raw byte count.
- **Values.** Each text or JSON value is cut at `MAX_VALUE_BYTES`. An array is decoded in full unless its text is more than 16 times that size, and then it is cut as text at `MAX_VALUE_BYTES`. Each `bytea` value is cut at `MAX_BINARY_PREVIEW_BYTES`. The wire keeps `MAX_VALUE_BYTES` characters of a longer value's hex text, so that value shows `(MAX_VALUE_BYTES - 2) / 2` bytes.

`truncated: true` always means the result is partial, and it is never silent. Add a `LIMIT`, an aggregate or fewer columns, and use `ORDER BY` for a stable page.

## Server log access

The server log holds errors, slow statements, connection events and, if pgaudit is loaded, audit records. Reading it is often the fastest way to see why something failed. MySQL can write its general and slow logs to tables that SQL can query. PostgreSQL has no such tables by default: its log is a set of files on the server. This server reads those files through a narrowly scoped `SECURITY DEFINER` function, rather than granting the role access to the filesystem.

Setup takes three steps, run once on each server:

1. Set `logging_collector = on` in `postgresql.conf`, or with `ALTER SYSTEM`, and restart PostgreSQL. Use `log_destination = jsonlog` (recommended), `csvlog` or `stderr`. The functions read the files the collector writes under `log_directory`.
2. As a superuser, run [`sql/log_reader.sql`](sql/log_reader.sql) in the database that the server uses. It creates the `pgmcp` schema, a `NOLOGIN` owner role `pgmcp_log_reader`, and two functions: `pgmcp.read_log_file(name, offset, length)` and `pgmcp.list_log_files()`. It grants no application role.
3. Grant the server's role the two privileges it needs:

```sql
GRANT USAGE ON SCHEMA pgmcp TO mcp_reader;
GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_reader;
```

`read_log_file` reads at most 1 MiB per call. It accepts only a file name that matches `^[A-Za-z0-9][A-Za-z0-9._-]*$` and that PostgreSQL lists in `log_directory`. The functions run with a fixed `search_path`, and `EXECUTE` is revoked from `PUBLIC`, so only roles granted it can call them. An invalid request raises `invalid log file request`. Both functions must be `SECURITY DEFINER` and owned by `pgmcp_log_reader` or by a superuser. Otherwise `read_server_log` reports that they were not installed by `sql/log_reader.sql`.

The `read_server_log` tool, in the `logs` toolset, uses these functions. Its arguments are `list_files` (true to list the log files and the logging settings instead of entries), `since` and `until` (ISO timestamps), `min_severity` (`DEBUG` up to `PANIC`), `contains` (case-insensitive text), `user`, `entry_database` (the database named in the log entry, not the connection), `pid`, `file` (one log file by name), `limit`, and `cursor`. Entries are newest first. Each has a timestamp, a severity and the message, and, when the log format provides them, the user, database, pid, SQLSTATE, detail, hint and statement. jsonlog and csvlog are parsed into fields, and plain stderr lines have their severity read from the prefix when possible. Passwords in log entries (the message, detail, statement and context) are masked on a best-effort basis, and so are passwords in statement text from `list_activity` and `query_stats`. Masking covers `PASSWORD` literals, including escape-string (`E'...'`), Unicode (`U&'...'`) and dollar-quoted ones, the `password=`, `sslpassword=` and `passfile=` settings, and passwords in URLs. One call scans a bounded amount of log, so it can return zero entries with `scannedToEnd` false. That means to call again with the `nextCursor`. pgaudit records are in the same log, and `contains: "AUDIT:"` finds them.

What the tool can read: the files the collector writes into `log_directory`. What it cannot read: anything outside that directory, such as data files and WAL. With `logging_collector` off, PostgreSQL writes its log to stderr rather than to files, so there is nothing for the functions to read, and the tool's result says what to change.

The gate refuses calls to these functions in `execute_query`, so log text always passes through the tool's masking.

## TimescaleDB

The four TimescaleDB tools show the parts of TimescaleDB that the generic tools cannot: hypertables with their dimensions and columnstore settings, continuous aggregates with their refresh policies and watermarks, and background jobs with their history. They read the `timescaledb_information` views and the job history, and they probe which views and columns the installed version offers, so they name only what exists.

Everything else works through the generic tools. A hypertable is an ordinary table to `describe_table` and `list_objects`, a continuous aggregate is a view, and `time_bucket`, `time_bucket_gapfill` and `locf` are accepted in `execute_query`:

```sql
SELECT time_bucket('1 hour', ts) AS bucket, device_id, avg(temperature) AS avg_temperature
FROM metrics.readings
GROUP BY bucket, device_id
ORDER BY bucket DESC
LIMIT 100;
```

Versions tested. The test stack runs PostgreSQL 15, 18 and 19. TimescaleDB runs in the test stack on PostgreSQL 18 only, at version 2.32.1. The timescale tools are tested only where the extension is installed.

## Security model

The threat model and every layer are described in [SECURITY.md](SECURITY.md). In short:

- **Database role.** The role is the real boundary. Use the read-only role above, with `default_transaction_read_only` set, and never share it with an application.
- **Gate.** Each statement is parsed and checked against an allow-list of node types, a deny-list of functions, and lists of credential catalogs and secret settings. The statistics views `pg_stats`, `pg_stats_ext` and `pg_stats_ext_exprs` are read through a filter that drops the rows of pg_authid, pg_user_mapping, pg_subscription, pg_db_role_setting, pg_statistic, pg_statistic_ext_data and pg_largeobject, with a planner fence so that a caller's predicate cannot run on a hidden row. This holds for every role, superusers included. The TOAST tables of all catalogs are refused by name, and so are the foreign server and foreign-data wrapper catalogs.
- **Password hash scrubber.** Every tool result, resource body, completion and error text, and every log field that can carry text from the database, is scanned before it leaves the server, and text shaped like a PostgreSQL password hash in its stored form (SCRAM-SHA-256 verifier or md5 hash) is replaced with [redacted password hash]. It is always on and cannot be configured off. Each successful tool result carries the number of markers it returns as `redactedHashes`; the audit line and a warning line carry the same count for tools, resources and completions. A quoted literal that follows the keyword PASSWORD after whitespace or at most 256 bytes of comments, as in CREATE ROLE or ALTER ROLE, is replaced with '***' (''***'' when nested in a quoted statement) in every string value and column name on a best-effort basis; keys of JSON objects inside values are not masked, and that mask is not counted. Error texts and log lines get the hash replacement only.
- **Transaction.** Every call runs in `BEGIN READ ONLY` with statement, lock and idle timeouts, and is rolled back. A query that outlives its time limit is cancelled on the server.
- **Session.** Each connection is checked before use and reset with `ROLLBACK` and `DISCARD ALL` after it, so no session state reaches the next caller.
- **Caps.** Rows, values, response bytes, request bytes and SQL text are all capped.
- **Bind.** The HTTP listener binds `127.0.0.1` unless `MCP_HOST` says otherwise.
- **Origin, key and Host.** A request to `/mcp` is checked in this order. An `Origin` header must be a loopback origin or one in `ALLOWED_ORIGINS`, or the request gets 403. The API key comes next. Then the `Host` header must name a loopback host or one in `ALLOWED_HOSTS`, or the request is refused. Loopback origins are always allowed, so a web page served from the same machine can send requests to the server when no API key is set. It cannot read the responses, but it can still make the calls. When a browser runs on the same machine as the server, set `API_KEY` even on loopback.
- **API key.** When `API_KEY` is set, `/mcp` requires it in `X-API-Key` or `Authorization: Bearer`. The key is compared in constant time as SHA-256 digests. `GET /health` stays open for probes.
- **Audit.** With `AUDIT_LOG` on (the default), each tool call, each resource read and each completion request writes one `audit` line to stderr. It holds the tool name, the database name, whether the call succeeded, its duration, the row count, the SQLSTATE of a database error, and the first 16 hex characters of the SHA-256 of the SQL text. It never holds the SQL text, values, error messages, client addresses or keys.

Deliberately absent: no write tool, no flag or setting that enables writes, and no multi-user authentication. One API key is shared by everyone who holds it, and there is no per-user identity or per-user policy inside the server.

For per-person access, policies and audit across many MCP servers, put a gateway in front of it, such as [Doorward](https://github.com/matpb/doorward).

## Development and tests

Three scripts prove a change. None of them needs a CI service, because the project has no CI configuration by design. Run the first two before you open a pull request.

- **`scripts/verify.sh`** needs no database. It runs `cargo fmt --check`, `cargo clippy` with warnings as errors, the library and non-database test targets (`lib`, `config`, `encode`, `gate` and `http_guard`), `cargo audit` and `cargo deny check`. The last two need `cargo-audit` and `cargo-deny` installed.
- **`scripts/integration.sh`** starts [`docker-compose.test.yml`](docker-compose.test.yml), runs every cargo test target with `--test-threads=4`, and removes the stack afterwards. Pass `--keep` to leave the stack running for the next run. The stack has four PostgreSQL servers on loopback: `timescaledb-ha` on PostgreSQL 18 with TimescaleDB 2.32.1 on port 15432, `postgres` 19 on port 15433 (csvlog), `postgres` 15 on port 15434 and `postgres` 19 with TLS on port 15435 (`pgtls`). The `pgtls` server has a private CA, a server certificate for `localhost` and `pgtls.test.example`, and client certificates for the `mcp_cert` role. [`docker/tls-initdb/10_tls.sh`](docker/tls-initdb/10_tls.sh) generates them with `openssl` at the first start, so no key or certificate is in the repository. The TimescaleDB server also preloads `pg_stat_statements` and pgaudit. The databases are seeded with the `app`, `shop` and `types` schemas, a `metrics` schema on the TimescaleDB server, and test roles with throwaway passwords: `mcp_ro`, which has the broad profile (`pg_read_all_data` and `pg_monitor`) and stays as the hostile test role, `mcp_recipe`, which has the README recipe with `pg_monitor`, `mcp_strict`, which has per-schema `SELECT` grants and `pg_read_all_stats`, and `mcp_min`, which may select only from `app.items`.
- **`scripts/docker-smoke.sh`** builds the image as `postgres-mcp:smoke`, runs it against the test database on PostgreSQL 19, and checks the health route, the 401 without a key, `tools/list`, a `SELECT`, a refused `INSERT`, one stdio `tools/call` round trip, the absence of a shell and the read-only root filesystem.

The cargo test targets are these. `lib` (the unit tests in `src/`), `config`, `encode`, `gate`, `http_guard`, `tls` and `wire_fake` need no database. `wire`, `session`, `types_exact`, `hardening`, `schema_tools`, `monitor_tools`, `timescale_tools`, `logs_tools`, `mcp_http`, `mcp_stdio`, `resources` and `tls_real` need the test stack. `tls_real` runs TLS against `pgtls` through the wire client, the pool and the binary. `tests/types_exact.rs` checks the value-encoding table above against PostgreSQL 15, 18 and 19. `tls` runs a server in-process with certificates made at test time, and `wire_fake` runs the wire client against scripted servers. The test databases are seeded from [`docker/initdb`](docker/initdb), and the tests do not run DDL, so an object that a test needs belongs in the seed.

Tests that need a database connect only to the test stack on loopback ports 15432 to 15435. The library and non-database tests run without any database.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Startup stops with `configuration error: no database configured: set PG_DATABASES, DATABASE_URL, or PGDATABASE with PGHOST and PGUSER` (exit 2) | No database is configured. | Set `PG_DATABASES`, `DATABASE_URL`, or `PGDATABASE` with `PGHOST` and `PGUSER`. See [Databases](#databases). |
| HTTP 401 from `/mcp`, with `"error":"unauthorized"` | `API_KEY` is set, and the request sends no key or a different one. | Send the key in `X-API-Key` or `Authorization: Bearer`. `GET /health` needs no key. |
| Startup stops with `configuration error: API_KEY: must not start or end with whitespace` (exit 2) | The `API_KEY` value has a leading or trailing space. | Remove the space. A key read from `API_KEY_FILE` is trimmed instead. |
| HTTP 403 from `/mcp`, with `"message":"Origin not allowed"` | The `Origin` header is neither a loopback origin nor in `ALLOWED_ORIGINS`. | Add the origin to `ALLOWED_ORIGINS`. Loopback origins need no entry. See [HTTP and authentication](#http-and-authentication). |
| HTTP 403 with `Forbidden: Host header is not allowed`, typically behind a reverse proxy | The `Host` header names a host that is neither loopback nor in `ALLOWED_HOSTS`. | Add the public host name to `ALLOWED_HOSTS`. |
| `Database "appdb" is unavailable: authentication failed` | The password or user is wrong, or the server asks for MD5 or cleartext and `require_auth` does not allow that method. | Check the credentials. If the server uses MD5 or cleartext, list the method in `require_auth`; cleartext also needs TLS. See [Authentication to PostgreSQL](#authentication-to-postgresql). |
| `Database "appdb" is unavailable: TLS negotiation failed` | The TLS handshake failed: the server does not offer TLS, or its certificate did not verify. | Use an `sslmode` the server supports. For `verify-ca` or `verify-full`, set `sslrootcert` to the CA that signed the server certificate; a private CA needs it. See [TLS](#tls). |
| `Database "appdb" is unavailable: TLS negotiation failed` with `sslmode=verify-full`, and the URL names an IP address or a host that the certificate does not list | Certificate name mismatch: the host name is not one of the names in the server certificate. | Connect with a name the certificate lists, or reissue the certificate with that name. `verify-ca` checks the chain without the name. See [TLS with a private certificate authority](#tls-with-a-private-certificate-authority). |
| `Database "appdb" is unavailable: TLS negotiation failed` with `sslmode=verify-full` and a private CA whose certificate has no subject alternative name | The certificate names the host only in its common name. The server does not accept a common name as the host name, although libpq does. | Reissue the certificate with `subjectAltName=DNS:<host>`. The server log line for the connection names the cause. |
| `Database "appdb" is unavailable: TLS negotiation failed` with a server certificate from a private CA | Unknown issuer: `sslrootcert` is missing, or names a CA other than the one that signed the server certificate. | Set `sslrootcert`, or `sslrootcert_pem` in JSON, to the CA certificate that signed the server certificate. |
| `Database "appdb" is unavailable: authentication failed`, when the server requires a client certificate | The client sent no certificate, or none that the server trusts. The server's reply is `connection requires a valid client certificate` and is written to the server log only. | Set `sslcert` and `sslkey` (or `PGSSLCERT` and `PGSSLKEY`, or the `_PEM` forms) to a certificate that the server's CA signed. With `clientcert=verify-full` its CN must equal the role name. A certificate from an untrusted CA gives `TLS negotiation failed` instead. |
| Startup stops with `sslmode=verify-ca needs sslrootcert` | `verify-ca` checks the chain against a root certificate, and none was given. | Set `sslrootcert` to the CA file. |
| `Query rejected: Parameter placeholders ($1) are not supported. Inline the value.` | The SQL contains `$1`. `execute_query` takes no bind values. | Write the values into the SQL. |
| `Query rejected: Send exactly one statement per call; found 2.` | The call holds more than one statement. | Send one statement per call. One trailing `;` is fine. |
| `Query rejected: Only read-only statements are accepted`, or `Function NAME() is not allowed: ...` | The statement writes or changes state, or it calls a function the gate denies. The message names the construct or the reason. | Rewrite the call as a read. Writes are not offered. |
| Result has `"truncated": true` with `truncatedReason` `row_limit` or `response_size` | The rows passed `MAX_ROWS`, or the response passed `MAX_RESPONSE_BYTES`. | Add a `LIMIT`, an aggregate or fewer columns, and an `ORDER BY` for a stable page. The limits are in [Limits and timeouts](#limits-and-timeouts). |
| `The query exceeded the N ms time limit and was cancelled on the server.` | The statement ran past `STATEMENT_TIMEOUT_MS`, or the database's `statement_timeout_ms`. | Narrow the query with `WHERE`, `LIMIT` or an aggregate, or raise the limit. |
| `Database "appdb" is unavailable: all connections are busy, retry shortly` | Every pooled connection to that database stayed in use for 10 seconds. The pool size is the database's `max_connections`. | Retry after a few seconds, or raise `max_connections` for that database. `MAX_CONCURRENT_REQUESTS` caps the requests in flight, and the rest wait. |
| Other sessions' query text is `null` in `list_activity` | The role lacks `pg_read_all_stats`, so PostgreSQL hides other users' statement text. | Grant it: `GRANT pg_read_all_stats TO mcp_reader;`. The tool's note names the same grant. |
| `query_stats` reports `"available": false` | `pg_stat_statements` is not created, or it is created but not in `shared_preload_libraries`. | Add `pg_stat_statements` to `shared_preload_libraries`, restart the server, then run `CREATE EXTENSION pg_stat_statements;`. |
| `read_server_log` reports `The log reader functions are not installed in this database.` | The setup steps under [Server log access](#server-log-access) were not done. | Run the three steps: `logging_collector`, `sql/log_reader.sql` as a superuser, and the grants. |
| TimescaleDB tools report `"timescaledb": false` with `TimescaleDB is not installed in this database.` | The extension is not installed in the database that was named. | Name the database that has it. `list_databases` shows the TimescaleDB version of each. |
| A client cannot parse the stdio replies, or reports text before the first message | Something other than the server writes to stdout, such as a wrapper script or a shell profile. Logs go to stderr. | Send that output to stderr. Stdout carries only JSON-RPC messages. |

## Limitations

- **One statement per call.** A call that sends two statements is refused. `execute_query` refuses placeholders (`$1`). `explain_query` accepts them only with `generic_plan`, and then binds no values (see [Placeholders and generic plans](#placeholders-and-generic-plans)).
- **Authentication to PostgreSQL.** SCRAM-SHA-256 is used without channel binding (SCRAM-SHA-256-PLUS is not implemented). MD5 and cleartext passwords are refused unless `require_auth` lists them, and cleartext also needs TLS. See [Authentication to PostgreSQL](#authentication-to-postgresql).
- **Certificate checks.** `prefer` and `require` do not verify the server certificate. Use `verify-ca` or `verify-full` wherever the network is not trusted. A private certificate authority needs `sslrootcert` or `sslrootcert_pem`, and client certificates need an unencrypted key, as described in [TLS with a private certificate authority](#tls-with-a-private-certificate-authority).
- **Encrypted private keys are not supported.** Give `sslkey` an unencrypted PEM key. An encrypted key stops startup.
- **No LISTEN, NOTIFY or COPY.** The gate refuses them.
- **Large objects.** `lo_get(oid)` reads a large object through `execute_query`, and the value limits apply to its bytes. Writing, importing and exporting large objects are refused.
- **Transaction-mode poolers are not supported.** PgBouncer in transaction mode and similar proxies are untested. Connect the server to PostgreSQL directly or through a session pool.
- **HTTP keeps no session state.** Each POST to `/mcp` is answered independently with a JSON body.
- **Log tool needs file access.** Managed PostgreSQL services without access to log files cannot use `read_server_log`, and the tool reports that.
- **Shared key.** The API key is one secret for every caller. Rotate it by restarting the server with a new value.
- **Several round trips per call.** Each tool call opens a read-only transaction, checks the session, runs the statement and resets the session, which is five or six round trips. Place the server close to the database.

## License

Released under the MIT License. See [LICENSE](LICENSE) for the full text.
