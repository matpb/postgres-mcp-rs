# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- TLS with a private certificate authority: client certificates (`sslcert` and `sslkey`, `PGSSLCERT` and `PGSSLKEY`), inline PEM (`sslrootcert_pem`, `sslcert_pem`, `sslkey_pem` and the `PGSSL*_PEM` variables), all checked once at startup, and a `pgtls` test service on PostgreSQL 19 with TLS.

## [0.1.0]

### Added

- Serving: Streamable HTTP at `/mcp` with `GET /health` (the default `http` command), stdio (`stdio`), and the `healthcheck`, `--help` and `--version` commands.
- Databases: several connections behind one server, configured with `DATABASE_URL`, libpq `PG*` variables, or a `PG_DATABASES` / `PG_DATABASES_FILE` JSON array.
- TLS modes `disable`, `prefer`, `require`, `verify-ca` and `verify-full`, with an optional `sslrootcert` file.
- Core tools: `list_databases`, `server_info`, `execute_query` and `explain_query`.
- Schema tools: `list_schemas`, `list_objects`, `describe_table`, `describe_function`, `search_schema` and `get_privileges`.
- Monitoring tools: `list_activity`, `query_stats`, `database_stats`, `table_stats` and `replication_status`.
- TimescaleDB tools: `list_hypertables`, `describe_hypertable`, `list_continuous_aggregates` and `list_jobs`.
- Toolset selection with `TOOLSETS` (`core`, `schema`, `monitor`, `logs`, `timescale`, `all`).
- Typed JSON results: exact numerics as strings, 64-bit integers beyond 2^53-1 as strings, ISO date and time text, timestamptz in UTC.
- Size caps for rows, values, binary previews, response bytes, request bytes and SQL text, with truncation markers and flags.
- Per-call audit line without SQL text, configurable with `AUDIT_LOG`; log format selectable with `LOG_FORMAT`.
- Logs toolset: `read_server_log`, which reads the server log files, or lists them, through the helper functions below.
- `sql/log_reader.sql`, which creates the `pgmcp.read_log_file` and `pgmcp.list_log_files` helper functions for server log access.
- Container image: multi-stage Dockerfile on a distroless base, running as a non-root user, and an example `docker-compose.yml` bound to loopback.
- Local proof scripts: `scripts/verify.sh`, `scripts/integration.sh` and `scripts/docker-smoke.sh`.
- `explain_query` with `generic_plan` works on PostgreSQL 16 and newer. The plan shows the `$1` placeholders, and no values are bound.
- `get_privileges` reports database privileges under `databasePrivileges`.
- `describe_table` lists at most 200 partitions of a partitioned table, and reports `partitionsTruncated` when there are more.
- `require_auth` for URLs, JSON entries and the `PG*` form (`PGREQUIREAUTH`).
- MCP resources and completions when the `schema` toolset is on: `postgres://<database>` (a summary), `postgres://<database>/<schema>` and `postgres://<database>/<schema>/<table>`, with completion for the template arguments. Each read and each completion request writes one audit line.
- Each `/mcp` request has a time limit: the largest statement timeout of any database plus 30 seconds, body included. A request past it gets 408 `request_timeout`.
- `database_stats` `wait_events` carries each event's description on PostgreSQL 17 and newer.

### Changed

- A bare table name that several schemas hold is an error in `describe_table` that lists the schemas.
- Array columns are reported as `<element>[]` for built-in and custom element types alike. A domain column reports its base type.
- A value longer than `MAX_VALUE_BYTES` is cut while it is read, and the row is still returned. `truncatedValues` counts it.
- An HTTP request body over `MAX_REQUEST_BYTES` gets 413 with the same JSON body, whether it is sent chunked or with a length. A body that cannot be read gets 400.
- The default log filter is `info,rmcp=warn`. `LOG_LEVEL=x` gives `x,rmcp=warn`, except `debug` and `trace`. `RUST_LOG` is used verbatim.
- Every tool rejects an argument field it does not declare, with invalid params that name the field.
- `describe_table` reports `tableBytes` as `pg_table_size`, the same measure as `table_stats`.
- The SQL gate runs on a blocking thread, so a long parse does not stall the async runtime.

### Fixed

- `explain_query` with `serialize` emits `SERIALIZE TEXT`. The boolean form failed on PostgreSQL 17 and newer.
- A NUL byte or invalid byte in a resource URI segment is an unknown-URI resource error, not an internal error with PostgreSQL text.
- Table completion lists only tables in schemas the role may use, as schema completion does.

### Security

- Read-only by construction: a SQL gate that accepts one read-only statement, every statement run in a `READ ONLY` transaction that is rolled back, and a session that is checked and reset around each call.
- Denied at the gate: data-modifying statements and CTEs, `SELECT ... INTO`, row locks, placeholders in `execute_query`, file and large-object writes, server control functions, and catalogs and settings that expose credentials.
- Field selection that names a denied function is refused. `(expr).name` and `rel.name` call `name(expr)` in PostgreSQL, so the last name after a dot is checked like a function call.
- `pgmcp.read_log_file` and `pgmcp.list_log_files` cannot be called from `execute_query`, so log text always passes through the tool's masking.
- `pg_statistic`, `pg_statistic_ext_data` and `information_schema.user_mapping_options` are refused like the other credential catalogs.
- `current_setting()` in a dotted form, such as `('ssl_key_file'::text).current_setting`, is refused like the function call.
- Rejected HTTP requests are logged with their reason (`missing key`, `wrong key` or `origin not allowed`) and their path, never the key or the Origin value.
- Connection failures are logged with the connection name, host and port, and a short reason, never the user or password.
- Optional API key, compared in constant time, accepted as `X-API-Key` or `Authorization: Bearer`.
- Origin and Host header validation, with the HTTP listener bound to `127.0.0.1` by default.
- Authentication policy `require_auth` (the `PGREQUIREAUTH` variable, the `require_auth` URL query parameter and the JSON field) lists the methods the server may use: `scram-sha-256`, `md5`, `password` and `none`. The default is `scram-sha-256,none`. MD5 and cleartext passwords are refused unless listed, and cleartext also needs TLS.
- The SCRAM client refuses a server that ends authentication without proving it knows the password.
- `sslmode=verify-ca` requires `sslrootcert`, and the configuration is refused without it.
- Connection failures reach clients as short fixed texts. The PostgreSQL message and detail are written to the server log only.
- `current_setting()` takes only a literal, non-secret setting name. A computed name is refused.
- The server's own catalog queries run with `search_path = pg_catalog`, so objects planted in user schemas cannot hijack them.
- The server log reader's helper functions must be `SECURITY DEFINER` and owned by `pgmcp_log_reader` or a superuser. Otherwise the tool reports them as not installed by `sql/log_reader.sql`.
- Password masking covers escape-string and dollar-quoted literals, and the statement text of `list_activity` and `query_stats` as well as log entries.
