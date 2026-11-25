# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.5]

### Fixed

- A quote that follows a dollar-quoted PASSWORD literal no longer swallows the text after it, which could expose a later password.
- A nested PASSWORD literal that starts with a space, a comma, a semicolon or a parenthesis is masked.
- Any amount of whitespace between PASSWORD and its literal is accepted; only comments count against the 256-byte limit.
- Column names and row keys are the same string in every case.
- The statement text of list_activity and query_stats and the entries of read_server_log mask a literal that follows PASSWORD and a comment.

## [0.1.4]

### Fixed

- The PASSWORD mask is linear again on text with many comments after the keyword.
- A password literal nested in a quoted statement, as in EXECUTE 'ALTER ROLE ... PASSWORD ''...''', is masked again.
- An md5 hash is replaced when the value cut lands inside the token that follows it.
- A hex-form marker is never cut in half.
- A nested PASSWORD literal is written as ''***'' in results and in list_activity, query_stats and read_server_log; 0.1.3 wrote '***'.
- An md5 hash at the end of a value is replaced when only the first letters of md5 or SCRAM-SHA-256$ follow it.
- An odd hex digit after an md5 hash cut at the end of a hex run is dropped with the hash.

## [0.1.3]

### Fixed

- The scrubber is linear again on values that hold many adjacent hashes.
- The PASSWORD mask in results no longer changes SQL text such as 'password'::text or a message that ends in the word password. A literal that ends in the word password and a space can still be rewritten.
- Two SCRAM verifiers with no separator are replaced as one marker; 0.1.2 returned the second one without its leading SCRAM.
- The PASSWORD mask in results needs whitespace or a comment between the keyword and the literal: PASSWORD'x' is not masked in results.
- Dollar-quote tags with non-ASCII letters are recognised after PASSWORD.
- Hex digits around a replaced hash keep their case, and the warning text is now "redaction markers are present in a result".
- An md5 hash in hex form that the value cut splits keeps none of its digits.
- Column names are masked the same way as row keys.

## [0.1.2]

### Fixed

- The `execute_query` output schema listed `redactedHashes` twice in `required`, which JSON Schema forbids, so clients that validate schemas could not call the tool.
- The PASSWORD mask in results covers only a quoted literal after the keyword PASSWORD and writes it as `'***'`. `password=`, `sslpassword=` and `passfile=` settings and URL passwords are no longer masked in results; server log entries and the statement text of `list_activity` and `query_stats` still mask them.
- `redactedHashes` counts only the markers in the text that is returned: a replacement in text that a cut removed is not counted, and a marker is never cut in half. It counts marker occurrences, not hashes: a hash-shaped column name counts once in `columns` and once per row, text that already holds the marker counts, and a hash inside a PASSWORD literal shows as `'***'` and does not.
- Hash-shaped column names are replaced before duplicate names are numbered, so `columns[].name`, `originalName` and the row keys agree.
- An md5 hash directly before a SCRAM verifier, or two md5 hashes with no separator, are each replaced; an md5 hash directly after a SCRAM verifier is replaced together with it.
- An md5 hash that PostgreSQL cut short keeps none of its digits in the query field of `list_activity` and `query_stats`.
- A hash inside a record's text, where a bytea value is written in hex, is replaced in its hex form.

## [0.1.1]

### Changed

- The statistics views `pg_stats`, `pg_stats_ext` and `pg_stats_ext_exprs` are read through a filter that drops the rows of the catalogs that hold password hashes and stored passwords, and a planner fence keeps a caller's predicate from running on a hidden row. The gate rewrites each reference and refuses forms it cannot rewrite with `relation_denied`. The filter applies to every role, superusers included.
- The gate also refuses the foreign server and wrapper catalogs and their information_schema views, whose options can hold a connection password, and the pageinspect page-item and `pg_mcv_list_items` functions.
- The recommended role recipe uses `pg_monitor` instead of `pg_read_all_stats`, and the docs warn against `pg_read_all_data` and superuser connections.
- The gate refuses TOAST tables by name (`pg_toast` schema and `pg_toast_<digits>` relations), which hold the out-of-line values of the credential catalogs, and the functions that return raw write-ahead log data (`pg_get_wal_*`), with `relation_denied` and `function_denied`.
- Statement text is masked on the way out: a password literal after PASSWORD, as in a typed `ALTER ROLE`, shows as `'***'`, in every tool result and resource.

### Added

- A password-hash scrubber. Every tool result, resource, completion, error text and database-bearing log field is scanned, and text shaped like a SCRAM-SHA-256 verifier or an md5 hash is replaced with `[redacted password hash]`. Each successful tool result carries `redactedHashes`; resources, completions and error results carry no count field, and the audit line carries `redacted_hashes`.
- A credential exposure test matrix that runs each role on each test server through every known path, the statistics-view and audit tests, and a false-positive scan of every seeded table.

## [0.1.0]

### Added

- TLS with a private certificate authority: client certificates (`sslcert` and `sslkey`, `PGSSLCERT` and `PGSSLKEY`), inline PEM (`sslrootcert_pem`, `sslcert_pem`, `sslkey_pem` and the `PGSSL*_PEM` variables), all checked once at startup, and a `pgtls` test service on PostgreSQL 19 with TLS.
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
