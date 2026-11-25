# Security

This document describes what postgres-mcp-rs defends against, how each defence is built, and what remains open. Read it before you expose the server to anything beyond your own machine.

## Threat model

**Trusted:** the operator. The operator chooses the database role, writes the configuration, decides which network the server listens on, and runs the process.

**Not trusted:**

- The AI client, and anything that can make it send SQL. That includes text the model reads from the database or from other tools, which can carry instructions (prompt injection).
- Other web pages open in a browser on the same machine. A page from a non-loopback origin is stopped by the Origin check. A page served from a loopback origin is not, so it can send requests to `127.0.0.1` (see the residual risks below).
- The data in the database. Its contents are returned to the model as data, and nothing in them is executed.
- The network between the server and the database, unless TLS with verification is used.

**Goal:** a client that sends any SQL, from any source, cannot change data, change session state, reach the server's files or processes, or read anything the database role cannot read. Within what the role can read, the client may read all of it, one capped page at a time. That exposure is by design, and the role is how you limit it.

## Defence layers

Each layer is independent. None is claimed to be sufficient alone. The code location is given for each one.

**1. Database role (operator).** The role's privileges are the final limit on what can be read. A role with only `SELECT` cannot write, and cannot see tables it was not granted. The README gives the recipe. `default_transaction_read_only` is set for the role, and the server also requests it at connect time. Locations: README "Create a read-only role"; `connect_config` in `src/config.rs`.

**2. Session pinning.** Every connection starts with fixed parameters: `DateStyle`, `IntervalStyle`, `TimeZone`, `bytea_output`, `extra_float_digits`, `standard_conforming_strings`, `default_transaction_read_only` and `client_encoding`. Before any user SQL runs on a checked-out connection, the server reads back `transaction_read_only`, `DateStyle`, `IntervalStyle`, `TimeZone`, `bytea_output`, `standard_conforming_strings` and `client_encoding`, and checks `current_user = session_user`. A mismatch closes the connection. Pinning `standard_conforming_strings` keeps the server's string parsing the same as the parser gate's. Locations: `connect_config` in `src/config.rs`; `SESSION_CHECK` and `verify_session` in `src/pg/session.rs`.

**3. Read-only transaction.** Each call runs inside `BEGIN READ ONLY` with the timeouts described in layer 4, and the transaction is always rolled back. PostgreSQL refuses writes in a read-only transaction, so a statement that slipped past the gate still cannot write. Location: `begin_sql` and `run_held` in `src/pg/session.rs`.

**4. Time limits.** Each statement is limited by `statement_timeout` (default 30 seconds). Lock waits are limited by `lock_timeout` (default 5 seconds). `idle_in_transaction_session_timeout` is the statement limit plus 10 seconds, and on PostgreSQL 17 and later `transaction_timeout` is the statement limit plus 5 seconds. The client waits for the statement limit plus a 5-second grace period, then sends a server-side cancel request and closes the connection instead of reusing it. Location: `begin_sql`, `run_held`, `stop_query` and `CLIENT_GRACE_MS` in `src/pg/session.rs`; `CancelHandle` in `src/pg/wire.rs`.

**5. Session reset.** After a call, the connection gets `ROLLBACK` and then `DISCARD ALL`, sent as two messages, and must return to the idle state. Only then is it returned to the pool. A failed reset closes the connection. This stops session state from reaching the next caller: `SET`, prepared statements, temporary tables, session-level locks and `LISTEN`. Location: `reset`, `reset_and_release` in `src/pg/session.rs`.

**6. Parser gate.** Before anything reaches the database, the SQL is parsed with PostgreSQL's own parser (`pg_query`). The gate then accepts only:

- exactly one statement, of at most `MAX_SQL_BYTES` bytes, with no NUL byte;
- statements built only from node types on an allow-list (`ALLOWED_NODES`), so an unknown construct is refused;
- `SELECT`, `EXPLAIN` of a `SELECT` with options from an allow-list, and `SHOW`;
- no `SELECT ... INTO`, no `FOR UPDATE` or `FOR SHARE`, and no data-modifying statement inside `WITH`;
- no parameter placeholders, except in `explain_query` with `generic_plan`, which plans them and binds no values;
- no function on the deny-list (`DENIED_FUNCTIONS`), matched by name or prefix. The deny-list covers side-effect, file and network functions of core and common extensions. No cron scheduling function when called as `cron.`, and no call into the TimescaleDB internal schemas (`_timescaledb_functions`, `_timescaledb_internal`, `_timescaledb_catalog`);
- no field selection that names a denied function: PostgreSQL treats (expr).name and rel.name as the call name(expr), so the last name after a dot is checked like a function call;
- no call into the `pgmcp` schema, which holds the server log helper functions;
- `current_setting()` only with a literal setting name, and not a secret one;
- a parse tree no deeper than 5000 levels, walked without recursion.

The deny-list cannot know every function that an extension provides. The read-only transaction and the role's privileges are the real barrier, and the gate is one layer above them.

For `explain_query` with `generic_plan`, the statement is sent with the simple query protocol, and only after the server has parsed the identical text through the extended protocol as a single statement. The reply must be exactly one EXPLAIN result. This is the only place where user text reaches the simple protocol (`explain_unbound` in `src/pg/wire.rs`).

Location: `check`, `analyse`, `walk`, `check_node`, `check_function`, `check_current_setting` in `src/gate.rs`. The accept and reject corpus is in `tests/gate_corpus/allow.sql` and `tests/gate_corpus/deny.sql`, and `tests/gate.rs` also runs property tests that mutate the corpus.

**7. Credential catalogs and secret settings.** Relations that hold credentials (`pg_authid`, `pg_shadow`, `pg_user_mapping`, `pg_user_mappings`, `information_schema._pg_user_mappings`, `information_schema.user_mapping_options`, `pg_subscription`, `pg_settings`, the file-settings views, and the statistics relations `pg_statistic` and `pg_statistic_ext_data`) are refused by name. Settings that can expose credentials or local paths (`primary_conninfo`, `ssl_key_file`, the archive and restore commands and similar) are refused in `SHOW` and in `current_setting`. `current_setting()` takes only a literal name, so a computed name cannot reach a secret setting. `SHOW ALL` results drop the rows for those settings. Location: `CREDENTIAL_RELATIONS`, `SECRET_SETTINGS`, `check_relation`, `check_setting` in `src/gate.rs`; `is_secret_row` in `src/tools/envelope.rs`. The `server_info` tool reads a fixed list of settings that hold no credentials: `SERVER_INFO_SETTINGS` in `src/tools/core.rs`. The statistics views pg_stats, pg_stats_ext and pg_stats_ext_exprs are read through a filter that drops the rows of pg_authid, pg_user_mapping, pg_subscription, pg_db_role_setting, pg_statistic, pg_statistic_ext_data and pg_largeobject, with a planner fence so that a caller's predicate cannot run on a hidden row. This holds for every role, superusers included. The TOAST tables of all catalogs are refused by name, and so are the foreign server and foreign-data wrapper catalogs.

**8. Result caps.** A call returns at most `MAX_ROWS` rows (default 1000), and the raw bytes of its values are capped by `MAX_RESPONSE_BYTES` (default 48000). Each text or JSON value is cut at `MAX_VALUE_BYTES` (default 4096), an array is cut at that size when its text is more than 16 times larger, and each `bytea` value is cut at `MAX_BINARY_PREVIEW_BYTES` (default 256). A value longer than its cut is cut while it is read, and the rest is discarded without being held; the row is still returned and `truncatedValues` counts it. A cut is always marked, and `truncated` tells the caller the result is partial. When a row or byte cap is reached, the client sends a cancel request so the server stops producing rows, then reads the connection back to a known state. Location: `stream_row` and `keep_row` in `src/pg/wire.rs`; `build` in `src/tools/envelope.rs`; `src/encode/mod.rs`.

**9. API key.** When `API_KEY` or `API_KEY_FILE` is set, `/mcp` requires the key. A key shorter than 16 characters stops startup. The presented key is hashed with SHA-256, and the digest is compared with the configured key's digest in constant time, so the comparison does not depend on the key's length or content. Location: `ApiKey` and `guard` in `src/http_guard.rs`; `MIN_API_KEY_CHARS` in `src/config.rs`.

**10. Origin and Host validation.** The Origin check runs first. A request with an `Origin` header must come from a loopback origin (`localhost`, `127.0.0.1` or `[::1]`) or from an entry in `ALLOWED_ORIGINS`, and anything else gets 403. Requests without an `Origin` header are not checked by this layer. The Host check runs in the MCP layer and accepts `localhost`, `127.0.0.1`, `::1` and the entries in `ALLOWED_HOSTS`. Together these stop DNS rebinding and cross-site requests from ordinary web pages. Location: `origin_allowed` and `guard` in `src/http_guard.rs`; `build_router` in `src/server.rs`.

**11. Loopback bind.** The HTTP listener binds `127.0.0.1` unless `MCP_HOST` says otherwise. The server logs a warning when it binds a non-loopback address without an API key. Location: `MCP_HOST` default in `src/config.rs`; the warning in `serve_http` in `src/server.rs`. The example compose file publishes the port on `127.0.0.1` only.

**12. Container hardening.** The image is built on a distroless base, runs as `nonroot` (UID 65532), and has no shell. The example compose file runs it with a read-only root filesystem, all capabilities dropped, `no-new-privileges`, a process limit and a memory limit. Location: `Dockerfile`, `docker-compose.yml`. `scripts/docker-smoke.sh` checks the image user, the read-only root filesystem and the absence of a shell on the built image.

**13. Audit line (detection, not prevention).** Each tool call and each completion request writes one `audit` line. It holds the tool name, the database name, success, duration, row count, the SQLSTATE of a database error, and the first 16 hex characters of the SHA-256 of the SQL text. It holds no SQL text, values, error text, client address or key. At debug and trace level the MCP library logs whole requests and responses, which include SQL text and result rows: use those levels only for troubleshooting. Location: `record` in `src/audit.rs`, called from `call_tool` in `src/tools/mod.rs`.

**14. Limits on work.** `MAX_CONCURRENT_REQUESTS` (default 16) bounds the requests handled at once on `/mcp`, and `MAX_REQUEST_BYTES` (default 1 MiB) bounds each request body. A `/mcp` request, body included, that is not complete within the largest statement timeout of any database plus 30 seconds gets 408. Each database has a bounded pool (4 connections by default, 1 to 64 in the JSON form), and a call waits at most 10 seconds for a free connection. Location: `limits` in `src/config.rs`; `POOL_WAIT` in `src/tools/mod.rs`; `Pool` in `src/pg/pool.rs`.

**15. TLS.** `verify-full` checks the chain and the host name, `verify-ca` checks the chain only, and `require` and `prefer` verify nothing. `verify-ca` needs `sslrootcert`, and the configuration is refused without it. A root certificate with `prefer`, `require` or `disable` also stops startup, so no configuration looks verified when it is not. The trusted roots are the `sslrootcert` file or inline `sslrootcert_pem` when given, and otherwise the bundled webpki roots. A client certificate and its key (`sslcert` and `sslkey`, or their `_pem` forms) are offered when the server asks; the key must be unencrypted PEM. Every setting is checked once at startup. Key material is never logged, never printed by `Debug`, and never in an error text. Location: `startup_client_config` and `client_identity` in `src/pg/tls.rs`; `resolve_tls` and `PemSource` in `src/config.rs`.

**16. Log and statement masking (best effort).** The gate refuses calls to the log helper functions in `execute_query`, so log text always passes through the tool's masking. Passwords in server log entries (message, detail, statement and context) and in statement text from `list_activity` and `query_stats` are replaced with `***` before they are returned. Masking covers `PASSWORD` literals (plain, escape, Unicode and dollar-quoted), `password=`, `sslpassword=` and `passfile=` settings, and passwords in URLs. This is a convenience, not a guarantee. Location: `src/tools/mask.rs`; `shape_query` in `src/tools/monitor/mod.rs`; the log entries in `src/tools/logs.rs`.

**17. Server SQL search path.** The server's own catalog queries run with `search_path = pg_catalog`, so an object that someone has planted in a user schema cannot hijack them. User SQL keeps the role's `search_path`. Location: `begin_sql` (`search_path_catalog_only`) in `src/pg/session.rs`; `internal_query` in `src/tools/mod.rs`.

**18. Authentication to PostgreSQL.** The server answers only the methods in `require_auth`, which defaults to `scram-sha-256,none`. A refused method is never answered, so no password is sent for it. Cleartext passwords are refused on an unencrypted connection. The SCRAM client refuses a server that ends authentication without proving it knows the password. Connection failures reach clients as short fixed texts, and the PostgreSQL message is written to the log only. Location: `AuthPolicy` and `authenticate` in `src/pg/wire.rs`; `connect_failure_text` in `src/pg/pool.rs`.

**19. Password hash scrubber.** Every tool result, resource body, completion and error text, and every log field that can carry text from the database, is scanned before it leaves the server, and text shaped like a PostgreSQL password hash in its stored form (SCRAM-SHA-256 verifier or md5 hash) is replaced with [redacted password hash]. A password literal after the word PASSWORD in statement text is masked the same way. It is always on and cannot be configured off. The audit line counts the replacements.

## Residual risks

These are the things the layers above do not stop. Read them as the boundary of the design.

- **Functions the gate allows run inside the read-only transaction.** The gate decides by name and by node type. It cannot know what an arbitrary function does. The deny-list names the side-effect, file and network functions of PostgreSQL and common extensions, but it cannot name every extension function. A function that PUBLIC may execute, a user-defined function, or an extension function that is not on the deny-list can still run, including `pg_sleep`, `lo_get`, `pg_ls_logdir` and `pg_ls_waldir`. The read-only transaction and the role's privileges are the real barrier against these. A function in an untrusted procedural language can act outside the database, for example on the server's files or network, with the operating system account of the PostgreSQL server. The read-only transaction stops ordinary writes, but it does not stop effects like these. Restrict `EXECUTE` on functions that the role must not run.
- **Table ownership and volatile functions.** A role that owns tables, or that owns functions with side effects, has more ability than a reader. The gate blocks `ALTER`, `DROP` and `GRANT` statements, and the read-only transaction blocks writes, but the operator should not give the server's role ownership of anything.
- **Remote data.** `dblink`, `dblink_exec` and `query_to_xml`-style functions are denied by name. A foreign table that the role can read is not denied: a `SELECT` on it reaches the remote server with the credentials in the user mapping. Do not give the role access to foreign tables that point at systems it should not reach.
- **Exfiltration by design.** Whatever the role can read, the model can read, capped per call and repeatable page by page. There is no per-client quota and no record of what was read beyond the audit line's row count.
- **Other people's query text.** With `pg_read_all_stats`, the role can see other sessions' statements (`list_activity`, `query_stats`). Those statements can contain literal values, including secrets that users typed into SQL. Passwords in them are masked on a best-effort basis (layer 16), which does not catch every secret.
- **Custom settings.** `current_setting('app.something')` and other settings that are not on the secret list are readable when the role can read them. Keep application secrets out of settings.
- **Views and functions written by others.** The server refuses the credential catalogs by name and filters them out of pg_stats, pg_stats_ext and pg_stats_ext_exprs. A view or a SECURITY DEFINER function in your own schemas that reads those catalogs with its owner's rights is not known to the server; the role's privileges decide whether it can be used. pg_roles also shows per-role settings (rolconfig).
- **Transformed hashes.** The scrubber recognises password hashes in their stored form. SQL that transforms a value before returning it (reverse, substring, encode) is not recognised; the gate, which refuses the credential catalogs and filters the statistics views, is what stops such a query from reaching a hash in the first place. A hash copied into an ordinary table by someone with access is caught only in its stored form. The gate also refuses TOAST tables and the functions that return raw page or write-ahead log data. Statement text of other sessions, visible to a role with pg_monitor, can hold a password hash that someone typed in a CREATE ROLE or ALTER ROLE statement; it is redacted in its stored form only.
- **Views and defaults.** The gate checks the statement that the client sends, not the definition of a view or a column default. A view whose definition calls a denied function runs that function when the role reads the view.
- **TimescaleDB job configuration.** `list_jobs` returns each job's `config` as it is stored, without masking. Keep secrets out of job configuration.
- **Server log content.** The log reader returns log text, which can contain statements with data values, and masking is best effort.
- **Loopback origins.** The Origin check always allows loopback origins. A web page served from any loopback origin, such as a local development server, passes the Origin check. If no API key is set, such a page can send requests to the tools. It cannot read the responses, because no CORS header is sent for it, but the calls are still made. Set `API_KEY` on any machine where you run other web software, and on loopback too when a browser runs on the same machine as the server.
- **Denial of service.** Timeouts, pool limits, the request limit and the body limit bound the damage, but a client can keep every connection busy with expensive queries up to those limits. There is no per-client rate limit.
- **Network and certificates.** `prefer` and `require` do not verify the server, so a network attacker can read or change traffic between the server and the database. Use `verify-full`.
- **Shared API key.** One key is shared by every caller. The server cannot tell callers apart, so the audit line does not identify the person.
- **Uncommon PostgreSQL features.** A gate allow-list is only as good as the node types it lists. New PostgreSQL versions can add syntax; the gate refuses unknown node types, but the corpus and the tests need updating for each new version.

## Operator checklist

1. Create a dedicated role with only the privileges it needs (see the README). Do not make it a superuser, a database owner or a member of a role that can write. Set `CONNECTION LIMIT`, and never share the role with an application.
2. Use `PGSSLMODE=verify-full` (or `sslmode=verify-full`) for any database reached over a network. Set `sslrootcert` (or `sslrootcert_pem`) for a private certificate authority, and connect by a name that the server certificate lists. Keep `require_auth` at its default, `scram-sha-256,none`, unless the server needs MD5 or cleartext passwords, and then list only what it needs. Cleartext passwords need TLS.
3. When the server listens beyond loopback, set `API_KEY_FILE` to a random key of at least 32 characters, and keep it out of shell history and process listings.
4. Put TLS in front of the server with a reverse proxy when it is reached over a network, and list the public host name in `ALLOWED_HOSTS`. Keep `MCP_HOST` on loopback when the proxy runs on the same machine.
5. Rotate the API key by changing it and restarting the server. Rotate the database password with `ALTER ROLE`, and update the configuration.
6. Revoke `EXECUTE` on functions that the role must never run, such as `pg_logical_emit_message`, if you do not want the server to be able to write WAL records.
7. Keep `AUDIT_LOG` on, and send the server's stderr to your log system.
8. Keep the container settings from the example compose file, and pin the image you deploy by digest.
9. Do not put the server behind a connection pooler in transaction mode. It is not supported.
10. Grant the log functions only to roles that need them. The `read_log_file` function exposes everything in the log directory that the role can name.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the **Security** tab of this repository on GitHub, then choose **Report a vulnerability**. Do not open a public issue or pull request for a vulnerability. Include the version (`postgres-mcp --version`), the configuration you used with the secrets removed, and the steps to reproduce.
