# Instructions for coding agents

postgres-mcp-rs is a read-only MCP server for PostgreSQL and TimescaleDB, written in Rust. The crate and binary are `postgres-mcp`. It serves Streamable HTTP or stdio, and it has 20 tools in five toolsets. Read `README.md` for the user-facing contract and `SECURITY.md` for the threat model.

## Ground rules

These invariants are the product. A change that weakens one is wrong, even when the tests still pass.

- **Read-only, always.** There is no write tool, no write flag and no path that sends a client's SQL around the gate. Enforced by: the gate in `src/gate.rs` (`check`, `ALLOWED_NODES`, `DENIED_FUNCTIONS`), and the read-only transaction in `src/pg/session.rs` (`begin_sql`, `run_held`). The `generic_plan` option of `explain_query` sends user SQL over the simple protocol, but only behind the server-side preflight in `explain_unbound`.
- **One statement per call, parser-based.** `src/gate.rs` parses with PostgreSQL's parser and refuses anything not on the node allow-list. Unknown constructs are refused, not allowed. Adding a node type means adding a corpus case in `tests/gate_corpus/allow.sql` or `deny.sql`.
- **Session state never leaks.** Each connection is checked before use (`verify_session`, `SESSION_CHECK` in `src/pg/session.rs`), pinned at connect time (`connect_config` in `src/config.rs`), and reset with `ROLLBACK` then `DISCARD ALL` (`reset` in `src/pg/session.rs`).
- **Credentials stay out of output.** Credential catalogs and secret settings are denied in `src/gate.rs` (`CREDENTIAL_RELATIONS`, `SECRET_SETTINGS`), and `SHOW ALL` rows for them are dropped in `src/tools/envelope.rs`. Passwords are redacted in `Debug` output (`src/pg/wire.rs`, `src/config.rs`).
- **Exposure stays narrow.** `MCP_HOST` defaults to `127.0.0.1`, and the compose example publishes the port on `127.0.0.1`. The Origin, API key and Host checks live in `src/http_guard.rs` and `build_router` in `src/server.rs`. Do not loosen them.
- **Stdout is the JSON-RPC channel in stdio mode.** Logs go to stderr (`init_logging` in `src/server.rs`). Never `println!` in a server path.
- **Caps hold.** Row, value, response, request and SQL-length caps are in `src/config.rs` (`Limits`) and enforced in `src/pg/wire.rs` (`keep_row`) and `src/gate.rs`.

## Commands

Run from the repository root.

- Build: `cargo build`, or `cargo build --release`
- Format check: `cargo fmt --check`
- Lint: `cargo clippy --all-targets --locked -- -D warnings`
- Proof without a database: `scripts/verify.sh` (needs cargo-audit and cargo-deny)
- Start the test stack: `docker compose -f docker-compose.test.yml up -d --wait`
- Proof with a database: `scripts/integration.sh` (add `--keep` to leave the stack running)
- Container proof: `scripts/docker-smoke.sh` (builds the image)
- One test target: `cargo test --locked --test gate`
- One test: `cargo test --locked --test gate allow_corpus_is_accepted`
- Stop the test stack: `docker compose -f docker-compose.test.yml down -v`

Tests that need PostgreSQL expect the test stack on `127.0.0.1` ports 15432 (TimescaleDB on PostgreSQL 18), 15433 (PostgreSQL 19) and 15434 (PostgreSQL 15). Start the stack before running them. `scripts/integration.sh` does that for you. Do not point a test at any other server.

## Repo map

- `src/main.rs`: binary entry point; calls `postgres_mcp::run`.
- `src/lib.rs`: module list.
- `src/server.rs`: command line (`http`, `stdio`, `healthcheck`), `AppState`, HTTP router, stdio serving, logging setup.
- `src/config.rs`: every environment variable, its bounds and errors; `ENV_VARS`; database forms.
- `src/http_guard.rs`: Origin check, API key digest comparison, 401 and 403 bodies.
- `src/audit.rs`: the per-call audit line.
- `src/gate.rs`: the SQL gate: allow-lists, deny-lists, credential and secret rules.
- `src/pg/wire.rs`: PostgreSQL wire client: startup, auth under `AuthPolicy` (SCRAM, MD5, cleartext, trust), extended and simple query (`explain_unbound` for user text), cancel, streamed rows with value and byte caps.
- `src/pg/session.rs`: `run_readonly`: transaction, session check, timeouts, reset.
- `src/pg/pool.rs`: per-database semaphore pool.
- `src/pg/tls.rs`: sslmode handling and certificate verifiers.
- `src/encode/`: value encoding; `mod.rs` decodes, `types.rs` holds the built-in OID table, `array.rs`, `range.rs`, `json.rs`, `columns.rs`.
- `src/typeinfo.rs`: type lookups for non-built-in OIDs, cached per database.
- `src/resources.rs`: MCP resources (database summary, schema and table views) and completions; enabled with the `schema` toolset.
- `src/tools/mod.rs`: `Runner`, `ToolError`, the MCP handler (`list_tools`, `call_tool`).
- `src/tools/text.rs`: tool titles, descriptions, parameter descriptions and server instructions.
- `src/tools/mask.rs`: best-effort masking of passwords in log text and statement text.
- `src/tools/core.rs`, `envelope.rs`: core tools and the result envelope.
- `src/tools/schema.rs` and `schema/`: schema tools. `monitor/`: monitor tools. `logs.rs` and `logs/`: the log tool. `timescale.rs` and `timescale/`: TimescaleDB tools.
- `tests/`: one file per area, plus `common/mod.rs` for helpers and ports, and `gate_corpus/` for the gate cases. `wire_fake.rs` runs the wire client against scripted fake servers, `tls.rs` runs TLS in-process with generated certificates, `types_exact.rs` pins the value encoding on PostgreSQL 15, 18 and 19, and `hardening.rs` checks that hostile public functions do not reach the server's own SQL.
- `docker/initdb/`: seed SQL for the test stack (roles, schemas, TimescaleDB data). `55_hostile.sql` creates the hostile functions, and `56_test_objects.sql` creates the objects the tests use.
- `sql/log_reader.sql`: the operator's setup for the server log functions.
- `scripts/`: `verify.sh`, `integration.sh`, `docker-smoke.sh`.
- `Dockerfile`, `docker-compose.yml` (example deployment), `docker-compose.test.yml` (test stack), `deny.toml` (cargo-deny policy).

## Conventions

- Comments are one or two factual lines. Say what the code does or why it must be so.
- No `unwrap()` or `expect()` in `src/`. Errors are `ToolError` values.
- A failed database or gate call is a tool result with `isError` set to true. Protocol errors are reserved for unknown tool names and invalid arguments (`invalid_params`).
- Tool titles, descriptions, parameter descriptions and server instructions live in `src/tools/text.rs` only. Error texts stay with the code that raises them. A behaviour change updates `text.rs` and `README.md` together.
- SQL uses bind parameters for values. Catalog names are schema-qualified (`pg_catalog.x`).
- Tests assert exact values and exact error messages, not only that something failed. Expected values come from the spec or from a live run, not from the code under test.
- Integration tests run against the test stack. Do not mock PostgreSQL.
- Config values are validated at startup with bounds. An invalid value stops startup with `configuration error: ...`, exit 2. The variables of a database form that is not in use are not checked.

## Landmines

Each of these looks harmless and breaks a guarantee or a test.

- **Binary result format.** The encoders parse text only. Requesting binary result columns changes the decoding contract and breaks `src/encode/`.
- **Reset order.** `ROLLBACK` must be its own message before `DISCARD ALL`, because `DISCARD ALL` cannot run inside a transaction block. Reordering or merging them breaks the reset check in `reset`.
- **Pinned parameters.** Changing a startup parameter in `connect_config` means changing `SESSION_EXPECTED` and `SESSION_CHECK` in `src/pg/session.rs` in the same commit. A changed value on a live connection poisons it.
- **Unqualified catalog names.** A bare `pg_class` or `format_type` in introspection SQL resolves through the role's `search_path`. Write `pg_catalog.` in front of every catalog name.
- **Parse-tree depth.** The gate walks the tree without recursion and caps depth at 5000. Adding recursion, or raising the cap without a test, risks a stack overflow.
- **Allow-list growth.** A new node type or function on the allow-list needs a corpus entry and a reason. Denying is the default.
- **Test stack ports.** The ports 15432 to 15434 appear in both `docker-compose.test.yml` and `tests/common/mod.rs`. Change both or neither.
- **Test stack required.** The integration tests fail without the stack. `verify.sh` does not need it.
- **Container bind address.** The image sets `MCP_HOST=0.0.0.0` so Docker's port mapping works. Changing it breaks the container, and the published port must stay on `127.0.0.1`.
- **Loopback origins.** Loopback origins are always allowed by design. Do not remove that exception without updating `SECURITY.md`.
- **`prefer` falls back to plaintext.** A server that answers `N` to the TLS request gets an unencrypted connection in `prefer` mode. Keep that behaviour documented, and do not describe `prefer` as encrypted.
- **`text.rs` layout.** The module is marked `#[rustfmt::skip]` in `src/tools/mod.rs`, so rustfmt leaves its string continuation layout alone. Keep the layout when editing it.
- **Log file access.** The log functions in `sql/log_reader.sql` are `SECURITY DEFINER`. Do not widen their argument checks or the file list they read.
- **User text on the simple protocol.** User SQL reaches the simple protocol only through `explain_unbound`, behind its extended-protocol preflight. Never add a second call site.
- **No DDL in tests.** Tests must not run DDL. Put the objects a test needs in the seed under `docker/initdb/`.
- **Internal SQL search path.** Internal SQL runs with `search_path = pg_catalog`, so an object from an extension installed in another schema needs an explicit schema qualification.

## Deeper docs

- `README.md`: the user contract, configuration, tools and result encoding.
- `SECURITY.md`: threat model, defence layers with code locations, residual risks, operator checklist.
- `CONTRIBUTING.md`: prerequisites, proof scripts, project rules, how to add a tool.
- `.env.example`: every configuration variable, one comment each.
