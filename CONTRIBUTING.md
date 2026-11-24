# Contributing

Thanks for looking at postgres-mcp-rs. The project is small on purpose: a read-only server with a short list of tools. Changes that keep it that way are welcome. Changes that add a write path, an opt-in flag for writes or a second way around the gate are not, and will not be merged.

## Prerequisites

- **Rust 1.88 or newer**, the `rust-version` in `Cargo.toml`. The Docker builder uses Rust 1.95.
- **clang and libclang**, because the SQL parser (`pg_query`) runs bindgen when it builds. On Debian or Ubuntu: `apt-get install clang libclang-dev build-essential pkg-config`.
- **Docker with the compose plugin**, for the integration tests and the container smoke test.
- **cargo-audit and cargo-deny**, for `scripts/verify.sh`: `cargo install cargo-audit cargo-deny`.
- **curl**, for `scripts/docker-smoke.sh`.

## Scripts

Three scripts prove a change. The project has no CI configuration by design, so the scripts are the proof, and you run them locally.

| Script | Needs | What it proves |
|--------|-------|----------------|
| `scripts/verify.sh` | Rust, cargo-audit, cargo-deny | Formatting, clippy with warnings as errors, the library and non-database test targets, `cargo audit`, `cargo deny check`. No database. |
| `scripts/integration.sh` | Docker | Starts `docker-compose.test.yml` (PostgreSQL 15, 18 and 19, with TimescaleDB on 18), runs every cargo test target against it, then removes the stack. `--keep` leaves it running. |
| `scripts/docker-smoke.sh` | Docker, curl | Builds `postgres-mcp:smoke` and checks the running container: health, 401 without a key, `tools/list`, a `SELECT`, a refused `INSERT`, no shell, read-only root filesystem. |

Before you open a pull request, `scripts/verify.sh` and `scripts/integration.sh` must both pass. Run `scripts/docker-smoke.sh` too when you change the `Dockerfile`, the compose files, the HTTP surface, or anything else the container runs.

Each script prints its steps and ends with `OK` when it passes. Quote the last lines in the pull request description.

## Project rules

- **Read-only forever.** There is no write path, no write tool and no opt-in flag, and changes that add one will not be merged.
- **The gate is the only way in.** Every SQL statement from a client goes through the gate in `src/gate.rs` and runs inside the read-only session in `src/pg/session.rs`. Do not add a path that skips either. Internal SQL the server runs itself is fixed text in the tool modules.
- **Tool text lives in `src/tools/text.rs`.** Tool titles, descriptions, parameter descriptions and the server instructions are there and nowhere else. Error texts stay with the code that raises them.
- **New SQL uses parameters only.** Values go through bind parameters. A name from a client that must appear as an identifier goes through `quote_ident`. Catalog names are schema-qualified (`pg_catalog.x`), so a role's `search_path` cannot change what they resolve to.
- **A new tool needs integration tests on every supported version.** Those are PostgreSQL 15, 18 and 19 where the tool applies, and TimescaleDB 2.32 on 18 for the TimescaleDB tools. Tests run against the compose stack, not a mock.
- **Change the README with the behaviour.** A change to a tool's behaviour or result shape updates `README.md` and the text in `src/tools/text.rs` in the same commit.
- **No CI configuration.** Do not add workflow files or CI badges.
- **No `unsafe` code.**
- **No `unwrap()` or `expect()` in `src/`** outside tests. Errors are values that become tool results.

## Adding a tool

Each toolset is one module under `src/tools/`: `core.rs`, `schema.rs`, `monitor/`, `logs.rs`, `timescale.rs`. A module offers two functions, and `src/tools/mod.rs` calls them in order.

1. **Text.** Add the title, the description and any parameter descriptions to `src/tools/text.rs`, and describe the new behaviour in `README.md`.
2. **Types.** Add an arguments struct that derives `Deserialize` and `JsonSchema`, and a result struct that derives `Serialize` and `JsonSchema`. The argument names are the JSON keys clients send.
3. **`catalog()`.** Add an entry to the module's `catalog()` that calls `tool::<Args, Result>(name, title, description, &[(param, doc), ...])` and tags it with the toolset. The helper sets the read-only annotations.
4. **`dispatch()`.** Add a match arm to the module's `dispatch()` that parses the arguments and runs the handler, the same way the existing arms do.
5. **Tests.** Add tests to the toolset's test file in `tests/` (for example `tests/schema_tools.rs`), using the helpers in `tests/common/mod.rs`. Assert exact values and exact error messages.

A new toolset also needs a line in the chain in `PgMcp::new` and in `call_tool` in `src/tools/mod.rs`, and a variant in `Toolset` and in `Toolsets` in `src/config.rs`.

## Commit style

Write a short imperative subject, for example `Add TimescaleDB tools` or `Reject placeholders in execute_query`. Keep it under about 60 characters, with no full stop. Add a body when the reason is not obvious from the diff, and wrap it at about 72 characters. Make each commit one logical change, and keep formatting-only changes out of behavioural commits.

## Code style

- `cargo fmt` before you commit. `cargo clippy --all-targets --locked -- -D warnings` must be clean.
- Comments are one or two factual lines. Say what the code does, or why it must be this way. Leave out history and reasoning about the change.
- Test "not provided" with `is None`, never by truthiness.
- Keep imports at the top of the file.
