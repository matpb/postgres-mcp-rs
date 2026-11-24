//! Shared helpers for the HTTP and stdio integration tests: configs for the test databases and JSON-RPC posts.
#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use http_body_util::BodyExt;
use postgres_mcp::config::Config;
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection};
use postgres_mcp::{AppState, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;

/// PostgreSQL 18 with TimescaleDB.
pub const PORT_18: u16 = 15432;
/// PostgreSQL 19.
pub const PORT_19: u16 = 15433;
/// PostgreSQL 15.
pub const PORT_15: u16 = 15434;
pub const DB_USER: &str = "mcp_ro";
pub const DB_PASSWORD: &str = "test-only-ro";
pub const DB_NAME: &str = "appdb";

pub const PROTOCOL_2025: &str = "2025-11-25";
pub const PROTOCOL_2026: &str = "2026-07-28";

/// One database entry for PG_DATABASES, pointing at a test server.
pub fn db_entry(name: &str, port: u16) -> Value {
    json!({
        "name": name,
        "host": "127.0.0.1",
        "port": port,
        "database": DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "sslmode": "disable",
    })
}

/// Builds a Config from PG_DATABASES and the extra variables, through the same lookup the binary uses.
pub fn config_with(databases: &[Value], extra: &[(&str, &str)]) -> Config {
    let mut vars: HashMap<String, String> = HashMap::new();
    vars.insert(
        "PG_DATABASES".to_owned(),
        serde_json::to_string(databases).expect("database list serializes"),
    );
    for (name, value) in extra {
        vars.insert((*name).to_owned(), (*value).to_owned());
    }
    Config::from_lookup(&|name| vars.get(name).cloned()).expect("test configuration is valid")
}

/// A config with one database on the given test port.
pub fn one_db(port: u16, extra: &[(&str, &str)]) -> Config {
    config_with(&[db_entry("appdb", port)], extra)
}

pub fn app(config: Config) -> Router {
    build_router(Arc::new(AppState::new(config)))
}

/// A response with its status, headers and raw body.
pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("response body is JSON")
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

pub async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("router service is infallible");
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body is readable")
        .to_bytes()
        .to_vec();
    Reply {
        status,
        headers,
        body,
    }
}

/// POSTs a JSON-RPC body to /mcp with the Accept and Content-Type headers rmcp requires, plus extra headers.
pub async fn post_mcp(app: &Router, body: &Value, headers: &[(&str, &str)]) -> Reply {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if !headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("host"))
    {
        builder = builder.header("host", "localhost:8432");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(Body::from(body.to_string()))
        .expect("request is well formed");
    send(app, request).await
}

/// A tools/call request for protocol 2025-11-25, sent without a prior initialize.
pub async fn call_tool(app: &Router, name: &str, arguments: Value) -> Value {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    });
    post_mcp(app, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
        .await
        .json()
}

/// The `result` member of a JSON-RPC response, which must exist.
pub fn result_of(response: &Value) -> &Value {
    response
        .get("result")
        .unwrap_or_else(|| panic!("no result in {response}"))
}

pub const SUPERUSER: &str = "postgres";
pub const SUPERUSER_PASSWORD: &str = "test-only-superuser";
/// Same statements as docker/initdb/55_hostile.sql, run on the live test servers too.
pub const HOSTILE_SETUP: &[&str] = &[
    "CREATE OR REPLACE FUNCTION public.starts_with(name, text) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$",
    "CREATE OR REPLACE FUNCTION public.lower(name) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$",
    "CREATE OR REPLACE FUNCTION public.strpos(name, text) RETURNS int LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$",
    "CREATE OR REPLACE FUNCTION public.format_type(oid, int) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$",
    "CREATE OR REPLACE FUNCTION public.pg_get_expr(pg_node_tree, oid) RETURNS text LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'pgmcp hostile %', 'function called'; END $$",
    "ALTER ROLE mcp_strict IN DATABASE appdb SET search_path = public, pg_catalog",
];
/// Decoy log reader for database `postgres` on PostgreSQL 19; same statements as docker/initdb/55_hostile.sql.
pub const DECOY_SETUP: &[&str] = &[
    "CREATE SCHEMA IF NOT EXISTS pgmcp AUTHORIZATION mcp_strict",
    "CREATE OR REPLACE FUNCTION pgmcp.read_log_file(p_name text, p_offset bigint, p_length integer) RETURNS bytea LANGUAGE sql AS $$ SELECT NULL::bytea $$",
    "CREATE OR REPLACE FUNCTION pgmcp.list_log_files() RETURNS TABLE(name text, size bigint, modification timestamptz) LANGUAGE sql AS $$ SELECT NULL::text, NULL::bigint, NULL::timestamptz WHERE false $$",
    "ALTER FUNCTION pgmcp.read_log_file(text, bigint, integer) OWNER TO mcp_strict",
    "ALTER FUNCTION pgmcp.list_log_files() OWNER TO mcp_strict",
    "GRANT USAGE ON SCHEMA pgmcp TO mcp_ro",
    "GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_ro",
];

/// Runs idempotent setup DDL as the superuser in one transaction that holds the setup advisory lock.
pub async fn superuser_setup(port: u16, database: &str, statements: &[&str]) {
    let config = ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: database.into(),
        user: SUPERUSER.into(),
        password: Some(SUPERUSER_PASSWORD.into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(10),
        startup_params: Vec::new(),
    };
    let mut conn = Connection::connect(&config)
        .await
        .expect("superuser connection to the test server");
    let mut script = vec!["BEGIN", "SELECT pg_advisory_xact_lock(815001)"];
    script.extend_from_slice(statements);
    script.push("COMMIT");
    for sql in script {
        if let Err(error) = conn.simple_query(sql).await {
            panic!("setup statement failed on port {port}: {error}: {sql}");
        }
    }
    conn.close().await;
}
