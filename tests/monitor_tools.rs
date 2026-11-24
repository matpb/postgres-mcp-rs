//! Integration tests for the monitoring tools against the test databases, as the read-only and strict roles.

mod common;

use std::time::Duration;

use common::{
    DB_NAME, DB_PASSWORD, PORT_15, PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with,
    one_db, post_mcp, result_of,
};
use postgres_mcp::config::Config;
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection};
use postgres_mcp::tools::monitor::{cut_chars, visible_text};
use serde_json::{Value, json};
use tokio::sync::Mutex;

const APP: &str = "pgmcp-monitor-test";
const HOLDER_APP: &str = "pgmcp-monitor-holder";
const WAITER_APP: &str = "pgmcp-monitor-waiter";
const SUPER_PASSWORD: &str = "test-only-superuser";
const STRICT_PASSWORD: &str = "test-only-strict";
const SECRETS: [&str; 3] = ["test-only-superuser", "test-only-ro", "test-only-strict"];
const NOT_INSTALLED: &str = "pg_stat_statements is not installed in this database.";
const HOW_TO_ENABLE: &str = "Add pg_stat_statements to shared_preload_libraries, restart, then CREATE EXTENSION pg_stat_statements;";
const VALID_STATES: &str = "active, idle, idle in transaction, idle in transaction (aborted)";
/// table_stats sizes lock every table it lists, so tests touching shop.blobs run one at a time.
static SHOP_LOCK: Mutex<()> = Mutex::const_new(());

fn ro_config(port: u16) -> Config {
    one_db(port, &[("PGAPPNAME", APP)])
}

fn strict_config(port: u16) -> Config {
    config_with(
        &[json!({
            "name": "appdb",
            "host": "127.0.0.1",
            "port": port,
            "database": DB_NAME,
            "user": "mcp_strict",
            "password": STRICT_PASSWORD,
            "sslmode": "disable",
        })],
        &[("PGAPPNAME", APP)],
    )
}

/// Calls one tool on a fresh server and returns its result object.
async fn call(config: Config, name: &str, arguments: Value) -> Value {
    result_of(&call_tool(&app(config), name, arguments).await).clone()
}

fn structured(result: &Value) -> &Value {
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent in {result}"))
}

fn is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn error_text(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .expect("error result has a text block")
        .to_owned()
}

fn sessions(result: &Value) -> Vec<Value> {
    structured(result)["sessions"]
        .as_array()
        .expect("sessions is an array")
        .clone()
}

fn session_of<'a>(sessions: &'a [Value], application: &str) -> Option<&'a Value> {
    sessions
        .iter()
        .find(|session| session["application"] == json!(application))
}

async fn raw(port: u16, user: &str, password: &str, application: &str) -> Connection {
    Connection::connect(&ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: DB_NAME.into(),
        user: user.into(),
        password: Some(password.into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: vec![("application_name".into(), application.into())],
    })
    .await
    .expect("direct connection to the test server")
}

async fn backend_pid(conn: &mut Connection) -> i64 {
    let result = conn
        .simple_query("SELECT pg_backend_pid()")
        .await
        .expect("pid query");
    result.rows[0][0]
        .as_deref()
        .and_then(|pid| pid.parse().ok())
        .expect("pid is a number")
}

/// A PostgreSQL LSN as printed by the server: hex digits, a slash, hex digits.
fn is_lsn(text: &str) -> bool {
    match text.split_once('/') {
        Some((high, low)) => {
            let hex = |part: &str| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(&b))
            };
            hex(high) && hex(low)
        }
        None => false,
    }
}

#[tokio::test]
async fn list_activity_gateway_session_is_self() {
    let result = call(ro_config(PORT_18), "list_activity", json!({})).await;
    assert!(!is_error(&result), "{result}");
    let all = sessions(&result);
    let selves: Vec<&Value> = all
        .iter()
        .filter(|session| session["isSelf"] == json!(true))
        .collect();
    assert_eq!(selves.len(), 1, "{result}");
    assert_eq!(selves[0]["user"], "mcp_ro");
    assert_eq!(selves[0]["application"], APP);
    assert_eq!(selves[0]["database"], DB_NAME);
    assert_eq!(structured(&result)["queryTextVisible"], json!(true));
    assert!(structured(&result).get("note").is_none());
    assert_eq!(structured(&result)["database"], DB_NAME);
}

#[tokio::test]
async fn list_activity_running_query_and_filters() {
    let mut holder = raw(PORT_18, "postgres", SUPER_PASSWORD, HOLDER_APP).await;
    let sleeper = tokio::spawn(async move { holder.simple_query("SELECT pg_sleep(8)").await });

    let mut last = Value::Null;
    for _ in 0..50 {
        last = call(ro_config(PORT_18), "list_activity", json!({})).await;
        let all = sessions(&last);
        if session_of(&all, HOLDER_APP).is_some_and(|s| s["state"] == json!("active")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let all = sessions(&last);
    let holder_row = session_of(&all, HOLDER_APP).cloned().unwrap_or(Value::Null);
    assert_eq!(holder_row["state"], "active", "{last}");
    assert!(
        holder_row["query"]
            .as_str()
            .is_some_and(|query| query.contains("pg_sleep")),
        "{last}"
    );
    assert!(holder_row["queryAgeMs"].as_i64().unwrap_or(0) > 0, "{last}");
    assert_eq!(holder_row["queryTruncated"], json!(false));
    assert_eq!(holder_row["user"], "postgres");
    assert!(
        holder_row["queryId"].is_string() || holder_row["queryId"].is_null(),
        "{last}"
    );

    let first_idle = all
        .iter()
        .position(|s| s["state"] != json!("active"))
        .unwrap_or(all.len());
    assert!(
        all[first_idle..]
            .iter()
            .all(|s| s["state"] != json!("active")),
        "active sessions come first: {last}"
    );
    assert!(
        all.iter()
            .all(|s| s["database"] == json!(DB_NAME) || s["database"].is_null()),
        "default lists this database only: {last}"
    );
    assert!(
        all.iter()
            .all(|s| s["backendType"] == json!("client backend")),
        "default lists client backends only: {last}"
    );
    let everything = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"include_background": true, "all_databases": true}),
    )
    .await;
    let everything_rows = sessions(&everything);
    assert!(everything_rows.len() >= all.len(), "{everything}");
    assert!(
        everything_rows
            .iter()
            .any(|s| s["backendType"] != json!("client backend")),
        "background workers listed: {everything}"
    );

    let active = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"state": "active"}),
    )
    .await;
    let active_rows = sessions(&active);
    assert!(session_of(&active_rows, HOLDER_APP).is_some(), "{active}");
    assert!(
        active_rows.iter().all(|s| s["state"] == json!("active")),
        "{active}"
    );

    let by_user = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"user": "postgres"}),
    )
    .await;
    let by_user_rows = sessions(&by_user);
    assert!(session_of(&by_user_rows, HOLDER_APP).is_some(), "{by_user}");
    assert!(
        by_user_rows.iter().all(|s| s["user"] == json!("postgres")),
        "{by_user}"
    );
    assert!(session_of(&by_user_rows, APP).is_none(), "{by_user}");

    let long = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"min_duration_ms": 3_600_000}),
    )
    .await;
    let long_rows = sessions(&long);
    assert!(session_of(&long_rows, HOLDER_APP).is_none(), "{long}");
    assert!(session_of(&long_rows, APP).is_none(), "{long}");

    let short = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"query_chars": 10}),
    )
    .await;
    let short_row = session_of(&sessions(&short), HOLDER_APP)
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(short_row["query"], "SELECT pg_", "{short}");
    assert_eq!(short_row["queryTruncated"], json!(true), "{short}");

    let bogus = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"state": "bogus"}),
    )
    .await;
    assert!(is_error(&bogus), "{bogus}");
    assert_eq!(
        error_text(&bogus),
        format!("Invalid state \"bogus\". Valid states: {VALID_STATES}.")
    );
    let too_many = call(
        ro_config(PORT_18),
        "list_activity",
        json!({"query_chars": 4001}),
    )
    .await;
    assert_eq!(
        error_text(&too_many),
        "query_chars must be between 0 and 4000."
    );
    let no_rows = call(ro_config(PORT_18), "list_activity", json!({"limit": 0})).await;
    assert_eq!(error_text(&no_rows), "limit must be between 1 and 500.");

    let finished = tokio::time::timeout(Duration::from_secs(20), sleeper).await;
    assert!(finished.is_ok(), "pg_sleep holder did not finish");
}

#[tokio::test]
async fn list_activity_only_blocked_lists_waiter_and_holder() {
    let _shop = SHOP_LOCK.lock().await;
    let mut holder = raw(PORT_18, "postgres", SUPER_PASSWORD, HOLDER_APP).await;
    let holder_pid = backend_pid(&mut holder).await;
    holder
        .simple_query("BEGIN")
        .await
        .expect("holder begins a transaction");
    holder
        .simple_query("LOCK TABLE shop.blobs IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("holder takes the lock");
    let mut waiter = raw(PORT_18, "mcp_ro", DB_PASSWORD, WAITER_APP).await;
    let waiter_pid = backend_pid(&mut waiter).await;
    let waiting = tokio::spawn(async move {
        waiter
            .simple_query("SELECT count(*) FROM shop.blobs")
            .await
            .map(|_| ())
    });

    let mut last = Value::Null;
    for _ in 0..100 {
        last = call(
            ro_config(PORT_18),
            "list_activity",
            json!({"only_blocked": true}),
        )
        .await;
        if sessions(&last)
            .iter()
            .any(|session| session["pid"] == json!(waiter_pid))
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let released = holder.simple_query("ROLLBACK").await;
    let joined = tokio::time::timeout(Duration::from_secs(10), waiting).await;

    assert!(released.is_ok(), "holder releases the lock");
    assert!(joined.is_ok(), "waiter finishes after the release");
    let all = sessions(&last);
    let waiter_row = all
        .iter()
        .find(|session| session["pid"] == json!(waiter_pid))
        .cloned()
        .unwrap_or(Value::Null);
    let holder_row = all
        .iter()
        .find(|session| session["pid"] == json!(holder_pid))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(waiter_row["blockedBy"], json!([holder_pid]), "{last}");
    assert_eq!(waiter_row["waitEventType"], "Lock", "{last}");
    assert_eq!(holder_row["blocking"], json!([waiter_pid]), "{last}");
    assert_eq!(holder_row["state"], "idle in transaction", "{last}");
    assert_eq!(structured(&last)["queryTextVisible"], json!(true));
}

#[tokio::test]
async fn list_activity_strict_role_sees_query_text() {
    let result = call(strict_config(PORT_18), "list_activity", json!({})).await;
    assert!(!is_error(&result), "{result}");
    assert_eq!(structured(&result)["queryTextVisible"], json!(true));
    let all = sessions(&result);
    let own = all
        .iter()
        .find(|session| session["isSelf"] == json!(true))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(own["user"], "mcp_strict");
    assert_eq!(own["application"], APP);
}

#[test]
fn hidden_statement_text_maps_to_null() {
    assert_eq!(visible_text(Some("<insufficient privilege>")), None);
    assert_eq!(visible_text(Some("SELECT 1")), Some("SELECT 1"));
    assert_eq!(visible_text(None), None);
    assert_eq!(visible_text(Some("")), Some(""));
    assert_eq!(cut_chars("abcdef", 3), ("abc".to_owned(), true));
    assert_eq!(cut_chars("abc", 3), ("abc".to_owned(), false));
    assert_eq!(cut_chars("héllo", 2), ("hé".to_owned(), true));
    assert_eq!(cut_chars("", 0), (String::new(), false));
}

#[tokio::test]
async fn query_stats_ranks_statements_on_primary() {
    let result = call(ro_config(PORT_18), "query_stats", json!({})).await;
    assert!(!is_error(&result), "{result}");
    let body = structured(&result);
    assert_eq!(body["available"], json!(true), "{result}");
    assert_eq!(body["database"], DB_NAME);
    let statements = body["statements"].as_array().expect("statements array");
    assert!(!statements.is_empty(), "{result}");
    for statement in statements {
        assert!(statement["calls"].as_i64().unwrap_or(0) >= 1, "{statement}");
        assert!(statement["totalExecTimeMs"].is_number(), "{statement}");
        assert!(statement["meanExecTimeMs"].is_number(), "{statement}");
        assert!(statement["queryId"].is_string(), "{statement}");
    }
    assert!(body.get("statsReset").is_some(), "{result}");
    assert!(body.get("dealloc").is_some(), "{result}");
}

#[tokio::test]
async fn query_stats_contains_and_order() {
    let contains = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"contains": "APP.ITEMS", "query_chars": 4000}),
    )
    .await;
    let statements = structured(&contains)["statements"]
        .as_array()
        .expect("statements array")
        .clone();
    assert!(!statements.is_empty(), "{contains}");
    for statement in &statements {
        let query = statement["query"]
            .as_str()
            .unwrap_or_default()
            .to_lowercase();
        assert!(query.contains("app.items"), "{statement}");
    }

    let by_calls = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"order_by": "calls", "limit": 50}),
    )
    .await;
    let calls: Vec<i64> = structured(&by_calls)["statements"]
        .as_array()
        .expect("statements array")
        .iter()
        .map(|s| s["calls"].as_i64().unwrap_or(-1))
        .collect();
    assert!(!calls.is_empty());
    assert!(calls.windows(2).all(|pair| pair[0] >= pair[1]), "{calls:?}");

    let bogus = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"order_by": "bogus"}),
    )
    .await;
    assert!(is_error(&bogus), "{bogus}");
    assert_eq!(
        error_text(&bogus),
        "Invalid order_by \"bogus\". Valid values: total_time, mean_time, calls, rows, io, temp."
    );
    let limited = call(ro_config(PORT_18), "query_stats", json!({"limit": 1})).await;
    assert_eq!(
        structured(&limited)["statements"].as_array().map(Vec::len),
        Some(1)
    );
    let cut_statement = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"query_chars": 5, "contains": "app.items"}),
    )
    .await;
    let first = &structured(&cut_statement)["statements"][0];
    assert_eq!(first["queryTruncated"], json!(true), "{cut_statement}");
    assert_eq!(first["query"].as_str().map(str::len), Some(5));
}

#[tokio::test]
async fn query_stats_every_ordering_and_min_calls() {
    for order in ["total_time", "mean_time", "calls", "rows", "io", "temp"] {
        let result = call(
            ro_config(PORT_18),
            "query_stats",
            json!({"order_by": order, "limit": 5}),
        )
        .await;
        assert!(!is_error(&result), "{order}: {result}");
        assert_eq!(structured(&result)["available"], json!(true), "{order}");
    }
    let frequent = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"min_calls": 2, "limit": 500}),
    )
    .await;
    assert!(!is_error(&frequent), "{frequent}");
    for statement in structured(&frequent)["statements"]
        .as_array()
        .expect("statements")
    {
        assert!(statement["calls"].as_i64().unwrap_or(0) >= 2, "{statement}");
    }
}

#[tokio::test]
async fn query_stats_not_installed_on_other_servers() {
    for port in [PORT_19, PORT_15] {
        let result = call(ro_config(port), "query_stats", json!({})).await;
        assert!(!is_error(&result), "{result}");
        let body = structured(&result);
        assert_eq!(body["available"], json!(false), "port {port}: {result}");
        assert_eq!(body["reason"], NOT_INSTALLED, "port {port}");
        assert_eq!(body["howToEnable"], HOW_TO_ENABLE, "port {port}");
        assert_eq!(body["statements"], json!([]), "port {port}");
    }
}

#[tokio::test]
async fn query_stats_strict_role_has_statement_text() {
    let result = call(strict_config(PORT_18), "query_stats", json!({})).await;
    assert!(!is_error(&result), "{result}");
    let body = structured(&result);
    assert_eq!(body["available"], json!(true), "{result}");
    assert!(body.get("note").is_none(), "{result}");
}

#[tokio::test]
async fn database_stats_default_sections_on_every_server() {
    for (port, major) in [(PORT_18, "18."), (PORT_19, "19."), (PORT_15, "15.")] {
        let result = call(ro_config(port), "database_stats", json!({})).await;
        assert!(!is_error(&result), "port {port}: {result}");
        let body = structured(&result);
        assert!(
            body["serverVersion"]
                .as_str()
                .is_some_and(|v| v.starts_with(major)),
            "{result}"
        );
        let sections = body["sections"].as_object().expect("sections object");
        assert!(sections.contains_key("database"), "{result}");
        assert!(sections.contains_key("checkpointer"), "{result}");
        assert!(sections.contains_key("progress"), "{result}");
        assert!(!sections.contains_key("io"), "{result}");
        assert!(!sections.contains_key("waitEvents"), "{result}");
        assert_eq!(body["unavailable"], json!([]), "{result}");
        let progress = sections["progress"].as_object().expect("progress object");
        for key in [
            "vacuum",
            "analyze",
            "createIndex",
            "cluster",
            "copy",
            "basebackup",
        ] {
            assert!(progress[key].is_array(), "{key}: {result}");
        }
    }
}

#[tokio::test]
async fn database_stats_database_section_values() {
    let result = call(ro_config(PORT_18), "database_stats", json!({})).await;
    let database = &structured(&result)["sections"]["database"];
    assert!(database["sizeBytes"].is_i64(), "{result}");
    assert!(database["xidAge"].is_i64(), "{result}");
    assert!(
        database["maxConnections"].as_i64().unwrap_or(0) > 0,
        "{result}"
    );
    assert!(
        database["connectionsUsed"].as_i64().unwrap_or(0) >= 1,
        "{result}"
    );
    assert!(database["numbackends"].is_i64(), "{result}");
    let ratio = &database["cacheHitRatio"];
    assert!(
        ratio.is_null() || ratio.as_f64().is_some_and(|r| (0.0..=1.0).contains(&r)),
        "{result}"
    );
    assert!(database["statsReset"].is_string() || database["statsReset"].is_null());
}

#[tokio::test]
async fn database_stats_io_on_16_and_newer_only() {
    for port in [PORT_18, PORT_19] {
        let result = call(
            ro_config(port),
            "database_stats",
            json!({"sections": ["io"]}),
        )
        .await;
        assert!(!is_error(&result), "port {port}: {result}");
        let body = structured(&result);
        assert!(body["sections"]["io"].is_array(), "port {port}: {result}");
        assert_eq!(body["unavailable"], json!([]), "port {port}: {result}");
    }
    let old = call(
        ro_config(PORT_15),
        "database_stats",
        json!({"sections": ["io"]}),
    )
    .await;
    let body = structured(&old);
    assert!(body["sections"].get("io").is_none(), "{old}");
    assert_eq!(
        body["unavailable"],
        json!([{
            "section": "io",
            "reason": "pg_stat_io needs PostgreSQL 16 or newer; this server is 15.",
        }]),
        "{old}"
    );
}

#[tokio::test]
async fn database_stats_checkpointer_source_by_version() {
    let expected = [
        (PORT_18, "pg_stat_checkpointer"),
        (PORT_19, "pg_stat_checkpointer"),
        (PORT_15, "pg_stat_bgwriter"),
    ];
    for (port, source) in expected {
        let result = call(
            ro_config(port),
            "database_stats",
            json!({"sections": ["checkpointer"]}),
        )
        .await;
        let checkpointer = &structured(&result)["sections"]["checkpointer"];
        assert_eq!(checkpointer["source"], source, "port {port}: {result}");
        assert!(checkpointer["checkpointsTimed"].is_i64(), "{result}");
        assert!(checkpointer["checkpointsRequested"].is_i64(), "{result}");
        assert!(checkpointer["buffersWritten"].is_i64(), "{result}");
        assert!(checkpointer["writeTimeMs"].is_number(), "{result}");
        assert!(checkpointer["syncTimeMs"].is_number(), "{result}");
    }
}

#[tokio::test]
async fn database_stats_wal_numbers_on_every_server() {
    for port in [PORT_18, PORT_19, PORT_15] {
        let result = call(
            ro_config(port),
            "database_stats",
            json!({"sections": ["wal"]}),
        )
        .await;
        assert!(!is_error(&result), "port {port}: {result}");
        let wal = &structured(&result)["sections"]["wal"];
        assert!(wal["walRecords"].is_i64(), "port {port}: {result}");
        assert!(wal["walBytes"].is_i64(), "port {port}: {result}");
        assert!(wal["walBuffersFull"].is_i64(), "port {port}: {result}");
    }
}

#[tokio::test]
async fn database_stats_wait_events_shape() {
    let result = call(
        ro_config(PORT_18),
        "database_stats",
        json!({"sections": ["wait_events"]}),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let events = structured(&result)["sections"]["waitEvents"]
        .as_array()
        .expect("waitEvents array");
    for event in events {
        assert!(event["type"].is_string(), "{event}");
        assert!(event["event"].is_string(), "{event}");
        assert!(event["sessions"].as_i64().unwrap_or(0) >= 1, "{event}");
    }
}

#[tokio::test]
async fn database_stats_unknown_section_is_error() {
    let result = call(
        ro_config(PORT_18),
        "database_stats",
        json!({"sections": ["bogus"]}),
    )
    .await;
    assert!(is_error(&result), "{result}");
    assert_eq!(
        error_text(&result),
        "Unknown section \"bogus\". Valid sections: database, io, wal, checkpointer, progress, wait_events."
    );
}

#[tokio::test]
async fn database_stats_strict_role_succeeds() {
    let result = call(strict_config(PORT_18), "database_stats", json!({})).await;
    assert!(!is_error(&result), "{result}");
    assert!(
        structured(&result)["sections"]["database"].is_object(),
        "{result}"
    );
}

#[tokio::test]
async fn table_stats_lists_shop_tables_with_sizes() {
    let _shop = SHOP_LOCK.lock().await;
    let result = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"schema": "shop", "limit": 100}),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let tables = structured(&result)["tables"]
        .as_array()
        .expect("tables array")
        .clone();
    assert!(structured(&result).get("statsReset").is_some(), "{result}");
    for wanted in ["orders", "customers", "order_items"] {
        let table = tables
            .iter()
            .find(|t| t["name"] == json!(wanted))
            .unwrap_or_else(|| panic!("{wanted} listed: {result}"));
        assert_eq!(table["schema"], "shop");
        assert!(table["totalBytes"].as_i64().unwrap_or(0) > 0, "{table}");
        assert!(table["tableBytes"].as_i64().unwrap_or(0) > 0, "{table}");
        assert!(table.get("indexes").is_none(), "{table}");
        assert!(
            table["deadRatio"].is_number() || table["deadRatio"].is_null(),
            "{table}"
        );
    }
}

#[tokio::test]
async fn table_stats_single_table_includes_indexes() {
    let _shop = SHOP_LOCK.lock().await;
    let result = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"table": "orders", "schema": "shop"}),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let tables = structured(&result)["tables"]
        .as_array()
        .expect("tables array");
    assert_eq!(tables.len(), 1, "{result}");
    let indexes = tables[0]["indexes"].as_array().expect("indexes listed");
    let primary = indexes
        .iter()
        .find(|index| index["primary"] == json!(true))
        .unwrap_or_else(|| panic!("primary index listed: {result}"));
    assert_eq!(primary["unique"], json!(true));
    assert_eq!(primary["valid"], json!(true));
    assert!(primary["sizeBytes"].as_i64().unwrap_or(0) > 0);
    assert!(
        indexes
            .iter()
            .any(|index| index["name"] == json!("orders_customer_placed_idx")),
        "{result}"
    );
    for index in indexes {
        assert!(index["scans"].is_i64(), "{index}");
        assert!(index["tupRead"].is_i64(), "{index}");
        assert!(index["tupFetch"].is_i64(), "{index}");
    }
}

#[tokio::test]
async fn table_stats_unused_indexes_exclude_keys() {
    let _shop = SHOP_LOCK.lock().await;
    let everything = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"schema": "shop", "include_indexes": true}),
    )
    .await;
    let mut keys: Vec<String> = Vec::new();
    for table in structured(&everything)["tables"]
        .as_array()
        .expect("tables")
    {
        for index in table["indexes"].as_array().expect("indexes") {
            if index["primary"] == json!(true) || index["unique"] == json!(true) {
                keys.push(index["name"].as_str().unwrap_or_default().to_owned());
            }
        }
    }
    assert!(!keys.is_empty(), "{everything}");

    let result = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"schema": "shop", "unused_indexes": true}),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let body = structured(&result);
    assert_eq!(body["tables"], json!([]), "{result}");
    let unused = body["unusedIndexes"]
        .as_array()
        .expect("unusedIndexes array");
    for index in unused {
        assert!(index["sizeBytes"].is_i64(), "{index}");
        assert!(
            index["definition"]
                .as_str()
                .is_some_and(|d| d.starts_with("CREATE")),
            "{index}"
        );
        let name = index["name"].as_str().unwrap_or_default();
        assert!(
            !keys.iter().any(|key| key == name),
            "key index {name} listed: {result}"
        );
    }
}

#[tokio::test]
async fn table_stats_paging_has_no_duplicates() {
    let _shop = SHOP_LOCK.lock().await;
    let mut names: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..20 {
        let mut arguments = json!({"schema": "shop", "limit": 2});
        if let Some(next) = &cursor {
            arguments["cursor"] = json!(next);
        }
        let result = call(ro_config(PORT_18), "table_stats", arguments).await;
        assert!(!is_error(&result), "{result}");
        let page = structured(&result);
        let rows = page["tables"].as_array().expect("tables array");
        assert!(rows.len() <= 2, "{result}");
        for row in rows {
            names.push(format!(
                "{}.{}",
                row["schema"].as_str().unwrap_or_default(),
                row["name"].as_str().unwrap_or_default()
            ));
        }
        match page["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), names.len(), "duplicates in {names:?}");
    for wanted in ["shop.orders", "shop.customers", "shop.order_items"] {
        assert!(names.iter().any(|n| n == wanted), "{wanted} in {names:?}");
    }
}

#[tokio::test]
async fn table_stats_default_listing_skips_timescale_internals() {
    let _shop = SHOP_LOCK.lock().await;
    let result = call(ro_config(PORT_18), "table_stats", json!({"limit": 500})).await;
    assert!(!is_error(&result), "{result}");
    let tables = structured(&result)["tables"]
        .as_array()
        .expect("tables")
        .clone();
    assert!(!tables.is_empty());
    for table in &tables {
        let schema = table["schema"].as_str().unwrap_or_default();
        assert!(!schema.starts_with("_timescaledb"), "{table}");
        assert!(!schema.starts_with("pg_"), "{table}");
        assert_ne!(schema, "information_schema", "{table}");
    }
    let named = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"schema": "_timescaledb_internal", "limit": 5}),
    )
    .await;
    assert!(!is_error(&named), "{named}");
    assert!(!tables_of(&named).is_empty(), "{named}");
}

fn tables_of(result: &Value) -> Vec<Value> {
    structured(result)["tables"]
        .as_array()
        .expect("tables array")
        .clone()
}

#[tokio::test]
async fn table_stats_every_ordering_runs() {
    let _shop = SHOP_LOCK.lock().await;
    for order in [
        "size",
        "seq_scan",
        "idx_scan",
        "dead_rows",
        "writes",
        "last_autovacuum",
    ] {
        let result = call(
            ro_config(PORT_18),
            "table_stats",
            json!({"schema": "shop", "order_by": order}),
        )
        .await;
        assert!(!is_error(&result), "{order}: {result}");
        assert!(!tables_of(&result).is_empty(), "{order}: {result}");
        assert!(
            structured(&result)["tables"][0].get("indexes").is_none(),
            "{result}"
        );
    }
}

#[tokio::test]
async fn table_stats_argument_errors() {
    let bad_order = call(
        ro_config(PORT_18),
        "table_stats",
        json!({"order_by": "bogus"}),
    )
    .await;
    assert!(is_error(&bad_order), "{bad_order}");
    assert_eq!(
        error_text(&bad_order),
        "Invalid order_by \"bogus\". Valid values: size, seq_scan, idx_scan, dead_rows, writes, last_autovacuum."
    );
    let bad_cursor = call(ro_config(PORT_18), "table_stats", json!({"cursor": "x:1"})).await;
    assert_eq!(error_text(&bad_cursor), "Invalid cursor.");
    let signed = call(ro_config(PORT_18), "table_stats", json!({"cursor": "o:+1"})).await;
    assert_eq!(error_text(&signed), "Invalid cursor.");
    let too_big = call(ro_config(PORT_18), "table_stats", json!({"limit": 501})).await;
    assert_eq!(error_text(&too_big), "limit must be between 1 and 500.");
}

#[tokio::test]
async fn table_stats_strict_role_lists_shop() {
    let _shop = SHOP_LOCK.lock().await;
    let result = call(
        strict_config(PORT_18),
        "table_stats",
        json!({"schema": "shop", "limit": 100}),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let tables = structured(&result)["tables"]
        .as_array()
        .expect("tables")
        .clone();
    assert!(
        tables.iter().any(|t| t["name"] == json!("orders")),
        "{result}"
    );
}

#[tokio::test]
async fn replication_status_primary_on_every_server() {
    for port in [PORT_18, PORT_19, PORT_15] {
        let result = call(ro_config(port), "replication_status", json!({})).await;
        assert!(!is_error(&result), "port {port}: {result}");
        let body = structured(&result);
        assert_eq!(body["role"], "primary", "port {port}: {result}");
        assert_eq!(body["inRecovery"], json!(false), "port {port}");
        assert!(
            body["currentLsn"].as_str().is_some_and(is_lsn),
            "port {port}: {result}"
        );
        assert!(body["receiveLsn"].is_null(), "port {port}: {result}");
        assert!(body["replayLsn"].is_null(), "port {port}: {result}");
        assert_eq!(body["standbys"], json!([]), "port {port}: {result}");
        assert_eq!(body["slots"], json!([]), "port {port}: {result}");
        assert!(body["walReceiver"].is_null(), "port {port}: {result}");
        assert!(body["publications"].is_array(), "port {port}: {result}");
        assert!(body["subscriptions"].is_array(), "port {port}: {result}");
        assert_eq!(body["warnings"], json!([]), "port {port}: {result}");
        assert!(!result.to_string().contains("conninfo"), "port {port}");
    }
}

#[tokio::test]
async fn replication_status_strict_role_degrades_without_error() {
    let result = call(strict_config(PORT_18), "replication_status", json!({})).await;
    assert!(!is_error(&result), "{result}");
    let body = structured(&result);
    assert_eq!(body["role"], "primary", "{result}");
    for section in ["standbys", "slots", "publications", "subscriptions"] {
        assert!(
            !body[section].is_null() || body.get(format!("{section}Error")).is_some(),
            "{section} neither listed nor explained: {result}"
        );
    }
    assert!(body["walReceiver"].is_null(), "{result}");
    assert!(body.get("walReceiverError").is_none(), "{result}");
    assert!(!result.to_string().contains("conninfo"), "{result}");
}

/// Each publication's `tables` equals its rows in pg_publication_tables, read through execute_query on the same server.
#[tokio::test]
async fn replication_status_publication_tables_match_catalog_view() {
    for port in [PORT_18, PORT_19, PORT_15] {
        let result = call(ro_config(port), "replication_status", json!({})).await;
        let publications = structured(&result)["publications"]
            .as_array()
            .expect("publications")
            .clone();
        assert!(!publications.is_empty(), "port {port}: {result}");
        for publication in &publications {
            let name = publication["name"].as_str().expect("publication name");
            let sql = format!(
                "SELECT count(*) AS n FROM pg_catalog.pg_publication_tables WHERE pubname = '{name}'"
            );
            let query = call(ro_config(port), "execute_query", json!({"sql": sql})).await;
            let expected = structured(&query)["rows"][0]["n"].clone();
            assert_eq!(
                publication["tables"], expected,
                "port {port} publication {name}"
            );
        }
    }
}

/// Exact table counts per membership kind on PostgreSQL 19: a schema, one table, a partition root and its leaves.
#[tokio::test]
async fn replication_status_publication_table_counts_by_kind() {
    let result = call(ro_config(PORT_19), "replication_status", json!({})).await;
    let publications = structured(&result)["publications"]
        .as_array()
        .expect("publications")
        .clone();
    let tables = |name: &str| {
        publications
            .iter()
            .find(|p| p["name"] == name)
            .unwrap_or_else(|| panic!("no publication {name}: {result}"))["tables"]
            .clone()
    };
    assert_eq!(tables("pub_one"), json!(1));
    assert_eq!(tables("pub_root"), json!(1), "partition root only");
    assert_eq!(
        tables("pub_leaves"),
        json!(3),
        "the three leaves of shop.events"
    );
    assert_eq!(tables("pub_schema"), json!(2), "the tables of schema app");
}

#[tokio::test]
async fn toolset_gating_hides_monitor_tools() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let headers = [("mcp-protocol-version", PROTOCOL_2025)];
    let core_only = app(one_db(PORT_18, &[("TOOLSETS", "core")]));
    let names: Vec<String> =
        result_of(&post_mcp(&core_only, &body, &headers).await.json())["tools"]
            .as_array()
            .expect("tools array")
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
            .collect();
    for monitor in [
        "list_activity",
        "query_stats",
        "database_stats",
        "table_stats",
        "replication_status",
    ] {
        assert!(!names.iter().any(|name| name == monitor), "{names:?}");
    }
    assert!(
        names.iter().any(|name| name == "execute_query"),
        "{names:?}"
    );

    let everything = app(one_db(PORT_18, &[]));
    let all: Vec<String> = result_of(&post_mcp(&everything, &body, &headers).await.json())["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect();
    for monitor in [
        "list_activity",
        "query_stats",
        "database_stats",
        "table_stats",
        "replication_status",
    ] {
        assert!(all.iter().any(|name| name == monitor), "{all:?}");
    }
}

#[tokio::test]
async fn no_secret_in_any_output() {
    let _shop = SHOP_LOCK.lock().await;
    let calls = [
        ("list_activity", json!({})),
        ("query_stats", json!({})),
        ("database_stats", json!({})),
        ("table_stats", json!({})),
        ("replication_status", json!({})),
    ];
    for (name, arguments) in calls {
        let result = call(ro_config(PORT_18), name, arguments).await;
        let text = result.to_string();
        for secret in SECRETS {
            assert!(!text.contains(secret), "{name} leaks {secret}");
        }
        assert!(!text.contains("conninfo"), "{name}");
    }
}

const MASK_HOLDER_APP: &str = "pgmcp-monitor-mask";
const MASK_MARKER: &str = "mask_marker_7731";

/// A harmless SELECT whose text carries a PASSWORD literal, as a superuser session on PORT_18.
fn password_text_sql(sleep: &str) -> String {
    format!("SELECT 'ALTER ROLE nobody PASSWORD ''hunter2-{MASK_MARKER}''' AS x, pg_sleep({sleep})")
}

#[tokio::test]
async fn list_activity_masks_password_in_statement_text() {
    let mut holder = raw(PORT_18, "postgres", SUPER_PASSWORD, MASK_HOLDER_APP).await;
    let sql = password_text_sql("5");
    let sleeper = tokio::spawn(async move { holder.simple_query(&sql).await });

    let mut last = Value::Null;
    for _ in 0..50 {
        last = call(ro_config(PORT_18), "list_activity", json!({})).await;
        let all = sessions(&last);
        if session_of(&all, MASK_HOLDER_APP).is_some_and(|s| s["state"] == json!("active")) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let all = sessions(&last);
    let row = session_of(&all, MASK_HOLDER_APP)
        .cloned()
        .unwrap_or(Value::Null);
    let query = row["query"].as_str().unwrap_or_default().to_owned();
    assert!(query.contains("pg_sleep(5)"), "{last}");
    assert!(query.contains("PASSWORD '***'"), "{query}");
    assert!(!query.contains("hunter2"), "{query}");
    assert!(!last.to_string().contains("hunter2"), "{last}");
    let finished = sleeper.await.expect("holder task");
    assert!(finished.is_ok(), "pg_sleep holder failed");
}

#[tokio::test]
async fn query_stats_masks_password_in_statement_text() {
    let mut holder = raw(PORT_18, "postgres", SUPER_PASSWORD, MASK_HOLDER_APP).await;
    let marker_alias = format!("mask_probe_{MASK_MARKER}");
    let sql =
        format!("SELECT 'ALTER ROLE nobody PASSWORD ''hunter2-{MASK_MARKER}''' AS {marker_alias}");
    holder.simple_query(&sql).await.expect("statement runs");
    let result = call(
        ro_config(PORT_18),
        "query_stats",
        json!({"contains": MASK_MARKER, "query_chars": 4000}),
    )
    .await;
    let statements = structured(&result)["statements"]
        .as_array()
        .expect("statements array")
        .clone();
    assert!(!statements.is_empty(), "{result}");
    for statement in &statements {
        let query = statement["query"].as_str().unwrap_or_default();
        assert!(!query.contains("hunter2"), "{query}");
    }
    assert!(!result.to_string().contains("hunter2"), "{result}");
}

/// The role with CONNECT and USAGE on app and SELECT on app.items only (docker/initdb/56_test_objects.sql).
fn min_config(port: u16) -> Config {
    config_with(
        &[json!({
            "name": "appdb",
            "host": "127.0.0.1",
            "port": port,
            "database": DB_NAME,
            "user": "mcp_min",
            "password": "test-only-min",
            "sslmode": "disable",
        })],
        &[],
    )
}

const MIN_NOTE: &str = "Query text of other users is hidden: GRANT pg_read_all_stats TO mcp_min;";

#[tokio::test]
async fn list_activity_min_role_hides_other_users_query_text() {
    let mut holder = raw(PORT_18, "postgres", SUPER_PASSWORD, "pgmcp-min-holder").await;
    let pid = backend_pid(&mut holder).await;
    let sleeper = tokio::spawn(async move { holder.simple_query("SELECT pg_sleep(6)").await });
    let mut last = Value::Null;
    for _ in 0..50 {
        last = call(
            min_config(PORT_18),
            "list_activity",
            json!({"include_background": true}),
        )
        .await;
        let all = sessions(&last);
        if all.iter().any(|s| s["pid"] == json!(pid)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(!is_error(&last), "{last}");
    assert_eq!(
        structured(&last)["queryTextVisible"],
        json!(false),
        "{last}"
    );
    assert_eq!(structured(&last)["note"], json!(MIN_NOTE), "{last}");
    let all = sessions(&last);
    let holder_row = all
        .iter()
        .find(|s| s["pid"] == json!(pid))
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(holder_row["user"], "postgres", "{last}");
    assert_eq!(holder_row["query"], Value::Null, "{last}");
    assert!(sleeper.await.expect("holder task").is_ok());
}

#[tokio::test]
async fn query_stats_min_role_hides_other_users_query_text() {
    let result = call(min_config(PORT_18), "query_stats", json!({})).await;
    assert!(!is_error(&result), "{result}");
    assert_eq!(structured(&result)["note"], json!(MIN_NOTE), "{result}");
    let statements = structured(&result)["statements"]
        .as_array()
        .expect("statements array")
        .clone();
    assert!(!statements.is_empty(), "{result}");
    for statement in &statements {
        if statement["user"] != json!("mcp_min") {
            assert_eq!(statement["query"], Value::Null, "{statement}");
        }
    }
}
