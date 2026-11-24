//! Integration tests for read_server_log against the test servers: jsonlog (15432), csvlog (15433), stderr (15434).

mod common;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use common::{
    DB_NAME, PORT_15, PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with, db_entry,
    one_db, post_mcp, result_of,
};
use postgres_mcp::config::Config;
use serde_json::{Value, json};

const NO_SECRETS: [&str; 3] = ["test-only-superuser", "test-only-ro", "test-only-strict"];

/// Runs one tool call and returns the JSON-RPC `result`.
async fn call(config: Config, name: &str, args: Value) -> Value {
    let router = app(config);
    result_of(&call_tool(&router, name, args).await).clone()
}

fn is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn text_of(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

fn structured(result: &Value) -> &Value {
    &result["structuredContent"]
}

fn entries_of(result: &Value) -> Vec<Value> {
    structured(result)["entries"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// A unique lowercase marker for one test run.
fn marker(tag: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("pgmcp-{tag}-{nanos:x}-{:x}", std::process::id())
}

/// An ISO 8601 UTC time `secs` seconds from now.
fn iso_at(secs: i64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let unix = now + secs;
    let days = unix.div_euclid(86_400);
    let rest = unix.rem_euclid(86_400);
    // Civil date from day count (proleptic Gregorian).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

async fn execute(port: u16, sql: &str) -> Value {
    call(one_db(port, &[]), "execute_query", json!({ "sql": sql })).await
}

/// Reads the log until entries come back or 5 seconds pass; returns the last reply.
async fn poll(port: u16, args: Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let result = call(one_db(port, &[]), "read_server_log", args.clone()).await;
        if !is_error(&result) && !entries_of(&result).is_empty() {
            return result;
        }
        if Instant::now() >= deadline {
            return result;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn mentions(entry: &Value, needle: &str) -> bool {
    ["message", "statement", "detail"]
        .iter()
        .filter_map(|key| entry[*key].as_str())
        .any(|text| text.contains(needle))
}

/// Shared round trip: marker and error entries are found, filters and paging behave.
async fn round_trip(port: u16, structured_format: bool) {
    let m1 = marker("ok");
    let m2 = marker("err");
    let ok = execute(port, &format!("SELECT '{m1}' AS m")).await;
    assert!(!is_error(&ok), "{ok}");
    let failed = execute(port, &format!("SELECT 1/0 AS \"{m2}\"")).await;
    assert!(is_error(&failed), "{failed}");
    assert!(
        text_of(&failed).starts_with("PostgreSQL error 22012: division by zero"),
        "{}",
        text_of(&failed)
    );

    let found = poll(port, json!({ "contains": m1 })).await;
    let entries = entries_of(&found);
    let hit = entries
        .iter()
        .find(|e| mentions(e, &m1))
        .unwrap_or_else(|| panic!("no entry for marker in {found}"));
    assert!(hit["pid"].is_u64(), "{hit}");
    if structured_format {
        assert_eq!(hit["user"], "mcp_ro", "{hit}");
        assert_eq!(hit["database"], DB_NAME, "{hit}");
    }

    let errors = poll(port, json!({ "contains": m2, "min_severity": "ERROR" })).await;
    let error_entry = entries_of(&errors)
        .into_iter()
        .find(|e| mentions(e, &m2))
        .unwrap_or_else(|| panic!("no error entry in {errors}"));
    assert_eq!(error_entry["severity"], "ERROR", "{error_entry}");
    if structured_format {
        assert_eq!(error_entry["sqlstate"], "22012", "{error_entry}");
    }

    let severe = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "min_severity": "ERROR", "limit": 100 }),
    )
    .await;
    let severe_entries = entries_of(&severe);
    let severities: Vec<&str> = severe_entries
        .iter()
        .filter_map(|e| e["severity"].as_str())
        .collect();
    assert!(!severities.is_empty(), "{severe}");
    assert!(
        severities
            .iter()
            .all(|s| matches!(*s, "ERROR" | "FATAL" | "PANIC")),
        "{severities:?}"
    );

    let future = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "since": iso_at(3600) }),
    )
    .await;
    assert!(entries_of(&future).is_empty(), "{future}");
    assert_eq!(structured(&future)["scannedToEnd"], true, "{future}");

    let recent = poll(port, json!({ "since": iso_at(-3600), "contains": m1 })).await;
    assert!(
        entries_of(&recent).iter().any(|e| mentions(e, &m1)),
        "{recent}"
    );

    let old = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "until": "2000-01-01T00:00:00Z", "contains": m1 }),
    )
    .await;
    assert!(entries_of(&old).is_empty(), "{old}");
    // A large log can exhaust the scan budget before its start, so either the start was reached or a cursor follows.
    let old_done = structured(&old)["scannedToEnd"] == true;
    assert!(
        old_done || structured(&old)["nextCursor"].is_string(),
        "{old}"
    );

    let bad = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "since": "not a time" }),
    )
    .await;
    assert!(is_error(&bad), "{bad}");
    assert_eq!(text_of(&bad), "since is not a valid timestamp.");

    let pid = hit["pid"].clone();
    let by_pid = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "pid": pid, "limit": 50 }),
    )
    .await;
    let pid_entries = entries_of(&by_pid);
    assert!(!pid_entries.is_empty(), "{by_pid}");
    assert!(pid_entries.iter().all(|e| e["pid"] == pid), "{by_pid}");

    paging(port).await;
    listing(port, structured_format).await;
}

/// Four pages of five entries: no duplicates, newest first.
async fn paging(port: u16) {
    let mut seen: Vec<(String, Value, String)> = Vec::new();
    let mut cursor: Option<String> = None;
    let mut previous_stamp: Option<String> = None;
    for page in 0..4 {
        let mut args = json!({ "limit": 5 });
        if let Some(value) = &cursor {
            args["cursor"] = json!(value);
        }
        let result = call(one_db(port, &[]), "read_server_log", args).await;
        assert!(!is_error(&result), "page {page}: {result}");
        let entries = entries_of(&result);
        assert_eq!(entries.len(), 5, "page {page}: {result}");
        for entry in &entries {
            let stamp = entry["timestamp"].as_str().unwrap_or_default().to_owned();
            if let Some(prev) = &previous_stamp {
                assert!(stamp.as_str() <= prev.as_str(), "{stamp} after {prev}");
            }
            previous_stamp = Some(stamp.clone());
            let key = (stamp, entry["pid"].clone(), mention_text(entry));
            assert!(!seen.contains(&key), "duplicate entry {key:?}");
            seen.push(key);
        }
        cursor = structured(&result)["nextCursor"]
            .as_str()
            .map(str::to_owned);
        assert!(cursor.is_some(), "page {page} has no nextCursor: {result}");
    }
}

fn mention_text(entry: &Value) -> String {
    entry["message"].as_str().unwrap_or_default().to_owned()
}

async fn listing(port: u16, structured_format: bool) {
    let result = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "list_files": true }),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    let files = structured(&result)["files"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!files.is_empty(), "{result}");
    assert_eq!(
        structured(&result)["settings"]["loggingCollector"],
        "on",
        "{result}"
    );
    for file in &files {
        let name = file["name"].as_str().unwrap_or_default();
        let expected = if name.ends_with(".json") {
            "jsonlog"
        } else if name.ends_with(".csv") {
            "csvlog"
        } else {
            "stderr"
        };
        assert_eq!(file["format"], expected, "{file}");
    }
    let wanted = match port {
        PORT_18 => "jsonlog",
        PORT_19 => "csvlog",
        _ => "stderr",
    };
    assert!(files.iter().any(|f| f["format"] == wanted), "{result}");
    assert_eq!(structured_format, wanted != "stderr", "{result}");

    let unknown = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "file": "no-such-file.log" }),
    )
    .await;
    assert!(is_error(&unknown), "{unknown}");
    assert_eq!(text_of(&unknown), "Unknown log file \"no-such-file.log\".");

    let garbage = call(
        one_db(port, &[]),
        "read_server_log",
        json!({ "cursor": "garbage" }),
    )
    .await;
    assert!(is_error(&garbage), "{garbage}");
    assert_eq!(text_of(&garbage), "Invalid cursor.");

    let limit = call(one_db(port, &[]), "read_server_log", json!({ "limit": 0 })).await;
    assert_eq!(text_of(&limit), "limit must be between 1 and 500.");
}

#[tokio::test]
async fn jsonlog_round_trip_and_paging() {
    round_trip(PORT_18, true).await;
}

#[tokio::test]
async fn csvlog_round_trip_and_paging() {
    round_trip(PORT_19, true).await;
}

#[tokio::test]
async fn stderr_round_trip_and_paging() {
    round_trip(PORT_15, false).await;
}

#[tokio::test]
async fn pgaudit_entries_are_readable() {
    // The AUDIT lines come from the seed DDL, so the search may need several budget-limited pages.
    let mut args = json!({ "contains": "AUDIT:" });
    let mut found = false;
    for _ in 0..60 {
        let result = call(one_db(PORT_18, &[]), "read_server_log", args.clone()).await;
        assert!(!is_error(&result), "{result}");
        if !entries_of(&result).is_empty() {
            found = true;
            break;
        }
        match structured(&result)["nextCursor"].as_str() {
            Some(cursor) => args["cursor"] = json!(cursor),
            None => break,
        }
    }
    assert!(found, "no AUDIT entry found in the log");
}

#[tokio::test]
async fn masking_is_applied_end_to_end() {
    let outside = marker("mask");
    let sql = format!("SELECT '{outside}' AS b WHERE 'PASSWORD ''hunter2-value''' IS NOT NULL");
    let ran = execute(PORT_18, &sql).await;
    assert!(!is_error(&ran), "{ran}");
    let found = poll(PORT_18, json!({ "contains": outside })).await;
    let text = entries_of(&found)
        .iter()
        .filter_map(|e| {
            let statement = e["statement"].as_str().unwrap_or_default();
            let message = e["message"].as_str().unwrap_or_default();
            [statement, message]
                .into_iter()
                .find(|s| s.contains(&outside))
                .map(str::to_owned)
        })
        .next()
        .unwrap_or_else(|| panic!("no statement entry in {found}"));
    assert!(text.contains("PASSWORD '***'"), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
}

#[tokio::test]
async fn unavailable_when_functions_are_not_installed() {
    let entry = json!({
        "name": "plain",
        "host": "127.0.0.1",
        "port": PORT_19,
        "database": "postgres",
        "user": "postgres",
        "password": "test-only-superuser",
        "sslmode": "disable",
    });
    let result = call(config_with(&[entry], &[]), "read_server_log", json!({})).await;
    assert!(!is_error(&result), "{result}");
    assert_eq!(structured(&result)["available"], false, "{result}");
    assert_eq!(
        structured(&result)["reason"],
        "The log reader functions are not installed in this database."
    );
    let how = structured(&result)["howToEnable"]
        .as_str()
        .unwrap_or_default();
    assert!(
        how.contains("GRANT USAGE ON SCHEMA pgmcp TO postgres;"),
        "{how}"
    );
}

#[tokio::test]
async fn strict_role_reads_through_the_grants() {
    let entry = json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": PORT_18,
        "database": DB_NAME,
        "user": "mcp_strict",
        "password": "test-only-strict",
        "sslmode": "disable",
    });
    let result = call(
        config_with(&[entry], &[]),
        "read_server_log",
        json!({ "list_files": true }),
    )
    .await;
    assert!(!is_error(&result), "{result}");
    assert_eq!(structured(&result)["available"], true, "{result}");
    assert!(
        structured(&result)["files"]
            .as_array()
            .is_some_and(|f| !f.is_empty()),
        "{result}"
    );
}

#[tokio::test]
async fn core_toolset_hides_the_tool() {
    let router = app(config_with(
        &[db_entry("appdb", PORT_18)],
        &[("TOOLSETS", "core")],
    ));
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    assert_eq!(reply.status, StatusCode::OK);
    let names: Vec<String> = result_of(&reply.json())["tools"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    assert!(!names.iter().any(|n| n == "read_server_log"), "{names:?}");
}

#[tokio::test]
async fn no_secret_in_any_output() {
    let mut serialized = String::new();
    for args in [json!({}), json!({ "list_files": true })] {
        let result = call(one_db(PORT_18, &[]), "read_server_log", args).await;
        serialized.push_str(&result.to_string());
    }
    for secret in NO_SECRETS {
        assert!(!serialized.contains(secret), "secret {secret} in output");
    }
}
