//! Hardening regressions: hostile public functions must not reach the server's own SQL.

mod common;

use common::{
    DB_NAME, HOSTILE_SETUP, PORT_15, PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with,
    db_entry, post_mcp, result_of, superuser_setup,
};
use postgres_mcp::config::Config;
use serde_json::{Value, json};

const MARKER: &str = "pgmcp hostile function called";

/// A config whose one database connects as mcp_strict, the role with the hostile search_path.
fn strict_config(port: u16) -> Config {
    let mut entry = db_entry("appdb", port);
    entry["user"] = json!("mcp_strict");
    entry["password"] = json!("test-only-strict");
    config_with(&[entry], &[])
}

/// Every tool with the arguments the hostile test calls it with, and whether it needs TimescaleDB.
fn calls() -> Vec<(&'static str, bool, Value)> {
    vec![
        ("list_databases", false, json!({})),
        ("execute_query", false, json!({"sql": "SELECT 1 AS one"})),
        (
            "explain_query",
            false,
            json!({"sql": "SELECT * FROM app.items WHERE id = 1"}),
        ),
        ("server_info", false, json!({})),
        ("list_schemas", false, json!({})),
        ("list_objects", false, json!({"schema": "app"})),
        ("describe_table", false, json!({"table": "app.items"})),
        ("describe_function", false, json!({"function": "lower"})),
        ("search_schema", false, json!({"query": "items"})),
        ("get_privileges", false, json!({})),
        ("list_activity", false, json!({})),
        ("query_stats", false, json!({})),
        ("database_stats", false, json!({})),
        ("table_stats", false, json!({})),
        ("replication_status", false, json!({})),
        ("read_server_log", false, json!({})),
        ("list_hypertables", true, json!({})),
        (
            "describe_hypertable",
            true,
            json!({"hypertable": "metrics.readings"}),
        ),
        ("list_continuous_aggregates", true, json!({})),
        ("list_jobs", true, json!({})),
    ]
}

/// A hostile call shows as the marker in any text. read_server_log returns log lines, and the log keeps
/// earlier marker errors, so for it only an error result carrying the marker counts.
fn reached_hostile(name: &str, response: &Value) -> bool {
    let text = response.to_string();
    if name == "read_server_log" {
        result_of(response)["isError"] == json!(true) && text.contains(MARKER)
    } else {
        text.contains(MARKER)
    }
}

async fn listed_tool_names(router: &axum::Router) -> Vec<String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = post_mcp(router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    result_of(&response.json())["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .map(|tool| tool["name"].as_str().expect("tool name").to_owned())
        .collect()
}

#[tokio::test]
async fn strict_role_user_sql_keeps_the_role_search_path() {
    superuser_setup(PORT_18, DB_NAME, HOSTILE_SETUP).await;
    let router = app(strict_config(PORT_18));

    let hostile = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT lower('A'::name) AS v"}),
    )
    .await;
    let result = result_of(&hostile);
    assert_eq!(result["isError"], json!(true), "{hostile}");
    let text = result["content"][0]["text"].as_str().expect("error text");
    assert!(text.contains(MARKER), "{text}");

    let qualified = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT pg_catalog.lower('A'::name) AS v"}),
    )
    .await;
    let result = result_of(&qualified);
    assert_eq!(result["isError"], json!(false), "{qualified}");
    assert_eq!(result["structuredContent"]["rows"][0]["v"], json!("a"));
}

#[tokio::test]
async fn server_sql_does_not_run_hostile_public_functions() {
    let mut reached = Vec::new();
    for (port, timescale) in [(PORT_18, true), (PORT_19, false), (PORT_15, false)] {
        superuser_setup(port, DB_NAME, HOSTILE_SETUP).await;
        let router = app(strict_config(port));
        let names = listed_tool_names(&router).await;
        let known: Vec<&str> = calls().iter().map(|(name, _, _)| *name).collect();
        for name in &names {
            assert!(
                known.contains(&name.as_str()),
                "tool {name} has no hostile-test call"
            );
        }
        for (name, needs_timescale, arguments) in calls() {
            if needs_timescale && !timescale {
                continue;
            }
            let response = call_tool(&router, name, arguments).await;
            if reached_hostile(name, &response) {
                reached.push(format!("{name} on port {port}: {response}"));
            }
        }
    }
    assert!(
        reached.is_empty(),
        "tools that reached a hostile function:\n{}",
        reached.join("\n")
    );
}

/// A loopback port with nothing listening: bound once to learn a free number, then released.
fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a free port");
    listener.local_addr().expect("local address").port()
}

fn text_of(response: &Value) -> String {
    result_of(response)["content"][0]["text"]
        .as_str()
        .expect("error text")
        .to_owned()
}

#[tokio::test]
async fn wrong_password_reports_only_the_short_text() {
    let mut entry = db_entry("bad", PORT_18);
    entry["password"] = json!("not-the-password");
    let router = app(config_with(&[entry], &[]));
    let response = call_tool(
        &router,
        "execute_query",
        json!({"database": "bad", "sql": "SELECT 1"}),
    )
    .await;
    assert_eq!(result_of(&response)["isError"], json!(true), "{response}");
    let text = text_of(&response);
    assert_eq!(
        text,
        "Database \"bad\" is unavailable: authentication failed"
    );
    assert!(!text.contains("mcp_ro"), "{text}");
    assert!(!text.contains("127.0.0.1"), "{text}");
}

#[tokio::test]
async fn unknown_database_reports_does_not_exist() {
    let mut entry = db_entry("nope_db", PORT_18);
    entry["database"] = json!("nope");
    let router = app(config_with(&[entry], &[]));
    let response = call_tool(
        &router,
        "execute_query",
        json!({"database": "nope_db", "sql": "SELECT 1"}),
    )
    .await;
    assert_eq!(
        text_of(&response),
        "Database \"nope_db\" is unavailable: the database does not exist"
    );
}

#[tokio::test]
async fn closed_port_reports_cannot_connect() {
    let entry = db_entry("closed", closed_port());
    let router = app(config_with(&[entry], &[]));
    let response = call_tool(
        &router,
        "execute_query",
        json!({"database": "closed", "sql": "SELECT 1"}),
    )
    .await;
    assert_eq!(
        text_of(&response),
        "Database \"closed\" is unavailable: cannot connect to the server"
    );
}

#[tokio::test]
async fn list_databases_shows_the_same_short_texts() {
    let mut wrong = db_entry("bad", PORT_18);
    wrong["password"] = json!("not-the-password");
    let mut missing = db_entry("nope_db", PORT_18);
    missing["database"] = json!("nope");
    let closed = db_entry("closed", closed_port());
    let config = config_with(&[wrong, missing, closed, db_entry("good", PORT_18)], &[]);
    let router = app(config);
    let response = call_tool(&router, "list_databases", json!({})).await;
    let databases = result_of(&response)["structuredContent"]["databases"]
        .as_array()
        .expect("databases array")
        .clone();
    let errors: Vec<Value> = databases
        .iter()
        .map(|db| db.get("error").cloned().unwrap_or(Value::Null))
        .collect();
    assert_eq!(
        errors,
        vec![
            json!("Database \"bad\" is unavailable: authentication failed"),
            json!("Database \"nope_db\" is unavailable: the database does not exist"),
            json!("Database \"closed\" is unavailable: cannot connect to the server"),
            Value::Null,
        ],
        "{response}"
    );
    assert_eq!(databases[3]["reachable"], json!(true));
    let serialized = response.to_string();
    assert!(!serialized.contains("mcp_ro"), "{serialized}");
    assert!(!serialized.contains("127.0.0.1"), "{serialized}");
}
