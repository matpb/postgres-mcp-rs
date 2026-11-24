//! Integration tests for the HTTP transport: protocol, tools, limits, guard and error texts against the test databases.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{
    DB_NAME, DB_PASSWORD, DB_USER, PORT_15, PORT_18, PORT_19, PROTOCOL_2025, PROTOCOL_2026, app,
    call_tool, config_with, db_entry, one_db, post_mcp, result_of, send,
};
use postgres_mcp::config::Config;
use postgres_mcp::gate::SECRET_SETTINGS;
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection};
use postgres_mcp::tools::core::SERVER_INFO_SETTINGS;
use postgres_mcp::tools::text;
use serde_json::{Value, json};

const API_KEY: &str = "test-api-key-0123456789";

fn is_error(result: &Value) -> bool {
    result
        .get("isError")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn text_of(result: &Value) -> String {
    result["content"][0]["text"]
        .as_str()
        .expect("result has a text block")
        .to_owned()
}

fn structured(result: &Value) -> &Value {
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent in {result}"))
}

/// Calls a tool on a server configured for one database and returns its result object.
async fn tool(config: Config, name: &str, arguments: Value) -> Value {
    let response = call_tool(&app(config), name, arguments).await;
    result_of(&response).clone()
}

/// The TimescaleDB version installed in appdb on the port, read through the wire client directly.
async fn installed_timescaledb(port: u16) -> Option<String> {
    let mut conn = Connection::connect(&ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: DB_NAME.into(),
        user: DB_USER.into(),
        password: Some(DB_PASSWORD.into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: Vec::new(),
    })
    .await
    .expect("direct connection to the test server");
    let result = conn
        .simple_query(
            "SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'timescaledb'",
        )
        .await
        .expect("direct query succeeds");
    result
        .rows
        .first()
        .and_then(|row| row.first().cloned().flatten())
}

fn initialize_body(id: u64) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_2025,
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0.0.0"},
        },
    })
}

#[tokio::test]
async fn health_is_open_and_plain() {
    let router = app(one_db(PORT_18, &[]));
    let reply = send(
        &router,
        axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.text(), "ok");
    assert!(
        reply
            .headers
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("text/plain"))
    );
}

#[tokio::test]
async fn health_is_open_with_api_key_configured() {
    let router = app(one_db(PORT_18, &[("API_KEY", API_KEY)]));
    let reply = send(
        &router,
        axum::http::Request::builder()
            .uri("/health")
            .body(axum::body::Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.text(), "ok");
}

#[tokio::test]
async fn initialize_reports_server_info_and_instructions() {
    let router = app(one_db(PORT_18, &[]));
    let reply = post_mcp(
        &router,
        &initialize_body(1),
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let body = reply.json();
    let result = result_of(&body);
    assert_eq!(result["serverInfo"]["name"], "postgres-mcp");
    assert_eq!(result["serverInfo"]["version"], env!("CARGO_PKG_VERSION"));
    let instructions = result["instructions"].as_str().expect("instructions");
    assert!(instructions.contains(DB_NAME), "{instructions}");
    assert!(result["capabilities"].get("tools").is_some(), "{result}");
}

#[tokio::test]
async fn stateless_2026_request_works() {
    let router = app(one_db(PORT_18, &[]));
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": PROTOCOL_2026,
                "io.modelcontextprotocol/clientInfo": {"name": "test-client", "version": "0.0.0"},
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    });
    let reply = post_mcp(
        &router,
        &body,
        &[
            ("mcp-protocol-version", PROTOCOL_2026),
            ("mcp-method", "tools/list"),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.text());
    let body = reply.json();
    let names: Vec<&str> = result_of(&body)["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str())
        .collect();
    assert!(names.contains(&"execute_query"), "{names:?}");
}

#[tokio::test]
async fn tools_list_has_core_tools_with_annotations() {
    let router = app(one_db(PORT_18, &[]));
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    let tools = result_of(&reply.json())["tools"].clone();
    let tools = tools.as_array().expect("tools array").clone();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for expected in [
        "list_databases",
        "execute_query",
        "explain_query",
        "server_info",
    ] {
        assert!(names.contains(&expected), "missing {expected} in {names:?}");
    }
    for tool in &tools {
        let name = tool["name"].as_str().expect("name");
        let annotations = &tool["annotations"];
        assert_eq!(annotations["readOnlyHint"], true, "{name}");
        assert_eq!(annotations["destructiveHint"], false, "{name}");
        assert!(
            tool["title"].as_str().is_some_and(|t| !t.is_empty()),
            "{name}"
        );
        assert_eq!(tool["outputSchema"]["type"], "object", "{name}");
    }
    let execute = tools
        .iter()
        .find(|t| t["name"] == "execute_query")
        .expect("execute_query listed");
    assert_eq!(execute["description"], text::EXECUTE_QUERY);
    assert_eq!(execute["title"], text::EXECUTE_QUERY_TITLE);
    let sql_doc = execute["inputSchema"]["properties"]["sql"]["description"].as_str();
    assert_eq!(sql_doc, Some(text::EXECUTE_QUERY_SQL_PARAM));
}

#[tokio::test]
async fn execute_query_returns_typed_rows() {
    let config = one_db(PORT_18, &[]);
    let result = tool(
        config,
        "execute_query",
        json!({"sql": "SELECT id, name, qty, price, NULL::text AS n FROM app.items WHERE id IN (1, 5000) ORDER BY id"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(
        content["rows"],
        json!([
            {"id": 1, "name": "item 1", "qty": 1000000000000_u64, "price": "1.50", "n": null},
            {"id": 5000, "name": "item 5000", "qty": 5000000000000000_u64, "price": "7500.00", "n": null},
        ])
    );
    let text: Value = serde_json::from_str(&text_of(&result)).expect("text is JSON");
    assert_eq!(&text, content, "text block equals structuredContent");
}

#[tokio::test]
async fn execute_query_encodes_every_type_exactly() {
    let config = one_db(PORT_18, &[]);
    let result = tool(
        config,
        "execute_query",
        json!({"sql": "SELECT 9007199254740993::int8 AS big, 1.10::numeric AS num, 'NaN'::float8 AS f, now() IS NOT NULL AS b, ARRAY[1,2,NULL] AS arr, '[1,5)'::int4range AS r, '{\"a\":1}'::jsonb AS j, 'x'::bytea AS by"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(
        content["rows"][0],
        json!({
            "big": "9007199254740993",
            "num": "1.10",
            "f": "NaN",
            "b": true,
            "arr": [1, 2, null],
            "r": {"lower": 1, "upper": 5, "lowerInc": true, "upperInc": false},
            "j": {"a": 1},
            "by": "\\x78",
        })
    );
    let columns = content["columns"].as_array().expect("columns");
    let types: Vec<&str> = columns.iter().filter_map(|c| c["type"].as_str()).collect();
    assert_eq!(
        types,
        [
            "int8",
            "numeric",
            "float8",
            "bool",
            "_int4",
            "int4range",
            "jsonb",
            "bytea"
        ]
    );
    let oids: Vec<u64> = columns
        .iter()
        .filter_map(|c| c["typeOid"].as_u64())
        .collect();
    assert_eq!(oids, [20, 1700, 701, 16, 1007, 3904, 3802, 17]);
}

#[tokio::test]
async fn execute_query_zero_rows_still_has_columns() {
    let result = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"sql": "SELECT id, name FROM app.items WHERE false"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(content["rows"], json!([]));
    assert_eq!(content["rowCount"], 0);
    let names: Vec<&str> = content["columns"]
        .as_array()
        .expect("columns")
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert_eq!(names, ["id", "name"]);
}

#[tokio::test]
async fn duplicate_columns_are_renamed() {
    let result = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"sql": "SELECT 1 AS id, 2 AS id"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(content["rows"], json!([{"id": 1, "id__2": 2}]));
    assert_eq!(content["columns"][1]["name"], "id__2");
    assert_eq!(content["columns"][1]["originalName"], "id");
    assert!(content["columns"][0].get("originalName").is_none());
}

#[tokio::test]
async fn row_cap_truncates() {
    let result = tool(
        one_db(PORT_18, &[("MAX_ROWS", "10")]),
        "execute_query",
        json!({"sql": "SELECT * FROM app.items ORDER BY id"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(content["rows"].as_array().map(Vec::len), Some(10));
    assert_eq!(content["rowCount"], 10);
    assert_eq!(content["truncated"], true);
    assert_eq!(content["truncatedReason"], "row_limit");
}

#[tokio::test]
async fn response_budget_truncates() {
    let result = tool(
        one_db(PORT_18, &[("MAX_RESPONSE_BYTES", "2048")]),
        "execute_query",
        json!({"sql": "SELECT * FROM app.items ORDER BY id"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let content = structured(&result);
    assert_eq!(content["truncated"], true);
    assert_eq!(content["truncatedReason"], "response_size");
    assert!(content["rows"].as_array().is_some_and(|r| !r.is_empty()));
}

#[tokio::test]
async fn writes_are_rejected_by_gate() {
    let router = app(one_db(PORT_18, &[]));
    let statements = [
        "INSERT INTO app.items (id, name, qty, price) VALUES (999999, 'x', 1, 1)",
        "UPDATE app.items SET qty = 0",
        "DELETE FROM app.items",
        "DROP TABLE app.items",
        "SELECT 1; SELECT 2",
        "SELECT pg_advisory_lock(1)",
        "SELECT * FROM pg_authid",
        "SET work_mem='1GB'",
    ];
    for sql in statements {
        let result =
            result_of(&call_tool(&router, "execute_query", json!({"sql": sql})).await).clone();
        assert!(is_error(&result), "{sql} was not rejected");
        assert!(
            text_of(&result).starts_with("Query rejected:"),
            "{sql}: {}",
            text_of(&result)
        );
    }
    let count = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"sql": "SELECT count(*) AS n FROM app.items"}),
    )
    .await;
    assert_eq!(structured(&count)["rows"][0]["n"], 5000);
}

#[tokio::test]
async fn db_errors_are_tool_errors() {
    let router = app(one_db(PORT_18, &[]));
    let divide =
        result_of(&call_tool(&router, "execute_query", json!({"sql": "SELECT 1/0"})).await).clone();
    assert!(is_error(&divide));
    assert!(text_of(&divide).contains("22012"), "{}", text_of(&divide));

    let missing = result_of(
        &call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT * FROM nope"}),
        )
        .await,
    )
    .clone();
    assert!(is_error(&missing));
    let text = text_of(&missing);
    assert!(text.contains("42P01"), "{text}");
    assert!(text.contains("Position"), "{text}");
}

#[tokio::test]
async fn timeout_is_reported() {
    let entry = json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": PORT_18,
        "database": DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "sslmode": "disable",
        "statement_timeout_ms": 300,
    });
    let router = app(config_with(&[entry], &[]));
    let started = std::time::Instant::now();
    let result = result_of(
        &call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT pg_sleep(5)"}),
        )
        .await,
    )
    .clone();
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    assert!(is_error(&result));
    assert!(
        text_of(&result).contains("time limit"),
        "{}",
        text_of(&result)
    );
}

#[tokio::test]
async fn unknown_database_is_tool_error() {
    let result = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"database": "nope", "sql": "SELECT 1"}),
    )
    .await;
    assert!(is_error(&result));
    assert!(
        text_of(&result).contains("unknown database \"nope\""),
        "{}",
        text_of(&result)
    );
}

#[tokio::test]
async fn database_optional_with_one_configured() {
    let result = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"sql": "SELECT 1 AS one"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    assert_eq!(structured(&result)["database"], DB_NAME);
}

#[tokio::test]
async fn database_required_with_two_configured() {
    let config = config_with(&[db_entry("pg18", PORT_18), db_entry("pg19", PORT_19)], &[]);
    let result = tool(config, "execute_query", json!({"sql": "SELECT 1"})).await;
    assert!(is_error(&result));
    assert!(
        text_of(&result).contains("'database' is required"),
        "{}",
        text_of(&result)
    );
}

#[tokio::test]
async fn show_all_hides_secret_settings() {
    let result = tool(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"sql": "SHOW ALL"}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let rows = structured(&result)["rows"]
        .as_array()
        .expect("rows")
        .clone();
    let names: Vec<&str> = rows.iter().filter_map(|r| r["name"].as_str()).collect();
    assert!(names.contains(&"work_mem"), "work_mem missing");
    for secret in SECRET_SETTINGS {
        assert!(!names.contains(secret), "{secret} leaked");
    }
}

#[tokio::test]
async fn explain_text_and_json() {
    let router = app(one_db(PORT_18, &[]));
    let json_plan = result_of(
        &call_tool(
            &router,
            "explain_query",
            json!({"sql": "SELECT * FROM app.items WHERE id < 10", "format": "json"}),
        )
        .await,
    )
    .clone();
    assert!(!is_error(&json_plan), "{}", text_of(&json_plan));
    let plan = &structured(&json_plan)["plan"];
    assert!(plan.is_array(), "{plan}");
    assert!(plan[0]["Plan"].is_object(), "{plan}");
    assert_eq!(structured(&json_plan)["format"], "json");

    let text_plan = result_of(
        &call_tool(
            &router,
            "explain_query",
            json!({"sql": "SELECT * FROM app.items WHERE id < 10"}),
        )
        .await,
    )
    .clone();
    assert!(!is_error(&text_plan), "{}", text_of(&text_plan));
    let plan = structured(&text_plan)["plan"].as_str().expect("text plan");
    assert!(plan.contains("Scan"), "{plan}");
}

#[tokio::test]
async fn explain_analyze_runs() {
    let result = tool(
        one_db(PORT_18, &[]),
        "explain_query",
        json!({"sql": "SELECT count(*) FROM app.items", "analyze": true}),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let plan = structured(&result)["plan"].as_str().expect("text plan");
    assert!(
        plan.contains("actual time") || plan.contains("Execution Time"),
        "{plan}"
    );
}

#[tokio::test]
async fn explain_rejects_writes() {
    let router = app(one_db(PORT_18, &[]));
    let result = result_of(
        &call_tool(
            &router,
            "explain_query",
            json!({"sql": "DELETE FROM app.items", "analyze": true}),
        )
        .await,
    )
    .clone();
    assert!(is_error(&result));
    assert!(
        text_of(&result).starts_with("Query rejected:"),
        "{}",
        text_of(&result)
    );
    let count = result_of(
        &call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT count(*) AS n FROM app.items"}),
        )
        .await,
    )
    .clone();
    assert_eq!(structured(&count)["rows"][0]["n"], 5000);
}

#[tokio::test]
async fn explain_requires_a_select_kind() {
    let result = tool(
        one_db(PORT_18, &[]),
        "explain_query",
        json!({"sql": "SHOW work_mem"}),
    )
    .await;
    assert!(is_error(&result));
    assert_eq!(
        text_of(&result),
        "Query rejected: explain_query takes a SELECT, WITH, VALUES or TABLE statement."
    );
}

#[tokio::test]
async fn explain_option_combinations_are_rejected() {
    let router = app(one_db(PORT_18, &[]));
    let cases = [
        (
            json!({"sql": "SELECT 1", "generic_plan": true, "analyze": true}),
            "generic_plan cannot be combined with analyze.",
        ),
        (
            json!({"sql": "SELECT 1", "wal": true}),
            "Option wal requires analyze=true.",
        ),
        (
            json!({"sql": "SELECT 1", "serialize": true}),
            "Option serialize requires analyze=true.",
        ),
    ];
    for (arguments, expected) in cases {
        let result = result_of(&call_tool(&router, "explain_query", arguments).await).clone();
        assert!(is_error(&result), "{expected}");
        assert_eq!(text_of(&result), expected);
    }
}

#[tokio::test]
async fn explain_option_version_gate() {
    let result = tool(
        one_db(PORT_15, &[]),
        "explain_query",
        json!({"sql": "SELECT 1", "memory": true}),
    )
    .await;
    assert!(is_error(&result));
    let text = text_of(&result);
    assert!(text.contains("PostgreSQL 17"), "{text}");
    assert!(text.contains("memory"), "{text}");
}

#[tokio::test]
async fn explain_generic_plan_returns_a_plan_with_the_placeholder() {
    for port in [PORT_18, PORT_19] {
        let result = tool(
            one_db(port, &[]),
            "explain_query",
            json!({"sql": "SELECT * FROM app.items WHERE id = $1", "generic_plan": true}),
        )
        .await;
        assert!(!is_error(&result), "port {port}: {}", text_of(&result));
        let plan = structured(&result)["plan"].as_str().unwrap_or_default();
        assert!(plan.contains("$1"), "port {port}: {plan}");
        assert!(plan.contains("Scan"), "port {port}: {plan}");
    }
}

#[tokio::test]
async fn explain_generic_plan_json_format_has_the_placeholder() {
    let result = tool(
        one_db(PORT_18, &[]),
        "explain_query",
        json!({
            "sql": "SELECT * FROM app.items WHERE id = $1 AND qty > $2",
            "generic_plan": true,
            "format": "json",
        }),
    )
    .await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let plan = &structured(&result)["plan"][0]["Plan"];
    let node = plan["Node Type"].as_str().unwrap_or_default();
    assert!(node.contains("Scan"), "{plan}");
    let condition = plan.to_string();
    assert!(
        condition.contains("$1") && condition.contains("$2"),
        "{plan}"
    );
}

#[tokio::test]
async fn explain_generic_plan_is_version_gated_on_pg15() {
    let result = tool(
        one_db(PORT_15, &[]),
        "explain_query",
        json!({"sql": "SELECT * FROM app.items WHERE id = $1", "generic_plan": true}),
    )
    .await;
    assert!(is_error(&result), "{result}");
    assert!(
        text_of(&result).starts_with(
            "Option generic_plan needs PostgreSQL 16 or newer; this server is PostgreSQL 15."
        ),
        "{}",
        text_of(&result)
    );
}

#[tokio::test]
async fn explain_placeholder_still_needs_generic_plan() {
    let result = tool(
        one_db(PORT_18, &[]),
        "explain_query",
        json!({"sql": "SELECT * FROM app.items WHERE id = $1"}),
    )
    .await;
    assert!(is_error(&result), "{result}");
    assert_eq!(
        text_of(&result),
        "Query rejected: Parameter placeholders ($1) are not supported. Inline the value."
    );
    let analyzed = tool(
        one_db(PORT_18, &[]),
        "explain_query",
        json!({"sql": "SELECT * FROM app.items WHERE id = $1", "generic_plan": true, "analyze": true}),
    )
    .await;
    assert!(is_error(&analyzed), "{analyzed}");
    assert_eq!(
        text_of(&analyzed),
        "generic_plan cannot be combined with analyze."
    );
}

#[tokio::test]
async fn list_databases_reports_all() {
    let config = config_with(
        &[
            db_entry("pg18", PORT_18),
            db_entry("pg19", PORT_19),
            db_entry("pg15", PORT_15),
            db_entry("dead", 15999),
        ],
        &[],
    );
    let result = tool(config, "list_databases", json!({})).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let databases = structured(&result)["databases"]
        .as_array()
        .expect("databases")
        .clone();
    assert_eq!(databases.len(), 4);
    let reachable: Vec<&Value> = databases
        .iter()
        .filter(|d| d["reachable"] == true)
        .collect();
    assert!(reachable.len() >= 2, "{databases:?}");
    for db in &reachable {
        let num = db["serverVersionNum"].as_u64().expect("version num");
        assert!([15, 18, 19].contains(&(num / 10_000)), "{db}");
    }
    for (name, port) in [("pg18", PORT_18), ("pg19", PORT_19), ("pg15", PORT_15)] {
        let db = databases
            .iter()
            .find(|d| d["name"] == name)
            .unwrap_or_else(|| panic!("{name} listed"));
        assert_eq!(db["reachable"], true, "{db}");
        // Expected value: what the server reports for pg_extension, read without the tool layer.
        let expected = installed_timescaledb(port).await;
        match expected {
            Some(version) => assert_eq!(db["timescaledb"], json!(version), "{db}"),
            None => assert!(db["timescaledb"].is_null(), "{db}"),
        }
    }
    let dead = databases
        .iter()
        .find(|d| d["name"] == "dead")
        .expect("dead listed");
    assert_eq!(dead["reachable"], false);
    assert!(dead["error"].is_string());
    let serialized = serde_json::to_string(structured(&result)).expect("serializes");
    for secret in ["test-only-ro", "15432", "mcp_ro"] {
        assert!(!serialized.contains(secret), "{secret} in {serialized}");
    }
}

#[tokio::test]
async fn server_info_shape() {
    let result = tool(one_db(PORT_18, &[]), "server_info", json!({})).await;
    assert!(!is_error(&result), "{}", text_of(&result));
    let info = structured(&result);
    assert_eq!(info["role"]["name"], DB_USER);
    assert_eq!(info["role"]["superuser"], false);
    let members: Vec<&str> = info["role"]["memberOf"]
        .as_array()
        .expect("memberOf")
        .iter()
        .filter_map(|m| m.as_str())
        .collect();
    assert!(members.contains(&"pg_read_all_data"), "{members:?}");
    assert!(members.contains(&"pg_monitor"), "{members:?}");
    let extensions: Vec<&str> = info["extensions"]
        .as_array()
        .expect("extensions")
        .iter()
        .filter_map(|e| e["name"].as_str())
        .collect();
    assert!(extensions.contains(&"plpgsql"), "{extensions:?}");
    let settings = info["settings"].as_array().expect("settings");
    let find = |name: &str| {
        settings
            .iter()
            .find(|s| s["name"] == name)
            .and_then(|s| s["value"].as_str())
            .map(str::to_owned)
    };
    assert_eq!(find("TimeZone").as_deref(), Some("UTC"));
    assert_eq!(find("default_transaction_read_only").as_deref(), Some("on"));
    assert_eq!(info["warnings"], json!([]));
}

#[test]
fn server_info_settings_hide_secrets() {
    for secret in SECRET_SETTINGS {
        assert!(
            !SERVER_INFO_SETTINGS.contains(secret),
            "{secret} is in the server_info settings"
        );
    }
}

#[tokio::test]
async fn api_key_required() {
    let router = app(one_db(PORT_18, &[("API_KEY", API_KEY)]));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let headers = [("mcp-protocol-version", PROTOCOL_2025)];

    let missing = post_mcp(&router, &body, &headers).await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing
            .headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Bearer")
    );

    let mut wrong_headers = headers.to_vec();
    wrong_headers.push(("x-api-key", "wrong-api-key-000000"));
    assert_eq!(
        post_mcp(&router, &body, &wrong_headers).await.status,
        StatusCode::UNAUTHORIZED
    );

    let mut x_key = headers.to_vec();
    x_key.push(("x-api-key", API_KEY));
    assert_eq!(
        post_mcp(&router, &body, &x_key).await.status,
        StatusCode::OK
    );

    let bearer_value = format!("Bearer {API_KEY}");
    let mut bearer = headers.to_vec();
    bearer.push(("authorization", bearer_value.as_str()));
    assert_eq!(
        post_mcp(&router, &body, &bearer).await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn origin_checked() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let headers = [("mcp-protocol-version", PROTOCOL_2025)];

    let evil = app(one_db(PORT_18, &[]));
    let mut evil_headers = headers.to_vec();
    evil_headers.push(("origin", "http://evil.example.com"));
    assert_eq!(
        post_mcp(&evil, &body, &evil_headers).await.status,
        StatusCode::FORBIDDEN
    );

    let mut loopback = headers.to_vec();
    loopback.push(("origin", "http://localhost:5173"));
    let loopback_reply = post_mcp(&evil, &body, &loopback).await;
    assert_eq!(loopback_reply.status, StatusCode::OK);
    assert!(
        loopback_reply
            .headers
            .get("access-control-allow-origin")
            .is_none()
    );

    let allowed = app(one_db(
        PORT_18,
        &[("ALLOWED_ORIGINS", "https://app.example.com")],
    ));
    let mut allowed_headers = headers.to_vec();
    allowed_headers.push(("origin", "https://app.example.com"));
    let reply = post_mcp(&allowed, &body, &allowed_headers).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply
            .headers
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.example.com")
    );
}

#[tokio::test]
async fn host_header_checked() {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let router = app(one_db(PORT_18, &[]));

    let evil = post_mcp(
        &router,
        &body,
        &[
            ("mcp-protocol-version", PROTOCOL_2025),
            ("host", "evil.example.com"),
        ],
    )
    .await;
    assert!(evil.status.is_client_error(), "{}", evil.status);

    let ok = post_mcp(
        &router,
        &body,
        &[
            ("mcp-protocol-version", PROTOCOL_2025),
            ("host", "localhost:8432"),
        ],
    )
    .await;
    assert_eq!(ok.status, StatusCode::OK, "{}", ok.text());
}

#[tokio::test]
async fn oversized_body_rejected() {
    let router = app(one_db(PORT_18, &[("MAX_REQUEST_BYTES", "2048")]));
    let padding = "x".repeat(10 * 1024);
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": padding}}});
    let encoded = body.to_string();
    let length = encoded.len().to_string();
    let reply = post_mcp(
        &router,
        &body,
        &[
            ("mcp-protocol-version", PROTOCOL_2025),
            ("content-length", length.as_str()),
        ],
    )
    .await;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn unknown_path_404() {
    let router = app(one_db(PORT_18, &[]));
    let reply = send(
        &router,
        axum::http::Request::builder()
            .uri("/nope")
            .body(axum::body::Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_on_mcp_does_not_open_stream_or_hang() {
    let router = app(one_db(PORT_18, &[]));
    let request = axum::http::Request::builder()
        .method("GET")
        .uri("/mcp")
        .header("accept", "text/event-stream")
        .body(axum::body::Body::empty())
        .expect("request");
    let reply = tokio::time::timeout(Duration::from_secs(2), send(&router, request))
        .await
        .expect("GET /mcp completes within 2 s");
    assert!(
        reply.status.is_client_error() || reply.body.is_empty(),
        "{}",
        reply.status
    );
}

#[tokio::test]
async fn error_messages_do_not_leak() {
    let entry = json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": PORT_18,
        "database": DB_NAME,
        "user": DB_USER,
        "password": "sekret-wrong-pw",
        "sslmode": "disable",
    });
    let result = tool(
        config_with(&[entry], &[]),
        "execute_query",
        json!({"sql": "SELECT 1"}),
    )
    .await;
    assert!(is_error(&result));
    let text = text_of(&result);
    assert!(text.contains("is unavailable"), "{text}");
    assert!(!text.contains("sekret-wrong-pw"), "{text}");
}

#[tokio::test]
async fn concurrent_calls() {
    let router = app(config_with(
        &[db_entry("appdb", PORT_18)],
        &[("MAX_CONCURRENT_REQUESTS", "32")],
    ));
    let mut set = tokio::task::JoinSet::new();
    for n in 0..20 {
        let router = router.clone();
        set.spawn(async move {
            let response = call_tool(
                &router,
                "execute_query",
                json!({"sql": format!("SELECT {n} AS n, pg_sleep(0.05)")}),
            )
            .await;
            (n, response)
        });
    }
    let mut seen = Vec::new();
    while let Some(joined) = set.join_next().await {
        let (n, response) = joined.expect("task completes");
        let result = result_of(&response);
        assert!(!is_error(result), "{}", text_of(result));
        assert_eq!(structured(result)["rows"][0]["n"], n);
        seen.push(n);
    }
    assert_eq!(seen.len(), 20);
}

/// Serves the router on a loopback port and POSTs the body with Transfer-Encoding: chunked and no
/// Content-Length. Returns the status code and the raw response text.
async fn post_chunked(router: axum::Router, body: &str, piece: usize) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback port");
    let port = listener.local_addr().expect("local address").port();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to the test server");
    let head = format!(
        "POST /mcp HTTP/1.1\r\nHost: localhost:8432\r\nContent-Type: application/json\r\n\
         Accept: application/json, text/event-stream\r\nMCP-Protocol-Version: {PROTOCOL_2025}\r\n\
         Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    );
    let mut request = head.into_bytes();
    for part in body.as_bytes().chunks(piece) {
        request.extend_from_slice(format!("{:x}\r\n", part.len()).as_bytes());
        request.extend_from_slice(part);
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"0\r\n\r\n");
    stream.write_all(&request).await.expect("send the request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read the response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_default();
    (status, text)
}

#[tokio::test]
async fn chunked_body_over_the_limit_gets_413() {
    let router = app(one_db(PORT_18, &[("MAX_REQUEST_BYTES", "2048")]));
    let padding = "x".repeat(10 * 1024);
    let body =
        json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {"pad": padding}});
    let (status, text) = post_chunked(router, &body.to_string(), 512).await;
    assert_eq!(status, 413, "{text}");
    assert!(
        text.contains(
            r#"{"error":"payload_too_large","message":"Request body exceeds 2048 bytes."}"#
        ),
        "{text}"
    );
}

#[tokio::test]
async fn chunked_body_under_the_limit_still_works() {
    let router = app(one_db(PORT_18, &[("MAX_REQUEST_BYTES", "2048")]));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let (status, text) = post_chunked(router, &body.to_string(), 7).await;
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("\"name\":\"execute_query\""), "{text}");
}
