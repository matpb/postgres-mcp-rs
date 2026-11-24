//! Integration tests for MCP resources, resource templates and completions over HTTP, against the test databases.

mod common;

use axum::Router;
use common::{
    PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with, db_entry, one_db, post_mcp,
    result_of,
};
use postgres_mcp::config::Config;
use serde_json::{Value, json};

const DATABASE_DESCRIPTION: &str = "Summary of this database: PostgreSQL version, TimescaleDB version when installed, schemas with their object counts, and installed extensions.";
const SCHEMA_DESCRIPTION: &str = "Tables, views, materialized views, sequences and functions of one schema, with comments, estimated rows and sizes. Same content as the list_objects tool.";
const TABLE_DESCRIPTION: &str = "Full definition of one table or view: columns, keys, indexes, policies and statistics. Same content as the describe_table tool.";
const UNKNOWN_URI: &str = "Unknown resource URI. Use postgres://<database>, postgres://<database>/<schema> or postgres://<database>/<schema>/<table>.";
const SCHEMA_TEMPLATE: &str = "postgres://{database}/{schema}";
const TABLE_TEMPLATE: &str = "postgres://{database}/{schema}/{table}";
const RESOURCE_NOT_FOUND: i64 = -32002;
const INTERNAL_ERROR: i64 = -32603;
const METHOD_NOT_FOUND: i64 = -32601;

fn initialize_body() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_2025,
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0.0.0"},
        },
    })
}

/// One JSON-RPC request over HTTP, as the full response object.
async fn rpc(app: &Router, method: &str, params: Value) -> Value {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    post_mcp(app, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
        .await
        .json()
}

/// Reads one resource and parses its single text content, checking the URI and mime type echoed back.
async fn read_json(app: &Router, uri: &str) -> Value {
    let response = rpc(app, "resources/read", json!({"uri": uri})).await;
    let contents = result_of(&response)["contents"]
        .as_array()
        .unwrap_or_else(|| panic!("no contents in {response}"))
        .clone();
    assert_eq!(contents.len(), 1, "{response}");
    assert_eq!(contents[0]["uri"], uri);
    assert_eq!(contents[0]["mimeType"], "application/json");
    let text = contents[0]["text"].as_str().expect("text content");
    serde_json::from_str(text).expect("text content is JSON")
}

/// The (code, message) of a JSON-RPC error response.
fn error_of(response: &Value) -> (i64, String) {
    let error = response
        .get("error")
        .unwrap_or_else(|| panic!("no error in {response}"));
    (
        error["code"].as_i64().expect("error code"),
        error["message"].as_str().expect("error message").to_owned(),
    )
}

/// A tool call's structured content, or its error text when the tool reported isError.
async fn tool_outcome(config: Config, name: &str, arguments: Value) -> Result<Value, String> {
    let response = call_tool(&app(config), name, arguments).await;
    let result = result_of(&response).clone();
    if result.get("isError") == Some(&json!(true)) {
        Err(result["content"][0]["text"]
            .as_str()
            .expect("error text")
            .to_owned())
    } else {
        Ok(result["structuredContent"].clone())
    }
}

/// A completion request for one argument of a template; the `completion` member of the result.
async fn complete(
    app: &Router,
    template: &str,
    name: &str,
    value: &str,
    context: Option<Value>,
) -> Value {
    let mut params = json!({
        "ref": {"type": "ref/resource", "uri": template},
        "argument": {"name": name, "value": value},
    });
    if let Some(context) = context {
        params["context"] = context;
    }
    let response = rpc(app, "completion/complete", params).await;
    result_of(&response)["completion"].clone()
}

fn shop_context() -> Value {
    json!({"arguments": {"database": "appdb", "schema": "shop"}})
}

#[tokio::test]
async fn capabilities_advertise_resources_and_completions() {
    let reply = post_mcp(
        &app(one_db(PORT_18, &[])),
        &initialize_body(),
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await;
    let body = reply.json();
    let capabilities = &result_of(&body)["capabilities"];
    assert_eq!(capabilities["resources"], json!({}), "{body}");
    assert_eq!(capabilities["completions"], json!({}), "{body}");
    assert!(capabilities["tools"].is_object(), "{body}");
}

#[tokio::test]
async fn core_toolset_advertises_neither_and_refuses_the_methods() {
    let router = app(one_db(PORT_18, &[("TOOLSETS", "core")]));
    let reply = post_mcp(
        &router,
        &initialize_body(),
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await;
    let body = reply.json();
    let capabilities = &result_of(&body)["capabilities"];
    assert!(capabilities.get("resources").is_none(), "{body}");
    assert!(capabilities.get("completions").is_none(), "{body}");

    let refused = [
        ("resources/list", json!({})),
        ("resources/templates/list", json!({})),
        ("resources/read", json!({"uri": "postgres://appdb"})),
        (
            "completion/complete",
            json!({"ref": {"type": "ref/resource", "uri": SCHEMA_TEMPLATE}, "argument": {"name": "database", "value": ""}}),
        ),
    ];
    for (method, params) in refused {
        let response = rpc(&router, method, params).await;
        assert_eq!(
            error_of(&response),
            (METHOD_NOT_FOUND, method.to_owned()),
            "{method}"
        );
    }
}

#[tokio::test]
async fn list_has_one_resource_per_database_in_configuration_order() {
    let router = app(config_with(
        &[db_entry("warehouse", PORT_19), db_entry("appdb", PORT_18)],
        &[],
    ));
    let response = rpc(&router, "resources/list", json!({})).await;
    assert_eq!(
        result_of(&response)["resources"],
        json!([
            {
                "uri": "postgres://warehouse",
                "name": "warehouse",
                "title": "Database warehouse",
                "mimeType": "application/json",
                "description": DATABASE_DESCRIPTION,
            },
            {
                "uri": "postgres://appdb",
                "name": "appdb",
                "title": "Database appdb",
                "mimeType": "application/json",
                "description": DATABASE_DESCRIPTION,
            },
        ]),
        "{response}"
    );
}

#[tokio::test]
async fn templates_list_is_exact() {
    let router = app(one_db(PORT_18, &[]));
    let response = rpc(&router, "resources/templates/list", json!({})).await;
    assert_eq!(
        result_of(&response)["resourceTemplates"],
        json!([
            {
                "uriTemplate": "postgres://{database}/{schema}",
                "name": "schema",
                "title": "Schema",
                "mimeType": "application/json",
                "description": SCHEMA_DESCRIPTION,
            },
            {
                "uriTemplate": "postgres://{database}/{schema}/{table}",
                "name": "table",
                "title": "Table or view",
                "mimeType": "application/json",
                "description": TABLE_DESCRIPTION,
            },
        ]),
        "{response}"
    );
}

#[tokio::test]
async fn database_summary_reports_version_schemas_and_extensions() {
    let router = app(one_db(PORT_18, &[]));
    let summary = read_json(&router, "postgres://appdb").await;
    assert_eq!(summary["database"], "appdb", "{summary}");
    let number = summary["serverVersionNum"]
        .as_u64()
        .expect("version number");
    assert_eq!(number / 10_000, 18, "{summary}");
    assert!(
        summary["serverVersion"]
            .as_str()
            .is_some_and(|v| v.starts_with("18.")),
        "{summary}"
    );

    let schemas = summary["schemas"].as_array().expect("schemas array");
    assert!(schemas.iter().any(|s| s["name"] == "shop"), "{summary}");
    let listed = tool_outcome(
        one_db(PORT_18, &[]),
        "list_schemas",
        json!({"database": "appdb"}),
    )
    .await
    .expect("list_schemas succeeds");
    assert_eq!(summary["schemas"], listed["schemas"]);

    let extensions = summary["extensions"].as_array().expect("extensions array");
    assert!(
        extensions
            .iter()
            .any(|e| e["name"] == "plpgsql" && e["schema"] == "pg_catalog"),
        "{summary}"
    );
    let info = tool_outcome(
        one_db(PORT_18, &[]),
        "server_info",
        json!({"database": "appdb"}),
    )
    .await
    .expect("server_info succeeds");
    assert_eq!(summary["timescaledb"], info["timescaledb"], "{summary}");
    assert!(summary["timescaledb"].is_string(), "{summary}");
}

#[tokio::test]
async fn schema_resource_is_the_list_objects_tool_result() {
    let router = app(one_db(PORT_18, &[]));
    let listing = read_json(&router, "postgres://appdb/shop").await;
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"database": "appdb", "schema": "shop"}),
    )
    .await
    .expect("list_objects succeeds");
    assert_eq!(listing, tool);
    assert!(
        listing["objects"]
            .as_array()
            .expect("objects")
            .iter()
            .any(|o| o["name"] == "orders"),
        "{listing}"
    );
}

#[tokio::test]
async fn schema_resource_keeps_the_next_cursor_of_a_long_listing() {
    let router = app(one_db(PORT_18, &[]));
    let listing = read_json(&router, "postgres://appdb/shop_parts").await;
    assert_eq!(listing["objects"].as_array().expect("objects").len(), 100);
    assert_eq!(listing["nextCursor"], "o:100", "{listing}");
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"database": "appdb", "schema": "shop_parts"}),
    )
    .await
    .expect("list_objects succeeds");
    assert_eq!(listing, tool);
}

#[tokio::test]
async fn table_resource_is_the_describe_table_tool_result() {
    let router = app(one_db(PORT_18, &[]));
    let resource = read_json(&router, "postgres://appdb/shop/orders").await;
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "describe_table",
        json!({"database": "appdb", "table": "orders", "schema": "shop"}),
    )
    .await
    .expect("describe_table succeeds");
    assert_eq!(resource, tool);
    assert_eq!(resource["name"], "orders");
    assert_eq!(resource["schema"], "shop");
}

#[tokio::test]
async fn names_with_dots_and_uppercase_resolve_bare_and_encoded() {
    let router = app(one_db(PORT_18, &[]));
    let bare = read_json(&router, "postgres://appdb/shop/Odd.Name").await;
    let encoded = read_json(&router, "postgres://appdb/shop/Odd%2EName").await;
    assert_eq!(bare, encoded);
    assert_eq!(bare["name"], "Odd.Name", "{bare}");
    assert_eq!(bare["columns"][0]["name"], "Select", "{bare}");
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "describe_table",
        json!({"database": "appdb", "table": "Odd.Name", "schema": "shop"}),
    )
    .await
    .expect("describe_table succeeds");
    assert_eq!(bare, tool);
}

#[tokio::test]
async fn an_encoded_slash_is_part_of_the_name() {
    let router = app(one_db(PORT_18, &[]));
    let response = rpc(
        &router,
        "resources/read",
        json!({"uri": "postgres://appdb/shop/a%2Fb"}),
    )
    .await;
    assert_eq!(
        error_of(&response),
        (RESOURCE_NOT_FOUND, "Table \"a/b\" not found.".to_owned()),
        "{response}"
    );
}

#[tokio::test]
async fn low_privilege_role_gets_the_tool_outcome() {
    let entry = json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": PORT_18,
        "database": "appdb",
        "user": "mcp_min",
        "password": "test-only-min",
        "sslmode": "disable",
        "max_connections": 1,
    });
    let router = app(config_with(std::slice::from_ref(&entry), &[]));
    let response = rpc(
        &router,
        "resources/read",
        json!({"uri": "postgres://appdb/shop/orders"}),
    )
    .await;
    let tool = tool_outcome(
        config_with(&[entry], &[]),
        "describe_table",
        json!({"database": "appdb", "table": "orders", "schema": "shop"}),
    )
    .await;
    match tool {
        Ok(value) => {
            let contents = result_of(&response)["contents"][0]["text"]
                .as_str()
                .expect("text content");
            assert_eq!(
                serde_json::from_str::<Value>(contents).expect("JSON"),
                value
            );
        }
        Err(text) => assert_eq!(error_of(&response).1, text, "{response}"),
    }
}

#[tokio::test]
async fn unknown_uri_shapes_are_resource_not_found() {
    let router = app(one_db(PORT_18, &[]));
    for uri in [
        "postgres://",
        "postgres://appdb/",
        "postgres:///shop",
        "postgres://appdb/shop/orders/extra",
        "postgres://appdb/shop?x=1",
        "postgres://appdb/shop#frag",
        "postgres://appdb/%zz",
        "http://appdb",
        "file:///etc/passwd",
    ] {
        let response = rpc(&router, "resources/read", json!({"uri": uri})).await;
        assert_eq!(
            error_of(&response),
            (RESOURCE_NOT_FOUND, UNKNOWN_URI.to_owned()),
            "{uri}"
        );
    }
}

#[tokio::test]
async fn unknown_database_uses_the_tool_text() {
    let router = app(one_db(PORT_18, &[]));
    let response = rpc(&router, "resources/read", json!({"uri": "postgres://nope"})).await;
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "execute_query",
        json!({"database": "nope", "sql": "SELECT 1"}),
    )
    .await
    .expect_err("unknown database is a tool error");
    assert_eq!(
        error_of(&response),
        (RESOURCE_NOT_FOUND, tool.clone()),
        "{response}"
    );
    assert_eq!(
        tool,
        "unknown database \"nope\": configured databases are appdb"
    );
}

#[tokio::test]
async fn unknown_schema_listing_is_the_tool_result() {
    let router = app(one_db(PORT_18, &[]));
    let listing = read_json(&router, "postgres://appdb/nosuch").await;
    let tool = tool_outcome(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"database": "appdb", "schema": "nosuch"}),
    )
    .await
    .expect("list_objects succeeds");
    assert_eq!(listing, tool);
    assert_eq!(listing["objects"], json!([]));
}

#[tokio::test]
async fn unknown_table_uses_the_tool_text() {
    let router = app(one_db(PORT_18, &[]));
    let response = rpc(
        &router,
        "resources/read",
        json!({"uri": "postgres://appdb/shop/nosuch"}),
    )
    .await;
    assert_eq!(
        error_of(&response),
        (RESOURCE_NOT_FOUND, "Table \"nosuch\" not found.".to_owned()),
        "{response}"
    );
}

#[tokio::test]
async fn database_failure_returns_the_short_text_without_secrets() {
    let router = app(config_with(&[db_entry("down", 15999)], &[]));
    let response = rpc(&router, "resources/read", json!({"uri": "postgres://down"})).await;
    let (code, message) = error_of(&response);
    assert_eq!(code, INTERNAL_ERROR, "{response}");
    assert!(
        message.starts_with("Database \"down\" is unavailable: "),
        "{message}"
    );
    assert!(!message.contains("test-only"), "{message}");
    let tool = tool_outcome(
        config_with(&[db_entry("down", 15999)], &[]),
        "server_info",
        json!({"database": "down"}),
    )
    .await
    .expect_err("unreachable database is a tool error");
    assert_eq!(message, tool);
}

#[tokio::test]
async fn database_completion_matches_prefix_case_insensitively() {
    let router = app(config_with(
        &[
            db_entry("warehouse", PORT_19),
            db_entry("appdb", PORT_18),
            db_entry("app_archive", PORT_19),
        ],
        &[],
    ));
    let completion = complete(&router, SCHEMA_TEMPLATE, "database", "APP", None).await;
    assert_eq!(completion["values"], json!(["app_archive", "appdb"]));
    assert!(completion.get("total").is_none(), "{completion}");
    assert!(completion.get("hasMore").is_none(), "{completion}");
}

#[tokio::test]
async fn schema_completion_uses_the_context_database_and_prefix() {
    let router = app(one_db(PORT_18, &[]));
    let with_context = complete(
        &router,
        SCHEMA_TEMPLATE,
        "schema",
        "sh",
        Some(json!({"arguments": {"database": "appdb"}})),
    )
    .await;
    assert_eq!(with_context["values"], json!(["shop", "shop_parts"]));
    let without_context = complete(&router, SCHEMA_TEMPLATE, "schema", "sh", None).await;
    assert_eq!(without_context["values"], json!(["shop", "shop_parts"]));
}

#[tokio::test]
async fn system_schemas_appear_only_for_a_pg_or_information_schema_prefix() {
    let router = app(one_db(PORT_18, &[]));
    let plain = complete(&router, SCHEMA_TEMPLATE, "schema", "", None).await;
    let values: Vec<&str> = plain["values"]
        .as_array()
        .expect("values")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(values.contains(&"shop"), "{values:?}");
    assert!(!values.contains(&"pg_catalog"), "{values:?}");
    assert!(!values.contains(&"information_schema"), "{values:?}");

    let pg = complete(&router, SCHEMA_TEMPLATE, "schema", "pg_", None).await;
    assert!(
        pg["values"]
            .as_array()
            .expect("values")
            .contains(&json!("pg_catalog")),
        "{pg}"
    );
}

#[tokio::test]
async fn table_completion_lists_tables_and_views_of_the_context_schema() {
    let router = app(one_db(PORT_18, &[]));
    let completion = complete(
        &router,
        TABLE_TEMPLATE,
        "table",
        "ord",
        Some(shop_context()),
    )
    .await;
    assert_eq!(completion["values"], json!(["order_items", "orders"]));
    assert!(completion.get("total").is_none(), "{completion}");
}

#[tokio::test]
async fn table_completion_cuts_at_one_hundred_values_and_reports_the_total() {
    let router = app(one_db(PORT_18, &[]));
    let context = json!({"arguments": {"database": "appdb", "schema": "shop_parts"}});
    let completion = complete(&router, TABLE_TEMPLATE, "table", "", Some(context)).await;
    let mut expected: Vec<String> = (0..=200).map(|i| format!("many_parts_{i}")).collect();
    expected.sort();
    expected.truncate(100);
    assert_eq!(completion["values"], json!(expected));
    assert_eq!(completion["total"], 201, "{completion}");
    assert_eq!(completion["hasMore"], true, "{completion}");
}

#[tokio::test]
async fn wildcards_in_the_prefix_match_nothing() {
    let router = app(one_db(PORT_18, &[]));
    let schemas = complete(&router, SCHEMA_TEMPLATE, "schema", "%", None).await;
    assert_eq!(schemas["values"], json!([]), "{schemas}");
    let tables = complete(&router, TABLE_TEMPLATE, "table", "%", Some(shop_context())).await;
    assert_eq!(tables["values"], json!([]), "{tables}");
    let underscore = complete(&router, TABLE_TEMPLATE, "table", "_", Some(shop_context())).await;
    assert_eq!(underscore["values"], json!([]), "{underscore}");
}

#[tokio::test]
async fn table_completion_without_a_schema_is_empty() {
    let router = app(one_db(PORT_18, &[]));
    let no_context = complete(&router, TABLE_TEMPLATE, "table", "ord", None).await;
    assert_eq!(no_context["values"], json!([]), "{no_context}");
    let no_schema = complete(
        &router,
        TABLE_TEMPLATE,
        "table",
        "ord",
        Some(json!({"arguments": {"database": "appdb"}})),
    )
    .await;
    assert_eq!(no_schema["values"], json!([]), "{no_schema}");
}

#[tokio::test]
async fn other_refs_and_arguments_complete_to_nothing() {
    let router = app(one_db(PORT_18, &[]));
    let table_argument_on_schema = complete(
        &router,
        SCHEMA_TEMPLATE,
        "table",
        "ord",
        Some(shop_context()),
    )
    .await;
    assert_eq!(table_argument_on_schema["values"], json!([]));
    let unknown_template = complete(&router, "postgres://{database}", "database", "a", None).await;
    assert_eq!(unknown_template["values"], json!([]));
    let unknown_argument = complete(&router, SCHEMA_TEMPLATE, "view", "o", None).await;
    assert_eq!(unknown_argument["values"], json!([]));
}

#[tokio::test]
async fn database_error_completes_to_nothing() {
    let router = app(config_with(&[db_entry("down", 15999)], &[]));
    let completion = complete(
        &router,
        SCHEMA_TEMPLATE,
        "schema",
        "sh",
        Some(json!({"arguments": {"database": "down"}})),
    )
    .await;
    assert_eq!(completion["values"], json!([]), "{completion}");
}
