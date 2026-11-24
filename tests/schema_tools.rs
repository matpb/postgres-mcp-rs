//! Integration tests for the schema toolset: catalog introspection against the seed databases, through the HTTP router.

mod common;

use axum::Router;
use common::{
    DB_NAME, PORT_15, PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with, one_db,
    post_mcp, result_of,
};
use postgres_mcp::config::Config;
use serde_json::{Value, json};

const STRICT_USER: &str = "mcp_strict";
const STRICT_PASSWORD: &str = "test-only-strict";
const SUPER_USER: &str = "postgres";
const SUPER_PASSWORD: &str = "test-only-superuser";
const SECRETS: [&str; 3] = ["test-only-superuser", "test-only-ro", "test-only-strict"];

/// One database entry for a given login, named appdb.
fn login(port: u16, user: &str, password: &str) -> Value {
    json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": port,
        "database": DB_NAME,
        "user": user,
        "password": password,
        "sslmode": "disable",
    })
}

fn config_as(port: u16, user: &str, password: &str) -> Config {
    config_with(&[login(port, user, password)], &[])
}

/// The result object of one tool call through a router.
async fn call_on(router: &Router, name: &str, arguments: Value) -> Value {
    result_of(&call_tool(router, name, arguments).await).clone()
}

async fn call(config: Config, name: &str, arguments: Value) -> Value {
    call_on(&app(config), name, arguments).await
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
        .expect("result has a text block")
        .to_owned()
}

/// The structured content of a successful call; a tool error fails the test with its text.
fn ok(result: &Value) -> &Value {
    assert!(!is_error(result), "tool error: {}", text_of(result));
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent in {result}"))
}

/// The text of a tool error, which must be one.
fn error_text(result: &Value) -> String {
    assert!(is_error(result), "expected a tool error, got {result}");
    text_of(result)
}

fn names_of(items: &[Value]) -> Vec<String> {
    items
        .iter()
        .filter_map(|item| item["name"].as_str().map(str::to_owned))
        .collect()
}

/// The entry of `items` whose `key` is `value`.
fn find<'a>(items: &'a [Value], key: &str, value: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item[key] == value)
        .unwrap_or_else(|| panic!("no entry with {key} = {value} in {items:?}"))
}

fn array<'a>(value: &'a Value, what: &str) -> &'a Vec<Value> {
    value
        .as_array()
        .unwrap_or_else(|| panic!("{what} is not an array: {value}"))
}

fn lists_objects(value: &Value) -> Vec<Value> {
    array(&value["objects"], "objects").clone()
}

/// Every object of a schema, read page by page with the given page size.
async fn walk_objects(router: &Router, arguments: Value, limit: u64) -> Vec<Value> {
    let mut collected = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = arguments.clone();
        args["limit"] = json!(limit);
        if let Some(next) = &cursor {
            args["cursor"] = json!(next);
        }
        let page = ok(&call_on(router, "list_objects", args).await).clone();
        collected.extend(lists_objects(&page));
        match page.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    collected
}

fn object_key(object: &Value) -> String {
    format!(
        "{}.{}.{}.{}",
        object["schema"].as_str().unwrap_or_default(),
        object["kind"].as_str().unwrap_or_default(),
        object["name"].as_str().unwrap_or_default(),
        object["arguments"].as_str().unwrap_or_default(),
    )
}

// ---------------------------------------------------------------- list_schemas

#[tokio::test]
async fn list_schemas_hides_system_schemas_by_default() {
    let result = call(one_db(PORT_18, &[]), "list_schemas", json!({})).await;
    let body = ok(&result).clone();
    assert_eq!(body["database"], "appdb");
    let schemas = array(&body["schemas"], "schemas").clone();
    let names = names_of(&schemas);
    for expected in ["app", "metrics", "pgmcp", "public", "shop", "types"] {
        assert!(names.contains(&expected.to_owned()), "{names:?}");
    }
    for hidden in [
        "pg_catalog",
        "information_schema",
        "_timescaledb_internal",
        "_timescaledb_catalog",
        "pg_toast",
    ] {
        assert!(!names.contains(&hidden.to_owned()), "{names:?}");
    }
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted, "ordered by name");
    let shop = find(&schemas, "name", "shop");
    // 11 original tables, shop.many_parts and shop."Odd.Name".
    assert_eq!(shop["tables"], 13, "{shop}");
    assert_eq!(shop["views"], 2, "{shop}");
    assert_eq!(shop["functions"], 7, "{shop}");
    assert_eq!(shop["owner"], "postgres", "{shop}");
}

#[tokio::test]
async fn list_schemas_include_system_adds_catalogs() {
    let result = call(
        one_db(PORT_18, &[]),
        "list_schemas",
        json!({"include_system": true}),
    )
    .await;
    let schemas = array(&ok(&result)["schemas"], "schemas").clone();
    let names = names_of(&schemas);
    assert!(names.contains(&"pg_catalog".to_owned()), "{names:?}");
    assert!(
        names.contains(&"information_schema".to_owned()),
        "{names:?}"
    );
}

#[tokio::test]
async fn list_schemas_as_strict_role_shows_only_usable_schemas() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(&router, "list_schemas", json!({})).await;
    let schemas = array(&ok(&result)["schemas"], "schemas").clone();
    let names = names_of(&schemas);
    for expected in ["app", "shop", "types", "public", "pgmcp"] {
        assert!(names.contains(&expected.to_owned()), "{names:?}");
    }
    assert!(!names.contains(&"sess_test".to_owned()), "{names:?}");
    let shop = find(&schemas, "name", "shop");
    assert_eq!(shop["tables"], 13, "counts do not depend on USAGE: {shop}");
}

// ---------------------------------------------------------------- list_objects

#[tokio::test]
async fn list_objects_default_kinds_in_shop() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "list_objects", json!({"schema": "shop"})).await;
    let objects = lists_objects(ok(&result));
    let kind_of = |name: &str| -> String {
        find(&objects, "name", name)["kind"]
            .as_str()
            .unwrap_or_default()
            .to_owned()
    };
    assert_eq!(kind_of("customers"), "table");
    assert!(
        find(&objects, "name", "customers")
            .get("rowEstimate")
            .is_some(),
        "rowEstimate is always present for tables"
    );
    assert_eq!(kind_of("events"), "partitioned_table");
    assert_eq!(kind_of("open_orders"), "view");
    assert_eq!(kind_of("customer_totals"), "materialized_view");
    assert_eq!(kind_of("items_remote"), "foreign_table");
    assert_eq!(kind_of("invoice_seq"), "sequence");
    let partition = find(&objects, "name", "events_2024_q1");
    assert_eq!(partition["isPartition"], true);
    assert_eq!(partition["partitionOf"], "shop.events");
    assert!(
        find(&objects, "name", "events")
            .get("isPartition")
            .is_none(),
        "isPartition only on partitions"
    );
    for object in &objects {
        let kind = object["kind"].as_str().unwrap_or_default();
        assert!(
            !["function", "procedure", "type"].contains(&kind),
            "default kinds exclude {kind}: {object}"
        );
    }
    let remote = find(&objects, "name", "items_remote");
    assert!(
        remote.get("rowEstimate").is_none(),
        "no estimate for foreign tables: {remote}"
    );
}

#[tokio::test]
async fn list_objects_functions_and_procedures_in_shop() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "list_objects",
        json!({"schema": "shop", "kinds": ["function", "procedure"]}),
    )
    .await;
    let objects = lists_objects(ok(&result));
    assert_eq!(objects.len(), 7, "{objects:?}");
    let order_total = find(&objects, "name", "order_total");
    assert_eq!(order_total["kind"], "function");
    assert_eq!(order_total["arguments"], "bigint");
    assert_eq!(order_total["returns"], "numeric");
    assert_eq!(
        order_total["comment"],
        "Sum of order totals for one customer"
    );
    let fmts: Vec<&Value> = objects.iter().filter(|o| o["name"] == "fmt").collect();
    let mut arguments: Vec<&str> = fmts
        .iter()
        .filter_map(|o| o["arguments"].as_str())
        .collect();
    arguments.sort_unstable();
    assert_eq!(arguments, vec!["integer", "text"]);
    let noop = find(&objects, "name", "noop");
    assert_eq!(noop["kind"], "procedure");
    assert!(noop.get("returns").is_none(), "{noop}");
}

#[tokio::test]
async fn list_objects_types_in_types_schema() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "list_objects",
        json!({"schema": "types", "kinds": ["type"]}),
    )
    .await;
    let objects = lists_objects(ok(&result));
    let mut names = names_of(&objects);
    names.sort();
    assert_eq!(names, vec!["floatrange", "mood", "pair", "posint"]);
    let mood = find(&objects, "name", "mood");
    assert_eq!(mood["enumLabels"], json!(["sad", "ok", "happy"]));
    assert_eq!(mood["typeKind"], "enum");
    assert_eq!(find(&objects, "name", "posint")["typeKind"], "domain");
    assert_eq!(find(&objects, "name", "pair")["typeKind"], "composite");
    assert_eq!(find(&objects, "name", "floatrange")["typeKind"], "range");
    assert!(
        mood.get("enumLabels").is_some()
            && find(&objects, "name", "pair").get("enumLabels").is_none(),
        "enumLabels only on enums"
    );
}

#[tokio::test]
async fn list_objects_unknown_kind_is_an_error() {
    let result = call(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"kinds": ["bogus"]}),
    )
    .await;
    assert_eq!(
        error_text(&result),
        "Unknown kind \"bogus\". Valid kinds: table, partitioned_table, view, materialized_view, foreign_table, sequence, function, procedure, type."
    );
}

#[tokio::test]
async fn list_objects_empty_kinds_selects_nothing() {
    let result = call(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"schema": "shop", "kinds": []}),
    )
    .await;
    assert!(lists_objects(ok(&result)).is_empty());
}

#[tokio::test]
async fn list_objects_paging_has_no_gaps_or_duplicates() {
    let router = app(one_db(PORT_18, &[]));
    let all = walk_objects(&router, json!({"schema": "shop"}), 500).await;
    let paged = walk_objects(&router, json!({"schema": "shop"}), 2).await;
    let all_keys: Vec<String> = all.iter().map(object_key).collect();
    let paged_keys: Vec<String> = paged.iter().map(object_key).collect();
    assert_eq!(paged_keys, all_keys, "same objects, same order");
    let mut unique = paged_keys.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), paged_keys.len(), "no duplicates");
    assert!(all.len() > 4, "shop has several objects: {}", all.len());
}

#[tokio::test]
async fn list_objects_next_cursor_absent_on_last_page() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "list_objects",
        json!({"schema": "types", "kinds": ["type"], "limit": 500}),
    )
    .await;
    assert!(ok(&result).get("nextCursor").is_none());
}

#[tokio::test]
async fn list_objects_name_like_is_case_insensitive_substring() {
    let result = call(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"schema": "shop", "name_like": "ORDER"}),
    )
    .await;
    let mut names = names_of(&lists_objects(ok(&result)));
    names.sort();
    // orders_id_seq is the bigserial sequence, listed by default.
    assert_eq!(
        names,
        vec!["open_orders", "order_items", "orders", "orders_id_seq"]
    );
}

#[tokio::test]
async fn list_objects_name_like_escapes_wildcards() {
    let router = app(one_db(PORT_18, &[]));
    let percent = call_on(
        &router,
        "list_objects",
        json!({"schema": "shop", "name_like": "%"}),
    )
    .await;
    assert!(lists_objects(ok(&percent)).is_empty());
    let underscore = call_on(
        &router,
        "list_objects",
        json!({"schema": "shop", "name_like": "_"}),
    )
    .await;
    let names = names_of(&lists_objects(ok(&underscore)));
    assert!(names.contains(&"order_items".to_owned()), "{names:?}");
    assert!(!names.contains(&"customers".to_owned()), "{names:?}");
}

#[tokio::test]
async fn list_objects_without_schema_hides_extension_functions() {
    let result = call(
        one_db(PORT_18, &[]),
        "list_objects",
        json!({"kinds": ["function"], "limit": 500}),
    )
    .await;
    let objects = lists_objects(ok(&result));
    assert!(!objects.is_empty());
    for object in &objects {
        let name = object["name"].as_str().unwrap_or_default();
        assert!(
            !name.starts_with("st_"),
            "PostGIS function listed: {object}"
        );
        assert_ne!(object["schema"], "pg_catalog", "{object}");
    }
    assert!(
        objects.iter().any(|o| o["name"] == "order_total"),
        "user functions are listed"
    );
}

#[tokio::test]
async fn list_objects_limit_and_cursor_are_validated() {
    let router = app(one_db(PORT_18, &[]));
    for limit in [0, 501] {
        let result = call_on(&router, "list_objects", json!({"limit": limit})).await;
        assert_eq!(
            error_text(&result),
            "limit must be between 1 and 500.",
            "limit {limit}"
        );
    }
    for cursor in ["x", "o:", "o:-1", "o:abc"] {
        let result = call_on(&router, "list_objects", json!({"cursor": cursor})).await;
        assert_eq!(error_text(&result), "Invalid cursor.", "cursor {cursor}");
    }
}

#[tokio::test]
async fn list_objects_as_strict_role_reads_shop() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(&router, "list_objects", json!({"schema": "shop"})).await;
    let objects = lists_objects(ok(&result));
    assert!(objects.iter().any(|o| o["name"] == "customers"));
}

// ---------------------------------------------------------------- describe_table

#[tokio::test]
async fn describe_table_orders_columns_and_keys() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "describe_table", json!({"table": "shop.orders"})).await;
    let body = ok(&result).clone();
    assert_eq!(body["schema"], "shop");
    assert_eq!(body["name"], "orders");
    assert_eq!(body["kind"], "table");
    assert_eq!(body["persistence"], "permanent");
    assert_eq!(body["comment"], "Orders placed by customers");
    assert_eq!(
        body["rowSecurity"],
        json!({"enabled": false, "forced": false})
    );
    assert!(
        body["sizes"]["totalBytes"].as_i64().unwrap_or_default() > 0,
        "{body}"
    );

    let columns = array(&body["columns"], "columns").clone();
    let expected = [
        ("id", "bigint"),
        ("customer_id", "bigint"),
        ("status", "text"),
        ("total", "numeric(12,2)"),
        ("placed_at", "timestamp with time zone"),
        ("notes", "text"),
    ];
    let names: Vec<(&str, &str)> = columns
        .iter()
        .map(|c| {
            (
                c["name"].as_str().unwrap_or_default(),
                c["type"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(names, expected.to_vec());
    let id = find(&columns, "name", "id");
    assert!(
        id["default"]
            .as_str()
            .unwrap_or_default()
            .contains("nextval"),
        "{id}"
    );
    assert_eq!(id["nullable"], false);
    let notes = find(&columns, "name", "notes");
    assert_eq!(notes["collation"], "C", "{notes}");
    assert_eq!(notes["nullable"], true);
    assert!(find(&columns, "name", "total").get("comment").is_some());
    assert_eq!(
        find(&columns, "name", "total")["comment"],
        "Order total, two decimals"
    );

    assert_eq!(body["primaryKey"]["name"], "orders_pkey");
    assert_eq!(body["primaryKey"]["columns"], json!(["id"]));

    let indexes = array(&body["indexes"], "indexes").clone();
    let mut index_names = names_of(&indexes);
    index_names.sort();
    assert_eq!(
        index_names,
        vec![
            "orders_customer_placed_idx",
            "orders_lower_status_idx",
            "orders_open_placed_idx",
            "orders_pkey",
        ]
    );
    let partial = find(&indexes, "name", "orders_open_placed_idx");
    assert!(
        partial["definition"]
            .as_str()
            .unwrap_or_default()
            .contains("WHERE")
    );
    let expression = find(&indexes, "name", "orders_lower_status_idx");
    assert!(
        expression["definition"]
            .as_str()
            .unwrap_or_default()
            .contains("lower(status)")
    );
    assert_eq!(find(&indexes, "name", "orders_pkey")["primary"], true);
    assert_eq!(find(&indexes, "name", "orders_pkey")["method"], "btree");

    let foreign_keys = array(&body["foreignKeys"], "foreignKeys").clone();
    assert_eq!(foreign_keys.len(), 1, "{foreign_keys:?}");
    let fk = &foreign_keys[0];
    assert_eq!(fk["columns"], json!(["customer_id"]));
    assert_eq!(fk["referencesTable"], "shop.customers");
    assert_eq!(fk["referencesColumns"], json!(["id"]));
    assert_eq!(fk["onDelete"], "CASCADE");
    assert_eq!(fk["onUpdate"], "NO ACTION");
    assert_eq!(fk["deferrable"], false);

    let referenced = array(&body["referencedBy"], "referencedBy").clone();
    let by_items = find(&referenced, "table", "shop.order_items");
    assert_eq!(by_items["columns"], json!(["order_id"]));
    assert_eq!(by_items["referencesColumns"], json!(["id"]));

    let triggers = array(&body["triggers"], "triggers").clone();
    let touch = find(&triggers, "name", "orders_touch");
    assert_eq!(touch["timing"], "BEFORE");
    assert_eq!(touch["events"], json!(["UPDATE"]));
    assert_eq!(touch["level"], "ROW");
    assert_eq!(touch["enabled"], true);
    assert_eq!(touch["function"], "shop.touch_order");
    assert!(
        body.as_object()
            .is_some_and(|m| m.keys().all(|k| !k.ends_with("Error"))),
        "no section failed: {body}"
    );
}

#[tokio::test]
async fn describe_table_customers_identity_generated_check_unique() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.customers"}),
    )
    .await;
    let body = ok(&result).clone();
    let columns = array(&body["columns"], "columns").clone();
    assert_eq!(find(&columns, "name", "id")["identity"], "always");
    let email = find(&columns, "name", "email");
    assert_eq!(email["type"], "citext");
    assert_eq!(email["comment"], "Case-insensitive login email");
    let generated = find(&columns, "name", "name_upper");
    assert!(
        generated["generated"]
            .as_str()
            .unwrap_or_default()
            .contains("upper"),
        "{generated}"
    );
    assert_eq!(generated["default"], Value::Null);
    let checks = array(&body["checkConstraints"], "checkConstraints").clone();
    assert!(
        checks.iter().any(|c| c["definition"]
            .as_str()
            .unwrap_or_default()
            .contains("tier")),
        "{checks:?}"
    );
    let uniques = array(&body["uniqueConstraints"], "uniqueConstraints").clone();
    assert!(
        uniques.iter().any(|u| u["columns"] == json!(["email"])),
        "{uniques:?}"
    );
    assert_eq!(body["comment"], "Customer accounts");
}

#[tokio::test]
async fn describe_table_partitioned_events_and_partition() {
    let router = app(one_db(PORT_18, &[]));
    let parent = call_on(&router, "describe_table", json!({"table": "shop.events"})).await;
    let body = ok(&parent).clone();
    assert_eq!(body["kind"], "partitioned_table");
    let partitioning = &body["partitioning"];
    assert_eq!(partitioning["strategy"], "range");
    assert!(
        partitioning["key"]
            .as_str()
            .unwrap_or_default()
            .contains("happened_at")
    );
    assert_eq!(partitioning["parent"], Value::Null);
    assert_eq!(partitioning["partitionsTruncated"], false);
    let partitions = array(&partitioning["partitions"], "partitions").clone();
    assert_eq!(partitions.len(), 3, "{partitions:?}");
    let default_partition = find(&partitions, "name", "shop.events_default");
    assert!(
        default_partition["bound"]
            .as_str()
            .unwrap_or_default()
            .contains("DEFAULT")
    );

    let child = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.events_2024_q1"}),
    )
    .await;
    let child_body = ok(&child).clone();
    assert_eq!(child_body["partitioning"]["parent"], "shop.events");
    assert!(
        child_body["partitioning"]["bound"]
            .as_str()
            .unwrap_or_default()
            .contains("FOR VALUES")
    );
    assert_eq!(child_body["comment"], "Events in 2024 Q1");
}

#[tokio::test]
async fn describe_table_row_security_policy() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.tenant_data"}),
    )
    .await;
    let body = ok(&result).clone();
    assert_eq!(body["rowSecurity"]["enabled"], true);
    assert_eq!(body["rowSecurity"]["forced"], false);
    let policies = array(&body["policies"], "policies").clone();
    let policy = find(&policies, "name", "tenant_isolation");
    assert!(
        policy["using"]
            .as_str()
            .unwrap_or_default()
            .contains("tenant"),
        "{policy}"
    );
    assert_eq!(policy["command"], "ALL");
    assert_eq!(policy["permissive"], true);
    assert_eq!(policy["roles"], json!(["public"]));
}

#[tokio::test]
async fn describe_table_view_and_materialized_view() {
    let router = app(one_db(PORT_18, &[]));
    let view = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.open_orders"}),
    )
    .await;
    let view_body = ok(&view).clone();
    assert_eq!(view_body["kind"], "view");
    assert!(
        view_body["viewDefinition"]
            .as_str()
            .unwrap_or_default()
            .contains("open")
    );
    assert_eq!(view_body["sizes"], Value::Null);
    assert_eq!(view_body["comment"], "Orders with status open");

    let matview = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.customer_totals"}),
    )
    .await;
    let matview_body = ok(&matview).clone();
    assert_eq!(matview_body["kind"], "materialized_view");
    let indexes = array(&matview_body["indexes"], "indexes").clone();
    let unique = find(&indexes, "name", "customer_totals_customer_idx");
    assert_eq!(unique["unique"], true);
    assert!(matview_body["viewDefinition"].is_string());
}

#[tokio::test]
async fn describe_table_foreign_table_hides_passwords() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.items_remote"}),
    )
    .await;
    let body = ok(&result).clone();
    assert_eq!(body["kind"], "foreign_table");
    assert_eq!(body["foreign"]["server"], "loopback");
    let options = body["foreign"]["options"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert_eq!(options.get("schema_name"), Some(&json!("app")));
    assert_eq!(options.get("table_name"), Some(&json!("items")));
    let serialized = body.to_string();
    for secret in SECRETS {
        assert!(!serialized.contains(secret), "{secret} in {serialized}");
    }
    assert!(!serialized.contains("password"), "{serialized}");
}

#[tokio::test]
async fn describe_table_inheritance() {
    let router = app(one_db(PORT_18, &[]));
    let child = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.audit_child"}),
    )
    .await;
    assert_eq!(ok(&child)["inherits"], json!(["shop.audit_base"]));
    let parent = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.audit_base"}),
    )
    .await;
    assert_eq!(ok(&parent)["inheritedBy"], json!(["shop.audit_child"]));
    assert_eq!(ok(&parent)["inherits"], json!([]));
}

#[tokio::test]
async fn describe_table_all_types_sample() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "types.all_types"}),
    )
    .await;
    let columns = array(&ok(&result)["columns"], "columns").clone();
    let expected = [
        ("c_varchar", "character varying(20)"),
        ("c_bpchar", "character(5)"),
        ("c_bit", "bit(4)"),
        ("c_int4_arr", "integer[]"),
        ("c_mood", "types.mood"),
        ("c_mood_arr", "types.mood[]"),
        ("c_int4multirange", "int4multirange"),
        ("c_timestamptz_arr", "timestamp with time zone[]"),
        ("c_numeric", "numeric"),
        ("c_money", "money"),
        ("c_varbit", "bit varying"),
        ("c_citext", "citext"),
        ("c_pair", "types.pair"),
        ("c_posint", "types.posint"),
        ("c_floatrange", "types.floatrange"),
    ];
    for (name, ty) in expected {
        assert_eq!(find(&columns, "name", name)["type"], ty, "{name}");
    }
    assert_eq!(
        find(&columns, "name", "c_numeric")["comment"],
        "Arbitrary-precision numeric, including NaN in row 2"
    );
}

#[tokio::test]
async fn describe_table_hypertable_is_a_table_on_15432() {
    let result = call(
        one_db(PORT_18, &[]),
        "describe_table",
        json!({"table": "metrics.readings"}),
    )
    .await;
    let body = ok(&result).clone();
    assert_eq!(body["kind"], "table");
    assert_eq!(body["schema"], "metrics");
    assert_eq!(array(&body["columns"], "columns").len(), 4, "{body}");
}

#[tokio::test]
async fn describe_table_name_resolution() {
    let router = app(one_db(PORT_18, &[]));
    // app.orders exists too, so a bare name is ambiguous.
    let bare = call_on(&router, "describe_table", json!({"table": "orders"})).await;
    assert_eq!(
        error_text(&bare),
        "Table \"orders\" exists in several schemas: app, shop. Pass schema."
    );
    let qualified = call_on(&router, "describe_table", json!({"table": "shop.orders"})).await;
    assert_eq!(ok(&qualified)["name"], "orders");
    let quoted = call_on(&router, "describe_table", json!({"table": "\"orders\""})).await;
    assert_eq!(
        error_text(&quoted),
        "Table \"\"orders\"\" exists in several schemas: app, shop. Pass schema."
    );
    let with_schema = call_on(
        &router,
        "describe_table",
        json!({"table": "orders", "schema": "shop"}),
    )
    .await;
    assert_eq!(ok(&with_schema)["schema"], "shop");
    let unique = call_on(&router, "describe_table", json!({"table": "items"})).await;
    assert_eq!(ok(&unique)["schema"], "app");
}

#[tokio::test]
async fn describe_table_unknown_name_suggests_similar_tables() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "describe_table", json!({"table": "order"})).await;
    assert_eq!(
        error_text(&result),
        "Table \"order\" not found. Did you mean: app.orders, shop.open_orders, shop.order_items, shop.orders?"
    );
    let wrong_schema = call_on(
        &router,
        "describe_table",
        json!({"table": "open_orders", "schema": "app"}),
    )
    .await;
    let text = error_text(&wrong_schema);
    assert!(
        text.starts_with("Table \"open_orders\" not found."),
        "{text}"
    );
    let sequence = call_on(&router, "describe_table", json!({"table": "invoice_seq"})).await;
    assert!(error_text(&sequence).starts_with("Table \"invoice_seq\" not found."));
}

#[tokio::test]
async fn describe_table_warns_when_role_cannot_select() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "public.pgmcp_seed_done"}),
    )
    .await;
    let body = ok(&result).clone();
    assert_eq!(
        body["warnings"],
        json!(["The connected role cannot SELECT from this table."])
    );
    assert_eq!(array(&body["columns"], "columns").len(), 1, "{body}");
}

#[tokio::test]
async fn describe_table_as_strict_role_on_shop_has_no_warning() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(&router, "describe_table", json!({"table": "shop.orders"})).await;
    assert_eq!(ok(&result)["warnings"], json!([]));
    assert_eq!(ok(&result)["primaryKey"]["name"], "orders_pkey");
}

// ---------------------------------------------------------------- describe_function

#[tokio::test]
async fn describe_function_overloads_and_attributes() {
    let router = app(one_db(PORT_18, &[]));
    let fmt = call_on(
        &router,
        "describe_function",
        json!({"function": "shop.fmt"}),
    )
    .await;
    let fmt_body = ok(&fmt).clone();
    let overloads = array(&fmt_body["functions"], "functions").clone();
    assert_eq!(overloads.len(), 2, "{overloads:?}");
    assert_eq!(overloads[0]["arguments"], "integer");
    assert_eq!(overloads[1]["arguments"], "text");
    assert_eq!(overloads[0]["returns"], "text");
    assert_eq!(overloads[0]["volatility"], "immutable");
    assert_eq!(overloads[0]["language"], "sql");

    let total = call_on(
        &router,
        "describe_function",
        json!({"function": "order_total"}),
    )
    .await;
    let total_body = ok(&total).clone();
    let function = &array(&total_body["functions"], "functions")[0];
    assert_eq!(function["schema"], "shop");
    assert_eq!(function["kind"], "function");
    assert_eq!(function["volatility"], "stable");
    assert_eq!(function["language"], "sql");
    assert_eq!(function["arguments"], "bigint");
    assert_eq!(function["returns"], "numeric");
    assert_eq!(function["comment"], "Sum of order totals for one customer");
    assert!(
        function["source"]
            .as_str()
            .unwrap_or_default()
            .contains("SELECT")
    );
    assert!(function.get("sourceNote").is_none());
    assert_eq!(function["config"], json!([]));
    assert_eq!(function["parallel"], "unsafe");
    assert_eq!(function["strict"], false);
}

#[tokio::test]
async fn describe_function_security_definer_and_procedure() {
    let router = app(one_db(PORT_18, &[]));
    let secret = call_on(
        &router,
        "describe_function",
        json!({"function": "shop.secret_fn"}),
    )
    .await;
    let secret_fn = &array(&ok(&secret)["functions"], "functions")[0].clone();
    assert_eq!(secret_fn["securityDefiner"], true);
    assert_eq!(secret_fn["language"], "plpgsql");
    assert!(
        secret_fn["source"]
            .as_str()
            .unwrap_or_default()
            .contains("pgmcp secret")
    );

    let noop = call_on(
        &router,
        "describe_function",
        json!({"function": "shop.noop"}),
    )
    .await;
    let noop_fn = &array(&ok(&noop)["functions"], "functions")[0].clone();
    assert_eq!(noop_fn["kind"], "procedure");
    assert_eq!(noop_fn["returns"], Value::Null);
}

#[tokio::test]
async fn describe_function_compiled_has_no_source() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_function",
        json!({"function": "pg_catalog.version"}),
    )
    .await;
    let function = &array(&ok(&result)["functions"], "functions")[0].clone();
    assert_eq!(function["schema"], "pg_catalog");
    assert_eq!(function["language"], "internal");
    assert_eq!(function["source"], Value::Null);
    assert_eq!(function["sourceNote"], "compiled");
}

#[tokio::test]
async fn describe_function_not_found_and_system_schemas() {
    let router = app(one_db(PORT_18, &[]));
    let missing = call_on(&router, "describe_function", json!({"function": "nope"})).await;
    assert_eq!(error_text(&missing), "Function \"nope\" not found.");
    let system = call_on(&router, "describe_function", json!({"function": "version"})).await;
    assert_eq!(error_text(&system), "Function \"version\" not found.");
    let with_schema = call_on(
        &router,
        "describe_function",
        json!({"function": "fmt", "schema": "shop"}),
    )
    .await;
    assert_eq!(array(&ok(&with_schema)["functions"], "functions").len(), 2);
}

#[tokio::test]
async fn describe_function_as_strict_role_reads_definer_source() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(
        &router,
        "describe_function",
        json!({"function": "shop.secret_fn"}),
    )
    .await;
    assert_eq!(array(&ok(&result)["functions"], "functions").len(), 1);
}

// ---------------------------------------------------------------- search_schema

#[tokio::test]
async fn search_finds_column_by_name() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "search_schema", json!({"query": "email"})).await;
    let matches = array(&ok(&result)["matches"], "matches").clone();
    let column = matches
        .iter()
        .find(|m| m["kind"] == "column" && m["schema"] == "shop" && m["table"] == "customers")
        .unwrap_or_else(|| panic!("{matches:?}"));
    assert_eq!(column["name"], "email");
    assert_eq!(column["type"], "citext");
    assert_eq!(column["matched"], "name");
    assert_eq!(column["comment"], "Case-insensitive login email");
}

#[tokio::test]
async fn search_ranks_exact_then_prefix_then_substring_then_comment() {
    let router = app(one_db(PORT_18, &[]));
    let exact = call_on(&router, "search_schema", json!({"query": "orders"})).await;
    let first = &array(&ok(&exact)["matches"], "matches")[0].clone();
    assert_eq!(first["kind"], "table");
    assert_eq!(first["name"], "orders");
    // app.orders and shop.orders are both exact matches; ties sort by schema name.
    assert_eq!(first["schema"], "app");

    let prefix = call_on(&router, "search_schema", json!({"query": "order"})).await;
    let matches = array(&ok(&prefix)["matches"], "matches").clone();
    let names: Vec<&str> = matches.iter().filter_map(|m| m["name"].as_str()).collect();
    assert!(
        names.contains(&"orders") && names.contains(&"order_items"),
        "{names:?}"
    );
    let last_name_match = matches
        .iter()
        .rposition(|m| m["matched"] == "name")
        .unwrap_or_default();
    let first_comment_match = matches
        .iter()
        .position(|m| m["matched"] == "comment")
        .unwrap_or(usize::MAX);
    assert!(
        first_comment_match > last_name_match,
        "comment matches come after every name match"
    );
    assert!(
        matches[0]["name"]
            .as_str()
            .unwrap_or_default()
            .starts_with("order")
    );
}

#[tokio::test]
async fn search_matches_comment_only_text() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "search_schema", json!({"query": "Quantity"})).await;
    let matches = array(&ok(&result)["matches"], "matches").clone();
    let hit = matches
        .iter()
        .find(|m| m["name"] == "qty")
        .unwrap_or_else(|| panic!("{matches:?}"));
    assert_eq!(hit["kind"], "column");
    assert_eq!(hit["table"], "order_items");
    assert_eq!(hit["matched"], "comment");
    assert_eq!(hit["comment"], "Quantity ordered");
}

#[tokio::test]
async fn search_query_length_and_wildcards() {
    let router = app(one_db(PORT_18, &[]));
    for query in ["%", "a", ""] {
        let result = call_on(&router, "search_schema", json!({"query": query})).await;
        assert_eq!(
            error_text(&result),
            "query must be at least 2 characters.",
            "query {query:?}"
        );
    }
    let literal = call_on(&router, "search_schema", json!({"query": "a%"})).await;
    for m in array(&ok(&literal)["matches"], "matches") {
        let name = m["name"].as_str().unwrap_or_default();
        let comment = m["comment"].as_str().unwrap_or_default();
        assert!(name.contains("a%") || comment.contains("a%"), "{m}");
    }
}

#[tokio::test]
async fn search_paging_is_stable() {
    let router = app(one_db(PORT_18, &[]));
    let all = call_on(
        &router,
        "search_schema",
        json!({"query": "order", "limit": 500}),
    )
    .await;
    let all_matches = array(&ok(&all)["matches"], "matches").clone();
    let mut paged = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"query": "order", "limit": 2});
        if let Some(next) = &cursor {
            args["cursor"] = json!(next);
        }
        let page = call_on(&router, "search_schema", args).await;
        let body = ok(&page).clone();
        paged.extend(array(&body["matches"], "matches").clone());
        match body.get("nextCursor").and_then(Value::as_str) {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(paged, all_matches);
}

#[tokio::test]
async fn search_kinds_limit_to_functions() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "search_schema",
        json!({"query": "order", "kinds": ["function"]}),
    )
    .await;
    let matches = array(&ok(&result)["matches"], "matches").clone();
    assert!(!matches.is_empty());
    assert!(
        matches.iter().all(|m| m["kind"] == "function"),
        "{matches:?}"
    );
    assert!(matches.iter().any(|m| m["name"] == "order_total"));
}

#[tokio::test]
async fn search_excludes_extension_functions() {
    let router = app(one_db(PORT_18, &[]));
    // PostGIS functions live in public and are extension-owned, so none may be listed.
    let postgis = call_on(
        &router,
        "search_schema",
        json!({"query": "makepoint", "kinds": ["function"]}),
    )
    .await;
    assert_eq!(array(&ok(&postgis)["matches"], "matches").len(), 0);
    let prefix = call_on(
        &router,
        "search_schema",
        json!({"query": "st_", "kinds": ["function"], "limit": 500}),
    )
    .await;
    let matches = array(&ok(&prefix)["matches"], "matches").clone();
    assert!(
        matches.iter().all(|m| m["schema"] != "public"),
        "{matches:?}"
    );
    assert!(
        matches.iter().any(|m| m["name"] == "list_log_files"),
        "{matches:?}"
    );
}

#[tokio::test]
async fn search_unknown_kind_is_an_error() {
    let result = call(
        one_db(PORT_18, &[]),
        "search_schema",
        json!({"query": "order", "kinds": ["index"]}),
    )
    .await;
    assert_eq!(
        error_text(&result),
        "Unknown kind \"index\". Valid kinds: table, view, column, function."
    );
}

#[tokio::test]
async fn search_as_strict_role_finds_shop_objects() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(&router, "search_schema", json!({"query": "customer"})).await;
    let matches = array(&ok(&result)["matches"], "matches").clone();
    assert!(
        matches
            .iter()
            .any(|m| m["name"] == "customers" && m["schema"] == "shop")
    );
}

// ---------------------------------------------------------------- get_privileges

#[tokio::test]
async fn privileges_read_only_role_on_15432() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "get_privileges", json!({})).await;
    let body = ok(&result).clone();
    assert_eq!(body["database"], "appdb");
    assert_eq!(body["role"]["name"], "mcp_ro");
    assert_eq!(body["role"]["superuser"], false);
    let member_of = array(&body["role"]["memberOf"], "memberOf").clone();
    for role in ["pg_read_all_data", "pg_monitor", "pg_read_all_stats"] {
        assert!(member_of.contains(&json!(role)), "{member_of:?}");
    }
    let predefined = &body["predefinedRoles"];
    assert_eq!(predefined["pgReadAllData"], true);
    assert_eq!(predefined["pgMonitor"], true);
    assert_eq!(predefined["pgReadAllStats"], true);
    assert_eq!(predefined["pgWriteAllData"], false);
    assert_eq!(body["databasePrivileges"]["connect"], true);
    let features = &body["features"];
    assert_eq!(features["serverLog"]["available"], true);
    assert_eq!(features["pgStatStatements"]["available"], true);
    assert_eq!(features["timescaledb"]["installed"], true);
    assert_eq!(features["otherSessionsQueryText"]["available"], true);
    assert_eq!(body["beyondReadOnly"], json!([]));
    let schemas = array(&body["schemas"], "schemas").clone();
    let shop = find(&schemas, "name", "shop");
    assert_eq!(shop["selectableTables"], 13);
    assert_eq!(shop["unselectableTables"], 0);
}

#[tokio::test]
async fn privileges_without_pg_stat_statements_say_how_to_enable_it() {
    let router = app(one_db(PORT_15, &[]));
    let result = call_on(&router, "get_privileges", json!({})).await;
    let features = ok(&result)["features"].clone();
    assert_eq!(features["pgStatStatements"]["available"], false);
    assert_eq!(
        features["pgStatStatements"]["missing"],
        "CREATE EXTENSION pg_stat_statements; (and add it to shared_preload_libraries)"
    );
    assert_eq!(features["timescaledb"]["installed"], false);
    assert_eq!(features["timescaledb"]["version"], Value::Null);
}

/// The decoy log reader on database postgres (PostgreSQL 19) is owned by mcp_strict and is not SECURITY DEFINER.
#[tokio::test]
async fn privileges_decoy_log_reader_is_not_available() {
    let mut entry = login(PORT_19, "mcp_ro", "test-only-ro");
    entry["database"] = json!("postgres");
    let router = app(config_with(&[entry], &[]));
    let result = call_on(&router, "get_privileges", json!({})).await;
    assert_eq!(
        ok(&result)["features"]["serverLog"],
        json!({
            "available": false,
            "missing": "Run sql/log_reader.sql as a superuser, then GRANT USAGE ON SCHEMA pgmcp TO mcp_ro; GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_ro;"
        }),
    );
}

#[tokio::test]
async fn privileges_strict_role_is_limited() {
    let router = app(config_as(PORT_18, STRICT_USER, STRICT_PASSWORD));
    let result = call_on(&router, "get_privileges", json!({})).await;
    let body = ok(&result).clone();
    assert_eq!(body["role"]["name"], "mcp_strict");
    assert_eq!(body["predefinedRoles"]["pgReadAllData"], false);
    assert_eq!(body["predefinedRoles"]["pgReadAllStats"], true);
    assert_eq!(
        body["features"]["otherSessionsQueryText"]["available"],
        true
    );
    assert_eq!(body["features"]["serverLog"]["available"], true);
    let schemas = array(&body["schemas"], "schemas").clone();
    let sess = find(&schemas, "name", "sess_test");
    assert_eq!(sess["usage"], false);
    let shop = find(&schemas, "name", "shop");
    assert_eq!(shop["usage"], true);
    assert_eq!(shop["unselectableTables"], 0);
    let public = find(&schemas, "name", "public");
    assert!(
        public["unselectableTables"].as_i64().unwrap_or_default() >= 1,
        "{public}"
    );
}

#[tokio::test]
async fn privileges_superuser_is_flagged() {
    let router = app(config_as(PORT_18, SUPER_USER, SUPER_PASSWORD));
    let result = call_on(&router, "get_privileges", json!({})).await;
    let beyond = array(&ok(&result)["beyondReadOnly"], "beyondReadOnly").clone();
    assert!(beyond.contains(&json!("superuser")), "{beyond:?}");
}

// ---------------------------------------------------------------- toolsets and secrets

#[tokio::test]
async fn schema_tools_are_absent_when_toolset_is_off() {
    let router = app(one_db(PORT_18, &[("TOOLSETS", "core")]));
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    let tools = array(&result_of(&reply.json())["tools"], "tools").clone();
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for name in [
        "list_schemas",
        "list_objects",
        "describe_table",
        "describe_function",
        "search_schema",
        "get_privileges",
    ] {
        assert!(!names.contains(&name), "{names:?}");
    }
    assert!(names.contains(&"list_databases"), "{names:?}");
    let call_body = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "list_schemas", "arguments": {}},
    });
    let call_reply = post_mcp(
        &router,
        &call_body,
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await;
    let response = call_reply.json();
    assert!(response.get("error").is_some(), "{response}");
    assert!(response.get("result").is_none(), "{response}");
}

#[tokio::test]
async fn schema_tools_are_listed_by_default() {
    let router = app(one_db(PORT_18, &[]));
    let body = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
    let reply = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    let tools = array(&result_of(&reply.json())["tools"], "tools").clone();
    for tool in &tools {
        if [
            "list_schemas",
            "list_objects",
            "describe_table",
            "describe_function",
            "search_schema",
            "get_privileges",
        ]
        .contains(&tool["name"].as_str().unwrap_or_default())
        {
            assert_eq!(tool["annotations"]["readOnlyHint"], true, "{tool}");
            assert_eq!(tool["annotations"]["destructiveHint"], false, "{tool}");
            assert!(tool["title"].is_string(), "{tool}");
        }
    }
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    assert!(names.contains(&"describe_table") && names.contains(&"get_privileges"));
}

#[tokio::test]
async fn no_secret_in_any_output() {
    let router = app(one_db(PORT_18, &[]));
    let calls = [
        ("list_schemas", json!({})),
        ("list_objects", json!({})),
        ("describe_table", json!({"table": "shop.items_remote"})),
        ("describe_function", json!({"function": "shop.fmt"})),
        ("search_schema", json!({"query": "remote"})),
        ("get_privileges", json!({})),
    ];
    for (name, arguments) in calls {
        let result = call_on(&router, name, arguments).await;
        let serialized = result.to_string();
        for secret in SECRETS {
            assert!(!serialized.contains(secret), "{name} leaks {secret}");
        }
    }
}

#[tokio::test]
async fn list_schemas_across_all_three_servers() {
    for port in [PORT_18, PORT_19, PORT_15] {
        let result = call(one_db(port, &[]), "list_schemas", json!({})).await;
        let schemas = array(&ok(&result)["schemas"], "schemas").clone();
        let shop = find(&schemas, "name", "shop");
        assert_eq!(shop["tables"], 13, "port {port}");
        assert_eq!(shop["views"], 2, "port {port}");
    }
}

#[tokio::test]
async fn describe_table_orders_on_all_three_servers() {
    for port in [PORT_18, PORT_19, PORT_15] {
        let result = call(
            one_db(port, &[]),
            "describe_table",
            json!({"table": "shop.orders"}),
        )
        .await;
        let body = ok(&result).clone();
        assert_eq!(body["name"], "orders", "port {port}");
        let names = names_of(array(&body["columns"], "columns"));
        assert_eq!(
            names,
            vec!["id", "customer_id", "status", "total", "placed_at", "notes"],
            "port {port}"
        );
        assert_eq!(body["primaryKey"]["name"], "orders_pkey", "port {port}");
        assert_eq!(array(&body["indexes"], "indexes").len(), 4, "port {port}");
        assert_eq!(
            array(&body["foreignKeys"], "foreignKeys").len(),
            1,
            "port {port}"
        );
        assert_eq!(body["triggers"][0]["name"], "orders_touch", "port {port}");
    }
}

#[tokio::test]
async fn describe_table_internal_triggers_are_not_listed() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.customers"}),
    )
    .await;
    let body = ok(&result).clone();
    assert_eq!(
        body["triggers"],
        json!([]),
        "foreign key triggers are internal"
    );
    assert!(body["sizes"]["totalBytes"].as_i64().unwrap_or_default() > 0);
    assert!(body["stats"].is_object(), "{body}");
    assert!(body["stats"]["liveRows"].is_number(), "{body}");
    assert!(body["stats"].get("deadRows").is_some(), "{body}");
    let indexes = array(&body["indexes"], "indexes").clone();
    let email_key = find(&indexes, "name", "customers_email_key");
    assert_eq!(email_key["unique"], true);
    assert_eq!(email_key["method"], "btree");
    assert!(
        email_key["sizeBytes"].as_i64().unwrap_or_default() > 0,
        "{email_key}"
    );
    assert!(email_key["scans"].is_number(), "{email_key}");
}

#[tokio::test]
async fn describe_table_partitioned_row_estimate_is_leaf_sum_or_unknown() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "describe_table", json!({"table": "shop.events"})).await;
    let estimate = ok(&result)["rowEstimate"].as_i64();
    assert!(
        estimate == Some(300) || estimate == Some(-1),
        "sum of analyzed leaves (300) or -1: {estimate:?}"
    );
    let objects = call_on(
        &router,
        "list_objects",
        json!({"schema": "shop", "kinds": ["partitioned_table"]}),
    )
    .await;
    let events = find(&lists_objects(ok(&objects)).clone(), "name", "events").clone();
    assert_eq!(events["rowEstimate"].as_i64(), estimate, "{events}");
    assert!(
        events["totalBytes"].as_i64().unwrap_or_default() > 0,
        "{events}"
    );
}

/// The value of column `v` in the single row of an execute_query result on the same router.
async fn scalar_through_query(router: &Router, sql: &str) -> Value {
    let result = call_on(router, "execute_query", json!({"sql": sql})).await;
    let rows = array(&ok(&result)["rows"], "rows").clone();
    assert_eq!(rows.len(), 1, "{sql}");
    rows[0]["v"].clone()
}

#[tokio::test]
async fn table_bytes_agree_across_describe_table_table_stats_and_pg_table_size() {
    let router = app(one_db(PORT_18, &[]));
    let described = call_on(&router, "describe_table", json!({"table": "shop.orders"})).await;
    let described_table = ok(&described)["sizes"]["tableBytes"].clone();
    let stats = call_on(
        &router,
        "table_stats",
        json!({"schema": "shop", "table": "orders", "include_indexes": false}),
    )
    .await;
    let rows = array(&ok(&stats)["tables"], "tables").clone();
    assert_eq!(rows.len(), 1, "{stats}");
    let stats_table = rows[0]["tableBytes"].clone();
    let pg_table = scalar_through_query(
        &router,
        "SELECT pg_table_size('shop.orders'::regclass) AS v",
    )
    .await;
    assert_eq!(described_table, pg_table, "{described}");
    assert_eq!(stats_table, pg_table, "{stats}");
    assert!(pg_table.as_i64().unwrap_or_default() > 0, "{pg_table}");
}

#[tokio::test]
async fn describe_table_sizes_match_postgres_for_leaf_parent_and_plain_table() {
    let router = app(one_db(PORT_18, &[]));
    let leaf = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.events_2024_q1"}),
    )
    .await;
    let leaf_sizes = ok(&leaf)["sizes"].clone();
    let leaf_total = scalar_through_query(
        &router,
        "SELECT pg_total_relation_size('shop.events_2024_q1'::regclass) AS v",
    )
    .await;
    assert_eq!(leaf_sizes["totalBytes"], leaf_total, "{leaf_sizes}");
    let leaf_table = scalar_through_query(
        &router,
        "SELECT pg_table_size('shop.events_2024_q1'::regclass) AS v",
    )
    .await;
    assert_eq!(leaf_sizes["tableBytes"], leaf_table, "{leaf_sizes}");

    let parent = call_on(&router, "describe_table", json!({"table": "shop.events"})).await;
    let parent_total = ok(&parent)["sizes"]["totalBytes"].clone();
    let leaves_total = scalar_through_query(
        &router,
        "SELECT sum(pg_total_relation_size(t.relid))::bigint AS v \
         FROM pg_catalog.pg_partition_tree('shop.events'::regclass) t WHERE t.isleaf",
    )
    .await;
    assert_eq!(parent_total, leaves_total, "{parent}");
    assert!(parent_total.as_i64().unwrap_or_default() > 0, "{parent}");

    let plain = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.customers"}),
    )
    .await;
    let plain_total = scalar_through_query(
        &router,
        "SELECT pg_total_relation_size('shop.customers'::regclass) AS v",
    )
    .await;
    assert_eq!(ok(&plain)["sizes"]["totalBytes"], plain_total, "{plain}");
}

#[tokio::test]
async fn describe_function_aggregate_and_window_kinds() {
    let router = app(one_db(PORT_18, &[]));
    let aggregate = call_on(
        &router,
        "describe_function",
        json!({"function": "pg_catalog.count"}),
    )
    .await;
    let aggregates = array(&ok(&aggregate)["functions"], "functions").clone();
    assert!(!aggregates.is_empty());
    assert!(
        aggregates.iter().all(|f| f["kind"] == "aggregate"),
        "{aggregates:?}"
    );
    let window = call_on(
        &router,
        "describe_function",
        json!({"function": "pg_catalog.row_number"}),
    )
    .await;
    let windows = array(&ok(&window)["functions"], "functions").clone();
    assert!(!windows.is_empty());
    assert!(windows.iter().all(|f| f["kind"] == "window"), "{windows:?}");
}

#[tokio::test]
async fn search_kinds_table_includes_partitioned_and_views_by_kind() {
    let router = app(one_db(PORT_18, &[]));
    let tables = call_on(
        &router,
        "search_schema",
        json!({"query": "events", "schema": "shop", "kinds": ["table"]}),
    )
    .await;
    let matches = array(&ok(&tables)["matches"], "matches").clone();
    let events = find(&matches, "name", "events");
    assert_eq!(events["kind"], "table");
    assert!(matches.iter().all(|m| m["kind"] != "view"), "{matches:?}");
    let views = call_on(
        &router,
        "search_schema",
        json!({"query": "orders", "schema": "shop", "kinds": ["view"]}),
    )
    .await;
    let view_matches = array(&ok(&views)["matches"], "matches").clone();
    assert!(!view_matches.is_empty());
    assert!(
        view_matches
            .iter()
            .all(|m| m["kind"] == "view" || m["kind"] == "materialized_view"),
        "{view_matches:?}"
    );
    assert!(view_matches.iter().any(|m| m["name"] == "open_orders"));
}

#[tokio::test]
async fn privileges_report_session_user() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(&router, "get_privileges", json!({})).await;
    assert_eq!(ok(&result)["role"]["sessionUser"], "mcp_ro");
    assert_eq!(ok(&result)["role"]["inherit"], true);
    assert_eq!(ok(&result)["role"]["connectionLimit"], 20);
}

/// The role with CONNECT, USAGE on app and SELECT on app.items only (docker/initdb/56_test_objects.sql).
fn min_config(port: u16) -> Config {
    config_as(port, "mcp_min", "test-only-min")
}

#[tokio::test]
async fn privileges_min_role_reports_missing_grants() {
    let router = app(min_config(PORT_18));
    let result = call_on(&router, "get_privileges", json!({})).await;
    let body = ok(&result).clone();
    assert_eq!(body["role"]["name"], "mcp_min");
    assert_eq!(body["predefinedRoles"]["pgReadAllStats"], false);
    let features = &body["features"];
    assert_eq!(
        features["otherSessionsQueryText"],
        json!({"available": false, "missing": "GRANT pg_read_all_stats TO mcp_min;"})
    );
    assert_eq!(
        features["serverLog"],
        json!({
            "available": false,
            "missing": "Run sql/log_reader.sql as a superuser, then GRANT USAGE ON SCHEMA pgmcp TO mcp_min; GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO mcp_min;"
        })
    );
    // pg_stat_statements grants SELECT to PUBLIC, so the role can read the view.
    assert_eq!(features["pgStatStatements"], json!({"available": true}));
    assert_eq!(features["timescaledb"]["installed"], true);
}

#[tokio::test]
async fn list_schemas_min_role_shows_only_usable_schemas() {
    let router = app(min_config(PORT_18));
    let result = call_on(&router, "list_schemas", json!({})).await;
    let schemas = array(&ok(&result)["schemas"], "schemas").clone();
    assert_eq!(names_of(&schemas), vec!["app", "public"], "{schemas:?}");
}

#[tokio::test]
async fn describe_table_min_role_reads_its_own_table() {
    let router = app(min_config(PORT_18));
    let result = call_on(&router, "describe_table", json!({"table": "app.items"})).await;
    let body = ok(&result).clone();
    assert_eq!(body["schema"], "app");
    assert_eq!(body["name"], "items");
    assert_eq!(body["warnings"], json!([]), "{body}");
}

#[tokio::test]
async fn describe_table_min_role_warns_it_cannot_select_other_schemas() {
    let router = app(min_config(PORT_18));
    let result = call_on(&router, "describe_table", json!({"table": "shop.orders"})).await;
    let body = ok(&result).clone();
    assert_eq!(body["name"], "orders");
    assert_eq!(
        body["warnings"],
        json!(["The connected role cannot SELECT from this table."]),
        "{body}"
    );
}

#[tokio::test]
async fn describe_table_lists_at_most_200_partitions() {
    let router = app(one_db(PORT_18, &[]));
    let result = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.many_parts"}),
    )
    .await;
    let partitioning = &ok(&result)["partitioning"];
    assert_eq!(
        array(&partitioning["partitions"], "partitions").len(),
        200,
        "{partitioning}"
    );
    assert_eq!(partitioning["partitionsTruncated"], true, "{partitioning}");
}

#[tokio::test]
async fn describe_table_quoted_name_with_dot_and_uppercase() {
    let router = app(one_db(PORT_18, &[]));
    let bare = call_on(
        &router,
        "describe_table",
        json!({"table": "Odd.Name", "schema": "shop"}),
    )
    .await;
    assert_eq!(ok(&bare)["name"], "Odd.Name");
    assert_eq!(ok(&bare)["schema"], "shop");
    let qualified = call_on(
        &router,
        "describe_table",
        json!({"table": "shop.\"Odd.Name\""}),
    )
    .await;
    assert_eq!(ok(&qualified)["name"], "Odd.Name");
    let rows = call_on(
        &router,
        "execute_query",
        json!({"sql": "SELECT \"Select\" FROM shop.\"Odd.Name\""}),
    )
    .await;
    assert_eq!(ok(&rows)["columns"][0]["name"], "Select", "{rows}");
    assert_eq!(ok(&rows)["rows"], json!([{"Select": 1}]), "{rows}");
}
