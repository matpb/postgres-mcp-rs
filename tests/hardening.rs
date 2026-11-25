//! Hardening regressions: hostile public functions must not reach the server's own SQL.

mod common;

use std::time::Duration;

use common::{
    PORT_15, PORT_18, PORT_19, PORT_TLS, PROTOCOL_2025, app, call_tool, config_with, db_entry,
    one_db, post_mcp, result_of,
};
use postgres_mcp::config::Config;
use postgres_mcp::gate::{GateOptions, check, credential_roots};
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection};
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

const SERVERS: [u16; 3] = [PORT_18, PORT_19, PORT_15];

const CURRENT_SETTING_DOTTED: &str = "\"current_setting\" after a dot would call current_setting() with a computed name, which is not allowed. Use current_setting('name') with a literal name. If it is a column of yours, give it another name with AS in a subquery.";
const TERMINATE_DOTTED: &str = "\"pg_terminate_backend\" after a dot would call the function pg_terminate_backend(), which is not allowed: it controls the server or other sessions. If it is a column of yours, give it another name with AS in a subquery.";
const TS_STAT_DOTTED: &str = "\"ts_stat\" after a dot would call the function ts_stat(), which is not allowed: it executes SQL text the gate cannot inspect. If it is a column of yours, give it another name with AS in a subquery.";

#[tokio::test]
async fn dotted_function_names_are_refused_on_every_server() {
    let cases = [
        (
            "SELECT ('ssl_key_file'::text).current_setting;",
            CURRENT_SETTING_DOTTED,
        ),
        (
            "SELECT (pid).pg_terminate_backend FROM pg_stat_activity;",
            TERMINATE_DOTTED,
        ),
        (
            "SELECT (x).ts_stat FROM (VALUES ('select 1')) v(x);",
            TS_STAT_DOTTED,
        ),
    ];
    for port in SERVERS {
        let router = app(one_db(port, &[]));
        for (sql, message) in cases {
            let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
            assert_eq!(
                result_of(&response)["isError"],
                json!(true),
                "{port} {sql} {response}"
            );
            assert_eq!(
                text_of(&response),
                format!("Query rejected: {message}"),
                "{port} {sql}"
            );
        }
    }
}

fn superuser_config(port: u16) -> ConnectConfig {
    // The TLS-only server refuses a plain connection.
    let ssl_mode = if port == PORT_TLS {
        SslMode::Require
    } else {
        SslMode::Disable
    };
    ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: "appdb".into(),
        user: "postgres".into(),
        password: Some("test-only-superuser".into()),
        ssl_mode,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: Vec::new(),
    }
}

/// Runs a query as the superuser and returns the first column of the first row.
async fn superuser_scalar(port: u16, sql: &str) -> String {
    let mut conn = Connection::connect(&superuser_config(port))
        .await
        .expect("superuser connect");
    let result = conn.simple_query(sql).await.expect("superuser query");
    result.rows[0][0].clone().expect("non-null value")
}

#[tokio::test]
async fn dotted_terminate_leaves_a_live_canary_backend_running() {
    for port in SERVERS {
        let canary = format!("pgmcp-canary-{port}");
        let mut canary_config = superuser_config(port);
        canary_config.user = "mcp_ro".into();
        canary_config.password = Some("test-only-ro".into());
        canary_config.startup_params = vec![("application_name".into(), canary.clone())];
        let conn = Connection::connect(&canary_config)
            .await
            .expect("canary connect");
        let cancel = conn.cancel_handle();
        let sleeper = tokio::spawn(async move {
            let mut conn = conn;
            conn.simple_query("SELECT pg_sleep(20)").await
        });

        let count_sql = format!(
            "SELECT count(*) FROM pg_stat_activity WHERE application_name = '{canary}' \
             AND state = 'active' AND query LIKE '%pg_sleep(20)%'"
        );
        let mut seen = false;
        for _ in 0..50 {
            if superuser_scalar(port, &count_sql).await == "1" {
                seen = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(seen, "canary backend never became active on {port}");

        let router = app(one_db(port, &[]));
        let sql = format!(
            "SELECT (pid).pg_terminate_backend FROM pg_stat_activity WHERE application_name = '{canary}'"
        );
        let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
        assert_eq!(result_of(&response)["isError"], json!(true), "{response}");
        assert_eq!(
            text_of(&response),
            format!("Query rejected: {TERMINATE_DOTTED}")
        );

        assert_eq!(superuser_scalar(port, &count_sql).await, "1", "{port}");
        cancel.cancel().await.expect("cancel the canary");
        let outcome = sleeper.await.expect("canary task joins");
        assert!(outcome.is_err(), "canary query was cancelled on {port}");
    }
}

#[tokio::test]
async fn server_log_helpers_are_refused_in_execute_query_on_every_server() {
    let log_reason = "the server log helper functions are reserved for the read_server_log tool";
    let cases = [
        (
            "SELECT pgmcp.read_log_file('postgresql.log', 0, 10)",
            format!("Function read_log_file() is not allowed: {log_reason}."),
        ),
        (
            "SELECT * FROM pgmcp.list_log_files()",
            format!("Function list_log_files() is not allowed: {log_reason}."),
        ),
    ];
    for port in SERVERS {
        let router = app(one_db(port, &[]));
        for (sql, message) in &cases {
            let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
            assert_eq!(
                result_of(&response)["isError"],
                json!(true),
                "{port} {sql} {response}"
            );
            assert_eq!(
                text_of(&response),
                format!("Query rejected: {message}"),
                "{port}"
            );
        }
    }
}

/// Name parts that mark a function which reads files or signals, changes or writes the server, or changes
/// sequences, settings, sessions or large objects. The audit prints every match with the gate's verdict.
const SUSPECT_FUNCTION_PARTS: &[&str] = &[
    "wal",
    "page",
    "raw",
    "tuple",
    "heap",
    "read_file",
    "read_binary",
    "ls_dir",
    "stat_file",
    "rotate",
    "reload",
    "terminate",
    "cancel_backend",
    "advisory",
    "_file_",
    "import",
    "export",
    "logical_emit",
    "replication_slot",
    "replication_origin",
    "nextval",
    "setval",
    "set_config",
    "notify",
    "promote",
    "switch_wal",
    "restore_point",
    "stat_reset",
    "to_xml",
    "dblink",
    "lo_",
    "backup",
    "wal_replay",
    "create_restore",
    "drop_",
    "copy_",
    "snapshot",
    "restore_",
    "clear_",
    "import_system",
    "binary_upgrade",
    "pg_log_",
    "signal",
    "prewarm",
    "buffercache_evict",
    "truncate",
    "reindex",
    "vacuum",
    "analyze",
];

/// A match of any of these that the gate allows fails the audit, unless `read_only_by_inspection` accepts it.
const STRICT_FUNCTION_PARTS: &[&str] = &[
    "wal",
    "page",
    "raw",
    "tuple",
    "heap",
    "read_file",
    "read_binary",
    "ls_dir",
    "stat_file",
    "rotate_logfile",
    "reload_conf",
    "terminate_backend",
    "cancel_backend",
    "advisory",
    "logical_emit",
    "replication_slot",
    "replication_origin",
    "switch_wal",
    "restore_point",
    "stat_reset",
    "to_xml",
    "binary_upgrade",
    "import_system_collations",
    "pg_restore_",
    "pg_clear_",
    "pg_log_backend",
    "pg_log_standby",
    "buffercache_evict",
    "pg_prewarm",
    "autoprewarm",
];

/// Matches of STRICT_FUNCTION_PARTS that only read fixed server state; the gate allows them on purpose.
/// The `pg_ls_*dir` listings read one fixed directory each, and pg_ls_dir (any path) is denied.
fn read_only_by_inspection(name: &str) -> bool {
    (name.starts_with("pg_ls_") && name.ends_with("dir") && name != "pg_ls_dir")
        || name.starts_with("pg_stat_get_")
        || matches!(
            name,
            "pg_get_replication_slots"
                | "pg_show_replication_origin_status"
                | "heap_tableam_handler"
                | "raw_array_subscript_handler"
                | "pg_current_wal_flush_lsn"
                | "pg_current_wal_insert_lsn"
                | "pg_current_wal_lsn"
                | "pg_last_wal_receive_lsn"
                | "pg_last_wal_replay_lsn"
                | "pg_get_wal_replay_pause_state"
                | "pg_get_wal_resource_managers"
                | "pg_get_wal_summarizer_state"
                | "pg_is_wal_replay_paused"
                | "pg_split_walfile_name"
                | "pg_walfile_name"
                | "pg_walfile_name_offset"
                | "pg_wal_lsn_diff"
        )
}

/// Functions of pg_catalog and of installed extensions, one row per schema and name.
const FUNCTION_NAMES_SQL: &str = "SELECT DISTINCT n.nspname, p.proname \
     FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
     WHERE n.nspname = 'pg_catalog' OR p.oid IN \
       (SELECT d.objid FROM pg_catalog.pg_depend d \
        WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.deptype = 'e') \
     ORDER BY 1, 2";

/// The gate's verdict for a call to one function: denied by name, or allowed.
fn function_verdict(schema: &str, name: &str) -> &'static str {
    let sql = format!("SELECT {}.{}()", quoted(schema), quoted(name));
    match check(&sql, &GateOptions::default()) {
        Ok(_) => "ALLOWED",
        Err(rejection) if rejection.code == "function_denied" => "denied",
        Err(rejection) => panic!("unexpected rejection of {sql}: {rejection:?}"),
    }
}

fn quoted(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// Every connection of the audit: the four test servers, with the TLS one as superuser over TLS.
const AUDIT_SERVERS: [(u16, &str); 4] = [
    (PORT_18, "15432"),
    (PORT_19, "15433"),
    (PORT_15, "15434"),
    (PORT_TLS, "15435"),
];

/// Runs a query as the superuser and returns every row as text cells, with NULL as an empty string.
async fn superuser_rows(port: u16, sql: &str) -> Vec<Vec<String>> {
    let mut conn = Connection::connect(&superuser_config(port))
        .await
        .expect("superuser connect");
    let result = conn.simple_query(sql).await.expect("superuser query");
    result
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| cell.clone().unwrap_or_default())
                .collect()
        })
        .collect()
}

#[tokio::test]
async fn catalog_audit_of_suspect_function_names() {
    let mut misses = Vec::new();
    for (port, label) in AUDIT_SERVERS {
        println!("== server {label}");
        for row in superuser_rows(port, FUNCTION_NAMES_SQL).await {
            let (schema, name) = (&row[0], &row[1]);
            let lowered = name.to_ascii_lowercase();
            if !SUSPECT_FUNCTION_PARTS
                .iter()
                .any(|part| lowered.contains(part))
            {
                continue;
            }
            let verdict = function_verdict(schema, name);
            println!("{schema}.{name} -> {verdict}");
            let strict = STRICT_FUNCTION_PARTS
                .iter()
                .any(|part| lowered.contains(part));
            if verdict == "ALLOWED" && strict && !read_only_by_inspection(&lowered) {
                misses.push(format!("{label} {schema}.{name}"));
            }
        }
    }
    assert!(
        misses.is_empty(),
        "the gate allows functions that match a strict name part:\n{}",
        misses.join("\n")
    );
}

/// Columns that hold a password or a password hash, as the audit's credential test.
const CREDENTIAL_COLUMNS: &[&str] = &["umoptions", "rolpassword", "subconninfo", "passwd"];

/// Relations with those columns that the gate reads on purpose: PostgreSQL shows `********` in both.
const KEEP_READABLE_RELATIONS: &[(&str, &str)] =
    &[("pg_catalog", "pg_roles"), ("pg_catalog", "pg_user")];

#[tokio::test]
async fn relation_audit_of_credential_columns_on_pg19() {
    let sql = "SELECT c.table_schema, c.table_name, string_agg(c.column_name, ',' ORDER BY c.column_name) \
         FROM information_schema.columns c \
         WHERE c.table_schema IN ('pg_catalog', 'information_schema') \
           AND c.column_name ~* '(password|passwd|conninfo|options|rolpassword|subconninfo|umoptions|srvoptions|ftoptions)' \
         GROUP BY c.table_schema, c.table_name ORDER BY 1, 2";
    let mut misses = Vec::new();
    for row in superuser_rows(PORT_19, sql).await {
        let (schema, table, columns) = (&row[0], &row[1], &row[2]);
        let sql = format!("SELECT * FROM {}.{}", quoted(schema), quoted(table));
        let verdict = match check(&sql, &GateOptions::default()) {
            Ok(_) => "readable",
            Err(rejection) if rejection.code == "relation_denied" => "denied",
            Err(rejection) => panic!("unexpected rejection of {sql}: {rejection:?}"),
        };
        println!("{schema}.{table} [{columns}] -> {verdict}");
        let holds_credential = columns
            .split(',')
            .any(|column| CREDENTIAL_COLUMNS.contains(&column));
        let kept = KEEP_READABLE_RELATIONS
            .iter()
            .any(|(s, t)| *s == schema.as_str() && *t == table.as_str());
        if holds_credential && verdict == "readable" && !kept {
            misses.push(format!("{schema}.{table}"));
        }
    }
    assert!(
        misses.is_empty(),
        "the gate reads relations that hold a credential column:\n{}",
        misses.join("\n")
    );
    for (schema, table) in KEEP_READABLE_RELATIONS {
        let column = if *table == "pg_roles" {
            "rolpassword"
        } else {
            "passwd"
        };
        let unmasked = superuser_scalar(
            PORT_19,
            &format!(
                "SELECT count(*) FROM {schema}.{table} WHERE {column} IS NOT NULL AND {column} <> '********'"
            ),
        )
        .await;
        assert_eq!(unmasked, "0", "{schema}.{table}.{column} shows a value");
    }
}

/// Every view and materialized view with its definition on one line, for the closure below.
const VIEW_DEFINITIONS_SQL: &str = "SELECT n.nspname, c.relname, replace(pg_catalog.pg_get_viewdef(c.oid, true), chr(10), ' ') \
     FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
     WHERE c.relkind IN ('v', 'm') AND n.nspname <> 'pg_toast' ORDER BY 1, 2";

/// Views that read a credential catalog and show no credential. Each is proven by the column names it has.
const KEEP_VIEWS: &[(&str, &str)] = &[
    (
        "information_schema._pg_foreign_table_columns",
        "foreign table column options, not server or mapping options",
    ),
    (
        "information_schema._pg_foreign_tables",
        "foreign table names and options, not server or mapping options",
    ),
    (
        "information_schema.administrable_role_authorizations",
        "role names and the admin flag",
    ),
    (
        "information_schema.applicable_roles",
        "role names and the inherit flag",
    ),
    (
        "information_schema.column_options",
        "foreign table column options",
    ),
    (
        "information_schema.column_privileges",
        "privilege and object names",
    ),
    ("information_schema.enabled_roles", "role names"),
    (
        "information_schema.foreign_table_options",
        "foreign table options",
    ),
    ("information_schema.foreign_tables", "foreign table names"),
    (
        "information_schema.role_column_grants",
        "privilege and object names",
    ),
    (
        "information_schema.role_routine_grants",
        "privilege and object names",
    ),
    (
        "information_schema.role_table_grants",
        "privilege and object names",
    ),
    (
        "information_schema.role_udt_grants",
        "privilege and object names",
    ),
    (
        "information_schema.role_usage_grants",
        "privilege and object names",
    ),
    (
        "information_schema.routine_privileges",
        "privilege and object names",
    ),
    ("information_schema.schemata", "schema names and owners"),
    (
        "information_schema.table_privileges",
        "privilege and object names",
    ),
    (
        "information_schema.udt_privileges",
        "privilege and object names",
    ),
    (
        "information_schema.usage_privileges",
        "privilege and object names",
    ),
    (
        "information_schema.user_mappings",
        "mapping owner and server name, without the options",
    ),
    ("pg_catalog.pg_group", "group names and member ids"),
    (
        "pg_catalog.pg_policies",
        "policy names and expressions the owner wrote",
    ),
    ("pg_catalog.pg_prepared_xacts", "transaction ids and owners"),
    ("pg_catalog.pg_seclabels", "security label names"),
    (
        "pg_catalog.pg_stat_activity",
        "session state; the query column is not a credential catalog",
    ),
    (
        "pg_catalog.pg_stat_replication",
        "replication positions and client addresses",
    ),
    (
        "pg_catalog.pg_stat_subscription",
        "subscription progress without the connection string",
    ),
    (
        "pg_catalog.pg_stat_subscription_stats",
        "subscription counters",
    ),
    ("public.geometry_columns", "table and column names"),
    ("timescaledb_information.job_stats", "job run statistics"),
];

/// Views whose credential column PostgreSQL masks as `********`; proven by counting unmasked values.
const MASKED_VIEWS: &[(&str, &str, &str)] = &[
    ("pg_catalog", "pg_roles", "rolpassword"),
    ("pg_catalog", "pg_user", "passwd"),
];

/// Splits the view names that the definition text mentions as whole words.
fn mentions(text: &str, word: &str) -> bool {
    let identifier = |c: char| c.is_ascii_alphanumeric() || c == '_';
    text.match_indices(word).any(|(at, _)| {
        let before = text[..at].chars().next_back().is_some_and(identifier);
        let after = text[at + word.len()..]
            .chars()
            .next()
            .is_some_and(identifier);
        !before && !after
    })
}

/// Views that read a root, directly or through another such view. PostgreSQL records no dependency on a
/// pinned catalog, so the closure is taken from the definition text; it may include extra views.
fn reached_views(rows: &[Vec<String>]) -> Vec<(String, String)> {
    let mut reached = vec![false; rows.len()];
    let mut names: Vec<String> = credential_roots().into_iter().map(str::to_owned).collect();
    loop {
        let mut changed = false;
        for (index, row) in rows.iter().enumerate() {
            if reached[index] || !names.iter().any(|name| mentions(&row[2], name)) {
                continue;
            }
            reached[index] = true;
            changed = true;
            names.push(row[1].clone());
        }
        if !changed {
            break;
        }
    }
    rows.iter()
        .zip(reached)
        .filter(|(_, hit)| *hit)
        .map(|(row, _)| (row[0].clone(), row[1].clone()))
        .collect()
}

/// The gate's verdict for a read of one relation: denied, rewritten, or readable as it is.
fn view_verdict(schema: &str, name: &str) -> &'static str {
    let sql = format!("SELECT * FROM {}.{}", quoted(schema), quoted(name));
    match check(&sql, &GateOptions::default()) {
        Ok(accepted) if accepted.rewritten => "rewritten",
        Ok(_) => "readable",
        Err(rejection) if rejection.code == "relation_denied" => "denied",
        Err(rejection) => panic!("unexpected rejection of {sql}: {rejection:?}"),
    }
}

#[tokio::test]
async fn views_over_credential_catalogs_are_denied_rewritten_or_proven() {
    let mut misses = Vec::new();
    for (port, label) in AUDIT_SERVERS {
        let rows = superuser_rows(port, VIEW_DEFINITIONS_SQL).await;
        let reached = reached_views(&rows);
        println!(
            "== server {label}: {} views reach a credential catalog",
            reached.len()
        );
        for (schema, name) in reached {
            let verdict = view_verdict(&schema, &name);
            println!("{schema}.{name} -> {verdict}");
            if verdict != "readable" {
                continue;
            }
            if let Some((_, _, column)) = MASKED_VIEWS
                .iter()
                .find(|(s, t, _)| *s == schema && *t == name)
            {
                let unmasked = superuser_scalar(
                    port,
                    &format!(
                        "SELECT count(*) FROM {schema}.{name} WHERE {column} IS NOT NULL AND {column} <> '********'"
                    ),
                )
                .await;
                assert_eq!(unmasked, "0", "{schema}.{name}.{column} shows a value");
                continue;
            }
            let kept = KEEP_VIEWS
                .iter()
                .any(|(view, _)| *view == format!("{schema}.{name}"));
            if !kept {
                misses.push(format!("{label} {schema}.{name}"));
                continue;
            }
            let credential_columns = superuser_scalar(
                port,
                &format!(
                    "SELECT count(*) FROM information_schema.columns WHERE table_schema = '{schema}' \
                     AND table_name = '{name}' AND column_name ~ 'password|passwd|conninfo|umoptions|srvoptions|rolpassword'"
                ),
            )
            .await;
            assert_eq!(
                credential_columns, "0",
                "{schema}.{name} has a credential column"
            );
        }
    }
    assert!(
        misses.is_empty(),
        "views read a credential catalog and are neither denied, rewritten nor kept:\n{}",
        misses.join("\n")
    );
}

/// Name parts of a function that could return stored values of a table or its statistics.
const STORED_VALUE_PARTS: [&str; 7] = [
    "stats",
    "statistic",
    "to_xml",
    "to_json",
    "relation",
    "page",
    "tuple",
];

/// Matching functions the gate allows on purpose, with the reason. A trailing `_` makes the entry a prefix.
const READ_ONLY_NAMED: &[(&str, &str)] = &[
    (
        "pg_stat_get_",
        "server counters and activity, no table values",
    ),
    (
        "pg_relation_",
        "sizes, paths and flags of a relation, no values",
    ),
    ("pg_total_relation_size", "size of a relation"),
    (
        "pg_filenode_relation",
        "maps a file node to a relation name",
    ),
    (
        "pg_get_statisticsobjdef",
        "definitions of extended statistics objects",
    ),
    (
        "pg_get_statisticsobjdef_columns",
        "column names of a statistics object",
    ),
    (
        "pg_get_statisticsobjdef_expressions",
        "expressions of a statistics object",
    ),
    ("pg_statistics_obj_is_visible", "boolean visibility check"),
    (
        "pg_stat_have_stats",
        "boolean: whether the server holds counters for an object",
    ),
    (
        "pg_get_multixact_stats",
        "multixact usage counters, no table values",
    ),
    ("to_json", "converts a value that the caller passes in"),
    ("to_jsonb", "converts a value that the caller passes in"),
    ("row_to_json", "converts a row that the caller passes in"),
    (
        "array_to_json",
        "converts an array that the caller passes in",
    ),
    (
        "hstore_to_json",
        "converts an hstore that the caller passes in",
    ),
    (
        "hstore_to_json_loose",
        "converts an hstore that the caller passes in",
    ),
    (
        "hstore_to_jsonb",
        "converts an hstore that the caller passes in",
    ),
    (
        "hstore_to_jsonb_loose",
        "converts an hstore that the caller passes in",
    ),
    ("relation_size", "size of a relation, TimescaleDB internal"),
    (
        "relation_approximate_size",
        "approximate size of a relation, TimescaleDB internal",
    ),
    (
        "chunk_compression_stats",
        "compression counters of hypertable chunks",
    ),
    (
        "hypertable_compression_stats",
        "compression counters of a hypertable",
    ),
    (
        "chunk_columnstore_stats",
        "columnstore counters of hypertable chunks",
    ),
    (
        "hypertable_columnstore_stats",
        "columnstore counters of a hypertable",
    ),
    (
        "compressed_chunk_local_stats",
        "compression counters of a chunk, TimescaleDB internal",
    ),
    (
        "compressed_chunk_remote_stats",
        "compression counters of a chunk, TimescaleDB internal",
    ),
];

/// Every function whose name has a stored-value part is denied by the gate or is on READ_ONLY_NAMED.
#[tokio::test]
async fn functions_named_for_stored_values_are_denied_or_read_only() {
    let mut misses = Vec::new();
    for (port, label) in AUDIT_SERVERS {
        for row in superuser_rows(port, FUNCTION_NAMES_SQL).await {
            let (schema, name) = (&row[0], &row[1]);
            let lowered = name.to_ascii_lowercase();
            if !STORED_VALUE_PARTS.iter().any(|part| lowered.contains(part)) {
                continue;
            }
            let verdict = function_verdict(schema, name);
            println!("{label} {schema}.{name} -> {verdict}");
            let listed = READ_ONLY_NAMED
                .iter()
                .any(|(entry, _)| match entry.strip_suffix('_') {
                    Some(prefix) => lowered.starts_with(prefix),
                    None => lowered == *entry,
                });
            if verdict == "ALLOWED" && !listed {
                misses.push(format!("{label} {schema}.{name}"));
            }
        }
    }
    assert!(
        misses.is_empty(),
        "functions named for stored values are allowed and not listed:\n{}",
        misses.join("\n")
    );
}

/// Servers with the credential seeds; the TLS server has none.
const SEEDED_SERVERS: [(u16, &str); 3] =
    [(PORT_18, "15432"), (PORT_19, "15433"), (PORT_15, "15434")];

/// The sampled password hashes of pg_authid sit in pg_statistic, and large values there are stored out of line.
/// Superuser SQL here checks the seeds, so the connection bypasses the gate by design.
#[tokio::test]
async fn sampled_password_hashes_are_stored_out_of_line() {
    for (port, label) in SEEDED_SERVERS {
        let sql = if superuser_scalar(
            port,
            "SELECT current_setting('server_version_num')::int >= 170000",
        )
        .await
            == "t"
        {
            "SELECT count(*) > 0 FROM pg_catalog.pg_statistic s WHERE s.starelid = 'pg_catalog.pg_authid'::regclass \
             AND (pg_column_toast_chunk_id(s.stavalues1) IS NOT NULL OR pg_column_toast_chunk_id(s.stavalues2) IS NOT NULL \
             OR pg_column_toast_chunk_id(s.stavalues3) IS NOT NULL OR pg_column_toast_chunk_id(s.stavalues4) IS NOT NULL \
             OR pg_column_toast_chunk_id(s.stavalues5) IS NOT NULL)"
        } else {
            "SELECT count(*) > 0 FROM pg_toast.pg_toast_2619"
        };
        assert_eq!(
            superuser_scalar(port, sql).await,
            "t",
            "{label}: no out-of-line statistics"
        );
    }
}

/// The TOAST table of each credential root is refused by name, in both spellings, and each one is listed.
#[tokio::test]
async fn toast_tables_of_every_credential_root_are_refused() {
    let roots = credential_roots();
    let list = roots
        .iter()
        .map(|root| format!("'{root}'"))
        .collect::<Vec<_>>()
        .join(",");
    for (port, label) in SEEDED_SERVERS {
        println!("== server {label}");
        let sql = format!(
            "SELECT r.relname, COALESCE(t.relname, '') FROM pg_catalog.pg_class r \
             LEFT JOIN pg_catalog.pg_class t ON t.oid = r.reltoastrelid \
             WHERE r.relnamespace = 'pg_catalog'::regnamespace AND r.relname IN ({list}) ORDER BY 1"
        );
        let rows = superuser_rows(port, &sql).await;
        assert_eq!(rows.len(), roots.len(), "{label}: every root exists");
        let mut with_toast = 0;
        for row in rows {
            let (root, toast) = (&row[0], &row[1]);
            if toast.is_empty() {
                println!("{root} -> no TOAST table");
                continue;
            }
            with_toast += 1;
            let qualified = format!("SELECT count(*) FROM pg_toast.{toast}");
            let plain = format!("SELECT count(*) FROM {toast}");
            for sql in [qualified, plain] {
                let rejection = check(&sql, &GateOptions::default()).expect_err(&sql);
                assert_eq!(rejection.code, "relation_denied", "{label} {sql}");
                assert_eq!(
                    rejection.message,
                    "TOAST tables are not readable through this server. Read the table they belong to.",
                    "{label} {sql}"
                );
            }
            println!("{root} -> {toast} refused");
        }
        assert!(
            with_toast >= 2,
            "{label}: expected TOAST tables for pg_statistic and pg_authid"
        );
    }
}
