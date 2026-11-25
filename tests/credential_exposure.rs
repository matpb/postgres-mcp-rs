//! Credential exposure matrix: no role on any test server gets a password hash or a stored connection
//! password through any path, and the legitimate statistics rows still come back.

mod common;

use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

use axum::Router;
use common::{
    PORT_15, PORT_18, PORT_19, PROTOCOL_2025, app, call_tool, config_with, db_entry, one_db,
    post_mcp, result_of,
};
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection};
use serde_json::{Value, json};
/// Test servers as (name, port).
const SERVERS: [(&str, u16); 3] = [("15432", PORT_18), ("15433", PORT_19), ("15434", PORT_15)];
/// Roles as (name, password). mcp_ro holds pg_read_all_data; postgres is the superuser.
const ROLES: [(&str, &str); 4] = [
    ("mcp_ro", "test-only-ro"),
    ("mcp_recipe", "test-only-recipe"),
    ("mcp_strict", "test-only-strict"),
    ("postgres", "test-only-superuser"),
];
/// Text that must never reach a client: the salt and keys of every seeded SCRAM verifier and the md5 digits,
/// read as superuser, so a fragment without its prefix is caught too.
async fn needles() -> &'static [String] {
    static NEEDLES: tokio::sync::OnceCell<Vec<String>> = tokio::sync::OnceCell::const_new();
    NEEDLES.get_or_init(load_needles).await.as_slice()
}

async fn load_needles() -> Vec<String> {
    let mut out: Vec<String> = [
        "SCRAM-SHA-256",
        "test-only-ro",
        "test-only-superuser",
        "test-only-recipe",
        "test-only-strict",
    ]
    .iter()
    .map(|text| (*text).to_owned())
    .collect();
    for (_, port) in SERVERS {
        let verifiers = superuser_rows(
            port,
            "SELECT rolpassword FROM pg_catalog.pg_authid WHERE rolpassword LIKE 'SCRAM-SHA-256$%' \
             UNION ALL SELECT doc->>'scram' FROM app.leaky",
        )
        .await;
        for row in verifiers {
            out.extend(scram_parts(&row[0]));
        }
        for row in superuser_rows(
            port,
            "SELECT substr(doc->>'md5', 4) FROM app.leaky WHERE doc->>'md5' LIKE 'md5%'",
        )
        .await
        {
            out.push(row[0].clone());
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The salt and the two keys of a SCRAM verifier; the iteration count and the method name are not secret.
fn scram_parts(verifier: &str) -> Vec<String> {
    verifier
        .split(['$', ':'])
        .filter(|part| part.len() >= 8 && *part != "SCRAM-SHA-256")
        .map(str::to_owned)
        .collect()
}

/// The status of a path where the scrubber had to replace text: the gate or the filter let it through.
const SCRUBBER_CAUGHT: &str = "scrubber replaced text";

/// One way to ask the server for catalog data.
enum Path {
    Tool(&'static str, Value),
    Resource(&'static str),
}

fn paths() -> Vec<(&'static str, Path)> {
    let query = |sql: &'static str| Path::Tool("execute_query", json!({ "sql": sql }));
    let explain = |sql: &'static str| Path::Tool("explain_query", json!({ "sql": sql }));
    vec![
        (
            "pg_authid.rolpassword",
            query("SELECT rolpassword FROM pg_authid"),
        ),
        ("pg_shadow.passwd", query("SELECT passwd FROM pg_shadow")),
        (
            "pg_user_mapping.umoptions",
            query("SELECT umoptions FROM pg_user_mapping"),
        ),
        (
            "pg_user_mappings",
            query("SELECT umoptions FROM pg_user_mappings"),
        ),
        (
            "_pg_user_mappings",
            query("SELECT umoptions FROM information_schema._pg_user_mappings"),
        ),
        (
            "user_mapping_options",
            query("SELECT option_value FROM information_schema.user_mapping_options"),
        ),
        (
            "pg_toast.pg_toast_2619 raw",
            query("SELECT chunk_data FROM pg_toast.pg_toast_2619"),
        ),
        (
            "pg_toast.pg_toast_2619 base64",
            query("SELECT encode(chunk_data, 'base64') FROM pg_toast.pg_toast_2619"),
        ),
        (
            "pg_toast.pg_toast_2619 convert_from",
            query("SELECT convert_from(chunk_data, 'UTF8') FROM pg_toast.pg_toast_2619"),
        ),
        (
            "pg_toast.pg_toast_1260 raw",
            query("SELECT chunk_data FROM pg_toast.pg_toast_1260"),
        ),
        (
            "pg_stats pg_authid rows",
            query("SELECT * FROM pg_stats WHERE tablename = 'pg_authid'"),
        ),
        (
            "pg_stats pg_user_mapping rows",
            query("SELECT * FROM pg_stats WHERE tablename = 'pg_user_mapping'"),
        ),
        (
            "pg_stats mcv and histogram",
            query("SELECT most_common_vals::text, histogram_bounds::text FROM pg_stats"),
        ),
        ("pg_stats_ext all rows", query("SELECT * FROM pg_stats_ext")),
        (
            "pg_stats_ext_exprs all rows",
            query("SELECT * FROM pg_stats_ext_exprs"),
        ),
        ("pg_statistic", query("SELECT * FROM pg_statistic")),
        (
            "pg_statistic_ext_data",
            query("SELECT * FROM pg_statistic_ext_data"),
        ),
        (
            "error: histogram_bounds cast",
            query("SELECT * FROM pg_stats WHERE histogram_bounds::text::int8 = 1"),
        ),
        (
            "error: most_common_vals cast",
            query("SELECT * FROM pg_stats WHERE most_common_vals::text::int8 = 1"),
        ),
        (
            "pg_stats pg_authid mcv and histogram",
            query(
                "SELECT most_common_vals::text, histogram_bounds::text FROM pg_stats WHERE tablename = 'pg_authid'",
            ),
        ),
        (
            "error: pg_authid histogram cast",
            query(
                "SELECT * FROM pg_stats WHERE tablename = 'pg_authid' AND histogram_bounds::text::int8 = 1",
            ),
        ),
        (
            "error: pg_authid mcv cast",
            query(
                "SELECT * FROM pg_stats WHERE tablename = 'pg_authid' AND most_common_vals::text::int8 = 1",
            ),
        ),
        (
            "error: rolpassword histogram cast",
            query(
                "SELECT * FROM pg_stats WHERE attname = 'rolpassword' AND histogram_bounds::text::int8 = 1",
            ),
        ),
        (
            "error: pg_authid rolpassword cast",
            query(
                "SELECT * FROM pg_stats WHERE tablename = 'pg_authid' AND attname = 'rolpassword' AND histogram_bounds::text::int8 = 1",
            ),
        ),
        ("quoted \"pg_stats\"", query("SELECT * FROM \"pg_stats\"")),
        (
            "pg_catalog.pg_stats",
            query("SELECT * FROM pg_catalog.pg_stats"),
        ),
        (
            "pg_catalog.\"pg_stats\"",
            query("SELECT * FROM pg_catalog.\"pg_stats\""),
        ),
        ("PG_STATS", query("SELECT * FROM PG_STATS")),
        (
            "pg_stats in a JOIN",
            query(
                "SELECT s.histogram_bounds::text FROM (SELECT 1) AS x JOIN pg_stats AS s ON true",
            ),
        ),
        (
            "pg_stats in a subquery",
            query("SELECT * FROM (SELECT * FROM pg_stats) AS q"),
        ),
        (
            "pg_stats in a CTE body",
            query("WITH q AS (SELECT * FROM pg_stats) SELECT * FROM q"),
        ),
        (
            "pg_stats in a LATERAL",
            query("SELECT * FROM (SELECT 1) AS x, LATERAL (SELECT * FROM pg_stats) AS s"),
        ),
        (
            "EXPLAIN ANALYZE pg_stats",
            query("EXPLAIN (ANALYZE) SELECT * FROM pg_stats"),
        ),
        ("explain_query pg_stats", explain("SELECT * FROM pg_stats")),
        (
            "explain_query error cast",
            explain("SELECT * FROM pg_stats WHERE histogram_bounds::text::int8 = 1"),
        ),
        (
            "explain_query generic plan",
            Path::Tool(
                "explain_query",
                json!({ "sql": "SELECT * FROM pg_stats WHERE tablename = $1", "generic_plan": true }),
            ),
        ),
        (
            "(a).rolpassword",
            query("SELECT (a).rolpassword FROM pg_authid a"),
        ),
        (
            "whole row a from pg_stats",
            query("SELECT a FROM pg_stats a"),
        ),
        (
            "s.histogram_bounds",
            query("SELECT s.histogram_bounds FROM pg_stats s"),
        ),
        ("(s).* from pg_stats", query("SELECT (s).* FROM pg_stats s")),
        ("to_jsonb(s)", query("SELECT to_jsonb(s) FROM pg_stats s")),
        (
            "row_to_json(pg_stats)",
            query("SELECT row_to_json(pg_stats) FROM pg_stats"),
        ),
        (
            "describe_table pg_authid",
            Path::Tool("describe_table", json!({ "table": "pg_catalog.pg_authid" })),
        ),
        (
            "describe_table pg_stats",
            Path::Tool("describe_table", json!({ "table": "pg_catalog.pg_stats" })),
        ),
        (
            "search_schema pg_authid",
            Path::Tool("search_schema", json!({ "query": "pg_authid" })),
        ),
        (
            "resource pg_authid",
            Path::Resource("postgres://appdb/pg_catalog/pg_authid"),
        ),
        (
            "resource pg_stats",
            Path::Resource("postgres://appdb/pg_catalog/pg_stats"),
        ),
    ]
}

/// A router that connects to one server as one role.
fn router_for(port: u16, role: &str, password: &str) -> Router {
    let mut entry = db_entry("appdb", port);
    entry["user"] = json!(role);
    entry["password"] = json!(password);
    app(config_with(&[entry], &[]))
}

/// The superuser's rows for a query, as text cells.
fn superuser_config(port: u16) -> ConnectConfig {
    ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: "appdb".into(),
        user: "postgres".into(),
        password: Some("test-only-superuser".into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: std::time::Duration::from_secs(5),
        startup_params: Vec::new(),
    }
}

/// The superuser's rows for a query, as text cells.
async fn superuser_rows(port: u16, sql: &str) -> Vec<Vec<String>> {
    let config = superuser_config(port);
    let mut conn = Connection::connect(&config)
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

/// What one call came back with, in the words of the premise table. The scrubber's own marker or count
/// means the gate and the filter let the text through, which the matrix reports as its own status.
fn outcome(response: &Value, needles: &[String]) -> String {
    let text = response.to_string();
    if needles.iter().any(|needle| text.contains(needle.as_str())) {
        return "leaks".to_owned();
    }
    let redacted = response["result"]["structuredContent"]["redactedHashes"]
        .as_u64()
        .unwrap_or(0);
    if text.contains(REDACTED) || redacted > 0 {
        return SCRUBBER_CAUGHT.to_owned();
    }
    let Some(result) = response.get("result") else {
        return format!("error: {}", text.chars().take(60).collect::<String>());
    };
    if result.get("isError") == Some(&json!(true)) {
        let message = result["content"][0]["text"].as_str().unwrap_or_default();
        if message.starts_with("Query rejected") {
            return "refused by gate".to_owned();
        }
        if let Some(rest) = message.strip_prefix("PostgreSQL error ") {
            return format!(
                "refused by PostgreSQL ({})",
                rest.chars().take(5).collect::<String>()
            );
        }
        return format!("error: {}", message.chars().take(60).collect::<String>());
    }
    let truncated = result["structuredContent"]["truncated"] == json!(true);
    match result["structuredContent"]["rows"].as_array() {
        Some(rows) if rows.is_empty() => "no rows".to_owned(),
        Some(rows) if truncated => format!("rows, no hash, truncated ({})", rows.len()),
        Some(rows) => format!("rows, no hash ({})", rows.len()),
        None => "answered, no hash".to_owned(),
    }
}

async fn run(router: &Router, path: &Path) -> Value {
    match path {
        Path::Tool(name, args) => call_tool(router, name, args.clone()).await,
        Path::Resource(uri) => {
            let body = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": &uri}});
            post_mcp(router, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
                .await
                .json()
        }
    }
}

/// Every (server, role, path) with its outcome.
async fn matrix(needles: &[String]) -> Vec<(String, String, &'static str, String)> {
    let mut cells = Vec::new();
    for (server, port) in SERVERS {
        for (role, password) in ROLES {
            let router = router_for(port, role, password);
            for (label, path) in paths() {
                let response = run(&router, &path).await;
                cells.push((
                    server.to_owned(),
                    role.to_owned(),
                    label,
                    outcome(&response, needles),
                ));
            }
        }
    }
    cells
}

#[tokio::test]
async fn no_role_gets_hashes_through_any_path() {
    let cells = matrix(needles().await).await;
    for (server, role, label, result) in &cells {
        eprintln!("PREMISE {server} {role} {label} -> {result}");
    }
    let named = |wanted: &str| -> Vec<String> {
        cells
            .iter()
            .filter(|(_, _, label, result)| {
                result == wanted || (wanted == "toast" && label.starts_with("pg_toast"))
            })
            .map(|(server, role, label, result)| format!("{server} {role} {label} -> {result}"))
            .collect()
    };
    let leaks = named("leaks");
    assert!(
        leaks.is_empty(),
        "credential text reached a client: {leaks:#?}"
    );
    let caught = named(SCRUBBER_CAUGHT);
    assert!(
        caught.is_empty(),
        "the scrubber replaced text on a path the gate or the filter should stop: {caught:#?}"
    );
    let toast_not_refused: Vec<String> = cells
        .iter()
        .filter(|(_, _, label, result)| {
            label.starts_with("pg_toast") && result != "refused by gate"
        })
        .map(|(server, role, label, result)| format!("{server} {role} {label} -> {result}"))
        .collect();
    assert!(
        toast_not_refused.is_empty(),
        "a TOAST table was not refused by the gate: {toast_not_refused:#?}"
    );
}

/// pg_stats_ext lists only tables the role owns, so the extended statistics check runs as their owner.
#[tokio::test]
async fn legitimate_statistics_rows_still_come_back() {
    for (_, port) in SERVERS {
        let reader = router_for(port, "mcp_ro", "test-only-ro");
        let stats = call_tool(
            &reader,
            "execute_query",
            json!({"sql": "SELECT attname FROM pg_stats WHERE schemaname = 'app' AND tablename = 'items'"}),
        )
        .await;
        let rows = result_of(&stats)["structuredContent"]["rows"]
            .as_array()
            .expect("rows");
        assert!(
            !rows.is_empty(),
            "pg_stats has no rows for app.items: {stats}"
        );

        let owner = router_for(port, "postgres", "test-only-superuser");
        let ext = call_tool(
            &owner,
            "execute_query",
            json!({"sql": "SELECT statistics_name FROM pg_stats_ext WHERE schemaname = 'app'"}),
        )
        .await;
        let names = result_of(&ext)["structuredContent"]["rows"].to_string();
        assert!(names.contains("items_stx"), "{ext}");
    }
}

#[derive(Clone)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("log buffer").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The text of a tool result: the structured content, which holds the same text as the text block.
fn result_text(response: &Value) -> String {
    response.to_string()
}

/// No hash and no stored password appears in the text.
fn assert_clean(text: &str, context: &str, needles: &[String]) {
    for needle in needles {
        assert!(
            !text.contains(needle.as_str()),
            "{context}: {needle} in {text}"
        );
    }
}

const REDACTED: &str = "[redacted password hash]";
const SCRAM_LITERAL: &str = "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5";

/// Planted in app.leaky: one SCRAM hash and one md5 hash in each of text, text[] and jsonb.
#[tokio::test]
async fn planted_hashes_are_redacted_in_text_array_and_json_cells() {
    let needles = needles().await;
    for (server, port) in SERVERS {
        for (role, password) in ROLES {
            let router = router_for(port, role, password);
            let response = call_tool(
                &router,
                "execute_query",
                json!({"sql": "SELECT note, tags, doc FROM app.leaky"}),
            )
            .await;
            let result = result_of(&response);
            assert_eq!(
                result["isError"],
                json!(false),
                "{server} {role}: {response}"
            );
            let row = &result["structuredContent"]["rows"][0];
            assert_eq!(
                row["note"],
                json!(format!("scram {REDACTED} md5 {REDACTED}")),
                "{server} {role}"
            );
            assert_eq!(row["tags"], json!([REDACTED, REDACTED]), "{server} {role}");
            assert_eq!(
                row["doc"],
                json!({"scram": REDACTED, "md5": REDACTED}),
                "{server} {role}"
            );
            assert_eq!(
                result["structuredContent"]["redactedHashes"],
                json!(6),
                "{server} {role}"
            );
            assert_clean(
                &result_text(&response),
                &format!("{server} {role}"),
                needles,
            );
        }
    }
}

/// The audit line counts the replacements and never shows them; the warn line names the tool and count.
#[tokio::test]
async fn the_audit_line_and_the_warn_line_count_the_replacements() {
    let needles = needles().await;
    logs();
    let mut entry = db_entry("appdb", PORT_18);
    entry["name"] = json!("audit_test");
    entry["user"] = json!("postgres");
    entry["password"] = json!("test-only-superuser");
    let router = app(config_with(&[entry], &[("AUDIT_LOG", "on")]));
    let start = log_len();
    let response = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT note FROM app.leaky"}),
    )
    .await;
    let lines = log_since(start);
    assert_eq!(
        response["result"]["structuredContent"]["redactedHashes"],
        json!(2)
    );
    assert_eq!(
        audit_count(&lines, "execute_query", "audit_test"),
        2,
        "{lines}"
    );
    assert!(
        lines.contains("redaction markers are present in a result") && lines.contains("count=2"),
        "{lines}"
    );
    assert_clean(&lines, "log text", needles);
}
#[tokio::test]
async fn a_literal_hash_in_a_result_is_redacted_and_counted() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let response = call_tool(
        &router,
        "execute_query",
        json!({"sql": format!("SELECT '{SCRAM_LITERAL}'::text AS v")}),
    )
    .await;
    let result = result_of(&response);
    assert_eq!(
        result["structuredContent"]["rows"][0]["v"],
        json!(REDACTED),
        "{response}"
    );
    assert_eq!(
        result["structuredContent"]["redactedHashes"],
        json!(1),
        "{response}"
    );
}

/// A cast error quotes the value; the quoted hash must not reach the client.
#[tokio::test]
async fn a_cast_error_that_quotes_a_planted_hash_is_redacted() {
    let needles = needles().await;
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_ro", "test-only-ro");
        let response = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT note::int FROM app.leaky"}),
        )
        .await;
        let result = result_of(&response);
        assert_eq!(result["isError"], json!(true), "{response}");
        let text = result["content"][0]["text"].as_str().expect("error text");
        assert!(
            text.contains(&format!("\"scram {REDACTED} md5 {REDACTED}\"")),
            "{text}"
        );
        assert_clean(text, "error text", needles);
    }
}

/// A value longer than the cap, cut inside a SCRAM hash: the cut text holds no part of the hash.
#[tokio::test]
async fn a_value_cut_inside_a_scram_hash_holds_no_part_of_it() {
    let needles = needles().await;
    let router = app(config_with(
        &[{
            let mut entry = db_entry("appdb", PORT_18);
            entry["user"] = json!("mcp_ro");
            entry["password"] = json!("test-only-ro");
            entry
        }],
        &[("MAX_VALUE_BYTES", "64")],
    ));
    let sql = format!("SELECT repeat('x', 50) || '{SCRAM_LITERAL}' AS v");
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let value = result_of(&response)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .expect("value")
        .to_owned();
    assert_eq!(
        value,
        format!("{}…[truncated: 50 of 87 bytes]", "x".repeat(50))
    );
    assert!(!value.replace(REDACTED, "").contains("[reda"), "{value}");
    assert_clean(&value, "cut value", needles);
}

/// A value cut inside an md5 hash keeps none of its hex digits.
#[tokio::test]
async fn a_value_cut_inside_an_md5_hash_holds_no_digits() {
    let needles = needles().await;
    let router = app(config_with(
        &[{
            let mut entry = db_entry("appdb", PORT_18);
            entry["user"] = json!("mcp_ro");
            entry["password"] = json!("test-only-ro");
            entry
        }],
        &[("MAX_VALUE_BYTES", "64")],
    ));
    let sql = "SELECT repeat('x', 58) || ' md5d41d8cd98f00b204e9800998ecf8427e' AS v";
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let value = result_of(&response)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .expect("value")
        .to_owned();
    assert_eq!(
        value,
        format!("{} …[truncated: 59 of 94 bytes]", "x".repeat(58))
    );
    assert!(!value.replace(REDACTED, "").contains("[reda"), "{value}");
    assert_clean(&value, "cut value", needles);
}

/// Other reads of the planted table return no hash text: search, describe and the table resource.
#[tokio::test]
async fn schema_tools_and_the_table_resource_show_no_planted_hash() {
    let needles = needles().await;
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_ro", "test-only-ro");
        for (name, args) in [
            ("search_schema", json!({"query": "leaky"})),
            ("describe_table", json!({"table": "app.leaky"})),
            ("table_stats", json!({"table": "app.leaky"})),
        ] {
            let response = call_tool(&router, name, args).await;
            assert_clean(&response.to_string(), name, needles);
        }
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": "postgres://appdb/app/leaky"}});
        let response = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
            .await
            .json();
        assert_clean(&response.to_string(), "table resource", needles);
    }
}

/// Every seeded table on 15432, read in full through execute_query, except the planted one: no replacement.
#[tokio::test]
async fn seeded_tables_have_no_false_positive_replacements() {
    let router = app(config_with(
        &[{
            let mut entry = db_entry("appdb", PORT_18);
            entry["user"] = json!("mcp_ro");
            entry["password"] = json!("test-only-ro");
            entry
        }],
        &[("MAX_ROWS", "100000")],
    ));
    let listing = superuser_rows(
        PORT_18,
        "SELECT n.nspname, c.relname FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE c.relkind IN ('r', 'p') AND n.nspname NOT LIKE 'pg\\_%' \
           AND n.nspname NOT LIKE '\\_timescaledb%' AND n.nspname <> 'information_schema' \
           AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
             WHERE d.classid = 'pg_catalog.pg_class'::regclass AND d.objid = c.oid AND d.deptype = 'e') \
           AND NOT (n.nspname = 'app' AND c.relname = 'leaky') \
           AND NOT (n.nspname = 'hashes' AND c.relname = 'hash_sources') \
         ORDER BY 1, 2",
    )
    .await;
    let (mut tables, mut rows, mut cells, mut replacements) = (0_usize, 0_usize, 0_usize, 0_usize);
    let mut masked = Vec::new();
    for row in &listing {
        let (schema, table) = (&row[0], &row[1]);
        let sql = format!("SELECT * FROM \"{schema}\".\"{table}\"");
        for cells_of_row in superuser_rows(PORT_18, &sql).await {
            for cell in cells_of_row {
                if postgres_mcp::tools::mask::mask(&cell) != cell {
                    masked.push(format!(
                        "{schema}.{table}: {}",
                        cell.chars().take(80).collect::<String>()
                    ));
                }
            }
        }
        let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
        let result = result_of(&response);
        assert_eq!(
            result["isError"],
            json!(false),
            "{schema}.{table}: {response}"
        );
        let content = &result["structuredContent"];
        assert_eq!(content["redactedHashes"], json!(0), "{schema}.{table}");
        replacements += content["redactedHashes"].as_u64().unwrap_or(0) as usize;
        let found = content["rows"].as_array().map_or(0, Vec::len);
        let columns = content["columns"].as_array().map_or(0, Vec::len);
        tables += 1;
        rows += found;
        cells += found * columns;
    }
    eprintln!(
        "FALSE_POSITIVE tables={tables} rows={rows} cells={cells} replacements={replacements} masked={}",
        masked.len()
    );
    assert!(
        masked.is_empty(),
        "the mask changes seeded cells: {masked:#?}"
    );
    assert!(tables > 0);
}

/// The output schema of every tool lists redactedHashes.
#[tokio::test]
async fn every_output_schema_lists_redacted_hashes() {
    let router = app(one_db(PORT_18, &[]));
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let response = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
        .await
        .json();
    let tools = result_of(&response)["tools"].as_array().expect("tools");
    assert!(!tools.is_empty());
    for tool in tools {
        let name = tool["name"].as_str().expect("name");
        let schema = &tool["outputSchema"];
        assert_eq!(
            schema["properties"]["redactedHashes"]["type"],
            json!("integer"),
            "{name}"
        );
        assert!(
            schema["required"]
                .as_array()
                .is_some_and(|required| required.contains(&json!("redactedHashes"))),
            "{name}"
        );
    }
}

/// An error in rewritten text reports no position, because the position would name the rewritten text.
#[tokio::test]
async fn positions_are_reported_only_for_text_that_ran_as_written() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let rewritten = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT nosuch FROM pg_stats"}),
    )
    .await;
    let text = result_of(&rewritten)["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    assert!(text.contains("column \"nosuch\" does not exist"), "{text}");
    assert!(!text.contains("Position:"), "{text}");
    let plain = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT nosuch FROM app.items"}),
    )
    .await;
    let text = result_of(&plain)["content"][0]["text"]
        .as_str()
        .expect("text")
        .to_owned();
    assert!(text.contains("Position: 8"), "{text}");
}

/// The caller's predicate stays on the outer Subquery Scan, so a PostgreSQL release that drops the OFFSET 0
/// fence fails here.
#[tokio::test]
async fn the_callers_predicate_stays_above_the_injected_filter() {
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_ro", "test-only-ro");
        let plan = call_tool(
            &router,
            "explain_query",
            json!({"sql": "SELECT * FROM pg_stats WHERE tablename = 'items'"}),
        )
        .await;
        let text = result_of(&plan)["structuredContent"]["plan"]
            .as_str()
            .expect("plan")
            .to_owned();
        assert!(text.starts_with("Subquery Scan on pg_stats"), "{text}");
        assert_eq!(text.matches("'items'").count(), 1, "{text}");
        assert!(
            text.contains("Filter: (pg_stats.tablename = 'items'::name)"),
            "{text}"
        );
    }
}

/// The rewritten text runs on every path; PostgreSQL 15 refuses the generic-plan form by its own option check.
#[tokio::test]
async fn the_rewritten_text_is_what_runs_on_every_path() {
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_ro", "test-only-ro");
        let count = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT count(*) AS n FROM pg_stats WHERE tablename = 'pg_authid'"}),
        )
        .await;
        assert_eq!(
            result_of(&count)["structuredContent"]["rows"][0]["n"],
            json!(0),
            "{count}"
        );
        let plan = call_tool(
            &router,
            "explain_query",
            json!({"sql": "SELECT * FROM pg_stats WHERE tablename = 'pg_authid'"}),
        )
        .await;
        let text = result_of(&plan)["structuredContent"]["plan"]
            .as_str()
            .expect("plan")
            .to_owned();
        assert!(text.contains("pg_user_mapping"), "{text}");
    }
    for port in [PORT_18, PORT_19] {
        let generic = call_tool(
            &router_for(port, "mcp_ro", "test-only-ro"),
            "explain_query",
            json!({"sql": "SELECT * FROM pg_stats WHERE tablename = $1", "generic_plan": true}),
        )
        .await;
        let text = result_of(&generic)["structuredContent"]["plan"]
            .as_str()
            .expect("plan")
            .to_owned();
        assert!(text.contains("pg_user_mapping"), "{text}");
    }
    let pg15 = call_tool(
        &router_for(PORT_15, "mcp_ro", "test-only-ro"),
        "explain_query",
        json!({"sql": "SELECT * FROM pg_stats WHERE tablename = $1", "generic_plan": true}),
    )
    .await;
    let message = pg15["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(message.contains("needs PostgreSQL 16 or newer"), "{pg15}");
}

/// The README recipe role reads app, including a table created after the role, and gets PostgreSQL's
/// refusal outside app; the monitoring tools work.
#[tokio::test]
async fn the_recipe_role_reads_what_the_recipe_grants_and_nothing_else() {
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_recipe", "test-only-recipe");
        let items = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT count(*) AS n FROM app.items"}),
        )
        .await;
        assert_eq!(
            result_of(&items)["structuredContent"]["rows"][0]["n"],
            json!(5000),
            "{items}"
        );

        let later = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT label FROM app.recipe_later"}),
        )
        .await;
        assert_eq!(
            result_of(&later)["structuredContent"]["rows"][0]["label"],
            json!("created after the role"),
            "{later}"
        );

        let outside = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT count(*) FROM shop.customers"}),
        )
        .await;
        let text = result_of(&outside)["content"][0]["text"]
            .as_str()
            .expect("error text")
            .to_owned();
        assert_eq!(result_of(&outside)["isError"], json!(true), "{outside}");
        assert!(text.starts_with("PostgreSQL error 42501: "), "{text}");

        for name in ["list_activity", "database_stats", "query_stats"] {
            let response = call_tool(&router, name, json!({})).await;
            assert_eq!(
                result_of(&response)["isError"],
                json!(false),
                "{name} on {port}: {response}"
            );
        }
    }
}

/// Every log line of this test binary, written through one global subscriber. Each scoped call is found by the
/// database name its config gives it, which no other test uses.
fn logs() -> Arc<Mutex<Vec<u8>>> {
    static LOGS: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();
    LOGS.get_or_init(|| {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let sink = buffer.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Sink(sink.clone()))
            .finish();
        tracing::subscriber::set_global_default(subscriber)
            .expect("one subscriber per test binary");
        buffer
    })
    .clone()
}

fn log_len() -> usize {
    logs().lock().expect("log buffer").len()
}

fn log_since(start: usize) -> String {
    let buffer = logs();
    let bytes = buffer.lock().expect("log buffer");
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

/// The hash the planted values are built from; the tool results must show it only as the marker.
const PLANTED: &str = "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5";

/// The arguments the every-tool test calls each tool with. A tool without a case fails the test.
fn arguments_for(name: &str) -> Value {
    match name {
        "list_databases"
        | "server_info"
        | "list_schemas"
        | "get_privileges"
        | "replication_status"
        | "database_stats"
        | "list_hypertables"
        | "list_continuous_aggregates"
        | "list_jobs" => json!({}),
        "execute_query" => json!({"sql": "SELECT 1 AS one"}),
        "explain_query" => json!({"sql": "SELECT 1"}),
        "list_objects" => json!({"schema": "app"}),
        "describe_table" => json!({"table": "hash_sources", "schema": "hashes"}),
        "describe_function" => json!({"function": "hash_body", "schema": "hashes"}),
        "search_schema" => json!({"query": "hash"}),
        "list_activity" => json!({"all_databases": true}),
        "query_stats" => json!({"limit": 5}),
        "table_stats" => json!({"schema": "hashes", "table": "hash_sources"}),
        "read_server_log" => json!({"limit": 50}),
        "describe_hypertable" => json!({"hypertable": "metrics.readings"}),
        other => panic!("no case for tool {other}"),
    }
}

/// The redactedHashes of a result: the field of a tool result, or the markers of an error text.
fn reported_count(response: &Value) -> Option<u64> {
    let result = response.get("result")?;
    if let Some(count) = result["structuredContent"]["redactedHashes"].as_u64() {
        return Some(count);
    }
    if result["isError"] == json!(true) {
        let text = result["content"][0]["text"].as_str()?;
        return Some(text.matches(REDACTED).count() as u64);
    }
    None
}

/// The redacted_hashes of the one audit line that this call wrote for its tool and its database name.
fn audit_count(lines: &str, tool: &str, database: &str) -> u64 {
    let tool_field = format!("tool=\"{tool}\"");
    let database_field = format!("database=\"{database}\"");
    let audits: Vec<&str> = lines
        .lines()
        .filter(|line| line.contains("audit") && line.contains(&tool_field))
        .filter(|line| line.contains(&database_field) || !line.contains("database="))
        .collect();
    assert_eq!(audits.len(), 1, "{tool}: one audit line expected\n{lines}");
    let rest = audits[0]
        .split("redacted_hashes=")
        .nth(1)
        .expect("redacted_hashes field");
    rest.chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .expect("count")
}

/// One call against its own audit and warn lines: no planted text, and the counts agree. Returns the count.
fn check_call(
    tool: &str,
    response: &Value,
    lines: &str,
    needles: &[String],
    database: &str,
) -> u64 {
    assert!(
        response.get("result").is_some(),
        "{tool}: protocol error {response}"
    );
    assert_clean(&response.to_string(), tool, needles);
    assert_clean(lines, &format!("{tool} log lines"), needles);
    let audited = audit_count(lines, tool, database);
    if let Some(reported) = reported_count(response) {
        assert_eq!(
            reported, audited,
            "{tool}: result and audit disagree\n{response}\n{lines}"
        );
    }
    if let Some(structured) = response["result"].get("structuredContent") {
        let text = structured.to_string();
        let markers = (text.matches(REDACTED).count() + text.matches(&marker_hex()).count()) as u64;
        assert_eq!(
            markers, audited,
            "{tool}: markers returned vs redactedHashes\n{response}"
        );
    }
    if audited > 0 {
        assert!(
            lines.lines().any(|line| {
                line.contains("redaction markers are present in a result")
                    && line.contains(tool)
                    && line.contains(&format!("count={audited}"))
            }),
            "{tool}: no warn line with count={audited}\n{lines}"
        );
    }
    audited
}

/// The marker's bytes in hex, as a bytea value shows them.
fn marker_hex() -> String {
    REDACTED.bytes().map(|b| format!("{b:02x}")).collect()
}

/// Holds one idle superuser session whose application_name and last query carry the planted hash.
async fn park_session() -> Connection {
    let mut config = superuser_config(PORT_18);
    config.startup_params = vec![("application_name".to_owned(), PLANTED.to_owned())];
    let mut conn = Connection::connect(&config)
        .await
        .expect("parked superuser connect");
    conn.simple_query(&format!("SELECT '{PLANTED}'::text"))
        .await
        .expect("parked query");
    conn
}

/// Tools whose results carry no text from the seeded fixtures: their count must be zero.
const NO_SEEDED_TEXT: &[&str] = &[
    "list_databases",
    "server_info",
    "list_schemas",
    "get_privileges",
    "replication_status",
    "database_stats",
    "list_hypertables",
    "list_continuous_aggregates",
    "list_jobs",
    "table_stats",
    "describe_hypertable",
];

/// Every tool, every resource and one completion on 15432 as the superuser: no planted text reaches the client,
/// the planted sources show the marker, and each call's counts agree with its own audit line.
#[tokio::test]
async fn every_tool_resource_and_completion_scrubs_and_counts_what_it_returns() {
    let needles = needles().await;
    logs();
    let _parked = park_session().await;
    const SCOPE: &str = "every_tool";
    let mut entry = db_entry("appdb", PORT_18);
    entry["name"] = json!(SCOPE);
    entry["user"] = json!("postgres");
    entry["password"] = json!("test-only-superuser");
    let router = app(config_with(&[entry], &[("AUDIT_LOG", "on")]));

    let listed = post_mcp(
        &router,
        &json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await
    .json();
    let names: Vec<String> = result_of(&listed)["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name").to_owned())
        .collect();
    assert!(!names.is_empty());
    for name in &names {
        let start = log_len();
        let response = call_tool(&router, name, arguments_for(name)).await;
        let audited = check_call(name, &response, &log_since(start), needles, SCOPE);
        if NO_SEEDED_TEXT.contains(&name.as_str()) {
            assert_eq!(
                audited, 0,
                "{name} has no seeded text to replace: {response}"
            );
        }
    }

    // The failing statement puts a hash past the 4096-byte cut of its log line, where a cut could split it.
    let failing = format!("SELECT '{}{PLANTED}'::int", "x".repeat(4080));
    let _ = call_tool(&router, "execute_query", json!({ "sql": failing })).await;
    let _ = call_tool(
        &router,
        "execute_query",
        json!({"sql": format!("SELECT '{PLANTED}'::int")}),
    )
    .await;
    let _ = call_tool(
        &router,
        "execute_query",
        json!({"sql": format!("SELECT 1 AS \"{PLANTED}\" FROM pg_database LIMIT 1")}),
    )
    .await;
    let planted = [
        (
            "describe_table",
            json!({"table": "hash_sources", "schema": "hashes"}),
        ),
        (
            "describe_table",
            json!({"table": "hash_view", "schema": "hashes"}),
        ),
        (
            "describe_function",
            json!({"function": "hash_body", "schema": "hashes"}),
        ),
        (
            "execute_query",
            json!({"sql": format!("SELECT label, \"{PLANTED}\" FROM hashes.hash_sources")}),
        ),
        (
            "execute_query",
            json!({"sql": "SELECT label::int FROM hashes.hash_sources"}),
        ),
        (
            "explain_query",
            json!({"sql": format!("SELECT * FROM hashes.hash_sources WHERE label = '{PLANTED}'")}),
        ),
        ("list_activity", json!({"all_databases": true})),
        ("search_schema", json!({"query": "hash"})),
        ("list_objects", json!({"schema": "hashes"})),
        (
            "read_server_log",
            json!({"contains": "invalid input syntax for type integer", "limit": 50}),
        ),
        (
            "query_stats",
            json!({"contains": "pg_database LIMIT", "limit": 5}),
        ),
    ];
    for (tool, args) in planted {
        let start = log_len();
        let response = call_tool(&router, tool, args).await;
        let audited = check_call(tool, &response, &log_since(start), needles, SCOPE);
        assert!(audited > 0, "{tool} should show a planted hash: {response}");
        assert!(
            response.to_string().contains(REDACTED),
            "{tool}: {response}"
        );
    }
    let mut logged = false;
    for _ in 0..50 {
        let start = log_len();
        let response = call_tool(
            &router,
            "read_server_log",
            json!({"contains": "invalid input syntax", "limit": 50}),
        )
        .await;
        check_call(
            "read_server_log",
            &response,
            &log_since(start),
            needles,
            SCOPE,
        );
        if response.to_string().contains(REDACTED) {
            logged = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(logged, "the failing statement never reached the server log");

    for uri in [
        format!("postgres://{SCOPE}"),
        format!("postgres://{SCOPE}/app"),
        format!("postgres://{SCOPE}/hashes/hash_sources"),
        format!("postgres://{SCOPE}/hashes/hash_view"),
        format!("postgres://{SCOPE}/app/leaky"),
    ] {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": uri}});
        let start = log_len();
        let response = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
            .await
            .json();
        let label = match uri.matches('/').count() {
            2 => "resource:database",
            3 => "resource:schema",
            _ => "resource:table",
        };
        check_call(label, &response, &log_since(start), needles, SCOPE);
    }

    let completion = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "completion/complete",
        "params": {
            "ref": {"type": "ref/resource", "uri": "postgres://{database}/{schema}"},
            "argument": {"name": "schema", "value": "a"},
        },
    });
    let start = log_len();
    let response = post_mcp(
        &router,
        &completion,
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await
    .json();
    check_call("completion", &response, &log_since(start), needles, SCOPE);
}

/// A filter for a hash finds nothing: the filter runs on the redacted text, so no line with the marker comes back.
#[tokio::test]
async fn a_log_filter_for_a_hash_matches_nothing() {
    let needles = needles().await;
    let router = router_for(PORT_18, "postgres", "test-only-superuser");
    let _ = call_tool(
        &router,
        "execute_query",
        json!({"sql": format!("SELECT '{PLANTED}'::int")}),
    )
    .await;
    let shown = call_tool(
        &router,
        "read_server_log",
        json!({"contains": "invalid input syntax for type integer", "limit": 50}),
    )
    .await;
    assert!(shown.to_string().contains(REDACTED), "{shown}");
    let filtered = call_tool(
        &router,
        "read_server_log",
        json!({"contains": "c2FsdA==", "limit": 50}),
    )
    .await;
    assert_eq!(
        result_of(&filtered)["structuredContent"]["entries"],
        json!([]),
        "{filtered}"
    );
    assert_clean(&filtered.to_string(), "log filter", needles);
}

/// A hash in a log message is replaced before the 4096-byte cut, and the cut never leaves part of the marker.
#[tokio::test]
async fn a_hash_at_the_log_message_cut_is_not_returned_whole_or_in_part() {
    let needles = needles().await;
    let router = router_for(PORT_18, "postgres", "test-only-superuser");
    for (count, label) in [(4080, "past the cut"), (4050, "across the cut")] {
        let token = format!("uniq{count}");
        let failing = format!("SELECT '{token}{}{PLANTED}'::int", "x".repeat(count));
        let _ = call_tool(&router, "execute_query", json!({ "sql": failing })).await;
        let shown = call_tool(
            &router,
            "read_server_log",
            json!({"contains": token, "limit": 5}),
        )
        .await;
        let text = shown.to_string();
        assert_clean(&text, label, needles);
        let entries = result_of(&shown)["structuredContent"]["entries"].clone();
        let entries = entries.as_array().expect("entries");
        for entry in entries {
            let whole_only = entry.to_string().replace(REDACTED, "");
            assert!(
                !whole_only.contains("[redacted"),
                "{label}: a partial marker in {entry}"
            );
        }
        let ours = entries.iter().find(|entry| {
            entry["message"]
                .as_str()
                .is_some_and(|m| m.contains(&token))
        });
        let message = ours
            .and_then(|entry| entry["message"].as_str())
            .unwrap_or_default();
        assert!(message.contains("[truncated"), "{label}: {shown}");
        assert!(!message.contains("[redacted"), "{label}: {message}");
    }
}

/// A value that only looks like the end of an md5 hash is user data and comes back unchanged.
#[tokio::test]
async fn a_user_value_ending_in_md5_letters_is_returned_unchanged() {
    for text in ["note md5abc", "md5d41d8cd98f00b204e9800998ecf8427"] {
        assert_eq!(returned_text(text).await, text);
    }
}

/// Two hash-shaped column aliases: the names and the row keys carry the markers, numbered when they collide.
#[tokio::test]
async fn hash_shaped_column_names_are_replaced_before_they_are_numbered() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let first = "md5d41d8cd98f00b204e9800998ecf8427e";
    let second = "md50123456789abcdef0123456789abcdef";
    let sql = format!("SELECT 1 AS \"{first}\", 2 AS \"{second}\"");
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let content = &result_of(&response)["structuredContent"];
    let columns = content["columns"].as_array().expect("columns");
    assert_eq!(columns[0]["name"], json!(REDACTED), "{response}");
    assert_eq!(
        columns[1]["name"],
        json!("[redacted password hash]__2"),
        "{response}"
    );
    assert_eq!(content["rows"][0][REDACTED], json!(1), "{response}");
    assert_eq!(
        content["rows"][0]["[redacted password hash]__2"],
        json!(2),
        "{response}"
    );
    let markers = content.to_string().matches(REDACTED).count();
    assert_eq!(
        content["redactedHashes"],
        json!(markers as u64),
        "{response}"
    );
    assert!(!response.to_string().contains("md5d41"), "{response}");
    assert!(!response.to_string().contains("md50123"), "{response}");
}

/// A role whose search_path defines its own `<>` for name still gets the catalog's meaning in the filter.
#[tokio::test]
async fn a_search_path_operator_cannot_change_the_statistics_filter() {
    for (_, port) in SERVERS {
        let router = router_for(port, "mcp_path", "test-only-path");
        let hidden = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT tablename, attname FROM pg_stats WHERE tablename = 'pg_authid'"}),
        )
        .await;
        assert_eq!(
            result_of(&hidden)["structuredContent"]["rows"],
            json!([]),
            "{port}: {hidden}"
        );
        let kept = call_tool(
            &router,
            "execute_query",
            json!({"sql": "SELECT count(*) AS n FROM pg_stats WHERE tablename = 'items'"}),
        )
        .await;
        assert!(
            result_of(&kept)["structuredContent"]["rows"][0]["n"]
                .as_i64()
                .unwrap_or(0)
                > 0,
            "{port}: {kept}"
        );
    }
}

/// Statement text is masked on the way out: a typed password in pg_stat_statements shows as `'***'`.
#[tokio::test]
async fn a_typed_password_in_statement_text_is_masked() {
    let router = router_for(PORT_18, "postgres", "test-only-superuser");
    let response = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT query FROM pg_stat_statements WHERE query ILIKE '%seed_role_1%'"}),
    )
    .await;
    let text = response.to_string();
    assert!(!text.contains("plain-test-secret"), "{text}");
    assert!(
        text.contains("ALTER ROLE seed_role_1 PASSWORD '***'"),
        "{text}"
    );
}

/// The unknown-tool error echoes the name, so a planted hash in the name is replaced in the error message.
#[tokio::test]
async fn an_unknown_tool_name_with_a_hash_is_scrubbed_in_the_error() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let response = call_tool(&router, &format!("nope {PLANTED}"), json!({})).await;
    assert_eq!(
        response["error"]["message"],
        json!("unknown tool: nope [redacted password hash]"),
        "{response}"
    );
    assert!(!response.to_string().contains(PLANTED), "{response}");
}

/// A text value in execute_query, as the server returns it, for the given SQL text.
async fn returned_text(text: &str) -> String {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let sql = format!("SELECT '{}' AS v", text.replace('\'', "''"));
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    result_of(&response)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

/// Ordinary text that contains the word password is returned byte for byte.
#[tokio::test]
async fn ordinary_text_with_the_word_password_is_returned_unchanged() {
    for text in [
        "Forgot your password = reset it via the portal",
        "postgres://u:pw@h/db",
        "host=h password=secret",
        "passfile=/tmp/x",
    ] {
        assert_eq!(returned_text(text).await, text);
    }
}

/// A quoted literal after the keyword PASSWORD is masked in every string value, in every quoting form.
#[tokio::test]
async fn a_password_literal_after_the_keyword_is_masked_in_rows() {
    for (text, expected) in [
        (
            "ALTER ROLE x PASSWORD 'secret'",
            "ALTER ROLE x PASSWORD '***'",
        ),
        (
            "CREATE ROLE x ENCRYPTED PASSWORD 'secret'",
            "CREATE ROLE x ENCRYPTED PASSWORD '***'",
        ),
        (
            "CREATE ROLE x PASSWORD $$secret$$",
            "CREATE ROLE x PASSWORD '***'",
        ),
        (
            "CREATE ROLE x PASSWORD E'se\\'cret'",
            "CREATE ROLE x PASSWORD '***'",
        ),
    ] {
        assert_eq!(returned_text(text).await, expected, "{text}");
    }
}

/// PostgreSQL cuts a long statement at track_activity_query_size; the md5 digits it keeps are not returned.
#[tokio::test]
async fn a_statement_cut_by_postgres_keeps_no_digits_of_an_md5_hash() {
    let router = router_for(PORT_18, "postgres", "test-only-superuser");
    let mut config = superuser_config(PORT_18);
    config.startup_params = vec![("application_name".to_owned(), "tail_probe".to_owned())];
    let mut conn = Connection::connect(&config).await.expect("probe connect");
    let sql = format!(
        "SELECT pg_sleep(3), '{} md5fedcba9876543210fedcba9876543210'",
        "x".repeat(991)
    );
    let sleeper = tokio::spawn(async move { conn.simple_query(&sql).await.map(|_| ()) });
    let mut row = Value::Null;
    for _ in 0..50 {
        let listed = call_tool(
            &router,
            "list_activity",
            json!({"all_databases": true, "query_chars": 4000}),
        )
        .await;
        row = result_of(&listed)["structuredContent"]["sessions"]
            .as_array()
            .and_then(|sessions| {
                sessions.iter().find(|s| {
                    s["application"] == json!("tail_probe") && s["state"] == json!("active")
                })
            })
            .cloned()
            .unwrap_or(Value::Null);
        if !row.is_null() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let query = row["query"].as_str().expect("probe row").to_owned();
    assert!(query.ends_with(REDACTED), "{row}");
    let kept = superuser_rows(
        PORT_18,
        "SELECT query FROM pg_catalog.pg_stat_activity WHERE application_name = 'tail_probe'",
    )
    .await;
    assert!(
        kept.iter().any(|row| row[0].ends_with("md5fedcba9")),
        "{kept:?}"
    );
    assert!(!query.contains("fedcba98"), "{row}");
    sleeper
        .await
        .expect("probe task")
        .expect("probe statement ran");
}

/// A hash inside a record is hex in the record's text; the record comes back with the marker's hex, not the hash's.
#[tokio::test]
async fn a_hash_inside_a_record_is_replaced_in_its_hex_form() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let sql = format!("SELECT ROW(convert_to('{PLANTED}', 'UTF8'))::text AS v");
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let value = result_of(&response)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(!value.contains("534352414d2d5348412d"), "{value}");
    assert!(
        value.contains("5b72656461637465642070617373776f726420686173685d"),
        "{value}"
    );
}

/// A hash that an invalid argument echoes is replaced in the error text, and the error holds no needle.
#[tokio::test]
async fn an_invalid_argument_that_echoes_a_hash_is_scrubbed_in_the_error() {
    let needles = needles().await;
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let response = call_tool(&router, "query_stats", json!({ "limit": PLANTED })).await;
    assert_clean(&response.to_string(), "invalid argument", needles);
    assert!(response.to_string().contains(REDACTED), "{response}");
}

/// A resource name that holds a hash is replaced in the not-found error, and the error holds no needle.
#[tokio::test]
async fn a_resource_error_that_names_a_hash_is_scrubbed() {
    let needles = needles().await;
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "resources/read", "params": {"uri": format!("postgres://appdb/hashes/{PLANTED}")}});
    let response = post_mcp(&router, &body, &[("mcp-protocol-version", PROTOCOL_2025)])
        .await
        .json();
    assert_clean(&response.to_string(), "resource error", needles);
    assert!(response.to_string().contains(REDACTED), "{response}");
}

/// Table completion returns a hash-shaped table name as the marker, and no completion value holds the hash.
#[tokio::test]
async fn a_completion_returns_a_hash_shaped_table_name_as_the_marker() {
    let needles = needles().await;
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let completion = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "completion/complete",
        "params": {
            "ref": {"type": "ref/resource", "uri": "postgres://{database}/{schema}/{table}"},
            "argument": {"name": "table", "value": "SCRAM"},
            "context": {"arguments": {"database": "appdb", "schema": "hashes"}},
        },
    });
    let response = post_mcp(
        &router,
        &completion,
        &[("mcp-protocol-version", PROTOCOL_2025)],
    )
    .await
    .json();
    let values = response["result"]["completion"]["values"].to_string();
    assert!(values.contains(REDACTED), "{response}");
    assert_clean(&response.to_string(), "completion", needles);
}

/// A bytea array too large for the value cut keeps no hash in hex, and its count is the markers it returns.
#[tokio::test]
async fn a_large_bytea_array_holds_no_hash_hex() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let sql = format!(
        "SELECT ARRAY(SELECT convert_to('{PLANTED}', 'UTF8') FROM generate_series(1, 400)) AS v"
    );
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let content = &result_of(&response)["structuredContent"];
    let text = content["rows"][0]["v"].to_string();
    assert!(!text.contains("534352414d2d5348412d32353624"), "{response}");
    assert!(
        text.contains("5b72656461637465642070617373776f726420686173685d"),
        "{response}"
    );
    assert_eq!(
        content["redactedHashes"].as_u64(),
        Some(
            text.matches("5b72656461637465642070617373776f726420686173685d")
                .count() as u64
        ),
        "{response}"
    );
}

/// Ordinary SQL text that holds the word password comes back byte for byte through execute_query.
#[tokio::test]
async fn the_password_mask_leaves_ordinary_sql_text_byte_for_byte() {
    for text in [
        "ARRAY['password'::text, 'token'::text]",
        "IF NOT ok THEN RAISE EXCEPTION 'wrong password'; END IF; RETURN 1; END",
        "SELECT * FROM creds WHERE kind = 'password' AND v = 'x'",
        "CHECK (kind IN ('password', 'token', 'key'))",
    ] {
        assert_eq!(returned_text(text).await, text);
    }
}

/// The seeded function, table and view describe with their ordinary password text, and no mask.
#[tokio::test]
async fn describe_keeps_ordinary_sql_text_that_holds_the_word_password() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let function = call_tool(
        &router,
        "describe_function",
        json!({"function": "check_password", "schema": "masks"}),
    )
    .await;
    assert!(
        function
            .to_string()
            .contains("RAISE EXCEPTION 'wrong password'"),
        "{function}"
    );
    let table = call_tool(
        &router,
        "describe_table",
        json!({"table": "kinds", "schema": "masks"}),
    )
    .await;
    assert!(table.to_string().contains("'password'::text"), "{table}");
    let view = call_tool(
        &router,
        "describe_table",
        json!({"table": "password_rows", "schema": "masks"}),
    )
    .await;
    assert!(
        view.to_string().contains("kind = 'password'::text"),
        "{view}"
    );
    for response in [&function, &table, &view] {
        assert!(!response.to_string().contains("***"), "{response}");
    }
}

/// A column name with a password literal is masked the same way as its row key.
#[tokio::test]
async fn a_column_name_with_a_password_literal_is_masked_like_its_row_key() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let response = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT 1 AS \"password 'hunter2'\""}),
    )
    .await;
    let content = &result_of(&response)["structuredContent"];
    assert_eq!(
        content["columns"][0]["name"],
        json!("password '***'"),
        "{response}"
    );
    assert_eq!(content["rows"][0]["password '***'"], json!(1), "{response}");
    assert!(!response.to_string().contains("hunter2"), "{response}");
}

/// A record whose bytea text the value cut splits inside an md5 hash keeps none of the hash's digits.
#[tokio::test]
async fn a_hex_form_md5_split_by_the_value_cut_keeps_no_digits() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let md5 = "md50123456789abcdef0123456789abcdef";
    let sql =
        format!("SELECT ROW(convert_to(repeat('x', 2010) || ' {md5} tail', 'UTF8'))::text AS v");
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let value = result_of(&response)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let digits_in_hex: String = "0123456789".bytes().map(|b| format!("{b:02x}")).collect();
    assert!(!value.contains(&digits_in_hex), "{value}");
    assert!(!value.contains("6d6435"), "{value}");
    let marker_hex: String = REDACTED.bytes().map(|b| format!("{b:02x}")).collect();
    assert!(value.contains(&marker_hex), "{value}");
}

/// A password literal nested in a DO block comes back with no password character.
#[tokio::test]
async fn a_nested_password_literal_in_a_do_block_is_masked_in_results() {
    let value =
        returned_text("DO $$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''hunter2'''; END $$").await;
    assert_eq!(
        value,
        "DO $$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''***'''; END $$"
    );
}

/// A password literal nested in a dblink call comes back with no password character.
#[tokio::test]
async fn a_nested_password_literal_in_a_dblink_call_is_masked_in_results() {
    let value = returned_text("SELECT dblink_exec('ALTER ROLE app PASSWORD ''hunter2''')").await;
    assert_eq!(
        value,
        "SELECT dblink_exec('ALTER ROLE app PASSWORD ''***''')"
    );
}

/// A nested password literal that starts with a quote pair comes back with no password character.
#[tokio::test]
async fn a_nested_password_literal_after_a_quoted_keyword_is_masked_in_results() {
    let value = returned_text("'PASSWORD ''hunter2-m'''").await;
    assert_eq!(value, "'PASSWORD ''***'''");
}

/// A column name and its row key carry the same masked text.
#[tokio::test]
async fn a_column_name_and_its_row_key_are_masked_the_same_way() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let response = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT 1 AS \"password $$a$$'\""}),
    )
    .await;
    let content = &result_of(&response)["structuredContent"];
    let name = content["columns"][0]["name"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert_eq!(name, "password '***'", "{response}");
    assert_eq!(content["rows"][0][name.as_str()], json!(1), "{response}");
}

/// A cut anywhere between two packed hashes returns no whole md5 hash.
#[tokio::test]
async fn a_cut_between_packed_hashes_returns_no_whole_md5_hash() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let md5 = "md5d41d8cd98f00b204e9800998ecf8427e";
    let scram = "SCRAM-SHA-256$4096:c2FsdA==$a2V5:a2V5";
    for pad in 4050..4070 {
        for tail in [md5, scram] {
            let sql = format!("SELECT repeat('x', {pad}) || ' {md5}{tail}' AS v");
            let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
            let value = result_of(&response)["structuredContent"]["rows"][0]["v"]
                .as_str()
                .unwrap_or_default()
                .to_owned();
            assert!(!value.contains(md5), "pad {pad} tail {tail}: {value}");
        }
    }
}

/// A hex-form marker at the value cut is not left cut in half in a record's text.
#[tokio::test]
async fn a_hex_form_marker_is_not_cut_in_half_in_a_record() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let md5 = "md5d41d8cd98f00b204e9800998ecf8427e";
    let sql =
        format!("SELECT ROW(convert_to(repeat('x', 2030) || ' {md5} tail', 'UTF8'))::text AS v");
    let response = call_tool(&router, "execute_query", json!({ "sql": sql })).await;
    let content = &result_of(&response)["structuredContent"];
    let value = content["rows"][0]["v"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let marker_hex: String = REDACTED.bytes().map(|b| format!("{b:02x}")).collect();
    let kept = value.split('…').next().unwrap_or_default();
    for len in 8..marker_hex.len() {
        assert!(!kept.ends_with(&marker_hex[..len]), "{len}: {value}");
    }
    let shown = value.matches(&marker_hex).count() + value.matches(REDACTED).count();
    assert_eq!(content["redactedHashes"], json!(shown), "{response}");
}

/// A non-ASCII dollar tag after PASSWORD in a running statement is masked in list_activity.
#[tokio::test]
async fn a_non_ascii_dollar_tag_after_password_is_masked_in_list_activity() {
    let router = router_for(PORT_18, "postgres", "test-only-superuser");
    let mut config = superuser_config(PORT_18);
    config.startup_params = vec![("application_name".to_owned(), "dollar_probe".to_owned())];
    let mut conn = Connection::connect(&config).await.expect("probe connect");
    let sql = "SELECT pg_sleep(3) /* PASSWORD $é$hunter2$é$ */";
    let sleeper = tokio::spawn(async move { conn.simple_query(sql).await.map(|_| ()) });
    let mut query = String::new();
    for _ in 0..50 {
        let listed = call_tool(&router, "list_activity", json!({"all_databases": true})).await;
        query = result_of(&listed)["structuredContent"]["sessions"]
            .as_array()
            .and_then(|sessions| {
                sessions.iter().find(|s| {
                    s["application"] == json!("dollar_probe") && s["state"] == json!("active")
                })
            })
            .and_then(|s| s["query"].as_str())
            .unwrap_or_default()
            .to_owned();
        if !query.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    sleeper.await.expect("probe task").expect("probe query");
    assert!(query.contains("$é$***$é$"), "{query}");
    assert!(!query.contains("hunter2"), "{query}");
}

/// A bytea value shows its preview, and a value the wire cut short shows the bytes the wire kept.
#[tokio::test]
async fn a_bytea_value_shows_the_preview_or_the_bytes_the_wire_kept() {
    let router = router_for(PORT_18, "mcp_ro", "test-only-ro");
    let small = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT decode(repeat('78', 2047), 'hex') AS v"}),
    )
    .await;
    let value = result_of(&small)["structuredContent"]["rows"][0]["v"].clone();
    assert_eq!(
        value,
        json!(format!(
            "\\x{}…[truncated: 256 of 2047 bytes]",
            "78".repeat(256)
        ))
    );
    let large = call_tool(
        &router,
        "execute_query",
        json!({"sql": "SELECT decode(repeat('78', 5000), 'hex') AS v"}),
    )
    .await;
    let value = result_of(&large)["structuredContent"]["rows"][0]["v"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        value.ends_with("…[truncated: 2047 of 5000 bytes]"),
        "{value}"
    );
    assert_eq!(value.matches("78").count(), 2047, "{value}");
}
