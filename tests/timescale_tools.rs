//! Integration tests for the TimescaleDB tools against the seeded test databases, plus unit tests of the catalog probe.

mod common;

use std::collections::BTreeSet;
use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use common::{PORT_15, PORT_18, PORT_19, app, call_tool, config_with, one_db, post_mcp, result_of};
use postgres_mcp::tools::text;
use postgres_mcp::tools::timescale::parse::{parse_name_list, parse_orderby, quote_ident};
use postgres_mcp::tools::timescale::probe::{Features, Sources};
use serde_json::{Value, json};

const PROTOCOL_2025: &str = "2025-11-25";
const TIMESCALE_VERSION: &str = "2.32.1";
const READINGS_COMMENT: &str = "Hypertable of device readings, one row per 10 minutes";
const DENIED_WORDS: [&str; 3] = ["test-only-superuser", "test-only-ro", "test-only-strict"];

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

/// The structured content of a successful tool result.
fn ok(result: &Value) -> &Value {
    assert!(!is_error(result), "tool error: {}", text_of(result));
    result
        .get("structuredContent")
        .unwrap_or_else(|| panic!("no structuredContent in {result}"))
}

/// The tool error text of a failed tool result.
fn error_text(result: &Value) -> String {
    assert!(is_error(result), "expected a tool error, got {result}");
    text_of(result)
}

/// A tool result for one call on a router.
async fn call(router: &Router, name: &str, arguments: Value) -> Value {
    result_of(&call_tool(router, name, arguments).await).clone()
}

/// A router for mcp_ro on the TimescaleDB server.
fn ro() -> Router {
    app(one_db(PORT_18, &[]))
}

/// The number of chunks of metrics.readings, read through execute_query.
async fn live_chunk_count(router: &Router) -> u64 {
    let result = call(
        router,
        "execute_query",
        json!({"sql": "SELECT count(*) AS n FROM timescaledb_information.chunks WHERE hypertable_schema = 'metrics' AND hypertable_name = 'readings'"}),
    )
    .await;
    ok(&result)["rows"][0]["n"]
        .as_u64()
        .expect("chunk count is a number")
}

fn names_of(array: &Value, key: &str) -> Vec<String> {
    array
        .as_array()
        .expect("array")
        .iter()
        .map(|item| item[key].as_str().expect("string").to_owned())
        .collect()
}

#[tokio::test]
async fn list_hypertables_returns_the_seeded_hypertable() {
    let router = ro();
    let result = call(&router, "list_hypertables", json!({})).await;
    let body = ok(&result);
    assert_eq!(body["database"], "appdb");
    assert_eq!(body["timescaledb"], true);
    assert_eq!(body["version"], TIMESCALE_VERSION);
    assert!(body.get("nextCursor").is_none(), "{body}");
    let tables = body["hypertables"].as_array().expect("hypertables");
    assert_eq!(tables.len(), 1, "{tables:?}");
    let table = &tables[0];
    assert_eq!(table["schema"], "metrics");
    assert_eq!(table["name"], "readings");
    assert_eq!(table["owner"], "postgres");
    assert_eq!(table["comment"], READINGS_COMMENT);
    assert_eq!(table["timeColumn"], "ts");
    assert_eq!(table["timeColumnType"], "timestamp with time zone");
    assert_eq!(table["chunkInterval"], "P1D");
    assert_eq!(table["dimensions"], 1);
    assert_eq!(table["chunks"], live_chunk_count(&router).await);
    assert_eq!(table["chunks"], 7);
    assert_eq!(table["columnstoreEnabled"], true);
    assert!(table["totalBytes"].as_i64().expect("bytes") > 0, "{table}");
    // Compressed chunks report 0 rows until they are analyzed; observed 0 on the seed.
    assert!(
        table["approximateRows"].as_i64().expect("rows") >= 0,
        "{table}"
    );
    assert_eq!(table["isContinuousAggregateStorage"], false);
}

#[tokio::test]
async fn list_hypertables_schema_filter_and_empty_result() {
    let router = ro();
    let empty = call(&router, "list_hypertables", json!({"schema": "nope"})).await;
    let body = ok(&empty);
    assert_eq!(body["hypertables"], json!([]));
    assert!(body.get("nextCursor").is_none(), "{body}");

    let internal = call(
        &router,
        "list_hypertables",
        json!({"schema": "_timescaledb_internal"}),
    )
    .await;
    let tables = ok(&internal)["hypertables"].clone();
    assert_eq!(tables.as_array().expect("array").len(), 1, "{tables}");
    assert_eq!(tables[0]["schema"], "_timescaledb_internal");
    assert_eq!(tables[0]["isContinuousAggregateStorage"], true);
}

#[tokio::test]
async fn list_hypertables_rejects_bad_limit_and_cursor() {
    let router = ro();
    let low = call(&router, "list_hypertables", json!({"limit": 0})).await;
    assert_eq!(error_text(&low), "limit must be between 1 and 500.");
    let high = call(&router, "list_hypertables", json!({"limit": 501})).await;
    assert_eq!(error_text(&high), "limit must be between 1 and 500.");
    let cursor = call(&router, "list_hypertables", json!({"cursor": "bogus"})).await;
    assert_eq!(error_text(&cursor), "Invalid cursor.");
}

#[tokio::test]
async fn describe_hypertable_reports_dimensions_columnstore_and_policies() {
    let router = ro();
    let result = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "metrics.readings"}),
    )
    .await;
    let body = ok(&result);
    assert_eq!(body["database"], "appdb");
    assert_eq!(body["timescaledb"], true);
    assert_eq!(body["version"], TIMESCALE_VERSION);
    assert_eq!(body["schema"], "metrics");
    assert_eq!(body["name"], "readings");
    assert_eq!(body["owner"], "postgres");
    assert_eq!(body["comment"], READINGS_COMMENT);

    let dimensions = body["dimensions"].as_array().expect("dimensions");
    assert_eq!(dimensions.len(), 1, "{dimensions:?}");
    assert_eq!(dimensions[0]["column"], "ts");
    assert_eq!(dimensions[0]["type"], "timestamp with time zone");
    assert_eq!(dimensions[0]["kind"], "time");
    assert_eq!(dimensions[0]["interval"], "P1D");
    assert!(dimensions[0]["partitions"].is_null(), "{dimensions:?}");

    let columnstore = &body["columnstore"];
    assert_eq!(columnstore["enabled"], true, "{columnstore}");
    assert_eq!(columnstore["segmentBy"], json!(["device_id"]));
    assert_eq!(
        columnstore["orderBy"],
        json!([{"column": "ts", "descending": true, "nullsFirst": true}])
    );
    assert!(columnstore["columnstoreChunks"].as_u64().expect("count") >= 3);
    let before = columnstore["beforeBytes"].as_i64().expect("before");
    let after = columnstore["afterBytes"].as_i64().expect("after");
    assert!(after < before, "{columnstore}");
    assert!(columnstore["ratio"].as_f64().expect("ratio") > 1.0);

    let sizes = &body["sizes"];
    assert!(sizes["totalBytes"].as_i64().expect("total") > 0, "{sizes}");
    assert!(body["approximateRows"].as_i64().expect("rows") >= 0);

    let kinds = names_of(&body["policies"], "kind");
    assert!(kinds.contains(&"columnstore".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"retention".to_owned()), "{kinds:?}");
    assert!(!kinds.contains(&"refresh".to_owned()), "{kinds:?}");
    let columnstore_policy = &body["policies"][0];
    assert!(columnstore_policy["jobId"].is_i64(), "{columnstore_policy}");

    assert_eq!(
        body["continuousAggregates"],
        json!(["metrics.readings_hourly"])
    );

    let chunks = body["chunks"].as_array().expect("chunks");
    assert_eq!(chunks.len(), 7, "{chunks:?}");
    assert!(chunks[0]["rangeStart"].as_str() > chunks[1]["rangeStart"].as_str());
    let columnstore_chunks = chunks.iter().filter(|c| c["isColumnstore"] == true).count();
    assert!(columnstore_chunks >= 3, "{chunks:?}");
    assert!(chunks[0]["totalBytes"].as_i64().expect("bytes") > 0);
    assert!(body["nextChunkCursor"].is_null() || body.get("nextChunkCursor").is_none());
    assert_eq!(body["warnings"], json!([]));
}

#[tokio::test]
async fn describe_hypertable_chunk_paging_walks_every_chunk_once() {
    let router = ro();
    let total = live_chunk_count(&router).await;
    let mut seen: Vec<String> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"hypertable": "metrics.readings", "chunk_limit": 2});
        if let Some(value) = &cursor {
            args["chunk_cursor"] = json!(value);
        }
        let result = call(&router, "describe_hypertable", args).await;
        let body = ok(&result).clone();
        let chunks = body["chunks"].as_array().expect("chunks");
        assert!(chunks.len() <= 2, "{chunks:?}");
        for chunk in chunks {
            seen.push(chunk["name"].as_str().expect("name").to_owned());
        }
        match body["nextChunkCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(seen.len() as u64, total, "{seen:?}");
    let unique: BTreeSet<&String> = seen.iter().collect();
    assert_eq!(unique.len(), seen.len(), "duplicates in {seen:?}");
}

#[tokio::test]
async fn describe_hypertable_resolves_bare_name_and_reports_errors() {
    let router = ro();
    let bare = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "readings"}),
    )
    .await;
    let body = ok(&bare);
    assert_eq!(body["schema"], "metrics");
    assert_eq!(body["name"], "readings");

    let regular = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "shop.orders"}),
    )
    .await;
    assert_eq!(
        error_text(&regular),
        "Hypertable \"shop.orders\" not found. \"shop.orders\" is a regular table, not a hypertable: use describe_table."
    );

    let unknown = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "nope"}),
    )
    .await;
    assert_eq!(error_text(&unknown), "Hypertable \"nope\" not found.");

    let bounds_low = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "metrics.readings", "chunk_limit": 0}),
    )
    .await;
    assert_eq!(
        error_text(&bounds_low),
        "chunk_limit must be between 1 and 500."
    );
    let bounds_high = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "metrics.readings", "chunk_limit": 501}),
    )
    .await;
    assert_eq!(
        error_text(&bounds_high),
        "chunk_limit must be between 1 and 500."
    );
    let bad_cursor = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "metrics.readings", "chunk_cursor": "x"}),
    )
    .await;
    assert_eq!(error_text(&bad_cursor), "Invalid cursor.");
}

#[tokio::test]
async fn list_continuous_aggregates_describes_readings_hourly() {
    let router = ro();
    let result = call(&router, "list_continuous_aggregates", json!({})).await;
    let body = ok(&result);
    assert_eq!(body["database"], "appdb");
    assert_eq!(body["timescaledb"], true);
    assert_eq!(body["version"], TIMESCALE_VERSION);
    let caggs = body["continuousAggregates"].as_array().expect("caggs");
    assert_eq!(caggs.len(), 1, "{caggs:?}");
    let cagg = &caggs[0];
    assert_eq!(cagg["schema"], "metrics");
    assert_eq!(cagg["name"], "readings_hourly");
    assert_eq!(cagg["owner"], "postgres");
    assert_eq!(cagg["comment"], "Hourly continuous aggregate of readings");
    assert_eq!(cagg["hypertable"], "metrics.readings");
    assert_eq!(cagg["materializedOnly"], true);
    assert_eq!(cagg["realTime"], false);
    assert_eq!(cagg["compressionEnabled"], false);
    assert!(
        cagg["definition"]
            .as_str()
            .expect("def")
            .contains("time_bucket")
    );
    assert_eq!(
        cagg["materializationHypertable"],
        "_timescaledb_internal._materialized_hypertable_2"
    );
    let refresh = &cagg["refreshPolicy"];
    assert!(refresh.is_object(), "{cagg}");
    assert_eq!(refresh["schedule"], "PT1H");
    assert_eq!(refresh["endOffset"], "01:00:00");
    assert!(refresh["jobId"].is_i64(), "{refresh}");
    assert!(cagg["watermark"].is_string(), "{cagg}");
    assert!(cagg.get("nextCursor").is_none());
}

#[tokio::test]
async fn list_jobs_lists_policies_and_custom_jobs() {
    let router = ro();
    let result = call(&router, "list_jobs", json!({})).await;
    let body = ok(&result);
    assert_eq!(body["timescaledb"], true);
    assert_eq!(body["version"], TIMESCALE_VERSION);
    let jobs = body["jobs"].as_array().expect("jobs");
    let ids: Vec<i64> = jobs
        .iter()
        .map(|j| j["jobId"].as_i64().expect("id"))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted, "ordered by jobId");

    let find = |id: i64| -> &Value {
        jobs.iter()
            .find(|j| j["jobId"] == id)
            .unwrap_or_else(|| panic!("job {id} missing in {ids:?}"))
    };
    assert_eq!(find(1001)["kind"], "columnstore");
    assert_eq!(find(1002)["kind"], "retention");
    assert_eq!(find(1003)["kind"], "refresh");
    assert_eq!(find(1003)["hypertable"], "metrics.readings_hourly");
    assert_eq!(find(1002)["hypertable"], "metrics.readings");
    assert_eq!(find(1004)["kind"], "custom");
    assert_eq!(find(1004)["procedure"], "metrics.failing_job");
    assert_eq!(find(1005)["procedure"], "metrics.ok_job");
    assert_eq!(find(1005)["hypertable"], Value::Null);
    assert_eq!(find(1005)["owner"], "mcp_ro");

    let failing = find(1004);
    assert!(
        failing["totalFailures"].as_i64().expect("failures") >= 1,
        "{failing}"
    );
    assert_eq!(failing["lastRunStatus"], "Failed");
    assert_eq!(failing["schedule"], "PT1H");
    assert_eq!(failing["fixedSchedule"], true);
}

#[tokio::test]
async fn list_jobs_filters_by_job_id_and_pages() {
    let router = ro();
    let one = call(&router, "list_jobs", json!({"job_id": 1004})).await;
    let jobs = ok(&one)["jobs"].clone();
    assert_eq!(jobs.as_array().expect("array").len(), 1, "{jobs}");
    assert_eq!(jobs[0]["jobId"], 1004);

    let mut seen: Vec<i64> = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let mut args = json!({"limit": 2});
        if let Some(value) = &cursor {
            args["cursor"] = json!(value);
        }
        let result = call(&router, "list_jobs", args).await;
        let body = ok(&result).clone();
        let page = body["jobs"].as_array().expect("jobs");
        assert!(page.len() <= 2);
        seen.extend(page.iter().map(|j| j["jobId"].as_i64().expect("id")));
        match body["nextCursor"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    let unique: BTreeSet<i64> = seen.iter().copied().collect();
    assert_eq!(unique.len(), seen.len(), "duplicates in {seen:?}");
    assert!(unique.contains(&1004) && unique.contains(&1005), "{seen:?}");
}

#[tokio::test]
async fn list_jobs_history_shows_the_intentional_failure() {
    let router = ro();
    let result = call(
        &router,
        "list_jobs",
        json!({"history": true, "job_id": 1004}),
    )
    .await;
    let body = ok(&result);
    assert_eq!(body["source"], "job_history");
    let runs = body["runs"].as_array().expect("runs");
    assert!(!runs.is_empty(), "{body}");
    let failed = runs
        .iter()
        .find(|r| r["succeeded"] == false)
        .unwrap_or_else(|| panic!("no failed run in {runs:?}"));
    assert_eq!(failed["jobId"], 1004);
    assert_eq!(failed["procedure"], "metrics.failing_job");
    assert_eq!(failed["sqlstate"], "P0001");
    assert!(
        failed["errorMessage"]
            .as_str()
            .expect("message")
            .contains("pgmcp intentional job failure"),
        "{failed}"
    );
    assert!(failed["durationMs"].as_i64().expect("duration") >= 0);
    assert!(failed["startedAt"].is_string());
    assert!(failed["finishedAt"].is_string());
    assert!(body.get("note").is_none(), "{body}");
}

#[tokio::test]
async fn list_jobs_only_failures_returns_failed_runs_only() {
    let router = ro();
    let result = call(
        &router,
        "list_jobs",
        json!({"history": true, "only_failures": true}),
    )
    .await;
    let runs = ok(&result)["runs"].clone();
    let runs = runs.as_array().expect("runs");
    assert!(!runs.is_empty());
    assert!(runs.iter().all(|r| r["succeeded"] == false), "{runs:?}");
}

#[tokio::test]
async fn list_jobs_history_of_ok_job_has_a_success() {
    let router = ro();
    let mut found = false;
    for _ in 0..30 {
        let result = call(
            &router,
            "list_jobs",
            json!({"history": true, "job_id": 1005}),
        )
        .await;
        let runs = ok(&result)["runs"].clone();
        if runs
            .as_array()
            .expect("runs")
            .iter()
            .any(|r| r["succeeded"] == true)
        {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(found, "no successful run of job 1005 within 15 s");
}

#[tokio::test]
async fn list_jobs_history_pages_newest_first() {
    let router = ro();
    let result = call(&router, "list_jobs", json!({"history": true, "limit": 1})).await;
    let body = ok(&result).clone();
    let runs = body["runs"].as_array().expect("runs");
    assert_eq!(runs.len(), 1, "{body}");
    assert!(body["nextCursor"].is_string(), "{body}");
    let next = body["nextCursor"].as_str().expect("cursor").to_owned();
    let second = call(
        &router,
        "list_jobs",
        json!({"history": true, "limit": 1, "cursor": next}),
    )
    .await;
    let second_runs = ok(&second)["runs"].clone();
    assert_ne!(runs[0]["startedAt"], second_runs[0]["startedAt"], "{body}");
    assert!(
        runs[0]["startedAt"].as_str() >= second_runs[0]["startedAt"].as_str(),
        "newest first"
    );
}

#[tokio::test]
async fn not_installed_databases_report_timescaledb_false() {
    for port in [PORT_19, PORT_15] {
        let router = app(one_db(port, &[]));
        for (name, args) in [
            ("list_hypertables", json!({})),
            (
                "describe_hypertable",
                json!({"hypertable": "metrics.readings"}),
            ),
            ("list_continuous_aggregates", json!({})),
            ("list_jobs", json!({})),
        ] {
            let result = call(&router, name, args).await;
            let body = ok(&result);
            assert_eq!(body["database"], "appdb", "{name} on {port}");
            assert_eq!(body["timescaledb"], false, "{name} on {port}");
            assert_eq!(
                body["note"],
                text::NOT_INSTALLED_TIMESCALE,
                "{name} on {port}"
            );
            let keys: BTreeSet<&str> = body
                .as_object()
                .expect("object")
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                keys,
                BTreeSet::from(["database", "timescaledb", "note"]),
                "{name} on {port}"
            );
        }
    }
}

fn strict() -> Router {
    let entry = json!({
        "name": "appdb",
        "host": "127.0.0.1",
        "port": PORT_18,
        "database": "appdb",
        "user": "mcp_strict",
        "password": "test-only-strict",
        "sslmode": "disable",
    });
    app(config_with(&[entry], &[]))
}

#[tokio::test]
async fn strict_role_degrades_without_tool_errors() {
    let router = strict();
    let tables = call(&router, "list_hypertables", json!({})).await;
    let body = ok(&tables);
    assert_eq!(body["hypertables"][0]["name"], "readings");
    assert!(body["warnings"].is_array(), "{body}");

    let described = call(
        &router,
        "describe_hypertable",
        json!({"hypertable": "metrics.readings"}),
    )
    .await;
    assert_eq!(ok(&described)["name"], "readings");

    let caggs = call(&router, "list_continuous_aggregates", json!({})).await;
    assert_eq!(
        ok(&caggs)["continuousAggregates"][0]["name"],
        "readings_hourly"
    );

    let history = call(&router, "list_jobs", json!({"history": true})).await;
    let body = ok(&history);
    assert_eq!(body["runs"], json!([]));
    assert_eq!(
        body["note"],
        "Job history is visible only to the job owner, members of its role, or the database owner."
    );
}

/// The tool names a server built from the config lists.
async fn listed_tools(router: &Router) -> Vec<String> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
    let reply = post_mcp(router, &body, &[("mcp-protocol-version", PROTOCOL_2025)]).await;
    assert_eq!(reply.status, StatusCode::OK);
    result_of(&reply.json())["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect()
}

#[tokio::test]
async fn toolset_core_hides_the_timescale_tools() {
    let timescale_tools = [
        "list_hypertables",
        "describe_hypertable",
        "list_continuous_aggregates",
        "list_jobs",
    ];
    let core = listed_tools(&app(one_db(PORT_18, &[("TOOLSETS", "core")]))).await;
    for name in timescale_tools {
        assert!(!core.contains(&name.to_owned()), "{name} listed in core");
    }
    assert!(core.contains(&"execute_query".to_owned()));
    let all = listed_tools(&ro()).await;
    for name in timescale_tools {
        assert!(
            all.contains(&name.to_owned()),
            "{name} not listed by default"
        );
    }
}

#[tokio::test]
async fn unknown_argument_is_a_protocol_error() {
    let router = ro();
    let response = call_tool(&router, "list_jobs", json!({"job_id": "1004"})).await;
    assert!(response.get("error").is_some(), "{response}");
    let response = call_tool(&router, "list_hypertables", json!({"bogus": 1})).await;
    assert!(response.get("error").is_some(), "{response}");
}

#[tokio::test]
async fn no_secret_in_any_output() {
    let router = ro();
    for (name, args) in [
        ("list_hypertables", json!({})),
        (
            "describe_hypertable",
            json!({"hypertable": "metrics.readings"}),
        ),
        ("list_continuous_aggregates", json!({})),
        ("list_jobs", json!({})),
        ("list_jobs", json!({"history": true})),
    ] {
        let result = call(&router, name, args).await;
        let serialized = result.to_string();
        for word in DENIED_WORDS {
            assert!(!serialized.contains(word), "{name} leaks {word}");
        }
    }
}

#[test]
fn probe_picks_columnstore_names_when_present() {
    let features = Features::new(
        "appdb",
        Some("2.99.0"),
        Some("public"),
        &[
            ("hypertables", "columnstore_enabled"),
            ("hypertables", "compression_enabled"),
            ("chunks", "is_columnstore"),
            ("chunks", "is_compressed"),
            ("continuous_aggregates", "columnstore_enabled"),
            ("hypertable_columnstore_settings", "hypertable"),
            ("hypertable_columnstore_settings", "segmentby"),
            ("hypertable_columnstore_settings", "orderby"),
            ("hypertable_compression_settings", "hypertable"),
            ("hypertable_compression_settings", "segmentby"),
            ("hypertable_compression_settings", "orderby"),
            ("continuous_aggregates", "finalized"),
        ],
        &[
            ("public", "hypertable_columnstore_stats"),
            ("public", "hypertable_compression_stats"),
        ],
    );
    let sources = Sources::choose(&features);
    assert_eq!(sources.hypertable_flag, Some("columnstore_enabled"));
    assert_eq!(sources.chunk_flag, Some("is_columnstore"));
    assert_eq!(sources.cagg_flag, Some("columnstore_enabled"));
    assert_eq!(
        sources.settings_view,
        Some("hypertable_columnstore_settings")
    );
    assert_eq!(sources.stats_function, Some("hypertable_columnstore_stats"));
    assert!(sources.cagg_finalized);
}

#[test]
fn probe_falls_back_to_compression_names_and_omits_missing_sources() {
    let features = Features::new(
        "appdb",
        Some("2.32.1"),
        Some("public"),
        &[
            ("hypertables", "compression_enabled"),
            ("chunks", "is_compressed"),
            ("continuous_aggregates", "compression_enabled"),
            ("hypertable_compression_settings", "hypertable"),
            ("hypertable_compression_settings", "segmentby"),
            ("hypertable_compression_settings", "orderby"),
        ],
        &[("public", "hypertable_compression_stats")],
    );
    let sources = Sources::choose(&features);
    assert_eq!(sources.hypertable_flag, Some("compression_enabled"));
    assert_eq!(sources.chunk_flag, Some("is_compressed"));
    assert_eq!(sources.cagg_flag, Some("compression_enabled"));
    assert_eq!(
        sources.settings_view,
        Some("hypertable_compression_settings")
    );
    assert_eq!(sources.stats_function, Some("hypertable_compression_stats"));
    assert!(!sources.cagg_finalized, "finalized is not in this version");
    assert!(!sources.chunk_tablespace);
    assert!(!sources.job_fixed_schedule);

    let bare = Features::new("appdb", None, None, &[], &[]);
    let none = Sources::choose(&bare);
    assert_eq!(none.hypertable_flag, None);
    assert_eq!(none.settings_view, None);
    assert_eq!(none.stats_function, None);
    assert!(!bare.installed());
}

#[test]
fn probe_resolves_functions_in_the_extension_schema_only_when_present() {
    let features = Features::new(
        "appdb",
        Some("2.32.1"),
        Some("tsdb"),
        &[],
        &[
            ("tsdb", "hypertable_size"),
            ("_timescaledb_functions", "cagg_watermark"),
        ],
    );
    assert_eq!(
        features.extension_function("hypertable_size").as_deref(),
        Some("\"tsdb\".hypertable_size")
    );
    assert_eq!(features.extension_function("approximate_row_count"), None);
    assert_eq!(
        features
            .function("_timescaledb_functions", "cagg_watermark")
            .as_deref(),
        Some("\"_timescaledb_functions\".cagg_watermark")
    );
    assert!(features.require("chunks", &["chunk_name"]).is_err());
}

#[test]
fn quoted_identifiers_double_their_quotes() {
    assert_eq!(quote_ident("public"), "\"public\"");
    assert_eq!(quote_ident("we\"ird"), "\"we\"\"ird\"");
}

#[test]
fn name_lists_and_orderby_parse_catalog_text() {
    assert_eq!(parse_name_list("device_id"), vec!["device_id".to_owned()]);
    assert_eq!(
        parse_name_list(" device_id ,  region "),
        vec!["device_id".to_owned(), "region".to_owned()]
    );
    assert!(parse_name_list("").is_empty());

    let parsed = parse_orderby("ts DESC, temperature");
    assert_eq!(
        parsed,
        vec![
            json!({"column": "ts", "descending": true, "nullsFirst": true}),
            json!({"column": "temperature", "descending": false, "nullsFirst": false}),
        ]
    );
    let explicit = parse_orderby("ts DESC NULLS LAST");
    assert_eq!(
        explicit,
        vec![json!({"column": "ts", "descending": true, "nullsFirst": false})]
    );
    let ascending_first = parse_orderby("ts ASC NULLS FIRST");
    assert_eq!(
        ascending_first,
        vec![json!({"column": "ts", "descending": false, "nullsFirst": true})]
    );
}
