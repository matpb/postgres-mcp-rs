//! query_stats: pg_stat_statements rankings, found through the extension's catalog entry.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{
    bool_text, bounded, fail, first_object, flag, flag_of, hidden_text_note, present_columns,
    shape_query, text_visibility, wide_rows,
};
use crate::server::AppState;
use crate::tools::{Call, ToolError, value_of};

const ORDERS: [(&str, &str); 6] = [
    ("total_time", "s.total_exec_time DESC"),
    ("mean_time", "s.mean_exec_time DESC"),
    ("calls", "s.calls DESC"),
    ("rows", "s.rows DESC"),
    ("io", "s.shared_blks_read DESC"),
    ("temp", "s.temp_blks_written DESC"),
];
const NOT_INSTALLED: &str = "pg_stat_statements is not installed in this database.";
const NOT_LOADED: &str = "pg_stat_statements is installed but not loaded: add it to shared_preload_libraries and restart the server.";
const HOW_TO_ENABLE: &str = "Add pg_stat_statements to shared_preload_libraries, restart, then CREATE EXTENSION pg_stat_statements;";
/// SQLSTATE that PostgreSQL raises when the view is read without shared_preload_libraries.
const OBJECT_NOT_IN_PREREQUISITE_STATE: &str = "55000";

/// The extension's schema and whether its info view exists; the views are then named through that schema.
const EXTENSION_SQL: &str = "SELECT n.nspname::text AS \"schema\", \
    EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.relnamespace = e.extnamespace \
        AND c.relname = 'pg_stat_statements_info') AS \"info\" \
    FROM pg_catalog.pg_extension e \
    JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace \
    WHERE e.extname = 'pg_stat_statements'";
const OPTIONAL_COLUMNS: [&str; 2] = ["total_plan_time", "wal_bytes"];

/// `"schema".name` with the schema quoted, so the name resolves whatever the search_path is.
fn qualified_name(schema: &str, name: &str) -> String {
    format!("\"{}\".{name}", schema.replace('"', "\"\""))
}

fn info_sql(info_view: &str) -> String {
    format!("SELECT i.dealloc AS \"dealloc\", i.stats_reset AS \"statsReset\" FROM {info_view} i")
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QueryStatsArgs {
    pub database: Option<String>,
    pub order_by: Option<String>,
    pub min_calls: Option<i64>,
    pub contains: Option<String>,
    pub all_databases: Option<bool>,
    pub query_chars: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryStatsResult {
    pub database: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how_to_enable: Option<String>,
    pub statements: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats_reset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dealloc: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub async fn query_stats(state: &AppState, args: QueryStatsArgs, ct: &CancellationToken) -> Call {
    match statements_of(state, &args, ct).await {
        Ok(result) => {
            let rows = result.statements.len();
            let database = Some(result.database.clone());
            Call {
                result: value_of(&result),
                database,
                rows: Some(rows),
                sql: None,
            }
        }
        Err(error) => fail(error, state, args.database.as_deref()),
    }
}

async fn statements_of(
    state: &AppState,
    args: &QueryStatsArgs,
    ct: &CancellationToken,
) -> Result<QueryStatsResult, ToolError> {
    let order = order_clause(args.order_by.as_deref())?;
    let query_chars =
        usize::try_from(bounded("query_chars", args.query_chars, 500, 0, 4000)?).unwrap_or(0);
    let limit = bounded("limit", args.limit, 20, 1, 500)?;
    let database = args.database.as_deref();

    let extension = wide_rows(state, database, EXTENSION_SQL, &[], ct).await?;
    let Some(ext) = extension.rows.first() else {
        return Ok(unavailable(
            extension.database,
            NOT_INSTALLED.to_owned(),
            Some(HOW_TO_ENABLE),
        ));
    };
    let db_name = extension.database.clone();
    let schema = ext
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let view = qualified_name(schema, "pg_stat_statements");
    let has_info = flag_of(ext, "info");

    let visibility = text_visibility(state, database, ct).await?;
    let optional = present_columns(state, database, &view, &OPTIONAL_COLUMNS, ct).await?;
    let sql = statements_sql(&view, &optional, order, limit);
    let min_calls = args.min_calls.map(|calls| calls.to_string());
    let params: [Option<&str>; 3] = [
        Some(bool_text(flag(args.all_databases))),
        min_calls.as_deref(),
        args.contains.as_deref(),
    ];
    let envelope = match wide_rows(state, database, &sql, &params, ct).await {
        Ok(envelope) => envelope,
        Err(error) => {
            return match error.sqlstate() {
                Some(OBJECT_NOT_IN_PREREQUISITE_STATE) => Ok(unavailable(
                    db_name,
                    NOT_LOADED.to_owned(),
                    Some(HOW_TO_ENABLE),
                )),
                Some(_) => Ok(unavailable(db_name, error.message(), None)),
                None => Err(error),
            };
        }
    };

    let mut statements = envelope.rows;
    for row in &mut statements {
        shape_query(row, query_chars);
    }
    let (stats_reset, dealloc) = if has_info {
        let info_view = qualified_name(schema, "pg_stat_statements_info");
        let info = wide_rows(state, database, &info_sql(&info_view), &[], ct).await?;
        let row = first_object(info.rows);
        (
            row.get("statsReset")
                .and_then(Value::as_str)
                .map(str::to_owned),
            row.get("dealloc").and_then(Value::as_i64),
        )
    } else {
        (None, None)
    };
    Ok(QueryStatsResult {
        database: envelope.database,
        available: true,
        reason: None,
        how_to_enable: None,
        statements,
        stats_reset,
        dealloc,
        note: (!visibility.visible).then(|| hidden_text_note(&visibility.role)),
    })
}

fn unavailable(database: String, reason: String, how_to_enable: Option<&str>) -> QueryStatsResult {
    QueryStatsResult {
        database,
        available: false,
        reason: Some(reason),
        how_to_enable: how_to_enable.map(str::to_owned),
        statements: Vec::new(),
        stats_reset: None,
        dealloc: None,
        note: None,
    }
}

/// The ORDER BY clause for an order_by value; absent means total_time.
fn order_clause(order_by: Option<&str>) -> Result<&'static str, ToolError> {
    let key = order_by.unwrap_or("total_time");
    ORDERS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, clause)| *clause)
        .ok_or_else(|| {
            ToolError::Rejected(format!(
                "Invalid order_by \"{key}\". Valid values: total_time, mean_time, calls, rows, io, temp."
            ))
        })
}

/// The ranking query over the view; the optional columns are included only when the server has them.
fn statements_sql(view: &str, optional: &[String], order: &str, limit: i64) -> String {
    let has = |name: &str| optional.iter().any(|column| column == name);
    let mut extra = String::new();
    if has("total_plan_time") {
        extra.push_str("ROUND(s.total_plan_time::numeric, 3)::float8 AS \"totalPlanTimeMs\", ");
    }
    if has("wal_bytes") {
        extra.push_str("s.wal_bytes::bigint AS \"walBytes\", ");
    }
    format!(
        "SELECT s.queryid::text AS \"queryId\", r.rolname::text AS \"user\", d.datname::text AS \"database\", \
        s.query, NULL::boolean AS \"queryTruncated\", s.calls, \
        ROUND(s.total_exec_time::numeric, 3)::float8 AS \"totalExecTimeMs\", \
        ROUND(s.mean_exec_time::numeric, 3)::float8 AS \"meanExecTimeMs\", \
        ROUND(s.min_exec_time::numeric, 3)::float8 AS \"minExecTimeMs\", \
        ROUND(s.max_exec_time::numeric, 3)::float8 AS \"maxExecTimeMs\", \
        ROUND(s.stddev_exec_time::numeric, 3)::float8 AS \"stddevExecTimeMs\", \
        {extra}s.rows, s.shared_blks_hit AS \"sharedBlksHit\", s.shared_blks_read AS \"sharedBlksRead\", \
        s.shared_blks_dirtied AS \"sharedBlksDirtied\", s.temp_blks_written AS \"tempBlksWritten\", \
        CASE WHEN s.shared_blks_hit + s.shared_blks_read > 0 \
        THEN ROUND(s.shared_blks_hit::numeric / (s.shared_blks_hit + s.shared_blks_read), 4)::float8 END AS \"cacheHitRatio\" \
        FROM {view} s \
        LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.userid \
        LEFT JOIN pg_catalog.pg_database d ON d.oid = s.dbid \
        WHERE ($1::boolean OR s.dbid = (SELECT db.oid FROM pg_catalog.pg_database db WHERE db.datname = pg_catalog.current_database())) \
        AND ($2::bigint IS NULL OR s.calls >= $2::bigint) \
        AND ($3::text IS NULL OR strpos(lower(s.query), lower($3::text)) > 0) \
        ORDER BY {order}, s.queryid, s.userid, s.dbid LIMIT {limit}"
    )
}
