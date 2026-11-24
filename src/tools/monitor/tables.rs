//! table_stats: per-table activity, optional index detail, and the indexes never scanned.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{bounded, fail, first_object, flag, next_cursor, parse_offset, wide_rows};
use crate::server::AppState;
use crate::tools::{Call, ToolError, value_of};

const ORDERS: [(&str, &str); 6] = [
    ("size", "pg_catalog.pg_total_relation_size(s.relid) DESC"),
    ("seq_scan", "s.seq_scan DESC"),
    ("idx_scan", "s.idx_scan DESC NULLS LAST"),
    ("dead_rows", "s.n_dead_tup DESC"),
    ("writes", "(s.n_tup_ins + s.n_tup_upd + s.n_tup_del) DESC"),
    ("last_autovacuum", "s.last_autovacuum ASC NULLS FIRST"),
];
/// Relations of the schema filter: the system schemas and TimescaleDB internals are left out unless named.
const SCHEMA_FILTER: &str = "(($1::text IS NULL AND s.schemaname NOT IN ('pg_catalog', 'information_schema', \
    'timescaledb_information', 'timescaledb_experimental', 'toolkit_experimental') \
    AND NOT pg_catalog.starts_with(s.schemaname, 'pg_toast') AND NOT pg_catalog.starts_with(s.schemaname, 'pg_temp_') \
    AND NOT pg_catalog.starts_with(s.schemaname, '_timescaledb_')) OR s.schemaname = $1::text) \
    AND ($2::text IS NULL OR s.relname = $2::text)";
const INDEXES_JSON: &str = "LEFT JOIN LATERAL (SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object(\
    'name', ic.relname, 'scans', si.idx_scan, 'tupRead', si.idx_tup_read, 'tupFetch', si.idx_tup_fetch, \
    'sizeBytes', pg_catalog.pg_relation_size(i.indexrelid), 'unique', i.indisunique, \
    'primary', i.indisprimary, 'valid', i.indisvalid) ORDER BY ic.relname), '[]'::jsonb) AS indexes \
    FROM pg_catalog.pg_index i \
    JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid \
    JOIN pg_catalog.pg_stat_user_indexes si ON si.indexrelid = i.indexrelid \
    WHERE i.indrelid = s.relid) ix ON true";
const RESET_SQL: &str = "SELECT d.stats_reset AS \"statsReset\" FROM pg_catalog.pg_stat_database d \
    WHERE d.datname = pg_catalog.current_database()";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TableStatsArgs {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub table: Option<String>,
    pub order_by: Option<String>,
    pub include_indexes: Option<bool>,
    pub unused_indexes: Option<bool>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TableStatsResult {
    pub database: String,
    pub tables: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unused_indexes: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub stats_reset: Option<String>,
}

pub async fn table_stats(state: &AppState, args: TableStatsArgs, ct: &CancellationToken) -> Call {
    match tables_of(state, &args, ct).await {
        Ok(result) => {
            let rows = result.tables.len();
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

async fn tables_of(
    state: &AppState,
    args: &TableStatsArgs,
    ct: &CancellationToken,
) -> Result<TableStatsResult, ToolError> {
    let order = order_clause(args.order_by.as_deref())?;
    let limit = bounded("limit", args.limit, 100, 1, 500)?;
    let offset = parse_offset(args.cursor.as_deref())?;
    let include_indexes = args.include_indexes.unwrap_or(args.table.is_some());
    let unused = flag(args.unused_indexes);
    let page = format!("LIMIT {} OFFSET {offset}", limit + 1);
    let sql = if unused {
        unused_indexes_sql(&page)
    } else {
        tables_sql(include_indexes, order, &page)
    };
    let params: [Option<&str>; 2] = [args.schema.as_deref(), args.table.as_deref()];
    let envelope = wide_rows(state, args.database.as_deref(), &sql, &params, ct).await?;
    let reset = wide_rows(state, args.database.as_deref(), RESET_SQL, &[], ct).await?;
    let stats_reset = first_object(reset.rows)
        .get("statsReset")
        .and_then(Value::as_str)
        .map(str::to_owned);

    let mut rows = envelope.rows;
    let page_size = usize::try_from(limit).unwrap_or(0);
    let more = rows.len() > page_size;
    rows.truncate(page_size);
    let cursor = more.then(|| next_cursor(offset, limit));
    let (tables, unused_indexes) = if unused {
        (Vec::new(), Some(rows))
    } else {
        (rows, None)
    };
    Ok(TableStatsResult {
        database: envelope.database,
        tables,
        unused_indexes,
        next_cursor: cursor,
        stats_reset,
    })
}

/// The ORDER BY clause for an order_by value; absent means size.
fn order_clause(order_by: Option<&str>) -> Result<&'static str, ToolError> {
    let key = order_by.unwrap_or("size");
    ORDERS
        .iter()
        .find(|(name, _)| *name == key)
        .map(|(_, clause)| *clause)
        .ok_or_else(|| {
            ToolError::Rejected(format!(
                "Invalid order_by \"{key}\". Valid values: size, seq_scan, idx_scan, dead_rows, writes, last_autovacuum."
            ))
        })
}

fn tables_sql(include_indexes: bool, order: &str, page: &str) -> String {
    let indexes = if include_indexes {
        ", ix.indexes AS indexes"
    } else {
        ""
    };
    let lateral = if include_indexes { INDEXES_JSON } else { "" };
    format!(
        "SELECT s.schemaname AS \"schema\", s.relname AS \"name\", c.reltuples::bigint AS \"rowEstimate\", \
        s.n_live_tup AS \"liveRows\", s.n_dead_tup AS \"deadRows\", \
        CASE WHEN s.n_live_tup + s.n_dead_tup > 0 \
        THEN pg_catalog.ROUND(s.n_dead_tup::numeric / (s.n_live_tup + s.n_dead_tup), 4)::float8 END AS \"deadRatio\", \
        s.seq_scan AS \"seqScan\", s.seq_tup_read AS \"seqTupRead\", s.idx_scan AS \"idxScan\", \
        s.idx_tup_fetch AS \"idxTupFetch\", s.n_tup_ins AS \"inserts\", s.n_tup_upd AS \"updates\", \
        s.n_tup_hot_upd AS \"hotUpdates\", s.n_tup_del AS \"deletes\", \
        s.n_mod_since_analyze AS \"modsSinceAnalyze\", s.last_vacuum AS \"lastVacuum\", \
        s.last_autovacuum AS \"lastAutovacuum\", s.last_analyze AS \"lastAnalyze\", \
        s.last_autoanalyze AS \"lastAutoanalyze\", s.vacuum_count AS \"vacuumCount\", \
        s.autovacuum_count AS \"autovacuumCount\", pg_catalog.pg_total_relation_size(s.relid) AS \"totalBytes\", \
        pg_catalog.pg_table_size(s.relid) AS \"tableBytes\", pg_catalog.pg_indexes_size(s.relid) AS \"indexBytes\", \
        io.heap_blks_read AS \"heapBlksRead\", io.heap_blks_hit AS \"heapBlksHit\"{indexes} \
        FROM pg_catalog.pg_stat_user_tables s \
        JOIN pg_catalog.pg_class c ON c.oid = s.relid \
        LEFT JOIN pg_catalog.pg_statio_user_tables io ON io.relid = s.relid \
        {lateral} \
        WHERE {SCHEMA_FILTER} \
        ORDER BY {order}, s.schemaname, s.relname {page}"
    )
}

fn unused_indexes_sql(page: &str) -> String {
    format!(
        "SELECT s.schemaname AS \"schema\", s.relname AS \"table\", s.indexrelname AS \"name\", \
        pg_catalog.pg_relation_size(s.indexrelid) AS \"sizeBytes\", \
        pg_catalog.pg_get_indexdef(s.indexrelid) AS \"definition\" \
        FROM pg_catalog.pg_stat_user_indexes s \
        JOIN pg_catalog.pg_index i ON i.indexrelid = s.indexrelid \
        WHERE s.idx_scan = 0 AND NOT i.indisprimary AND NOT i.indisunique AND {SCHEMA_FILTER} \
        ORDER BY s.schemaname, s.relname, s.indexrelname {page}"
    )
}
