//! database_stats: cumulative statistics by section, each one degrading to an unavailable reason.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{fail, first_object, present_columns, select_items, wide_rows};
use crate::server::AppState;
use crate::tools::{Call, ToolError, value_of};

const SECTIONS: [&str; 6] = [
    "database",
    "io",
    "wal",
    "checkpointer",
    "progress",
    "wait_events",
];
const DEFAULT_SECTIONS: [&str; 3] = ["database", "checkpointer", "progress"];
const VERSION_SQL: &str = "SELECT pg_catalog.current_setting('server_version') AS \"serverVersion\", \
    pg_catalog.current_setting('server_version_num')::int AS \"versionNum\"";
const DATABASE_SQL: &str = "SELECT d.numbackends, d.xact_commit AS \"xactCommit\", \
    d.xact_rollback AS \"xactRollback\", d.blks_read AS \"blksRead\", d.blks_hit AS \"blksHit\", \
    CASE WHEN d.blks_hit + d.blks_read > 0 \
    THEN pg_catalog.ROUND(d.blks_hit::numeric / (d.blks_hit + d.blks_read), 4)::float8 END AS \"cacheHitRatio\", \
    d.tup_returned AS \"tupReturned\", d.tup_fetched AS \"tupFetched\", d.tup_inserted AS \"tupInserted\", \
    d.tup_updated AS \"tupUpdated\", d.tup_deleted AS \"tupDeleted\", d.conflicts, \
    d.temp_files AS \"tempFiles\", d.temp_bytes AS \"tempBytes\", d.deadlocks, \
    d.checksum_failures AS \"checksumFailures\", d.sessions, d.sessions_abandoned AS \"sessionsAbandoned\", \
    d.sessions_fatal AS \"sessionsFatal\", d.sessions_killed AS \"sessionsKilled\", d.stats_reset AS \"statsReset\", \
    pg_catalog.pg_database_size(d.datid) AS \"sizeBytes\", pg_catalog.age(db.datfrozenxid) AS \"xidAge\", \
    pg_catalog.current_setting('max_connections')::int AS \"maxConnections\", \
    (SELECT pg_catalog.count(*) FROM pg_catalog.pg_stat_activity a WHERE a.backend_type = 'client backend') AS \"connectionsUsed\" \
    FROM pg_catalog.pg_stat_database d \
    JOIN pg_catalog.pg_database db ON db.oid = d.datid \
    WHERE d.datname = pg_catalog.current_database()";
const IO_COLUMNS: [&str; 20] = [
    "backend_type",
    "object",
    "context",
    "reads",
    "read_bytes",
    "read_time",
    "writes",
    "write_bytes",
    "write_time",
    "writebacks",
    "writeback_time",
    "extends",
    "extend_bytes",
    "extend_time",
    "op_bytes",
    "hits",
    "evictions",
    "reuses",
    "fsyncs",
    "fsync_time",
];
/// Counters of pg_stat_io: a row with any of these nonzero has activity.
const IO_COUNTERS: [&str; 8] = [
    "reads",
    "writes",
    "writebacks",
    "extends",
    "hits",
    "evictions",
    "reuses",
    "fsyncs",
];
const WAL_COLUMNS: [&str; 10] = [
    "wal_records",
    "wal_fpi",
    "wal_bytes",
    "wal_fpi_bytes",
    "wal_buffers_full",
    "wal_write",
    "wal_sync",
    "wal_write_time",
    "wal_sync_time",
    "stats_reset",
];
const CHECKPOINTER_17_SQL: &str = "SELECT s.num_timed AS \"checkpointsTimed\", \
    s.num_requested AS \"checkpointsRequested\", s.write_time AS \"writeTimeMs\", \
    s.sync_time AS \"syncTimeMs\", s.buffers_written AS \"buffersWritten\", s.stats_reset AS \"statsReset\", \
    'pg_stat_checkpointer' AS source FROM pg_catalog.pg_stat_checkpointer s";
const CHECKPOINTER_BGWRITER_SQL: &str = "SELECT s.checkpoints_timed AS \"checkpointsTimed\", \
    s.checkpoints_req AS \"checkpointsRequested\", s.checkpoint_write_time AS \"writeTimeMs\", \
    s.checkpoint_sync_time AS \"syncTimeMs\", s.buffers_checkpoint AS \"buffersWritten\", \
    s.stats_reset AS \"statsReset\", 'pg_stat_bgwriter' AS source FROM pg_catalog.pg_stat_bgwriter s";
const WAIT_EVENTS_SQL: &str = "SELECT a.wait_event_type AS \"type\", a.wait_event AS \"event\", \
    pg_catalog.count(*) AS \"sessions\", NULL::text AS \"description\" FROM pg_catalog.pg_stat_activity a \
    WHERE a.wait_event_type IS NOT NULL \
    GROUP BY a.wait_event_type, a.wait_event \
    ORDER BY pg_catalog.count(*) DESC, a.wait_event_type, a.wait_event";
/// PostgreSQL 17 and newer: each wait event with its description from pg_wait_events.
const WAIT_EVENTS_DESCRIBED_SQL: &str = "SELECT a.wait_event_type AS \"type\", a.wait_event AS \"event\", \
    pg_catalog.count(*) AS \"sessions\", e.description AS \"description\" FROM pg_catalog.pg_stat_activity a \
    LEFT JOIN pg_catalog.pg_wait_events e ON e.type = a.wait_event_type AND e.name = a.wait_event \
    WHERE a.wait_event_type IS NOT NULL \
    GROUP BY a.wait_event_type, a.wait_event, e.description \
    ORDER BY pg_catalog.count(*) DESC, a.wait_event_type, a.wait_event";

/// One pg_stat_progress_* view with the counter columns it may have.
struct ProgressView {
    key: &'static str,
    view: &'static str,
    counters: &'static [&'static str],
}

const PROGRESS_VIEWS: [ProgressView; 6] = [
    ProgressView {
        key: "vacuum",
        view: "pg_stat_progress_vacuum",
        counters: &[
            "heap_blks_total",
            "heap_blks_scanned",
            "heap_blks_vacuumed",
            "index_vacuum_count",
            "max_dead_tuples",
            "num_dead_tuples",
            "max_dead_tuple_bytes",
            "dead_tuple_bytes",
            "num_dead_item_ids",
            "indexes_total",
            "indexes_processed",
            "delay_time",
        ],
    },
    ProgressView {
        key: "analyze",
        view: "pg_stat_progress_analyze",
        counters: &[
            "sample_blks_total",
            "sample_blks_scanned",
            "ext_stats_total",
            "ext_stats_computed",
            "child_tables_total",
            "child_tables_done",
            "delay_time",
        ],
    },
    ProgressView {
        key: "createIndex",
        view: "pg_stat_progress_create_index",
        counters: &[
            "lockers_total",
            "lockers_done",
            "blocks_total",
            "blocks_done",
            "tuples_total",
            "tuples_done",
            "partitions_total",
            "partitions_done",
        ],
    },
    ProgressView {
        key: "cluster",
        view: "pg_stat_progress_cluster",
        counters: &[
            "heap_tuples_scanned",
            "heap_tuples_written",
            "heap_blks_total",
            "heap_blks_scanned",
            "index_rebuild_count",
        ],
    },
    ProgressView {
        key: "copy",
        view: "pg_stat_progress_copy",
        counters: &[
            "bytes_processed",
            "bytes_total",
            "tuples_processed",
            "tuples_excluded",
            "tuples_skipped",
        ],
    },
    ProgressView {
        key: "basebackup",
        view: "pg_stat_progress_basebackup",
        counters: &[
            "backup_total",
            "backup_streamed",
            "tablespaces_total",
            "tablespaces_streamed",
        ],
    },
];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatabaseStatsArgs {
    pub database: Option<String>,
    pub sections: Option<Vec<String>>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseStatsResult {
    pub database: String,
    pub server_version: String,
    pub sections: Map<String, Value>,
    pub unavailable: Vec<Unavailable>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub struct Unavailable {
    pub section: String,
    pub reason: String,
}

/// A section's value, or why it is not available on this server.
enum Outcome {
    Ready(Value),
    Unavailable(String),
}

pub async fn database_stats(
    state: &AppState,
    args: DatabaseStatsArgs,
    ct: &CancellationToken,
) -> Call {
    match stats_of(state, &args, ct).await {
        Ok(result) => {
            let database = Some(result.database.clone());
            Call {
                result: value_of(&result),
                database,
                rows: None,
                sql: None,
            }
        }
        Err(error) => fail(error, state, args.database.as_deref()),
    }
}

async fn stats_of(
    state: &AppState,
    args: &DatabaseStatsArgs,
    ct: &CancellationToken,
) -> Result<DatabaseStatsResult, ToolError> {
    let requested = requested_sections(args.sections.as_deref())?;
    let database = args.database.as_deref();
    let version = wide_rows(state, database, VERSION_SQL, &[], ct).await?;
    let row = version
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no version row".to_owned()))?;
    let server_version = row
        .get("serverVersion")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let version_num = row.get("versionNum").and_then(Value::as_i64).unwrap_or(0);

    let mut sections = Map::new();
    let mut unavailable = Vec::new();
    for section in requested {
        let outcome = match section_of(state, database, section, version_num, ct).await {
            Ok(outcome) => outcome,
            Err(error) => match &error {
                ToolError::Db(_) => Outcome::Unavailable(error.message()),
                _ => return Err(error),
            },
        };
        match outcome {
            Outcome::Ready(value) => {
                sections.insert(key_of(section), value);
            }
            Outcome::Unavailable(reason) => unavailable.push(Unavailable {
                section: section.to_owned(),
                reason,
            }),
        }
    }
    Ok(DatabaseStatsResult {
        database: version.database,
        server_version,
        sections,
        unavailable,
    })
}

/// The requested section names in catalogue order, without duplicates; absent means the defaults.
fn requested_sections(list: Option<&[String]>) -> Result<Vec<&'static str>, ToolError> {
    let names: Vec<&str> = match list {
        Some(list) => list.iter().map(String::as_str).collect(),
        None => DEFAULT_SECTIONS.to_vec(),
    };
    if let Some(unknown) = names.iter().find(|name| !SECTIONS.contains(name)) {
        return Err(ToolError::Rejected(format!(
            "Unknown section \"{unknown}\". Valid sections: {}.",
            SECTIONS.join(", ")
        )));
    }
    Ok(SECTIONS
        .iter()
        .copied()
        .filter(|section| names.contains(section))
        .collect())
}

/// The key a section has in the result.
fn key_of(section: &str) -> String {
    match section {
        "wait_events" => "waitEvents".to_owned(),
        other => other.to_owned(),
    }
}

async fn section_of(
    state: &AppState,
    database: Option<&str>,
    section: &str,
    version_num: i64,
    ct: &CancellationToken,
) -> Result<Outcome, ToolError> {
    match section {
        "database" => {
            let envelope = wide_rows(state, database, DATABASE_SQL, &[], ct).await?;
            Ok(Outcome::Ready(Value::Object(first_object(envelope.rows))))
        }
        "io" => {
            if version_num < 160_000 {
                return Ok(Outcome::Unavailable(format!(
                    "pg_stat_io needs PostgreSQL 16 or newer; this server is {}.",
                    version_num / 10_000
                )));
            }
            io_section(state, database, ct).await
        }
        "wal" => {
            let columns =
                present_columns(state, database, "pg_catalog.pg_stat_wal", &WAL_COLUMNS, ct)
                    .await?;
            let sql = format!(
                "SELECT {} FROM pg_catalog.pg_stat_wal s",
                select_items("s", &columns)
            );
            let envelope = wide_rows(state, database, &sql, &[], ct).await?;
            Ok(Outcome::Ready(Value::Object(first_object(envelope.rows))))
        }
        "checkpointer" => {
            let sql = if version_num >= 170_000 {
                CHECKPOINTER_17_SQL
            } else {
                CHECKPOINTER_BGWRITER_SQL
            };
            let envelope = wide_rows(state, database, sql, &[], ct).await?;
            Ok(Outcome::Ready(Value::Object(first_object(envelope.rows))))
        }
        "progress" => {
            let mut lists = Map::new();
            for view in &PROGRESS_VIEWS {
                let rows = progress_rows(state, database, view, ct).await?;
                lists.insert(view.key.to_owned(), Value::Array(rows));
            }
            Ok(Outcome::Ready(Value::Object(lists)))
        }
        _ => {
            let sql = if version_num >= 170_000 {
                WAIT_EVENTS_DESCRIBED_SQL
            } else {
                WAIT_EVENTS_SQL
            };
            let envelope = wide_rows(state, database, sql, &[], ct).await?;
            Ok(Outcome::Ready(Value::Array(
                envelope.rows.into_iter().map(Value::Object).collect(),
            )))
        }
    }
}

async fn io_section(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Outcome, ToolError> {
    let columns =
        present_columns(state, database, "pg_catalog.pg_stat_io", &IO_COLUMNS, ct).await?;
    let active: Vec<String> = columns
        .iter()
        .filter(|column| IO_COUNTERS.contains(&column.as_str()))
        .map(|column| format!("COALESCE(s.{column}, 0) <> 0"))
        .collect();
    let filter = if active.is_empty() {
        "TRUE".to_owned()
    } else {
        active.join(" OR ")
    };
    let sql = format!(
        "SELECT {} FROM pg_catalog.pg_stat_io s WHERE {filter} \
        ORDER BY s.backend_type, s.object, s.context",
        select_items("s", &columns)
    );
    let envelope = wide_rows(state, database, &sql, &[], ct).await?;
    Ok(Outcome::Ready(Value::Array(
        envelope.rows.into_iter().map(Value::Object).collect(),
    )))
}

/// One pg_stat_progress_* view as a list: pid, relation name, phase and counters, for this database.
async fn progress_rows(
    state: &AppState,
    database: Option<&str>,
    view: &ProgressView,
    ct: &CancellationToken,
) -> Result<Vec<Value>, ToolError> {
    let relation = format!("pg_catalog.{}", view.view);
    let mut candidates: Vec<&str> = vec!["pid", "phase", "relid", "datid"];
    candidates.extend_from_slice(view.counters);
    let present = present_columns(state, database, &relation, &candidates, ct).await?;
    let has = |name: &str| present.iter().any(|column| column == name);

    let mut items = vec!["p.pid AS \"pid\"".to_owned()];
    let related = has("relid");
    if related {
        items.push(
            "CASE WHEN c.oid IS NULL THEN NULL ELSE n.nspname || '.' || c.relname END AS \"relation\""
                .to_owned(),
        );
    }
    if has("phase") {
        items.push("p.phase AS \"phase\"".to_owned());
    }
    let counters: Vec<String> = view
        .counters
        .iter()
        .filter(|counter| has(counter))
        .map(|counter| (*counter).to_owned())
        .collect();
    if !counters.is_empty() {
        items.push(select_items("p", &counters));
    }

    let mut sql = format!("SELECT {} FROM {relation} p", items.join(", "));
    if related {
        sql.push_str(
            " LEFT JOIN pg_catalog.pg_class c ON c.oid = p.relid \
            LEFT JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace",
        );
    }
    if has("datid") {
        sql.push_str(
            " WHERE p.datid = (SELECT db.oid FROM pg_catalog.pg_database db \
            WHERE db.datname = pg_catalog.current_database())",
        );
    }
    let envelope = wide_rows(state, database, &sql, &[], ct).await?;
    Ok(envelope.rows.into_iter().map(Value::Object).collect())
}
