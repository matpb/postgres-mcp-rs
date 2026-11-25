//! TimescaleDB tools: hypertables, continuous aggregates and background jobs, read from timescaledb_information and the extension's functions.

pub mod caggs;
pub mod hypertables;
pub mod jobs;
pub mod parse;
pub mod probe;

use rmcp::ErrorData as McpError;
use rmcp::model::Tool;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::core::{tool, tool_with_leading};
use super::envelope::{self, QueryEnvelope};
use super::text;
use super::{Call, INTERNAL_MAX_ROWS, Runner, Statement, ToolError, Toolset, parse_args};
use crate::pg::wire::FetchLimits;
use crate::server::AppState;

/// Rows per page when the caller gives no limit.
const DEFAULT_LIMIT: usize = 100;
/// Chunks per page of describe_hypertable when the caller gives no chunk_limit.
const DEFAULT_CHUNK_LIMIT: usize = 20;
/// Largest single value a catalog query may return; a longer value is an error, never a cut.
const MAX_VALUE_BYTES: usize = 1_048_576;
/// Largest response a catalog query may return.
const MAX_RESPONSE_BYTES: usize = 8 * 1_048_576;

const DIMENSION_COLUMNS: &[&str] = &[
    "hypertable_schema",
    "hypertable_name",
    "dimension_number",
    "dimension_type",
    "column_name",
    "column_type",
    "time_interval",
    "integer_interval",
    "num_partitions",
];
const CHUNK_COLUMNS: &[&str] = &[
    "hypertable_schema",
    "hypertable_name",
    "chunk_schema",
    "chunk_name",
    "range_start",
    "range_end",
    "range_start_integer",
    "range_end_integer",
];
const CAGG_COLUMNS: &[&str] = &[
    "view_schema",
    "view_name",
    "view_owner",
    "hypertable_schema",
    "hypertable_name",
    "materialized_only",
    "view_definition",
    "materialization_hypertable_schema",
    "materialization_hypertable_name",
];
const JOB_COLUMNS: &[&str] = &[
    "job_id",
    "application_name",
    "schedule_interval",
    "max_runtime",
    "max_retries",
    "retry_period",
    "proc_schema",
    "proc_name",
    "owner",
    "scheduled",
    "config",
    "next_start",
    "hypertable_schema",
    "hypertable_name",
];
const JOB_STATS_COLUMNS: &[&str] = &[
    "job_id",
    "last_run_started_at",
    "last_successful_finish",
    "last_run_status",
    "last_run_duration",
    "total_runs",
    "total_successes",
    "total_failures",
];
const HISTORY_COLUMNS: &[&str] = &[
    "id",
    "job_id",
    "succeeded",
    "proc_schema",
    "proc_name",
    "pid",
    "start_time",
    "finish_time",
    "sqlerrcode",
    "err_message",
];
const ERRORS_COLUMNS: &[&str] = &[
    "job_id",
    "proc_schema",
    "proc_name",
    "pid",
    "start_time",
    "finish_time",
    "sqlerrcode",
    "err_message",
];
/// SQL that finds the oid of one relation by schema and name.
const RELATION_OID_SQL: &str = "SELECT c.oid FROM pg_catalog.pg_class c \
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE n.nspname = $1::text AND c.relname = $2::text";

/// The four TimescaleDB tools with their toolset tag.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    vec![
        (
            Toolset::Timescale,
            tool::<hypertables::ListArgs, hypertables::ListResult>(
                "list_hypertables",
                text::LIST_HYPERTABLES_TITLE,
                text::LIST_HYPERTABLES,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("schema", text::SCHEMA_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
            ),
        ),
        (
            Toolset::Timescale,
            tool_with_leading::<hypertables::DescribeArgs, hypertables::DescribeResult>(
                "describe_hypertable",
                text::DESCRIBE_HYPERTABLE_TITLE,
                text::DESCRIBE_HYPERTABLE,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("hypertable", text::DESCRIBE_HYPERTABLE_HYPERTABLE_PARAM),
                    ("schema", text::DESCRIBE_HYPERTABLE_SCHEMA_PARAM),
                    ("chunk_limit", text::DESCRIBE_HYPERTABLE_CHUNK_LIMIT_PARAM),
                    ("chunk_cursor", text::DESCRIBE_HYPERTABLE_CHUNK_CURSOR_PARAM),
                ],
                &["hypertable", "schema", "chunk_limit", "chunk_cursor"],
            ),
        ),
        (
            Toolset::Timescale,
            tool::<caggs::ListArgs, caggs::ListResult>(
                "list_continuous_aggregates",
                text::LIST_CAGGS_TITLE,
                text::LIST_CAGGS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("schema", text::SCHEMA_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
            ),
        ),
        (
            Toolset::Timescale,
            tool_with_leading::<jobs::ListArgs, jobs::ListResult>(
                "list_jobs",
                text::LIST_JOBS_TITLE,
                text::LIST_JOBS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("job_id", text::LIST_JOBS_JOB_ID_PARAM),
                    ("history", text::LIST_JOBS_HISTORY_PARAM),
                    ("only_failures", text::LIST_JOBS_ONLY_FAILURES_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
                &["job_id", "history", "only_failures"],
            ),
        ),
    ]
}

/// Runs the named tool, or returns None when the name is not one of this module's tools.
pub async fn dispatch(
    state: &AppState,
    name: &str,
    args: Value,
    ct: &CancellationToken,
) -> Option<Result<Call, McpError>> {
    let call = match name {
        "list_hypertables" => match parse_args(args) {
            Ok(args) => hypertables::list(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "describe_hypertable" => match parse_args(args) {
            Ok(args) => hypertables::describe(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "list_continuous_aggregates" => match parse_args(args) {
            Ok(args) => caggs::list(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "list_jobs" => match parse_args(args) {
            Ok(args) => jobs::list(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        _ => return None,
    };
    Some(Ok(call))
}

/// Runs catalog SQL with the catalog limits. A result cut by a limit is an error, never a partial list.
async fn query(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    ct: &CancellationToken,
) -> Result<QueryEnvelope, ToolError> {
    let statement = Statement {
        sql,
        params,
        user_sql: false,
        fetch: FetchLimits {
            max_rows: INTERNAL_MAX_ROWS,
            max_bytes: MAX_RESPONSE_BYTES,
            max_value_bytes: MAX_VALUE_BYTES,
        },
        offset: Some(0),
        search_path_catalog_only: true,
    };
    let (name, output) = Runner::new(state)
        .internal_raw(database, statement, ct)
        .await?;
    let mut limits = state.config.limits.clone();
    limits.max_value_bytes = MAX_VALUE_BYTES;
    let envelope = envelope::build(&name, output, &limits, false);
    if envelope.truncated || envelope.truncated_values > 0 {
        return Err(ToolError::Internal(
            "a TimescaleDB catalog result exceeds the response limits".to_owned(),
        ));
    }
    Ok(envelope)
}

/// Runs one optional section: its rows, or None and a warning naming the section. Cancellation stays an error.
async fn section(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    label: &str,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<Map<String, Value>>>, ToolError> {
    match query(state, database, sql, params, ct).await {
        Ok(envelope) => Ok(Some(envelope.rows)),
        Err(error @ ToolError::Cancelled) => Err(error),
        Err(error) => {
            warnings.push(format!("{label}: {}", error.message()));
            Ok(None)
        }
    }
}

/// A section that needs view columns: its rows, or a warning when this TimescaleDB version lacks one.
#[allow(clippy::too_many_arguments)]
async fn checked_section(
    state: &AppState,
    database: Option<&str>,
    features: &probe::Features,
    needs: &[(&str, &[&str])],
    sql: &str,
    params: &[Option<&str>],
    label: &str,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Result<Option<Vec<Map<String, Value>>>, ToolError> {
    for (view, columns) in needs {
        if let Err(error) = features.require(view, columns) {
            warnings.push(format!("{label}: {}", error.message()));
            return Ok(None);
        }
    }
    section(state, database, sql, params, label, ct, warnings).await
}

/// Adds one value per relation of the rows (keyed by schema and name) from a guarded call.
/// A failing call leaves the value null and adds a warning; other rows are unaffected.
async fn add_per_relation(
    state: &AppState,
    database: &str,
    rows: &mut [Map<String, Value>],
    key: &str,
    function: &str,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Result<(), ToolError> {
    let sql = format!(
        "SELECT {function}(c.oid) AS value FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1::text AND c.relname = $2::text"
    );
    for row in rows.iter_mut() {
        let (Some(schema), Some(name)) = (text_of(row, "schema"), text_of(row, "name")) else {
            continue;
        };
        let label = format!("{schema}.{name} {key}");
        let params = [Some(schema.as_str()), Some(name.as_str())];
        let found = section(state, Some(database), &sql, &params, &label, ct, warnings).await?;
        let value = first_row(found)
            .and_then(|found| found.get("value").cloned())
            .unwrap_or(Value::Null);
        row.insert(key.to_owned(), value);
    }
    Ok(())
}

/// The first row of a section that ran and returned one.
fn first_row(rows: Option<Vec<Map<String, Value>>>) -> Option<Map<String, Value>> {
    rows?.into_iter().next()
}

/// A cell of a row, or null when the row or the cell is absent.
fn cell(row: &Option<Map<String, Value>>, key: &str) -> Value {
    row.as_ref()
        .and_then(|row| row.get(key).cloned())
        .unwrap_or(Value::Null)
}

/// The text of a cell, when it is a string.
fn text_of(row: &Map<String, Value>, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_owned)
}

/// Says that a catalog function is missing from this TimescaleDB version.
fn unavailable(warnings: &mut Vec<String>, function: &str) {
    warnings.push(format!(
        "{function} is not available in this TimescaleDB version."
    ));
}

/// One page of a paged list: how many rows it holds and where it starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub limit: usize,
    pub offset: usize,
}

impl Page {
    /// Reads limit and cursor; `name` is the limit's argument name in its error text.
    pub fn new(
        limit: Option<i64>,
        default: usize,
        name: &str,
        cursor: Option<&str>,
    ) -> Result<Page, ToolError> {
        let limit = match limit {
            None => default,
            Some(value) if (1..=500).contains(&value) => value as usize,
            Some(_) => {
                return Err(ToolError::Rejected(format!(
                    "{name} must be between 1 and 500."
                )));
            }
        };
        let offset = match cursor {
            None => 0,
            Some(text) => text
                .strip_prefix("o:")
                .and_then(|number| number.parse::<u32>().ok())
                .map(|number| number as usize)
                .ok_or_else(|| ToolError::Rejected("Invalid cursor.".to_owned()))?,
        };
        Ok(Page { limit, offset })
    }

    /// The SQL window: one row more than the page, so that a next page is known to exist.
    fn window(&self) -> String {
        format!("LIMIT {} OFFSET {}", self.limit + 1, self.offset)
    }

    /// Drops the extra row and returns the cursor of the next page when there is one.
    pub fn trim(&self, rows: &mut Vec<Map<String, Value>>) -> Option<String> {
        if rows.len() > self.limit {
            rows.truncate(self.limit);
            Some(format!("o:{}", self.offset.saturating_add(self.limit)))
        } else {
            None
        }
    }
}

/// The policy kind of a job row: columnstore, retention, reorder or refresh for the internal policy procedures, else custom.
fn job_kind_sql(alias: &str) -> String {
    format!(
        "CASE WHEN {alias}.proc_schema::text = '_timescaledb_functions' THEN CASE {alias}.proc_name::text \
         WHEN 'policy_compression' THEN 'columnstore' WHEN 'policy_recompression' THEN 'columnstore' \
         WHEN 'policy_retention' THEN 'retention' WHEN 'policy_reorder' THEN 'reorder' \
         WHEN 'policy_refresh_continuous_aggregate' THEN 'refresh' ELSE 'custom' END ELSE 'custom' END"
    )
}
