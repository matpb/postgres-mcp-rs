//! Monitoring tools: sessions and locks, statement statistics, cumulative statistics, table usage and replication.

mod activity;
mod replication;
mod statements;
mod stats;
mod tables;

use rmcp::ErrorData as McpError;
use rmcp::model::Tool;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::core::{failed, tool};
use super::envelope::{self, QueryEnvelope};
use super::mask::mask;
use super::{Call, INTERNAL_MAX_ROWS, Runner, Statement, ToolError, Toolset, parse_args, text};
use crate::config::Limits;
use crate::pg::wire::FetchLimits;
use crate::server::AppState;

/// Per-value and per-response byte limits for monitoring queries that return long text or jsonb.
const WIDE_VALUE_BYTES: usize = 1_048_576;
const WIDE_RESPONSE_BYTES: usize = 8 * 1_048_576;
/// PostgreSQL's placeholder for another role's statement text.
const HIDDEN_TEXT: &str = "<insufficient privilege>";
const VISIBILITY_SQL: &str = "SELECT pg_catalog.current_user()::text AS role, \
    pg_catalog.pg_has_role(pg_catalog.current_user(), 'pg_read_all_stats', 'USAGE') AS visible";

/// Monitoring tools with their toolset tag.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    vec![
        (
            Toolset::Monitor,
            tool::<activity::ListActivityArgs, activity::ListActivityResult>(
                "list_activity",
                text::LIST_ACTIVITY_TITLE,
                text::LIST_ACTIVITY,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("state", text::LIST_ACTIVITY_STATE_PARAM),
                    ("min_duration_ms", text::LIST_ACTIVITY_MIN_DURATION_MS_PARAM),
                    ("user", text::LIST_ACTIVITY_USER_PARAM),
                    ("all_databases", text::LIST_ACTIVITY_ALL_DATABASES_PARAM),
                    ("only_blocked", text::LIST_ACTIVITY_ONLY_BLOCKED_PARAM),
                    (
                        "include_background",
                        text::LIST_ACTIVITY_INCLUDE_BACKGROUND_PARAM,
                    ),
                    ("query_chars", text::LIST_ACTIVITY_QUERY_CHARS_PARAM),
                    ("limit", text::LIMIT_PARAM),
                ],
            ),
        ),
        (
            Toolset::Monitor,
            tool::<statements::QueryStatsArgs, statements::QueryStatsResult>(
                "query_stats",
                text::QUERY_STATS_TITLE,
                text::QUERY_STATS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("order_by", text::QUERY_STATS_ORDER_BY_PARAM),
                    ("min_calls", text::QUERY_STATS_MIN_CALLS_PARAM),
                    ("contains", text::QUERY_STATS_CONTAINS_PARAM),
                    ("all_databases", text::QUERY_STATS_ALL_DATABASES_PARAM),
                    ("query_chars", text::QUERY_STATS_QUERY_CHARS_PARAM),
                    ("limit", text::QUERY_STATS_LIMIT_PARAM),
                ],
            ),
        ),
        (
            Toolset::Monitor,
            tool::<stats::DatabaseStatsArgs, stats::DatabaseStatsResult>(
                "database_stats",
                text::DATABASE_STATS_TITLE,
                text::DATABASE_STATS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("sections", text::DATABASE_STATS_SECTIONS_PARAM),
                ],
            ),
        ),
        (
            Toolset::Monitor,
            tool::<tables::TableStatsArgs, tables::TableStatsResult>(
                "table_stats",
                text::TABLE_STATS_TITLE,
                text::TABLE_STATS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("schema", text::SCHEMA_PARAM),
                    ("table", text::TABLE_STATS_TABLE_PARAM),
                    ("order_by", text::TABLE_STATS_ORDER_BY_PARAM),
                    ("include_indexes", text::TABLE_STATS_INCLUDE_INDEXES_PARAM),
                    ("unused_indexes", text::TABLE_STATS_UNUSED_INDEXES_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
            ),
        ),
        (
            Toolset::Monitor,
            tool::<replication::ReplicationArgs, replication::ReplicationResult>(
                "replication_status",
                text::REPLICATION_STATUS_TITLE,
                text::REPLICATION_STATUS,
                &[("database", text::DATABASE_PARAM)],
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
        "list_activity" => match parse_args(args) {
            Ok(args) => activity::list_activity(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "query_stats" => match parse_args(args) {
            Ok(args) => statements::query_stats(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "database_stats" => match parse_args(args) {
            Ok(args) => stats::database_stats(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "table_stats" => match parse_args(args) {
            Ok(args) => tables::table_stats(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        "replication_status" => match parse_args(args) {
            Ok(args) => replication::replication_status(state, args, ct).await,
            Err(error) => return Some(Err(error)),
        },
        _ => return None,
    };
    Some(Ok(call))
}

/// Runs internal SQL with the wide value and response limits and encodes its rows.
pub async fn wide_rows(
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
            max_bytes: WIDE_RESPONSE_BYTES,
            max_value_bytes: WIDE_VALUE_BYTES,
        },
        offset: Some(0),
        search_path_catalog_only: true,
    };
    let (name, output) = Runner::new(state)
        .internal_raw(database, statement, ct)
        .await?;
    let limits = Limits {
        max_value_bytes: WIDE_VALUE_BYTES,
        ..state.config.limits.clone()
    };
    let envelope = envelope::build(&name, output, &limits, false);
    if envelope.truncated {
        return Err(ToolError::Internal(
            "the monitoring result is larger than MAX_RESPONSE_BYTES".to_owned(),
        ));
    }
    Ok(envelope)
}

/// Whether the connected role may read other sessions' statement text, and the role's name.
pub struct Visibility {
    pub role: String,
    pub visible: bool,
}

pub async fn text_visibility(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Visibility, ToolError> {
    let envelope = wide_rows(state, database, VISIBILITY_SQL, &[], ct).await?;
    let row = envelope
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no role row".to_owned()))?;
    Ok(Visibility {
        role: row
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        visible: flag_of(row, "visible"),
    })
}

/// The note that explains hidden statement text and how to show it.
pub fn hidden_text_note(role: &str) -> String {
    format!("Query text of other users is hidden: GRANT pg_read_all_stats TO {role};")
}

/// Maps PostgreSQL's placeholder for another role's statement text to None.
pub fn visible_text(raw: Option<&str>) -> Option<&str> {
    match raw {
        Some(HIDDEN_TEXT) => None,
        other => other,
    }
}

/// The first `limit` characters of the text, and whether any were cut.
pub fn cut_chars(text: &str, limit: usize) -> (String, bool) {
    match text.char_indices().nth(limit) {
        Some((index, _)) => {
            let end = crate::scrub::cut_index(text.as_bytes(), index);
            (text[..end].to_owned(), true)
        }
        None => (text.to_owned(), false),
    }
}

/// Sets a row's `query` to its visible text, masked for secrets, cut to `chars`; `queryTruncated` says whether it was cut.
pub fn shape_query(row: &mut Map<String, Value>, chars: usize) {
    let (text, truncated) = match visible_text(row.get("query").and_then(Value::as_str)) {
        Some(full) => {
            let (cut, was_cut) = cut_chars(&mask(&crate::scrub::scrub_tail(full)), chars);
            (Value::String(cut), was_cut)
        }
        None => (Value::Null, false),
    };
    row.insert("query".to_owned(), text);
    row.insert("queryTruncated".to_owned(), Value::Bool(truncated));
}

/// An optional integer argument with its default, checked against an inclusive range.
pub fn bounded(
    name: &str,
    value: Option<i64>,
    default: i64,
    min: i64,
    max: i64,
) -> Result<i64, ToolError> {
    let value = value.unwrap_or(default);
    if (min..=max).contains(&value) {
        Ok(value)
    } else {
        Err(ToolError::Rejected(format!(
            "{name} must be between {min} and {max}."
        )))
    }
}

/// An optional boolean argument; absent means false.
pub fn flag(value: Option<bool>) -> bool {
    value.unwrap_or(false)
}

pub fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Reads a boolean column of a row; absent or null means false.
pub fn flag_of(row: &Map<String, Value>, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// A snake_case column name as a camelCase result key.
pub fn camel(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut upper = false;
    for ch in name.chars() {
        if ch == '_' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// The candidate columns that the relation has on this server, in candidate order.
pub async fn present_columns(
    state: &AppState,
    database: Option<&str>,
    relation: &str,
    candidates: &[&str],
    ct: &CancellationToken,
) -> Result<Vec<String>, ToolError> {
    let list = format!("{{{}}}", candidates.join(","));
    let sql = "SELECT a.attname::text AS name FROM pg_catalog.pg_attribute a \
        WHERE a.attrelid = pg_catalog.to_regclass($1::text) AND a.attnum > 0 \
        AND NOT a.attisdropped AND a.attname = ANY($2::text[])";
    let envelope = wide_rows(
        state,
        database,
        sql,
        &[Some(relation), Some(list.as_str())],
        ct,
    )
    .await?;
    let names: Vec<String> = envelope
        .rows
        .iter()
        .filter_map(|row| row.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect();
    Ok(candidates
        .iter()
        .filter(|candidate| names.iter().any(|name| name == *candidate))
        .map(|candidate| (*candidate).to_owned())
        .collect())
}

/// `alias.column AS "camelCase"` for each column; byte counts are cast to bigint.
pub fn select_items(alias: &str, columns: &[String]) -> String {
    columns
        .iter()
        .map(|column| {
            let cast = if column.ends_with("_bytes") {
                "::bigint"
            } else {
                ""
            };
            format!("{alias}.{column}{cast} AS \"{}\"", camel(column))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// The offset encoded in an `o:<offset>` cursor; absent means the first page.
pub fn parse_offset(cursor: Option<&str>) -> Result<i64, ToolError> {
    let Some(text) = cursor else {
        return Ok(0);
    };
    text.strip_prefix("o:")
        .filter(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|digits| digits.parse::<i64>().ok())
        .ok_or_else(|| ToolError::Rejected("Invalid cursor.".to_owned()))
}

/// The cursor for the page after the one that starts at `offset`.
pub fn next_cursor(offset: i64, limit: i64) -> String {
    format!("o:{}", offset.saturating_add(limit))
}

/// The first row of a result as an object; an empty object when there is none.
pub fn first_object(rows: Vec<Map<String, Value>>) -> Map<String, Value> {
    rows.into_iter().next().unwrap_or_default()
}

/// Ends a tool call with a failure that names its database when it is known.
pub fn fail(error: ToolError, state: &AppState, database: Option<&str>) -> Call {
    failed(error, state.resolve_name(database))
}
