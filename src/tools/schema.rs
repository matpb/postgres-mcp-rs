//! Schema introspection: list_schemas, list_objects, describe_table, describe_function, search_schema and get_privileges.

mod describe;
mod listing;
mod privileges;
mod search;

use std::future::Future;

use rmcp::ErrorData as McpError;
use rmcp::model::Tool;
use serde::Serialize;
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::core::tool;
use super::envelope;
use super::{
    Call, INTERNAL_MAX_ROWS, Runner, Statement, ToolError, Toolset, parse_args, text, value_of,
};
use crate::config::Limits;
use crate::pg::wire::FetchLimits;
use crate::server::AppState;

const MIB: usize = 1_048_576;
const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;

/// Predicate on n.nspname: false for catalogs, TimescaleDB internals and temporary schemas.
const NON_SYSTEM: &str = "NOT (n.nspname IN ('pg_catalog', 'information_schema', 'pg_toast', \
    'timescaledb_information', 'timescaledb_experimental', 'toolkit_experimental') \
    OR n.nspname::text ~ '^(pg_temp_|pg_toast_temp_|_timescaledb_)')";

const INCLUDE_SYSTEM_PARAM: &str =
    "Also list system schemas such as pg_catalog and information_schema. Default false.";
const KINDS_PARAM: &str = "Kinds to include: table, partitioned_table, view, materialized_view, foreign_table, sequence, function, procedure, type. Default: all except function, procedure and type.";
const NAME_LIKE_PARAM: &str = "Case-insensitive substring the object name must contain.";
const TABLE_PARAM: &str = "Table, view or materialized view name; either bare (then give schema, or it is searched in every non-system schema) or as schema.name.";
const TABLE_SCHEMA_PARAM: &str =
    "Schema of the table. Optional when the name is unique or schema-qualified.";
const FUNCTION_PARAM: &str = "Function or procedure name, bare or as schema.name.";
const FUNCTION_SCHEMA_PARAM: &str = "Schema of the function. Optional.";
const QUERY_PARAM: &str = "Text to look for in names and comments, at least 2 characters. Case-insensitive substring; no wildcards.";
const SEARCH_KINDS_PARAM: &str = "Limit to: table, view, column, function. Default: all.";

/// The six schema tools with their toolset tag.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    vec![
        (
            Toolset::Schema,
            tool::<listing::ListSchemasArgs, listing::ListSchemasResult>(
                "list_schemas",
                text::LIST_SCHEMAS_TITLE,
                text::LIST_SCHEMAS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("include_system", INCLUDE_SYSTEM_PARAM),
                ],
            ),
        ),
        (
            Toolset::Schema,
            tool::<listing::ListObjectsArgs, listing::ListObjectsResult>(
                "list_objects",
                text::LIST_OBJECTS_TITLE,
                text::LIST_OBJECTS,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("schema", text::SCHEMA_PARAM),
                    ("kinds", KINDS_PARAM),
                    ("name_like", NAME_LIKE_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
            ),
        ),
        (
            Toolset::Schema,
            tool::<describe::DescribeTableArgs, describe::DescribeTableResult>(
                "describe_table",
                text::DESCRIBE_TABLE_TITLE,
                text::DESCRIBE_TABLE,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("table", TABLE_PARAM),
                    ("schema", TABLE_SCHEMA_PARAM),
                ],
            ),
        ),
        (
            Toolset::Schema,
            tool::<describe::DescribeFunctionArgs, describe::DescribeFunctionResult>(
                "describe_function",
                text::DESCRIBE_FUNCTION_TITLE,
                text::DESCRIBE_FUNCTION,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("function", FUNCTION_PARAM),
                    ("schema", FUNCTION_SCHEMA_PARAM),
                ],
            ),
        ),
        (
            Toolset::Schema,
            tool::<search::SearchSchemaArgs, search::SearchSchemaResult>(
                "search_schema",
                text::SEARCH_SCHEMA_TITLE,
                text::SEARCH_SCHEMA,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("query", QUERY_PARAM),
                    ("schema", text::SCHEMA_PARAM),
                    ("kinds", SEARCH_KINDS_PARAM),
                    ("limit", text::LIMIT_PARAM),
                    ("cursor", text::CURSOR_PARAM),
                ],
            ),
        ),
        (
            Toolset::Schema,
            tool::<privileges::GetPrivilegesArgs, privileges::GetPrivilegesResult>(
                "get_privileges",
                text::GET_PRIVILEGES_TITLE,
                text::GET_PRIVILEGES,
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
    match name {
        "list_schemas" => {
            run(parse_args::<listing::ListSchemasArgs>(args), |a| {
                listing::list_schemas(state, a, ct)
            })
            .await
        }
        "list_objects" => {
            run(parse_args::<listing::ListObjectsArgs>(args), |a| {
                listing::list_objects(state, a, ct)
            })
            .await
        }
        "describe_table" => {
            run(parse_args::<describe::DescribeTableArgs>(args), |a| {
                describe::describe_table(state, a, ct)
            })
            .await
        }
        "describe_function" => {
            run(parse_args::<describe::DescribeFunctionArgs>(args), |a| {
                describe::describe_function(state, a, ct)
            })
            .await
        }
        "search_schema" => {
            run(parse_args::<search::SearchSchemaArgs>(args), |a| {
                search::search_schema(state, a, ct)
            })
            .await
        }
        "get_privileges" => {
            run(parse_args::<privileges::GetPrivilegesArgs>(args), |a| {
                privileges::get_privileges(state, a, ct)
            })
            .await
        }
        _ => None,
    }
}

/// Runs one tool once its arguments parsed; bad arguments are a protocol error.
async fn run<A, F, Fut>(parsed: Result<A, McpError>, call: F) -> Option<Result<Call, McpError>>
where
    F: FnOnce(A) -> Fut,
    Fut: Future<Output = Call>,
{
    match parsed {
        Ok(args) => Some(Ok(call(args).await)),
        Err(error) => Some(Err(error)),
    }
}

/// The client-facing call: the value with the database it ran on, or the error with the requested name.
fn finish<T: Serialize>(
    state: &AppState,
    requested: Option<&str>,
    outcome: Result<(String, T), ToolError>,
) -> Call {
    match outcome {
        Ok((database, value)) => Call {
            result: value_of(&value),
            database: Some(database),
            rows: None,
            sql: None,
        },
        Err(error) => Call {
            result: Err(error),
            database: state.resolve_name(requested),
            rows: None,
            sql: None,
        },
    }
}

/// Runs one internal query with the large value limits. A cut row set or value is an error, never a partial result.
async fn run_rows(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    ct: &CancellationToken,
) -> Result<(String, Vec<Map<String, Value>>), ToolError> {
    let statement = Statement {
        sql,
        params,
        user_sql: false,
        fetch: FetchLimits {
            max_rows: INTERNAL_MAX_ROWS,
            max_bytes: 8 * MIB,
            max_value_bytes: MIB,
        },
        offset: 0,
    };
    let (name, output) = Runner::new(state)
        .internal_raw(database, statement, ct)
        .await?;
    let limits = Limits {
        max_value_bytes: MIB,
        ..state.config.limits.clone()
    };
    let envelope = envelope::build(&name, output, &limits, false);
    if envelope.truncated || envelope.truncated_values > 0 {
        return Err(ToolError::Internal(
            "a catalog result is larger than the response limit".to_owned(),
        ));
    }
    Ok((name, envelope.rows))
}

/// Runs one section query. On failure the section is None and its message goes under `<name>Error`.
async fn section(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    ct: &CancellationToken,
    errors: &mut Map<String, Value>,
    name: &str,
) -> Option<Value> {
    match run_value(state, database, sql, params, ct).await {
        Ok((_, value)) => Some(value),
        Err(error) => {
            errors.insert(format!("{name}Error"), Value::String(error.message()));
            None
        }
    }
}

/// Runs a query whose first row holds one value in column `v`; null when it returns no row.
async fn run_value(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    ct: &CancellationToken,
) -> Result<(String, Value), ToolError> {
    let (name, rows) = run_rows(state, database, sql, params, ct).await?;
    let value = rows
        .into_iter()
        .next()
        .and_then(|mut row| row.remove("v"))
        .unwrap_or(Value::Null);
    Ok((name, value))
}

/// The page size and the offset of the first row, from the paging arguments.
fn page(limit: Option<i64>, cursor: Option<&str>) -> Result<(i64, i64), ToolError> {
    let limit = match limit {
        None => DEFAULT_LIMIT,
        Some(n) if (1..=MAX_LIMIT).contains(&n) => n,
        Some(_) => {
            return Err(ToolError::Rejected(format!(
                "limit must be between 1 and {MAX_LIMIT}."
            )));
        }
    };
    let offset = match cursor {
        None => 0,
        Some(raw) => parse_cursor(raw)?,
    };
    Ok((limit, offset))
}

/// Reads an opaque cursor of the form o:<offset>.
fn parse_cursor(raw: &str) -> Result<i64, ToolError> {
    let invalid = || ToolError::Rejected("Invalid cursor.".to_owned());
    let digits = raw
        .strip_prefix("o:")
        .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(invalid)?;
    digits.parse::<i64>().map_err(|_| invalid())
}

/// The first `limit` rows, and the cursor of the next page when one more row exists.
fn take_page<T>(mut rows: Vec<T>, limit: i64, offset: i64) -> (Vec<T>, Option<String>) {
    let size = usize::try_from(limit).unwrap_or(usize::MAX);
    if rows.len() > size {
        rows.truncate(size);
        (rows, Some(format!("o:{}", offset.saturating_add(limit))))
    } else {
        (rows, None)
    }
}

/// Each requested kind must be one of `valid`; the error names them all.
fn check_kinds(kinds: &[String], valid: &[&str]) -> Result<(), ToolError> {
    for kind in kinds {
        if !valid.contains(&kind.as_str()) {
            return Err(ToolError::Rejected(format!(
                "Unknown kind \"{kind}\". Valid kinds: {}.",
                valid.join(", ")
            )));
        }
    }
    Ok(())
}

/// Escapes LIKE metacharacters so the text matches literally.
fn like_escape(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// A case-insensitive substring pattern for ILIKE.
fn contains_pattern(raw: &str) -> String {
    format!("%{}%", like_escape(raw))
}
