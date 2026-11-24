//! search_schema: tables, views, columns and functions whose name or comment contains the query.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::{NON_SYSTEM, ToolError, check_kinds, finish, like_escape, page, run_rows, take_page};
use crate::server::AppState;
use crate::tools::Call;

const MIN_QUERY_CHARS: usize = 2;
const SEARCH_KINDS: [&str; 4] = ["table", "view", "column", "function"];

/// Arguments of search_schema.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SearchSchemaArgs {
    pub database: Option<String>,
    pub query: String,
    pub schema: Option<String>,
    pub kinds: Option<Vec<String>>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

/// Matches ordered by how well the name fits, then by schema, table and name.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SearchSchemaResult {
    pub database: String,
    pub query: String,
    pub matches: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Which object classes a search covers.
struct Selection {
    tables: bool,
    views: bool,
    columns: bool,
    functions: bool,
}

impl Selection {
    fn of(kinds: &[String]) -> Selection {
        let has = |kind: &str| kinds.iter().any(|k| k == kind);
        Selection {
            tables: has("table"),
            views: has("view"),
            columns: has("column"),
            functions: has("function"),
        }
    }
}

/// The four UNION parts; every part references all parameters, and a disabled part is FALSE.
/// Parameters: $1 the query, $2 the prefix pattern, $3 the substring pattern, $4 the schema, $5 limit, $6 offset.
fn search_sql(selection: &Selection) -> String {
    let mut relkinds: Vec<&str> = Vec::new();
    if selection.tables {
        relkinds.extend(["r", "p", "f"]);
    }
    if selection.views {
        relkinds.extend(["v", "m"]);
    }
    let relations_enabled = if relkinds.is_empty() {
        "FALSE".to_owned()
    } else {
        format!("c.relkind::text IN ({})", quote_all(&relkinds))
    };
    let relations = format!(
        "SELECT CASE WHEN lower(c.relname::text) = lower($1::text) THEN 0 \
            WHEN c.relname::text ILIKE $2::text THEN 1 WHEN c.relname::text ILIKE $3::text THEN 2 ELSE 3 END, \
        n.nspname::text, ''::text, c.relname::text, \
        CASE c.relkind::text WHEN 'f' THEN 'foreign_table' WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' ELSE 'table' END, \
        ''::text, \
        jsonb_build_object('kind', CASE c.relkind::text WHEN 'f' THEN 'foreign_table' WHEN 'v' THEN 'view' \
                WHEN 'm' THEN 'materialized_view' ELSE 'table' END, \
            'schema', n.nspname::text, 'name', c.relname::text, \
            'matched', CASE WHEN c.relname::text ILIKE $3::text THEN 'name' ELSE 'comment' END, \
            'comment', pg_catalog.obj_description(c.oid, 'pg_class')) AS obj \
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
        WHERE {relations_enabled} AND {NON_SYSTEM} AND ($4::text IS NULL OR n.nspname::text = $4::text) \
        AND (c.relname::text ILIKE $3::text OR pg_catalog.obj_description(c.oid, 'pg_class') ILIKE $3::text)"
    );
    let columns = format!(
        "SELECT CASE WHEN lower(a.attname::text) = lower($1::text) THEN 0 \
            WHEN a.attname::text ILIKE $2::text THEN 1 WHEN a.attname::text ILIKE $3::text THEN 2 ELSE 3 END, \
        n.nspname::text, c.relname::text, a.attname::text, 'column'::text, ''::text, \
        jsonb_build_object('kind', 'column', 'schema', n.nspname::text, 'table', c.relname::text, \
            'name', a.attname::text, 'type', pg_catalog.format_type(a.atttypid, a.atttypmod), \
            'matched', CASE WHEN a.attname::text ILIKE $3::text THEN 'name' ELSE 'comment' END, \
            'comment', pg_catalog.col_description(c.oid, a.attnum)) AS obj \
        FROM pg_catalog.pg_attribute a \
        JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
        JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
        WHERE {columns_enabled} AND a.attnum > 0 AND NOT a.attisdropped AND c.relkind::text IN ('r', 'p', 'f', 'v', 'm') \
        AND {NON_SYSTEM} AND ($4::text IS NULL OR n.nspname::text = $4::text) \
        AND (a.attname::text ILIKE $3::text OR pg_catalog.col_description(c.oid, a.attnum) ILIKE $3::text)",
        columns_enabled = if selection.columns { "TRUE" } else { "FALSE" },
    );
    let functions = format!(
        "SELECT CASE WHEN lower(p.proname::text) = lower($1::text) THEN 0 \
            WHEN p.proname::text ILIKE $2::text THEN 1 WHEN p.proname::text ILIKE $3::text THEN 2 ELSE 3 END, \
        n.nspname::text, ''::text, p.proname::text, 'function'::text, \
        pg_catalog.pg_get_function_identity_arguments(p.oid), \
        jsonb_build_object('kind', 'function', 'schema', n.nspname::text, 'name', p.proname::text, \
            'matched', CASE WHEN p.proname::text ILIKE $3::text THEN 'name' ELSE 'comment' END, \
            'comment', pg_catalog.obj_description(p.oid, 'pg_proc')) AS obj \
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
        WHERE {functions_enabled} AND {NON_SYSTEM} AND ($4::text IS NULL OR n.nspname::text = $4::text) \
        AND (p.proname::text ILIKE $3::text OR pg_catalog.obj_description(p.oid, 'pg_proc') ILIKE $3::text) \
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
            WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')",
        functions_enabled = if selection.functions { "TRUE" } else { "FALSE" },
    );
    format!(
        "SELECT u.obj FROM ({relations} UNION ALL {columns} UNION ALL {functions}) \
        AS u(ord_rank, sch, tbl, nm, kd, args, obj) \
        ORDER BY u.ord_rank, u.sch, u.tbl, u.nm, u.kd, u.args LIMIT $5::bigint OFFSET $6::bigint"
    )
}

/// The codes as a quoted SQL list, e.g. 'r', 'p'. The codes are constants, never user input.
fn quote_all(codes: &[&str]) -> String {
    codes
        .iter()
        .map(|code| format!("'{code}'"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub async fn search_schema(
    state: &AppState,
    args: SearchSchemaArgs,
    ct: &CancellationToken,
) -> Call {
    let outcome = search_schema_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn search_schema_of(
    state: &AppState,
    args: &SearchSchemaArgs,
    ct: &CancellationToken,
) -> Result<(String, SearchSchemaResult), ToolError> {
    let query = args.query.as_str();
    if query.chars().count() < MIN_QUERY_CHARS {
        return Err(ToolError::Rejected(
            "query must be at least 2 characters.".to_owned(),
        ));
    }
    let kinds: Vec<String> = match &args.kinds {
        None => SEARCH_KINDS.iter().map(|k| (*k).to_owned()).collect(),
        Some(kinds) => {
            check_kinds(kinds, &SEARCH_KINDS)?;
            kinds.clone()
        }
    };
    let (limit, offset) = page(args.limit, args.cursor.as_deref())?;
    let prefix = format!("{}%", like_escape(query));
    let contains = format!("%{}%", like_escape(query));
    let sql = search_sql(&Selection::of(&kinds));
    let limit_text = (limit + 1).to_string();
    let offset_text = offset.to_string();
    let params = [
        Some(query),
        Some(prefix.as_str()),
        Some(contains.as_str()),
        args.schema.as_deref(),
        Some(limit_text.as_str()),
        Some(offset_text.as_str()),
    ];
    let (database, rows) = run_rows(state, args.database.as_deref(), &sql, &params, ct).await?;
    let matches: Vec<Value> = rows
        .into_iter()
        .map(|mut row| row.remove("obj").unwrap_or(Value::Null))
        .collect();
    let (matches, next_cursor) = take_page(matches, limit, offset);
    Ok((
        database.clone(),
        SearchSchemaResult {
            database,
            query: args.query.clone(),
            matches,
            next_cursor,
        },
    ))
}
