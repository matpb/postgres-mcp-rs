//! list_schemas and list_objects: one row per schema, and one page of tables, functions and types.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{
    NON_SYSTEM, ToolError, check_kinds, contains_pattern, finish, page, run_rows, take_page,
};
use crate::server::AppState;
use crate::tools::Call;

/// One row per schema the role may use; $1 is true to include the system schemas.
fn list_schemas_sql() -> String {
    format!(
        "SELECT n.nspname::text AS name, \
        pg_catalog.pg_get_userbyid(n.nspowner) AS owner, \
        pg_catalog.obj_description(n.oid, 'pg_namespace') AS comment, \
        (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c WHERE c.relnamespace = n.oid AND c.relkind::text IN ('r', 'p')) AS tables, \
        (SELECT pg_catalog.count(*) FROM pg_catalog.pg_class c WHERE c.relnamespace = n.oid AND c.relkind::text IN ('v', 'm')) AS views, \
        (SELECT pg_catalog.count(*) FROM pg_catalog.pg_proc p WHERE p.pronamespace = n.oid) AS functions \
        FROM pg_catalog.pg_namespace n \
        WHERE ($1::boolean OR {NON_SYSTEM}) \
        AND (pg_catalog.pg_has_role(current_user, 'pg_read_all_data', 'MEMBER') \
             OR pg_catalog.has_schema_privilege(n.oid, 'USAGE')) \
        ORDER BY n.nspname::text"
    )
}

/// Every object kind list_objects accepts, with the default selection.
const OBJECT_KINDS: [&str; 9] = [
    "table",
    "partitioned_table",
    "view",
    "materialized_view",
    "foreign_table",
    "sequence",
    "function",
    "procedure",
    "type",
];
const DEFAULT_OBJECT_KINDS: [&str; 6] = [
    "table",
    "partitioned_table",
    "view",
    "materialized_view",
    "foreign_table",
    "sequence",
];

/// The kind text of a pg_class row, from `c.relkind`.
const REL_KIND: &str = "CASE c.relkind::text WHEN 'r' THEN 'table' WHEN 'p' THEN 'partitioned_table' \
    WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view' WHEN 'f' THEN 'foreign_table' ELSE 'sequence' END";
const FUNCTION_KIND: &str = "CASE p.prokind::text WHEN 'p' THEN 'procedure' ELSE 'function' END";

/// Arguments of list_schemas.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListSchemasArgs {
    pub database: Option<String>,
    #[serde(default)]
    pub include_system: bool,
}

/// One schema per row, ordered by name.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListSchemasResult {
    pub database: String,
    pub schemas: Vec<Map<String, Value>>,
}

/// Arguments of list_objects.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListObjectsArgs {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub kinds: Option<Vec<String>>,
    pub name_like: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

/// One page of objects; each object is a JSON object as described by the tool.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListObjectsResult {
    pub database: String,
    pub objects: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

pub async fn list_schemas(state: &AppState, args: ListSchemasArgs, ct: &CancellationToken) -> Call {
    let outcome = list_schemas_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn list_schemas_of(
    state: &AppState,
    args: &ListSchemasArgs,
    ct: &CancellationToken,
) -> Result<(String, ListSchemasResult), ToolError> {
    let include_system = if args.include_system { "true" } else { "false" };
    let (database, rows) = run_rows(
        state,
        args.database.as_deref(),
        &list_schemas_sql(),
        &[Some(include_system)],
        ct,
    )
    .await?;
    Ok((
        database.clone(),
        ListSchemasResult {
            database,
            schemas: rows,
        },
    ))
}

/// The object classes one list_objects call selects.
#[derive(Debug, Default)]
struct Selection {
    relkinds: Vec<&'static str>,
    prokinds: Vec<&'static str>,
    types: bool,
}

impl Selection {
    fn of(kinds: &[String]) -> Selection {
        let has = |kind: &str| kinds.iter().any(|k| k == kind);
        let mut selection = Selection::default();
        for (kind, code) in [
            ("table", "r"),
            ("partitioned_table", "p"),
            ("view", "v"),
            ("materialized_view", "m"),
            ("foreign_table", "f"),
            ("sequence", "S"),
        ] {
            if has(kind) {
                selection.relkinds.push(code);
            }
        }
        if has("function") {
            selection.prokinds.extend(["f", "a", "w"]);
        }
        if has("procedure") {
            selection.prokinds.push("p");
        }
        selection.types = has("type");
        selection
    }
}

/// A SQL list of constant codes, or FALSE when there are none.
fn code_filter(column: &str, codes: &[&str]) -> String {
    if codes.is_empty() {
        return "FALSE".to_owned();
    }
    let quoted: Vec<String> = codes.iter().map(|c| format!("'{c}'")).collect();
    format!("{column} IN ({})", quoted.join(", "))
}

/// The UNION of pg_class, pg_proc and pg_type parts, paged by LIMIT and OFFSET.
/// Each part yields (sch, nm, kd, args, ident, obj); the parameters are schema, name pattern, limit and offset.
fn object_sql(selection: &Selection) -> String {
    let relations = format!(
        "SELECT n.nspname::text, c.relname::text, {REL_KIND}, ''::text, c.oid::bigint, \
         pg_catalog.jsonb_build_object('schema', n.nspname::text, 'name', c.relname::text, 'kind', {REL_KIND}, \
             'owner', pg_catalog.pg_get_userbyid(c.relowner), 'comment', pg_catalog.obj_description(c.oid, 'pg_class')) \
         || pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object( \
             'rowEstimate', CASE WHEN c.relkind::text IN ('r', 'm') THEN c.reltuples::bigint \
                 WHEN c.relkind::text = 'p' THEN (SELECT CASE WHEN pg_catalog.bool_and(l.reltuples >= 0) THEN pg_catalog.sum(l.reltuples)::bigint ELSE -1::bigint END \
                     FROM pg_catalog.pg_partition_tree(c.oid) t JOIN pg_catalog.pg_class l ON l.oid = t.relid WHERE t.isleaf) END, \
             'totalBytes', CASE WHEN c.relkind::text IN ('r', 'm') THEN pg_catalog.pg_total_relation_size(c.oid) \
                 WHEN c.relkind::text = 'p' THEN (SELECT COALESCE(pg_catalog.sum(pg_catalog.pg_total_relation_size(t.relid)), 0)::bigint \
                     FROM pg_catalog.pg_partition_tree(c.oid) t WHERE t.isleaf) END, \
             'partitionOf', CASE WHEN c.relispartition THEN (SELECT pn.nspname::text || '.' || pc.relname::text \
                 FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent \
                 JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace WHERE i.inhrelid = c.oid) END, \
             'isPartition', CASE WHEN c.relispartition THEN true END)) AS obj \
         FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE {rels} AND (CASE WHEN $1::text IS NULL THEN {NON_SYSTEM} ELSE n.nspname::text = $1::text END) \
         AND ($2::text IS NULL OR c.relname::text ILIKE $2::text)",
        rels = code_filter("c.relkind::text", &selection.relkinds),
    );
    let functions = format!(
        "SELECT n.nspname::text, p.proname::text, {FUNCTION_KIND}, \
         pg_catalog.pg_get_function_identity_arguments(p.oid), p.oid::bigint, \
         pg_catalog.jsonb_build_object('schema', n.nspname::text, 'name', p.proname::text, 'kind', {FUNCTION_KIND}, \
             'owner', pg_catalog.pg_get_userbyid(p.proowner), 'comment', pg_catalog.obj_description(p.oid, 'pg_proc')) \
         || pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object( \
             'arguments', pg_catalog.pg_get_function_identity_arguments(p.oid), \
             'returns', pg_catalog.pg_get_function_result(p.oid))) AS obj \
         FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
         WHERE {kinds} AND (CASE WHEN $1::text IS NULL THEN {NON_SYSTEM} ELSE n.nspname::text = $1::text END) \
         AND ($2::text IS NULL OR p.proname::text ILIKE $2::text) \
         AND (CASE WHEN $1::text IS NULL THEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
             WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e') ELSE true END)",
        kinds = code_filter("p.prokind::text", &selection.prokinds),
    );
    let types = format!(
        "SELECT n.nspname::text, t.typname::text, 'type'::text, ''::text, t.oid::bigint, \
         pg_catalog.jsonb_build_object('schema', n.nspname::text, 'name', t.typname::text, 'kind', 'type', \
             'owner', pg_catalog.pg_get_userbyid(t.typowner), 'comment', pg_catalog.obj_description(t.oid, 'pg_type'), \
             'typeKind', CASE t.typtype::text WHEN 'e' THEN 'enum' WHEN 'd' THEN 'domain' WHEN 'r' THEN 'range' ELSE 'composite' END) \
         || pg_catalog.jsonb_strip_nulls(pg_catalog.jsonb_build_object('enumLabels', CASE WHEN t.typtype::text = 'e' THEN \
             (SELECT COALESCE(pg_catalog.jsonb_agg(e.enumlabel::text ORDER BY e.enumsortorder), '[]'::jsonb) \
              FROM pg_catalog.pg_enum e WHERE e.enumtypid = t.oid) END)) AS obj \
         FROM pg_catalog.pg_type t JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace \
         WHERE {enabled} AND (t.typtype::text IN ('e', 'd', 'r') OR (t.typtype::text = 'c' AND EXISTS \
             (SELECT 1 FROM pg_catalog.pg_class rc WHERE rc.oid = t.typrelid AND rc.relkind::text = 'c'))) \
         AND (CASE WHEN $1::text IS NULL THEN {NON_SYSTEM} ELSE n.nspname::text = $1::text END) \
         AND ($2::text IS NULL OR t.typname::text ILIKE $2::text) \
         AND (CASE WHEN $1::text IS NULL THEN NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d \
             WHERE d.classid = 'pg_catalog.pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e') ELSE true END)",
        enabled = if selection.types { "TRUE" } else { "FALSE" },
    );
    format!(
        "SELECT u.obj FROM ({relations} UNION ALL {functions} UNION ALL {types}) \
         AS u(sch, nm, kd, args, ident, obj) \
         ORDER BY u.sch, u.nm, u.kd, u.args, u.ident LIMIT $3::bigint OFFSET $4::bigint"
    )
}

pub async fn list_objects(state: &AppState, args: ListObjectsArgs, ct: &CancellationToken) -> Call {
    let outcome = list_objects_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn list_objects_of(
    state: &AppState,
    args: &ListObjectsArgs,
    ct: &CancellationToken,
) -> Result<(String, ListObjectsResult), ToolError> {
    let kinds: Vec<String> = match &args.kinds {
        None => DEFAULT_OBJECT_KINDS
            .iter()
            .map(|k| (*k).to_owned())
            .collect(),
        Some(kinds) => {
            check_kinds(kinds, &OBJECT_KINDS)?;
            kinds.clone()
        }
    };
    let (limit, offset) = page(args.limit, args.cursor.as_deref())?;
    let pattern = args.name_like.as_deref().map(contains_pattern);
    let sql = object_sql(&Selection::of(&kinds));
    let limit_text = (limit + 1).to_string();
    let offset_text = offset.to_string();
    let params = [
        args.schema.as_deref(),
        pattern.as_deref(),
        Some(limit_text.as_str()),
        Some(offset_text.as_str()),
    ];
    let (database, rows) = run_rows(state, args.database.as_deref(), &sql, &params, ct).await?;
    let objects: Vec<Value> = rows
        .into_iter()
        .map(|mut row| row.remove("obj").unwrap_or(Value::Null))
        .collect();
    let (objects, next_cursor) = take_page(objects, limit, offset);
    Ok((
        database.clone(),
        ListObjectsResult {
            database,
            objects,
            next_cursor,
        },
    ))
}
