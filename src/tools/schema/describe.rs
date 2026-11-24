//! describe_table and describe_function: one relation or function in full, each section its own query.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use super::{COLUMN_TYPE_SQL, NON_SYSTEM, ToolError, contains_pattern, finish, run_rows, section};
use crate::server::AppState;
use crate::tools::Call;

/// Column names of the constraint's own table, from conkey in key order.
const LOCAL_COLUMNS: &str = "(SELECT pg_catalog.jsonb_agg(att.attname::text ORDER BY k.ord) FROM pg_catalog.unnest(con.conkey) WITH ORDINALITY AS k(num, ord) \
    JOIN pg_catalog.pg_attribute att ON att.attrelid = con.conrelid AND att.attnum = k.num)";
/// Column names a foreign key references, from confkey in key order.
const REFERENCED_COLUMNS: &str = "(SELECT pg_catalog.jsonb_agg(att.attname::text ORDER BY k.ord) FROM pg_catalog.unnest(con.confkey) WITH ORDINALITY AS k(num, ord) \
    JOIN pg_catalog.pg_attribute att ON att.attrelid = con.confrelid AND att.attnum = k.num)";

/// The relation row: names, kind, persistence, owner, comment, estimate and privileges.
const CORE_SQL: &str = "SELECT n.nspname::text AS schema, c.relname::text AS name, c.relkind::text AS relkind, \
    c.relpersistence::text AS persistence, pg_catalog.pg_get_userbyid(c.relowner) AS owner, \
    pg_catalog.obj_description(c.oid, 'pg_class') AS comment, \
    CASE WHEN c.relkind::text IN ('r', 'm') THEN c.reltuples::bigint \
        WHEN c.relkind::text = 'p' THEN (SELECT CASE WHEN pg_catalog.bool_and(l.reltuples >= 0) THEN pg_catalog.sum(l.reltuples)::bigint ELSE -1::bigint END \
            FROM pg_catalog.pg_partition_tree(c.oid) t JOIN pg_catalog.pg_class l ON l.oid = t.relid WHERE t.isleaf) END AS \"rowEstimate\", \
    pg_catalog.has_table_privilege(c.oid, 'SELECT') AS \"canSelect\", \
    c.relrowsecurity AS \"rlsEnabled\", c.relforcerowsecurity AS \"rlsForced\" \
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = $1::oid";

/// Sizes of the leaves, or of the relation itself when it is not a partition tree (a leaf lists itself in its tree).
const SIZES_SQL: &str = "WITH leaves AS ( \
    SELECT t.relid FROM pg_catalog.pg_partition_tree($1::oid) t WHERE t.isleaf \
    UNION ALL \
    SELECT $1::oid WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_partition_tree($1::oid))) \
    SELECT pg_catalog.jsonb_build_object( \
        'totalBytes', COALESCE(pg_catalog.sum(pg_catalog.pg_total_relation_size(l.relid)), 0)::bigint, \
        'tableBytes', COALESCE(pg_catalog.sum(pg_catalog.pg_relation_size(l.relid)), 0)::bigint, \
        'indexBytes', COALESCE(pg_catalog.sum(pg_catalog.pg_indexes_size(l.relid)), 0)::bigint, \
        'toastBytes', COALESCE(pg_catalog.sum(CASE WHEN c.reltoastrelid <> 0::oid THEN pg_catalog.pg_total_relation_size(c.reltoastrelid) ELSE 0 END), 0)::bigint) AS v \
    FROM leaves l JOIN pg_catalog.pg_class c ON c.oid = l.relid";

fn columns_sql() -> String {
    format!(
        "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object( \
        'position', a.attnum, 'name', a.attname::text, \
        'type', {COLUMN_TYPE_SQL}, \
        'nullable', NOT a.attnotnull, \
        'default', CASE WHEN a.attgenerated::text <> 's' THEN pg_catalog.pg_get_expr(d.adbin, d.adrelid) END, \
        'identity', CASE a.attidentity::text WHEN 'a' THEN 'always' WHEN 'd' THEN 'by default' END, \
        'generated', CASE WHEN a.attgenerated::text = 's' THEN pg_catalog.pg_get_expr(d.adbin, d.adrelid) END, \
        'collation', CASE WHEN a.attcollation <> 0 AND a.attcollation IS DISTINCT FROM t.typcollation \
            THEN (SELECT co.collname::text FROM pg_catalog.pg_collation co WHERE co.oid = a.attcollation) END, \
        'comment', pg_catalog.col_description(a.attrelid, a.attnum)) ORDER BY a.attnum), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_attribute a \
    JOIN pg_catalog.pg_type t ON t.oid = a.atttypid \
    LEFT JOIN pg_catalog.pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum \
    WHERE a.attrelid = $1::oid AND a.attnum > 0 AND NOT a.attisdropped"
    )
}

/// The primary key of the relation, or null.
fn primary_key_sql() -> String {
    format!(
        "SELECT (SELECT pg_catalog.jsonb_build_object('name', con.conname::text, 'columns', {LOCAL_COLUMNS}) \
        FROM pg_catalog.pg_constraint con WHERE con.conrelid = $1::oid AND con.contype = 'p') AS v"
    )
}

fn unique_sql() -> String {
    format!(
        "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name', con.conname::text, \
        'columns', {LOCAL_COLUMNS}, 'deferrable', con.condeferrable) ORDER BY con.conname), '[]'::jsonb) AS v \
        FROM pg_catalog.pg_constraint con WHERE con.conrelid = $1::oid AND con.contype = 'u'"
    )
}

const CHECK_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name', con.conname::text, \
    'definition', pg_catalog.pg_get_constraintdef(con.oid)) ORDER BY con.conname), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_constraint con WHERE con.conrelid = $1::oid AND con.contype = 'c'";

/// Foreign keys this relation declares.
fn foreign_keys_sql() -> String {
    format!(
        "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name', con.conname::text, \
        'columns', {LOCAL_COLUMNS}, \
        'referencesTable', (SELECT rn.nspname::text || '.' || rc.relname::text FROM pg_catalog.pg_class rc \
            JOIN pg_catalog.pg_namespace rn ON rn.oid = rc.relnamespace WHERE rc.oid = con.confrelid), \
        'referencesColumns', {REFERENCED_COLUMNS}, \
        'onUpdate', CASE con.confupdtype::text WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE' \
            WHEN 'n' THEN 'SET NULL' ELSE 'SET DEFAULT' END, \
        'onDelete', CASE con.confdeltype::text WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' WHEN 'c' THEN 'CASCADE' \
            WHEN 'n' THEN 'SET NULL' ELSE 'SET DEFAULT' END, \
        'deferrable', con.condeferrable) ORDER BY con.conname), '[]'::jsonb) AS v \
        FROM pg_catalog.pg_constraint con WHERE con.conrelid = $1::oid AND con.contype = 'f'"
    )
}

/// Foreign keys in other relations that reference this one.
fn referenced_by_sql() -> String {
    format!(
        "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('name', con.conname::text, \
        'table', (SELECT cn.nspname::text || '.' || cc.relname::text FROM pg_catalog.pg_class cc \
            JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace WHERE cc.oid = con.conrelid), \
        'columns', {LOCAL_COLUMNS}, 'referencesColumns', {REFERENCED_COLUMNS}) ORDER BY con.conname), '[]'::jsonb) AS v \
        FROM pg_catalog.pg_constraint con WHERE con.confrelid = $1::oid AND con.contype = 'f'"
    )
}

const INDEXES_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object( \
        'name', ic.relname::text, 'definition', pg_catalog.pg_get_indexdef(i.indexrelid), \
        'unique', i.indisunique, 'primary', i.indisprimary, 'valid', i.indisvalid, \
        'method', am.amname::text, 'sizeBytes', pg_catalog.pg_relation_size(i.indexrelid), \
        'scans', COALESCE(s.idx_scan, 0)) ORDER BY ic.relname::text), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_index i \
    JOIN pg_catalog.pg_class ic ON ic.oid = i.indexrelid \
    JOIN pg_catalog.pg_am am ON am.oid = ic.relam \
    LEFT JOIN pg_catalog.pg_stat_all_indexes s ON s.indexrelid = i.indexrelid \
    WHERE i.indrelid = $1::oid";

const TRIGGERS_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object( \
        'name', tg.tgname::text, \
        'timing', CASE WHEN tg.tgtype::integer & 64 <> 0 THEN 'INSTEAD OF' WHEN tg.tgtype::integer & 2 <> 0 THEN 'BEFORE' ELSE 'AFTER' END, \
        'events', (SELECT COALESCE(pg_catalog.jsonb_agg(ev.name ORDER BY ev.ord), '[]'::jsonb) \
            FROM (VALUES (4, 'INSERT', 1), (16, 'UPDATE', 2), (8, 'DELETE', 3), (32, 'TRUNCATE', 4)) AS ev(bit, name, ord) \
            WHERE tg.tgtype::integer & ev.bit <> 0), \
        'level', CASE WHEN tg.tgtype::integer & 1 <> 0 THEN 'ROW' ELSE 'STATEMENT' END, \
        'function', (SELECT pn.nspname::text || '.' || pp.proname::text FROM pg_catalog.pg_proc pp \
            JOIN pg_catalog.pg_namespace pn ON pn.oid = pp.pronamespace WHERE pp.oid = tg.tgfoid), \
        'enabled', tg.tgenabled::text <> 'D', \
        'definition', pg_catalog.pg_get_triggerdef(tg.oid)) ORDER BY tg.tgname::text), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_trigger tg WHERE tg.tgrelid = $1::oid AND NOT tg.tgisinternal";

const POLICIES_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object( \
        'name', pol.polname::text, \
        'command', CASE pol.polcmd::text WHEN 'r' THEN 'SELECT' WHEN 'a' THEN 'INSERT' WHEN 'w' THEN 'UPDATE' \
            WHEN 'd' THEN 'DELETE' ELSE 'ALL' END, \
        'permissive', pol.polpermissive, \
        'roles', (SELECT COALESCE(pg_catalog.jsonb_agg(CASE WHEN x.r = 0::oid THEN 'public' \
            ELSE (SELECT rolname::text FROM pg_catalog.pg_roles WHERE oid = x.r) END ORDER BY x.ord), '[]'::jsonb) \
            FROM pg_catalog.unnest(pol.polroles) WITH ORDINALITY AS x(r, ord)), \
        'using', pg_catalog.pg_get_expr(pol.polqual, pol.polrelid), \
        'withCheck', pg_catalog.pg_get_expr(pol.polwithcheck, pol.polrelid)) ORDER BY pol.polname::text), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_policy pol WHERE pol.polrelid = $1::oid";

/// Partition key and children for a partitioned table, and the parent and bound for a partition.
const PARTITIONING_SQL: &str = "SELECT CASE WHEN c.relkind::text = 'p' OR c.relispartition THEN pg_catalog.jsonb_build_object( \
        'key', CASE WHEN c.relkind::text = 'p' THEN pg_catalog.pg_get_partkeydef(c.oid) END, \
        'strategy', (SELECT CASE pt.partstrat::text WHEN 'l' THEN 'list' WHEN 'r' THEN 'range' WHEN 'h' THEN 'hash' END \
            FROM pg_catalog.pg_partitioned_table pt WHERE pt.partrelid = c.oid), \
        'partitions', (SELECT COALESCE(pg_catalog.jsonb_agg(x.item ORDER BY x.nm), '[]'::jsonb) FROM ( \
            SELECT cn.nspname::text || '.' || cc.relname::text AS nm, \
                pg_catalog.jsonb_build_object('name', cn.nspname::text || '.' || cc.relname::text, \
                    'bound', pg_catalog.pg_get_expr(cc.relpartbound, cc.oid)) AS item \
            FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class cc ON cc.oid = i.inhrelid \
            JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace \
            WHERE i.inhparent = c.oid ORDER BY cn.nspname::text, cc.relname::text LIMIT 200) x), \
        'partitionsTruncated', (SELECT pg_catalog.count(*) > 200 FROM pg_catalog.pg_inherits i WHERE i.inhparent = c.oid), \
        'parent', CASE WHEN c.relispartition THEN (SELECT pn.nspname::text || '.' || pc.relname::text \
            FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent \
            JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace WHERE i.inhrelid = c.oid) END, \
        'bound', CASE WHEN c.relispartition THEN pg_catalog.pg_get_expr(c.relpartbound, c.oid) END) END AS v \
    FROM pg_catalog.pg_class c WHERE c.oid = $1::oid";

const INHERITS_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(pn.nspname::text || '.' || pc.relname::text \
    ORDER BY pn.nspname::text, pc.relname::text), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class pc ON pc.oid = i.inhparent \
    JOIN pg_catalog.pg_namespace pn ON pn.oid = pc.relnamespace \
    WHERE i.inhrelid = $1::oid AND NOT (SELECT c.relispartition FROM pg_catalog.pg_class c WHERE c.oid = $1::oid)";

const INHERITED_BY_SQL: &str = "SELECT COALESCE(pg_catalog.jsonb_agg(cn.nspname::text || '.' || cc.relname::text \
    ORDER BY cn.nspname::text, cc.relname::text), '[]'::jsonb) AS v \
    FROM pg_catalog.pg_inherits i JOIN pg_catalog.pg_class cc ON cc.oid = i.inhrelid \
    JOIN pg_catalog.pg_namespace cn ON cn.oid = cc.relnamespace \
    WHERE i.inhparent = $1::oid AND NOT cc.relispartition";

const VIEW_SQL: &str = "SELECT pg_catalog.pg_get_viewdef($1::oid, true) AS v";

/// The server name and every table option; values are masked by `redact_options` before they are shown.
const FOREIGN_SQL: &str = "SELECT pg_catalog.jsonb_build_object('server', s.srvname::text, 'options', COALESCE( \
        (SELECT pg_catalog.jsonb_object_agg(pg_catalog.split_part(o, '=', 1), substring(o FROM position('=' IN o) + 1)) \
            FROM pg_catalog.unnest(ft.ftoptions) AS o), '{}'::jsonb)) AS v \
    FROM pg_catalog.pg_foreign_table ft JOIN pg_catalog.pg_foreign_server s ON s.oid = ft.ftserver \
    WHERE ft.ftrelid = $1::oid";

/// Foreign table option keys whose values are shown; every other option keeps its name with the value `***`.
const SHOWN_FOREIGN_OPTIONS: &[&str] = &[
    "schema_name",
    "table_name",
    "column_name",
    "fetch_size",
    "batch_size",
    "use_remote_estimate",
    "updatable",
    "truncatable",
    "async_capable",
    "analyze_sampling",
];
const HIDDEN_OPTION_VALUE: &str = "***";

/// Masks the value of every foreign table option whose key is not on SHOWN_FOREIGN_OPTIONS.
fn redact_options(foreign: &mut Value) {
    let Some(options) = foreign.get_mut("options").and_then(Value::as_object_mut) else {
        return;
    };
    for (key, value) in options.iter_mut() {
        if !SHOWN_FOREIGN_OPTIONS.contains(&key.as_str()) {
            *value = Value::String(HIDDEN_OPTION_VALUE.to_owned());
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::redact_options;

    #[test]
    fn listed_options_keep_their_values_and_every_other_is_masked() {
        let mut foreign = json!({"server": "loopback", "options": {
            "schema_name": "app", "table_name": "items", "column_name": "id", "fetch_size": "100",
            "batch_size": "10", "use_remote_estimate": "true", "updatable": "false",
            "truncatable": "false", "async_capable": "true", "analyze_sampling": "auto",
            "host": "10.0.0.5", "password": "hunter2", "sslpassword": "k", "passfile": "/x",
            "keyfile": "/y", "token_path": "/z", "user": "u", "SCHEMA_NAME": "app"
        }});
        redact_options(&mut foreign);
        let options = &foreign["options"];
        assert_eq!(options["schema_name"], json!("app"));
        assert_eq!(options["table_name"], json!("items"));
        assert_eq!(options["column_name"], json!("id"));
        assert_eq!(options["fetch_size"], json!("100"));
        assert_eq!(options["batch_size"], json!("10"));
        assert_eq!(options["use_remote_estimate"], json!("true"));
        assert_eq!(options["updatable"], json!("false"));
        assert_eq!(options["truncatable"], json!("false"));
        assert_eq!(options["async_capable"], json!("true"));
        assert_eq!(options["analyze_sampling"], json!("auto"));
        for key in [
            "host",
            "password",
            "sslpassword",
            "passfile",
            "keyfile",
            "token_path",
            "user",
            "SCHEMA_NAME",
        ] {
            assert_eq!(options[key], json!("***"), "{key}");
        }
        assert_eq!(foreign["server"], json!("loopback"));
    }

    #[test]
    fn missing_or_empty_options_are_left_alone() {
        let mut no_options = json!({"server": "loopback"});
        redact_options(&mut no_options);
        assert_eq!(no_options, json!({"server": "loopback"}));
        let mut empty = json!({"server": "loopback", "options": {}});
        redact_options(&mut empty);
        assert_eq!(empty, json!({"server": "loopback", "options": {}}));
    }
}

const STATS_SQL: &str = "SELECT pg_catalog.jsonb_build_object('lastVacuum', s.last_vacuum, 'lastAutovacuum', s.last_autovacuum, \
    'lastAnalyze', s.last_analyze, 'lastAutoanalyze', s.last_autoanalyze, \
    'liveRows', s.n_live_tup, 'deadRows', s.n_dead_tup) AS v \
    FROM pg_catalog.pg_stat_all_tables s WHERE s.relid = $1::oid";

/// Finds relations by exact name in the non-system schemas, or in the given schema.
fn resolve_sql() -> String {
    format!(
        "SELECT c.oid::text AS oid, n.nspname::text AS schema, c.relname::text AS name \
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
        WHERE c.relkind::text IN ('r', 'p', 'v', 'm', 'f') AND c.relname::text = $2::text \
        AND (CASE WHEN $1::text IS NULL THEN {NON_SYSTEM} ELSE n.nspname::text = $1::text END) \
        ORDER BY n.nspname::text"
    )
}

/// Up to five relations whose name equals or contains the given name, exact matches first.
fn suggest_sql() -> String {
    format!(
        "SELECT n.nspname::text AS schema, c.relname::text AS name \
        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
        WHERE c.relkind::text IN ('r', 'p', 'v', 'm', 'f') AND {NON_SYSTEM} \
        AND (c.relname::text = $1::text OR c.relname::text ILIKE $2::text) \
        ORDER BY (c.relname::text = $1::text) DESC, n.nspname::text, c.relname::text LIMIT 5"
    )
}

/// Every overload of a function by exact name, in the given schema or in the non-system schemas.
fn functions_sql() -> String {
    format!(
        "SELECT n.nspname::text AS schema, p.proname::text AS name, \
        CASE p.prokind::text WHEN 'f' THEN 'function' WHEN 'p' THEN 'procedure' WHEN 'a' THEN 'aggregate' ELSE 'window' END AS kind, \
        pg_catalog.pg_get_function_identity_arguments(p.oid) AS arguments, \
        pg_catalog.pg_get_function_result(p.oid) AS returns, \
        l.lanname::text AS language, \
        CASE p.provolatile::text WHEN 'i' THEN 'immutable' WHEN 's' THEN 'stable' ELSE 'volatile' END AS volatility, \
        CASE p.proparallel::text WHEN 's' THEN 'safe' WHEN 'r' THEN 'restricted' ELSE 'unsafe' END AS parallel, \
        p.proisstrict AS strict, p.prosecdef AS \"securityDefiner\", p.proleakproof AS leakproof, \
        pg_catalog.pg_get_userbyid(p.proowner) AS owner, \
        pg_catalog.obj_description(p.oid, 'pg_proc') AS comment, \
        COALESCE(p.proconfig, '{{}}'::text[]) AS config, \
        CASE WHEN l.lanname IN ('c', 'internal') THEN NULL ELSE p.prosrc END AS source, \
        l.lanname IN ('c', 'internal') AS compiled \
        FROM pg_catalog.pg_proc p \
        JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
        JOIN pg_catalog.pg_language l ON l.oid = p.prolang \
        WHERE p.proname::text = $2::text \
        AND (CASE WHEN $1::text IS NULL THEN {NON_SYSTEM} ELSE n.nspname::text = $1::text END) \
        ORDER BY n.nspname::text, pg_catalog.pg_get_function_identity_arguments(p.oid), p.oid"
    )
}

/// Arguments of describe_table.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeTableArgs {
    pub database: Option<String>,
    pub table: String,
    pub schema: Option<String>,
}

/// A relation's definition. A section the query failed for is null, with its message under `<section>Error`.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DescribeTableResult {
    pub database: String,
    pub schema: String,
    pub name: String,
    pub kind: String,
    pub owner: String,
    pub comment: Option<String>,
    pub persistence: String,
    pub row_estimate: Option<i64>,
    pub sizes: Option<Value>,
    pub columns: Option<Value>,
    pub primary_key: Option<Value>,
    pub unique_constraints: Option<Value>,
    pub check_constraints: Option<Value>,
    pub foreign_keys: Option<Value>,
    pub referenced_by: Option<Value>,
    pub indexes: Option<Value>,
    pub triggers: Option<Value>,
    pub policies: Option<Value>,
    pub row_security: Value,
    pub partitioning: Option<Value>,
    pub inherits: Option<Value>,
    pub inherited_by: Option<Value>,
    pub view_definition: Option<Value>,
    pub foreign: Option<Value>,
    pub stats: Option<Value>,
    pub warnings: Vec<String>,
    #[serde(flatten)]
    pub section_errors: Map<String, Value>,
}

/// Arguments of describe_function.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeFunctionArgs {
    pub database: Option<String>,
    pub function: String,
    pub schema: Option<String>,
}

/// Every overload of the named function, in order of schema and arguments.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DescribeFunctionResult {
    pub database: String,
    pub functions: Vec<Map<String, Value>>,
}

/// A relation found by name.
struct Relation {
    oid: String,
    schema: String,
    name: String,
}

/// Removes the double quotes of one quoted identifier; anything else is returned unchanged.
fn unquote(raw: &str) -> String {
    let Some(inner) = raw
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
    else {
        return raw.to_owned();
    };
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '"' {
            out.push(ch);
        } else if chars.peek() == Some(&'"') {
            chars.next();
            out.push('"');
        } else {
            return raw.to_owned();
        }
    }
    out
}

/// Splits `schema.name` at the first dot outside double quotes; None when there is no such dot.
fn split_first(raw: &str) -> Option<(String, String)> {
    let mut in_quotes = false;
    for (index, ch) in raw.char_indices() {
        match ch {
            '"' => in_quotes = !in_quotes,
            '.' if !in_quotes => {
                return Some((unquote(&raw[..index]), unquote(&raw[index + 1..])));
            }
            _ => {}
        }
    }
    None
}

fn text_of(row: &Map<String, Value>, key: &str) -> String {
    row.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// Relations named `name` in `schema`, or in every non-system schema when no schema is given.
async fn relations_named(
    state: &AppState,
    requested: Option<&str>,
    schema: Option<&str>,
    name: &str,
    ct: &CancellationToken,
) -> Result<(String, Vec<Relation>), ToolError> {
    let (database, rows) =
        run_rows(state, requested, &resolve_sql(), &[schema, Some(name)], ct).await?;
    let found = rows
        .iter()
        .map(|row| Relation {
            oid: text_of(row, "oid"),
            schema: text_of(row, "schema"),
            name: text_of(row, "name"),
        })
        .collect();
    Ok((database, found))
}

/// Resolves a table, view or materialized view name to exactly one relation.
async fn resolve_table(
    state: &AppState,
    requested: Option<&str>,
    table: &str,
    schema: Option<&str>,
    ct: &CancellationToken,
) -> Result<(String, Relation), ToolError> {
    let whole = unquote(table);
    let (database, mut found) = match schema {
        Some(_) => relations_named(state, requested, schema, &whole, ct).await?,
        None => {
            let first = relations_named(state, requested, None, &whole, ct).await?;
            if !first.1.is_empty() {
                first
            } else {
                match split_first(table) {
                    Some((schema_part, name_part)) => {
                        relations_named(state, requested, Some(&schema_part), &name_part, ct)
                            .await?
                    }
                    None => first,
                }
            }
        }
    };
    match found.len() {
        0 => {
            let bare = match (schema, split_first(table)) {
                (None, Some((_, name_part))) => name_part,
                _ => whole,
            };
            let suggestions = suggestions(state, Some(database.as_str()), &bare, ct).await?;
            let mut message = format!("Table \"{table}\" not found.");
            if !suggestions.is_empty() {
                message.push_str(&format!(" Did you mean: {}?", suggestions.join(", ")));
            }
            Err(ToolError::Rejected(message))
        }
        1 => Ok((database, found.remove(0))),
        _ => {
            let schemas: Vec<String> = found.into_iter().map(|r| r.schema).collect();
            Err(ToolError::Rejected(format!(
                "Table \"{table}\" exists in several schemas: {}. Pass schema.",
                schemas.join(", ")
            )))
        }
    }
}

/// Up to five `schema.name` relations that match the name, for the not-found message.
async fn suggestions(
    state: &AppState,
    database: Option<&str>,
    name: &str,
    ct: &CancellationToken,
) -> Result<Vec<String>, ToolError> {
    let pattern = contains_pattern(name);
    let (_, rows) = run_rows(
        state,
        database,
        &suggest_sql(),
        &[Some(name), Some(pattern.as_str())],
        ct,
    )
    .await?;
    Ok(rows
        .iter()
        .map(|row| format!("{}.{}", text_of(row, "schema"), text_of(row, "name")))
        .collect())
}

pub async fn describe_table(
    state: &AppState,
    args: DescribeTableArgs,
    ct: &CancellationToken,
) -> Call {
    let outcome = describe_table_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn describe_table_of(
    state: &AppState,
    args: &DescribeTableArgs,
    ct: &CancellationToken,
) -> Result<(String, DescribeTableResult), ToolError> {
    let (database, relation) = resolve_table(
        state,
        args.database.as_deref(),
        &args.table,
        args.schema.as_deref(),
        ct,
    )
    .await?;
    let db = Some(database.as_str());
    let oid = Some(relation.oid.as_str());
    let (_, rows) = run_rows(state, db, CORE_SQL, &[oid], ct).await?;
    let core = rows
        .into_iter()
        .next()
        .ok_or_else(|| ToolError::Internal("the relation was not found after lookup".to_owned()))?;
    let relkind = text_of(&core, "relkind");
    let can_select = core
        .get("canSelect")
        .and_then(Value::as_bool)
        .unwrap_or_default();
    let mut warnings = Vec::new();
    if !can_select {
        warnings.push("The connected role cannot SELECT from this table.".to_owned());
    }
    let row_security = json!({
        "enabled": core.get("rlsEnabled").and_then(Value::as_bool).unwrap_or_default(),
        "forced": core.get("rlsForced").and_then(Value::as_bool).unwrap_or_default(),
    });

    let mut errors = Map::new();
    let sizes = if relkind == "v" {
        None
    } else {
        section(state, db, SIZES_SQL, &[oid], ct, &mut errors, "sizes").await
    };
    let columns = section(
        state,
        db,
        &columns_sql(),
        &[oid],
        ct,
        &mut errors,
        "columns",
    )
    .await;
    let primary_key = section(
        state,
        db,
        &primary_key_sql(),
        &[oid],
        ct,
        &mut errors,
        "primaryKey",
    )
    .await;
    let unique_constraints = section(
        state,
        db,
        &unique_sql(),
        &[oid],
        ct,
        &mut errors,
        "uniqueConstraints",
    )
    .await;
    let check_constraints = section(
        state,
        db,
        CHECK_SQL,
        &[oid],
        ct,
        &mut errors,
        "checkConstraints",
    )
    .await;
    let foreign_keys = section(
        state,
        db,
        &foreign_keys_sql(),
        &[oid],
        ct,
        &mut errors,
        "foreignKeys",
    )
    .await;
    let referenced_by = section(
        state,
        db,
        &referenced_by_sql(),
        &[oid],
        ct,
        &mut errors,
        "referencedBy",
    )
    .await;
    let indexes = section(state, db, INDEXES_SQL, &[oid], ct, &mut errors, "indexes").await;
    let triggers = section(state, db, TRIGGERS_SQL, &[oid], ct, &mut errors, "triggers").await;
    let policies = section(state, db, POLICIES_SQL, &[oid], ct, &mut errors, "policies").await;
    let partitioning = section(
        state,
        db,
        PARTITIONING_SQL,
        &[oid],
        ct,
        &mut errors,
        "partitioning",
    )
    .await;
    let inherits = section(state, db, INHERITS_SQL, &[oid], ct, &mut errors, "inherits").await;
    let inherited_by = section(
        state,
        db,
        INHERITED_BY_SQL,
        &[oid],
        ct,
        &mut errors,
        "inheritedBy",
    )
    .await;
    let view_definition = if matches!(relkind.as_str(), "v" | "m") {
        section(
            state,
            db,
            VIEW_SQL,
            &[oid],
            ct,
            &mut errors,
            "viewDefinition",
        )
        .await
    } else {
        None
    };
    let foreign = if relkind == "f" {
        section(state, db, FOREIGN_SQL, &[oid], ct, &mut errors, "foreign")
            .await
            .map(|mut value| {
                redact_options(&mut value);
                value
            })
    } else {
        None
    };
    let stats = section(state, db, STATS_SQL, &[oid], ct, &mut errors, "stats").await;

    let result = DescribeTableResult {
        database: database.clone(),
        schema: relation.schema,
        name: relation.name,
        kind: relation_kind(&relkind),
        owner: text_of(&core, "owner"),
        comment: core
            .get("comment")
            .and_then(Value::as_str)
            .map(str::to_owned),
        persistence: persistence_word(&text_of(&core, "persistence")),
        row_estimate: core.get("rowEstimate").and_then(Value::as_i64),
        sizes,
        columns,
        primary_key,
        unique_constraints,
        check_constraints,
        foreign_keys,
        referenced_by,
        indexes,
        triggers,
        policies,
        row_security,
        partitioning,
        inherits,
        inherited_by,
        view_definition,
        foreign,
        stats,
        warnings,
        section_errors: errors,
    };
    Ok((database, result))
}

fn relation_kind(code: &str) -> String {
    match code {
        "r" => "table",
        "p" => "partitioned_table",
        "v" => "view",
        "m" => "materialized_view",
        "f" => "foreign_table",
        other => other,
    }
    .to_owned()
}

fn persistence_word(code: &str) -> String {
    match code {
        "u" => "unlogged",
        "t" => "temporary",
        _ => "permanent",
    }
    .to_owned()
}

pub async fn describe_function(
    state: &AppState,
    args: DescribeFunctionArgs,
    ct: &CancellationToken,
) -> Call {
    let outcome = describe_function_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn describe_function_of(
    state: &AppState,
    args: &DescribeFunctionArgs,
    ct: &CancellationToken,
) -> Result<(String, DescribeFunctionResult), ToolError> {
    let requested = args.database.as_deref();
    let whole = unquote(&args.function);
    let (database, mut rows) =
        functions_named(state, requested, args.schema.as_deref(), &whole, ct).await?;
    if rows.is_empty()
        && args.schema.is_none()
        && let Some((schema_part, name_part)) = split_first(&args.function)
    {
        (_, rows) = functions_named(state, requested, Some(&schema_part), &name_part, ct).await?;
    }
    if rows.is_empty() {
        return Err(ToolError::Rejected(format!(
            "Function \"{}\" not found.",
            args.function
        )));
    }
    let functions = rows
        .into_iter()
        .map(|mut row| {
            let compiled = row
                .remove("compiled")
                .and_then(|value| value.as_bool())
                .unwrap_or_default();
            if compiled {
                row.insert(
                    "sourceNote".to_owned(),
                    Value::String("compiled".to_owned()),
                );
            }
            row
        })
        .collect();
    Ok((
        database.clone(),
        DescribeFunctionResult {
            database,
            functions,
        },
    ))
}

/// The overloads named `name` in `schema`, or in every non-system schema when no schema is given.
async fn functions_named(
    state: &AppState,
    requested: Option<&str>,
    schema: Option<&str>,
    name: &str,
    ct: &CancellationToken,
) -> Result<(String, Vec<Map<String, Value>>), ToolError> {
    run_rows(
        state,
        requested,
        &functions_sql(),
        &[schema, Some(name)],
        ct,
    )
    .await
}
