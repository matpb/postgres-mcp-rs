//! get_privileges: what the connected role may read and write, and which monitoring features work.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use super::{NON_SYSTEM, ToolError, finish, run_rows, section};
use crate::server::AppState;
use crate::tools::Call;
use crate::tools::logs::query::log_reader_flags;

/// The predefined roles reported in predefinedRoles, with their JSON keys.
const PREDEFINED_ROLES: [(&str, &str); 7] = [
    ("pgReadAllData", "pg_read_all_data"),
    ("pgReadAllStats", "pg_read_all_stats"),
    ("pgReadAllSettings", "pg_read_all_settings"),
    ("pgMonitor", "pg_monitor"),
    ("pgReadServerFiles", "pg_read_server_files"),
    ("pgWriteAllData", "pg_write_all_data"),
    ("pgSignalBackend", "pg_signal_backend"),
];

const ROLE_SQL: &str = "SELECT jsonb_build_object( \
        'name', current_user::text, 'sessionUser', session_user::text, \
        'superuser', r.rolsuper, 'createDb', r.rolcreatedb, 'createRole', r.rolcreaterole, \
        'replication', r.rolreplication, 'bypassRls', r.rolbypassrls, 'inherit', r.rolinherit, \
        'connectionLimit', r.rolconnlimit, \
        'memberOf', (WITH RECURSIVE member_of(roleid) AS ( \
            SELECT a.roleid FROM pg_catalog.pg_auth_members a WHERE a.member = r.oid \
            UNION SELECT a.roleid FROM pg_catalog.pg_auth_members a JOIN member_of m ON a.member = m.roleid) \
            SELECT COALESCE(jsonb_agg(g.rolname::text ORDER BY g.rolname::text), '[]'::jsonb) \
            FROM member_of m JOIN pg_catalog.pg_roles g ON g.oid = m.roleid)) AS v \
    FROM pg_catalog.pg_roles r WHERE r.rolname = current_user";

const DATABASE_SQL: &str = "SELECT jsonb_build_object( \
        'connect', has_database_privilege(current_database(), 'CONNECT'), \
        'create', has_database_privilege(current_database(), 'CREATE'), \
        'temp', has_database_privilege(current_database(), 'TEMP')) AS v";

/// Per non-system schema: USAGE and CREATE, and how many of its tables the role can and cannot SELECT.
fn schemas_sql() -> String {
    format!(
        "SELECT COALESCE(jsonb_agg(jsonb_build_object('name', x.name, 'usage', x.usage, \
        'create', x.can_create, 'selectableTables', x.selectable, 'unselectableTables', x.unselectable) \
        ORDER BY x.name), '[]'::jsonb) AS v \
        FROM (SELECT n.nspname::text AS name, has_schema_privilege(n.oid, 'USAGE') AS usage, \
        has_schema_privilege(n.oid, 'CREATE') AS can_create, \
        count(c.oid) FILTER (WHERE has_table_privilege(c.oid, 'SELECT')) AS selectable, \
        count(c.oid) FILTER (WHERE NOT has_table_privilege(c.oid, 'SELECT')) AS unselectable \
        FROM pg_catalog.pg_namespace n \
        LEFT JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relkind::text IN ('r', 'p') \
        WHERE {NON_SYSTEM} \
        GROUP BY n.oid, n.nspname) x"
    )
}

/// The monitoring and server-log features, as flags; the JSON and the GRANT texts are built from them.
fn features_sql() -> String {
    let flags = log_reader_flags();
    format!(
        "SELECT pg_catalog.quote_ident(current_user) AS who, \
    CASE WHEN pg_catalog.to_regrole('pg_read_all_stats') IS NULL THEN false \
        ELSE pg_catalog.pg_has_role(current_user, 'pg_read_all_stats', 'USAGE') END AS \"queryText\", \
    EXISTS (SELECT 1 FROM pg_catalog.pg_extension WHERE extname = 'pg_stat_statements') AS \"pgssInstalled\", \
    COALESCE((SELECT pg_catalog.has_table_privilege(c.oid, 'SELECT') FROM pg_catalog.pg_extension e \
        JOIN pg_catalog.pg_class c ON c.relnamespace = e.extnamespace AND c.relname = 'pg_stat_statements' \
        WHERE e.extname = 'pg_stat_statements'), false) AS \"pgssSelect\", \
    (SELECT f.installed AND f.allowed AND f.authentic FROM (SELECT {flags}) AS f) AS \"logReader\", \
    (SELECT e.extversion::text FROM pg_catalog.pg_extension e WHERE e.extname = 'timescaledb') AS \"timescaleVersion\""
    )
}

/// One predefined role's membership as a boolean; false when the role does not exist on this version.
fn member_of(role: &str) -> String {
    format!(
        "CASE WHEN pg_catalog.to_regrole('{role}') IS NULL THEN false \
        ELSE pg_catalog.pg_has_role(current_user, '{role}', 'MEMBER') END"
    )
}

fn predefined_sql() -> String {
    let pairs: Vec<String> = PREDEFINED_ROLES
        .iter()
        .map(|(key, role)| format!("'{key}', {}", member_of(role)))
        .collect();
    format!("SELECT jsonb_build_object({}) AS v", pairs.join(", "))
}

/// Findings beyond read access, in a fixed order; an empty list when the role is read-only.
fn beyond_sql() -> String {
    let schemas = format!(
        "ARRAY(SELECT 'CREATE on schema ' || n.nspname::text FROM pg_catalog.pg_namespace n \
        WHERE {NON_SYSTEM} AND has_schema_privilege(n.oid, 'CREATE') ORDER BY n.nspname::text)"
    );
    let tables = format!(
        "ARRAY[(SELECT CASE WHEN count(*) > 0 THEN 'INSERT/UPDATE/DELETE/TRUNCATE on ' || count(*) || ' tables' END \
        FROM (SELECT c.oid FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
            WHERE c.relkind::text IN ('r', 'p') AND {NON_SYSTEM} LIMIT 5000) t \
        WHERE has_table_privilege(t.oid, 'INSERT') OR has_table_privilege(t.oid, 'UPDATE') \
            OR has_table_privilege(t.oid, 'DELETE') OR has_table_privilege(t.oid, 'TRUNCATE'))]"
    );
    let write_all = member_of("pg_write_all_data");
    let signal = member_of("pg_signal_backend");
    let read_files = member_of("pg_read_server_files");
    let exec = member_of("pg_execute_server_program");
    let write_files = member_of("pg_write_server_files");
    format!(
        "SELECT COALESCE(to_jsonb(ARRAY(SELECT m FROM unnest(\
        ARRAY[CASE WHEN r.rolsuper THEN 'superuser' END, \
        CASE WHEN {write_all} THEN 'member of pg_write_all_data' END, \
        CASE WHEN r.rolcreatedb THEN 'CREATEDB' END, \
        CASE WHEN r.rolcreaterole THEN 'CREATEROLE' END, \
        CASE WHEN r.rolreplication THEN 'REPLICATION' END, \
        CASE WHEN r.rolbypassrls THEN 'BYPASSRLS' END, \
        CASE WHEN has_database_privilege(current_database(), 'CREATE') THEN 'CREATE on database' END] \
        || {schemas} || {tables} \
        || ARRAY[CASE WHEN {signal} THEN 'member of pg_signal_backend' END, \
        CASE WHEN {read_files} THEN 'member of pg_read_server_files' END, \
        CASE WHEN {exec} THEN 'member of pg_execute_server_program' END, \
        CASE WHEN {write_files} THEN 'member of pg_write_server_files' END]) \
        WITH ORDINALITY AS u(m, ord) WHERE m IS NOT NULL ORDER BY ord)), '[]'::jsonb) AS v \
        FROM pg_catalog.pg_roles r WHERE r.rolname = current_user"
    )
}

/// Arguments of get_privileges.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GetPrivilegesArgs {
    pub database: Option<String>,
}

/// What the role may do. A section the query failed for is null, with its message under `<section>Error`.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GetPrivilegesResult {
    pub database: String,
    pub role: Option<Value>,
    pub predefined_roles: Option<Value>,
    pub database_privileges: Option<Value>,
    pub schemas: Option<Value>,
    pub features: Option<Value>,
    pub beyond_read_only: Option<Value>,
    #[serde(flatten)]
    pub section_errors: Map<String, Value>,
}

pub async fn get_privileges(
    state: &AppState,
    args: GetPrivilegesArgs,
    ct: &CancellationToken,
) -> Call {
    let outcome = get_privileges_of(state, &args, ct).await;
    finish(state, args.database.as_deref(), outcome)
}

async fn get_privileges_of(
    state: &AppState,
    args: &GetPrivilegesArgs,
    ct: &CancellationToken,
) -> Result<(String, GetPrivilegesResult), ToolError> {
    let database = state.pool(args.database.as_deref())?.0.name.clone();
    let db = Some(database.as_str());
    let mut errors = Map::new();
    let role = section(state, db, ROLE_SQL, &[], ct, &mut errors, "role").await;
    let predefined_roles = section(
        state,
        db,
        &predefined_sql(),
        &[],
        ct,
        &mut errors,
        "predefinedRoles",
    )
    .await;
    let database_privileges = section(
        state,
        db,
        DATABASE_SQL,
        &[],
        ct,
        &mut errors,
        "databasePrivileges",
    )
    .await;
    let schemas = section(state, db, &schemas_sql(), &[], ct, &mut errors, "schemas").await;
    let features = features(state, db, ct, &mut errors).await;
    let beyond_read_only = section(
        state,
        db,
        &beyond_sql(),
        &[],
        ct,
        &mut errors,
        "beyondReadOnly",
    )
    .await;
    let result = GetPrivilegesResult {
        database: database.clone(),
        role,
        predefined_roles,
        database_privileges,
        schemas,
        features,
        beyond_read_only,
        section_errors: errors,
    };
    Ok((database, result))
}

/// The feature availability section, built from the flags in one query.
async fn features(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
    errors: &mut Map<String, Value>,
) -> Option<Value> {
    match run_rows(state, database, &features_sql(), &[], ct).await {
        Ok((_, rows)) => Some(rows.first().map_or(Value::Null, feature_values)),
        Err(error) => {
            errors.insert("featuresError".to_owned(), Value::String(error.message()));
            None
        }
    }
}

fn flag(row: &Map<String, Value>, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or_default()
}

/// Each feature with `available`, and the exact statement an administrator would run when it is not.
fn feature_values(row: &Map<String, Value>) -> Value {
    let who = row.get("who").and_then(Value::as_str).unwrap_or_default();
    let query_text = flag(row, "queryText");
    let pgss_installed = flag(row, "pgssInstalled");
    let pgss_available = pgss_installed && flag(row, "pgssSelect");
    let log_reader = flag(row, "logReader");
    let timescale = row.get("timescaleVersion").and_then(Value::as_str);
    let pgss_missing = if pgss_installed {
        format!("GRANT SELECT ON pg_stat_statements TO {who};")
    } else {
        "CREATE EXTENSION pg_stat_statements; (and add it to shared_preload_libraries)".to_owned()
    };
    json!({
        "otherSessionsQueryText": availability(query_text, format!("GRANT pg_read_all_stats TO {who};")),
        "pgStatStatements": availability(pgss_available, pgss_missing),
        "serverLog": availability(
            log_reader,
            format!(
                "Run sql/log_reader.sql as a superuser, then GRANT USAGE ON SCHEMA pgmcp TO {who}; \
                GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO {who};"
            ),
        ),
        "timescaledb": {"installed": timescale.is_some(), "version": timescale},
    })
}

/// `{available: true}`, or `{available: false, missing}` with the statement that would enable it.
fn availability(available: bool, missing: String) -> Value {
    if available {
        json!({"available": true})
    } else {
        json!({"available": false, "missing": missing})
    }
}
