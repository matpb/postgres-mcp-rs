//! The four core tools: list_databases, execute_query, explain_query and server_info.

use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{Tool, ToolAnnotations};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::envelope::{QueryEnvelope, elapsed_ms};
use super::text;
use super::{Call, INTERNAL_MAX_ROWS, Runner, Statement, ToolError, Toolset, value_of};
use crate::gate::{GateOptions, StatementKind};
use crate::pg::session::RunOutput;
use crate::pg::wire::{FetchLimits, Field, Truncation};
use crate::server::AppState;

/// Time allowed per database for list_databases.
const PROBE_CAP: Duration = Duration::from_secs(5);

/// Settings that describe how to read data. None can hold credentials; a test checks this list.
pub const SERVER_INFO_SETTINGS: &[&str] = &[
    "statement_timeout",
    "lock_timeout",
    "idle_in_transaction_session_timeout",
    "TimeZone",
    "DateStyle",
    "IntervalStyle",
    "search_path",
    "default_transaction_read_only",
    "transaction_read_only",
    "max_connections",
    "shared_preload_libraries",
    "logging_collector",
    "log_destination",
    "log_directory",
    "log_filename",
    "log_min_duration_statement",
    "log_statement",
    "track_activity_query_size",
    "server_encoding",
    "client_encoding",
    "max_parallel_workers_per_gather",
    "work_mem",
    "wal_level",
    "max_prepared_transactions",
    "jit",
];

const CORE_SQL: &str = "SELECT pg_catalog.current_setting('server_version') AS server_version, \
    pg_catalog.current_setting('server_version_num')::int AS server_version_num, \
    pg_catalog.pg_postmaster_start_time()::text AS started_at, \
    pg_catalog.pg_is_in_recovery() AS in_recovery";
const DATABASE_SQL: &str = "SELECT pg_catalog.current_database() AS database_name, \
    pg_catalog.getdatabaseencoding() AS encoding, \
    pg_catalog.pg_database_size(pg_catalog.current_database()) AS database_size_bytes";
const ROLE_SQL: &str = "SELECT rolname AS name, rolsuper AS superuser, rolcreaterole AS create_role, \
    rolcreatedb AS create_db, rolreplication AS replication, rolbypassrls AS bypass_rls, \
    rolconnlimit AS connection_limit FROM pg_catalog.pg_roles WHERE rolname = pg_catalog.current_user()";
const MEMBERSHIP_SQL: &str = "WITH RECURSIVE member_of(roleid) AS (\
    SELECT a.roleid FROM pg_catalog.pg_auth_members a \
    WHERE a.member = (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname = pg_catalog.current_user()) \
    UNION SELECT a.roleid FROM pg_catalog.pg_auth_members a JOIN member_of m ON a.member = m.roleid) \
    SELECT r.rolname AS role_name FROM member_of m JOIN pg_catalog.pg_roles r ON r.oid = m.roleid \
    ORDER BY r.rolname";
/// Installed extensions; the schema column is read by the database resource, server_info ignores it.
pub(crate) const EXTENSIONS_SQL: &str = "SELECT e.extname AS name, e.extversion AS version, \
    n.nspname::text AS schema, \
    CASE WHEN a.default_version <> e.extversion THEN a.default_version END AS available_version \
    FROM pg_catalog.pg_extension e \
    JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace \
    LEFT JOIN pg_catalog.pg_available_extensions a ON a.name = e.extname ORDER BY e.extname";
const TIMESCALE_SQL: &str =
    "SELECT extversion AS timescaledb FROM pg_catalog.pg_extension WHERE extname = 'timescaledb'";
const SETTINGS_SQL: &str = "SELECT s.name, pg_catalog.current_setting(s.name) AS setting FROM pg_catalog.pg_settings s WHERE s.name = ANY($1::text[]) ORDER BY s.name";
/// The role's own search_path; the catalog-only session of SETTINGS_SQL would report pg_catalog.
const SEARCH_PATH_SQL: &str = "SELECT pg_catalog.current_setting('search_path') AS setting";
const VERSION_SQL: &str = "SELECT pg_catalog.current_setting('server_version') AS server_version, \
    pg_catalog.current_setting('server_version_num')::int AS server_version_num";

/// Arguments of list_databases, which takes none.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecuteArgs {
    pub database: Option<String>,
    pub sql: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatabaseArgs {
    pub database: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ExplainFormat {
    #[default]
    Text,
    Json,
    Yaml,
    Xml,
}

impl ExplainFormat {
    fn as_str(self) -> &'static str {
        match self {
            ExplainFormat::Text => "text",
            ExplainFormat::Json => "json",
            ExplainFormat::Yaml => "yaml",
            ExplainFormat::Xml => "xml",
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExplainArgs {
    pub database: Option<String>,
    pub sql: String,
    #[serde(default)]
    pub format: ExplainFormat,
    #[serde(default)]
    pub analyze: bool,
    #[serde(default)]
    pub buffers: bool,
    #[serde(default)]
    pub verbose: bool,
    #[serde(default)]
    pub settings: bool,
    #[serde(default)]
    pub wal: bool,
    #[serde(default)]
    pub memory: bool,
    #[serde(default)]
    pub serialize: bool,
    #[serde(default)]
    pub generic_plan: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListDatabasesResult {
    pub databases: Vec<DatabaseStatus>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseStatus {
    pub name: String,
    pub reachable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version_num: Option<u64>,
    /// Present for reachable databases; null when TimescaleDB is not installed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timescaledb: Option<Option<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplainResult {
    pub database: String,
    pub format: &'static str,
    pub plan: Value,
    pub execution_time_ms: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServerInfoResult {
    pub database: String,
    pub version: VersionInfo,
    pub started_at: String,
    pub in_recovery: bool,
    pub database_name: Option<String>,
    pub encoding: Option<String>,
    pub database_size_bytes: Option<i64>,
    pub role: Option<RoleInfo>,
    pub extensions: Option<Vec<ExtensionInfo>>,
    pub timescaledb: Option<String>,
    pub settings: Option<Vec<SettingInfo>>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub full: String,
    pub number: u64,
    pub major: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RoleInfo {
    pub name: String,
    pub superuser: bool,
    pub create_role: bool,
    pub create_db: bool,
    pub replication: bool,
    pub bypass_rls: bool,
    pub connection_limit: i64,
    pub member_of: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExtensionInfo {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_version: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SettingInfo {
    pub name: String,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
}

/// Every core tool with its toolset tag, title, description and schemas.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    vec![
        (
            Toolset::Core,
            tool::<NoArgs, ListDatabasesResult>(
                "list_databases",
                text::LIST_DATABASES_TITLE,
                text::LIST_DATABASES,
                &[],
            ),
        ),
        (
            Toolset::Core,
            tool::<ExecuteArgs, QueryEnvelope>(
                "execute_query",
                text::EXECUTE_QUERY_TITLE,
                text::EXECUTE_QUERY,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("sql", text::EXECUTE_QUERY_SQL_PARAM),
                ],
            ),
        ),
        (
            Toolset::Core,
            tool_with_leading::<ExplainArgs, ExplainResult>(
                "explain_query",
                text::EXPLAIN_QUERY_TITLE,
                text::EXPLAIN_QUERY,
                &[
                    ("database", text::DATABASE_PARAM),
                    ("sql", text::EXPLAIN_QUERY_SQL_PARAM),
                    ("format", text::EXPLAIN_QUERY_FORMAT_PARAM),
                    ("analyze", text::EXPLAIN_QUERY_ANALYZE_PARAM),
                    ("buffers", text::EXPLAIN_QUERY_BUFFERS_PARAM),
                    ("verbose", text::EXPLAIN_QUERY_VERBOSE_PARAM),
                    ("settings", text::EXPLAIN_QUERY_SETTINGS_PARAM),
                    ("wal", text::EXPLAIN_QUERY_WAL_PARAM),
                    ("memory", text::EXPLAIN_QUERY_MEMORY_PARAM),
                    ("serialize", text::EXPLAIN_QUERY_SERIALIZE_PARAM),
                    ("generic_plan", text::EXPLAIN_QUERY_GENERIC_PLAN_PARAM),
                ],
                &[
                    "sql",
                    "format",
                    "analyze",
                    "buffers",
                    "verbose",
                    "settings",
                    "wal",
                    "memory",
                    "serialize",
                    "generic_plan",
                ],
            ),
        ),
        (
            Toolset::Core,
            tool::<DatabaseArgs, ServerInfoResult>(
                "server_info",
                text::SERVER_INFO_TITLE,
                text::SERVER_INFO,
                &[("database", text::DATABASE_PARAM)],
            ),
        ),
    ]
}

/// Builds one tool: read-only annotations, schemas from the types, and the given property descriptions.
pub fn tool<I: JsonSchema + 'static, O: JsonSchema + 'static>(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    docs: &[(&str, &str)],
) -> Tool {
    tool_with_leading::<I, O>(name, title, description, docs, &[])
}

/// Like `tool`, and the descriptions of `leading` come first in their property objects.
pub fn tool_with_leading<I: JsonSchema + 'static, O: JsonSchema + 'static>(
    name: &'static str,
    title: &'static str,
    description: &'static str,
    docs: &[(&str, &str)],
    leading: &[&str],
) -> Tool {
    let mut tool = Tool::new(name, description, Arc::new(Map::new()))
        .with_title(title)
        .with_annotations(
            ToolAnnotations::with_title(title)
                .read_only(true)
                .destructive(false)
                .idempotent(true)
                .open_world(false),
        )
        .with_input_schema::<I>()
        .with_output_schema::<O>();
    set_descriptions(&mut tool.input_schema, docs, leading);
    tool
}

/// Replaces the description of each named property in a generated input schema. A `leading` property
/// gets its description first in its object, where the published schema has it for these fields.
fn set_descriptions(schema: &mut Arc<Map<String, Value>>, docs: &[(&str, &str)], leading: &[&str]) {
    let schema = Arc::make_mut(schema);
    let Some(Value::Object(properties)) = schema.get_mut("properties") else {
        return;
    };
    for (name, doc) in docs {
        if let Some(Value::Object(property)) = properties.get_mut(*name) {
            let text = Value::String((*doc).to_owned());
            if leading.contains(name) {
                let rest = std::mem::take(property);
                property.insert("description".to_owned(), text);
                for (key, value) in rest {
                    if key != "description" {
                        property.insert(key, value);
                    }
                }
            } else {
                property.insert("description".to_owned(), text);
            }
        }
    }
}

pub fn failed(error: ToolError, database: Option<String>) -> Call {
    Call {
        result: Err(error),
        database,
        rows: None,
        sql: None,
    }
}

pub async fn list_databases(state: Arc<AppState>, ct: &CancellationToken) -> Call {
    let mut probes = tokio::task::JoinSet::new();
    for (index, db) in state.config.databases.iter().enumerate() {
        let (state, name, ct) = (state.clone(), db.name.clone(), ct.clone());
        probes.spawn(async move { (index, probe(state, name, ct).await) });
    }
    let mut statuses = Vec::with_capacity(state.config.databases.len());
    while let Some(joined) = probes.join_next().await {
        match joined {
            Ok(pair) => statuses.push(pair),
            Err(error) => {
                return failed(
                    ToolError::Internal(format!("database probe failed: {error}")),
                    None,
                );
            }
        }
    }
    statuses.sort_by_key(|(index, _)| *index);
    let databases = statuses.into_iter().map(|(_, status)| status).collect();
    Call {
        result: value_of(&ListDatabasesResult { databases }),
        database: None,
        rows: None,
        sql: None,
    }
}

/// One database's reachability, version and TimescaleDB version, capped at PROBE_CAP.
async fn probe(state: Arc<AppState>, name: String, ct: CancellationToken) -> DatabaseStatus {
    let sql = "SELECT pg_catalog.current_setting('server_version') AS server_version, \
        pg_catalog.current_setting('server_version_num')::int AS server_version_num, \
        (SELECT extversion FROM pg_catalog.pg_extension WHERE extname = 'timescaledb') AS timescaledb";
    let runner = Runner::new(&state);
    let outcome = tokio::time::timeout(
        PROBE_CAP,
        runner.internal_query(Some(name.as_str()), sql, &[], &ct),
    )
    .await;
    let envelope = match outcome {
        Ok(Ok(envelope)) => envelope,
        Ok(Err(error)) => return unreachable_status(name, error.message()),
        Err(_) => {
            let message = format!("no answer within {} s", PROBE_CAP.as_secs());
            return unreachable_status(name, message);
        }
    };
    let Some(row) = envelope.rows.first() else {
        return unreachable_status(name, "the server returned no row".to_owned());
    };
    DatabaseStatus {
        name,
        reachable: true,
        server_version: text_of(row, "server_version"),
        server_version_num: row.get("server_version_num").and_then(Value::as_u64),
        timescaledb: Some(text_of(row, "timescaledb")),
        error: None,
    }
}

fn unreachable_status(name: String, error: String) -> DatabaseStatus {
    DatabaseStatus {
        name,
        reachable: false,
        server_version: None,
        server_version_num: None,
        timescaledb: None,
        error: Some(error),
    }
}

pub async fn execute_query(state: &AppState, args: ExecuteArgs, ct: &CancellationToken) -> Call {
    let result = Runner::new(state)
        .user_query(args.database.as_deref(), &args.sql, ct)
        .await;
    let database = match &result {
        Ok(envelope) => Some(envelope.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    let rows = result.as_ref().ok().map(|envelope| envelope.row_count);
    Call {
        result: result.and_then(|envelope| value_of(&envelope)),
        database,
        rows,
        sql: Some(args.sql),
    }
}

pub async fn explain_query(state: &AppState, args: ExplainArgs, ct: &CancellationToken) -> Call {
    let result = explain(state, &args, ct).await;
    let database = match &result {
        Ok(explained) => Some(explained.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    Call {
        result: result.and_then(|explained| value_of(&explained)),
        database,
        rows: None,
        sql: Some(args.sql),
    }
}

async fn explain(
    state: &AppState,
    args: &ExplainArgs,
    ct: &CancellationToken,
) -> Result<ExplainResult, ToolError> {
    // Resolves the database first, so an unknown name is reported before anything else.
    state.pool(args.database.as_deref())?;
    let limits = &state.config.limits;
    let options = GateOptions {
        allow_placeholders: args.generic_plan,
        max_sql_bytes: limits.max_sql_bytes,
    };
    let accepted = super::check_sql(&args.sql, options).await?;
    if accepted.kind != StatementKind::Select {
        return Err(ToolError::Rejected(
            "Query rejected: explain_query takes a SELECT, WITH, VALUES or TABLE statement."
                .to_owned(),
        ));
    }
    check_option_combinations(args)?;
    let runner = Runner::new(state);
    check_server_versions(&runner, args, ct).await?;

    let prefix = explain_prefix(args);
    let offset = u32::try_from(prefix.chars().count()).unwrap_or(u32::MAX);
    let sql = format!("{prefix}{}", args.sql);
    let fetch = FetchLimits {
        max_rows: INTERNAL_MAX_ROWS,
        max_bytes: limits.max_response_bytes,
        max_value_bytes: limits.max_response_bytes,
    };
    let (database, output) = if args.generic_plan {
        runner
            .internal_generic(args.database.as_deref(), &sql, fetch, offset, ct)
            .await?
    } else {
        let statement = Statement {
            sql: &sql,
            params: &[],
            user_sql: false,
            fetch,
            offset,
            search_path_catalog_only: false,
        };
        runner
            .internal_raw(args.database.as_deref(), statement, ct)
            .await?
    };
    let RunOutput {
        result, elapsed, ..
    } = output;
    if let Some(truncated) = result.truncated {
        return Err(truncated_plan_error(
            truncated,
            INTERNAL_MAX_ROWS,
            limits.max_response_bytes,
        ));
    }
    let plan = match args.format {
        ExplainFormat::Json => json_plan(&result.rows)?,
        _ => text_plan(&result.rows)?,
    };
    Ok(ExplainResult {
        database,
        format: args.format.as_str(),
        plan,
        execution_time_ms: elapsed_ms(elapsed),
    })
}

fn check_option_combinations(args: &ExplainArgs) -> Result<(), ToolError> {
    if args.generic_plan && args.analyze {
        return Err(ToolError::Rejected(
            "generic_plan cannot be combined with analyze.".to_owned(),
        ));
    }
    for (name, on) in [("wal", args.wal), ("serialize", args.serialize)] {
        if on && !args.analyze {
            return Err(ToolError::Rejected(format!(
                "Option {name} requires analyze=true."
            )));
        }
    }
    Ok(())
}

/// Rejects a requested option the connected server is too old for. Asks the server only when needed.
async fn check_server_versions(
    runner: &Runner<'_>,
    args: &ExplainArgs,
    ct: &CancellationToken,
) -> Result<(), ToolError> {
    let requested = [
        ("settings", 12_u64, args.settings),
        ("wal", 13, args.wal),
        ("generic_plan", 16, args.generic_plan),
        ("memory", 17, args.memory),
        ("serialize", 17, args.serialize),
    ];
    if !requested.iter().any(|(_, _, on)| *on) {
        return Ok(());
    }
    let envelope = runner
        .internal_query(args.database.as_deref(), VERSION_SQL, &[], ct)
        .await?;
    let row = envelope
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no version".to_owned()))?;
    let version = text_of(row, "server_version")
        .ok_or_else(|| ToolError::Internal("the server returned no version".to_owned()))?;
    let number = row
        .get("server_version_num")
        .and_then(Value::as_u64)
        .ok_or_else(|| ToolError::Internal("the server returned no version number".to_owned()))?;
    for (name, minimum, on) in requested {
        if on && number < minimum * 10_000 {
            return Err(ToolError::Rejected(format!(
                "Option {name} needs PostgreSQL {minimum} or newer; this server is PostgreSQL {version}."
            )));
        }
    }
    Ok(())
}

/// The EXPLAIN keyword and its options, ending in the space before the statement.
fn explain_prefix(args: &ExplainArgs) -> String {
    let mut options = vec![format!("FORMAT {}", args.format.as_str())];
    if args.analyze {
        options.push("ANALYZE true".to_owned());
    }
    let flags = [
        ("BUFFERS", args.buffers),
        ("VERBOSE", args.verbose),
        ("SETTINGS", args.settings),
        ("WAL", args.wal),
        ("MEMORY", args.memory),
        ("GENERIC_PLAN", args.generic_plan),
    ];
    options.extend(
        flags
            .iter()
            .filter(|(_, on)| *on)
            .map(|(name, _)| format!("{name} true")),
    );
    // SERIALIZE takes NONE, TEXT or BINARY on PostgreSQL 17 and newer, not a boolean.
    if args.serialize {
        options.push("SERIALIZE TEXT".to_owned());
    }
    format!("EXPLAIN ({}) ", options.join(", "))
}

/// The plan's text: each row's first column, joined by newlines.
fn text_plan(rows: &[Vec<Option<Field>>]) -> Result<Value, ToolError> {
    let mut lines = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(Some(field)) = row.first() {
            lines.push(String::from_utf8_lossy(whole(field)?).into_owned());
        }
    }
    Ok(Value::String(lines.join("\n")))
}

/// The error for a plan cut short: the row cap or the byte budget, whichever tripped.
fn truncated_plan_error(truncated: Truncation, max_rows: usize, max_bytes: usize) -> ToolError {
    ToolError::Internal(match truncated {
        Truncation::Rows => format!(
            "The plan has more than {max_rows} lines; use format \"json\" or explain a smaller statement."
        ),
        Truncation::Bytes => {
            format!("the plan is larger than MAX_RESPONSE_BYTES ({max_bytes} bytes)")
        }
    })
}

/// The plan as parsed JSON, from the single json value that FORMAT JSON returns.
fn json_plan(rows: &[Vec<Option<Field>>]) -> Result<Value, ToolError> {
    let field = rows
        .first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref)
        .ok_or_else(|| ToolError::Internal("the server returned no plan".to_owned()))?;
    serde_json::from_slice(whole(field)?)
        .map_err(|e| ToolError::Internal(format!("the plan is not valid JSON: {e}")))
}

/// The complete bytes of a field; a cut value is an error, never a partial plan.
fn whole(field: &Field) -> Result<&[u8], ToolError> {
    if field.full_len > field.data.len() {
        return Err(ToolError::Internal(format!(
            "the plan is larger than MAX_RESPONSE_BYTES ({} bytes)",
            field.full_len
        )));
    }
    Ok(&field.data[..])
}

pub async fn server_info(state: &AppState, args: DatabaseArgs, ct: &CancellationToken) -> Call {
    let result = server_info_of(state, args.database.as_deref(), ct).await;
    let database = match &result {
        Ok(info) => Some(info.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    Call {
        result: result.and_then(|info| value_of(&info)),
        database,
        rows: None,
        sql: None,
    }
}

async fn server_info_of(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<ServerInfoResult, ToolError> {
    let runner = Runner::new(state);
    let core = runner.internal_query(database, CORE_SQL, &[], ct).await?;
    let row = core
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no version row".to_owned()))?;
    let number = row
        .get("server_version_num")
        .and_then(Value::as_u64)
        .ok_or_else(|| ToolError::Internal("the server returned no version number".to_owned()))?;
    let version = VersionInfo {
        full: text_of(row, "server_version").unwrap_or_default(),
        number,
        major: number / 10_000,
    };
    let started_at = text_of(row, "started_at").unwrap_or_default();
    let in_recovery = row
        .get("in_recovery")
        .and_then(Value::as_bool)
        .unwrap_or_default();

    let mut warnings = Vec::new();
    let db_row = section(
        &runner,
        database,
        DATABASE_SQL,
        &[],
        "database",
        ct,
        &mut warnings,
    )
    .await
    .and_then(|rows| rows.into_iter().next())
    .unwrap_or_default();
    let role = match section(&runner, database, ROLE_SQL, &[], "role", ct, &mut warnings).await {
        Some(rows) => match rows.first() {
            Some(attrs) => section(
                &runner,
                database,
                MEMBERSHIP_SQL,
                &[],
                "role.memberOf",
                ct,
                &mut warnings,
            )
            .await
            .map(|members| RoleInfo {
                name: text_of(attrs, "name").unwrap_or_default(),
                superuser: flag(attrs, "superuser"),
                create_role: flag(attrs, "create_role"),
                create_db: flag(attrs, "create_db"),
                replication: flag(attrs, "replication"),
                bypass_rls: flag(attrs, "bypass_rls"),
                connection_limit: attrs
                    .get("connection_limit")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
                member_of: members
                    .iter()
                    .filter_map(|m| text_of(m, "role_name"))
                    .collect(),
            }),
            None => None,
        },
        None => None,
    };
    let extensions = section(
        &runner,
        database,
        EXTENSIONS_SQL,
        &[],
        "extensions",
        ct,
        &mut warnings,
    )
    .await
    .map(|rows| {
        rows.iter()
            .map(|r| ExtensionInfo {
                name: text_of(r, "name").unwrap_or_default(),
                version: text_of(r, "version").unwrap_or_default(),
                available_version: text_of(r, "available_version"),
            })
            .collect()
    });
    let timescaledb = section(
        &runner,
        database,
        TIMESCALE_SQL,
        &[],
        "timescaledb",
        ct,
        &mut warnings,
    )
    .await
    .and_then(|rows| rows.first().and_then(|r| text_of(r, "timescaledb")));
    let search_path = match runner.user_query(database, SEARCH_PATH_SQL, ct).await {
        Ok(envelope) => envelope.rows.first().and_then(|r| text_of(r, "setting")),
        Err(error) => {
            warnings.push(format!("settings.search_path: {}", error.message()));
            None
        }
    };
    let settings_list = format!("{{{}}}", SERVER_INFO_SETTINGS.join(","));
    let settings = section(
        &runner,
        database,
        SETTINGS_SQL,
        &[Some(settings_list.as_str())],
        "settings",
        ct,
        &mut warnings,
    )
    .await
    .map(|rows| {
        rows.iter()
            .filter_map(|r| {
                let name = text_of(r, "name").unwrap_or_default();
                // The catalog-only session reports pg_catalog for search_path: use the role's value or omit it.
                let value = if name == "search_path" {
                    search_path.clone()?
                } else {
                    text_of(r, "setting").unwrap_or_default()
                };
                Some(SettingInfo {
                    name,
                    value,
                    unit: None,
                })
            })
            .collect()
    });

    Ok(ServerInfoResult {
        database: core.database,
        version,
        started_at,
        in_recovery,
        database_name: text_of(&db_row, "database_name"),
        encoding: text_of(&db_row, "encoding"),
        database_size_bytes: db_row.get("database_size_bytes").and_then(Value::as_i64),
        role,
        extensions,
        timescaledb,
        settings,
        warnings,
    })
}

/// Runs one optional sub-query: its rows, or a warning naming the section and nothing else.
async fn section(
    runner: &Runner<'_>,
    database: Option<&str>,
    sql: &str,
    params: &[Option<&str>],
    label: &str,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Option<Vec<Map<String, Value>>> {
    match runner.internal_query(database, sql, params, ct).await {
        Ok(envelope) => Some(envelope.rows),
        Err(error) => {
            warnings.push(format!("{label}: {}", error.message()));
            None
        }
    }
}

fn text_of(row: &Map<String, Value>, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn flag(row: &Map<String, Value>, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_plan_names_the_reason_that_tripped() {
        let rows = truncated_plan_error(Truncation::Rows, 5000, 48_000);
        assert_eq!(
            rows.message(),
            "Internal error: The plan has more than 5000 lines; use format \"json\" or explain a smaller statement."
        );
        let bytes = truncated_plan_error(Truncation::Bytes, 5000, 48_000);
        assert_eq!(
            bytes.message(),
            "Internal error: the plan is larger than MAX_RESPONSE_BYTES (48000 bytes)"
        );
    }
}
