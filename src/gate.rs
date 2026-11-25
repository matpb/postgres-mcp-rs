//! Read-only query gate: accepts one statement that is provably read-only, rejects the rest.

use serde_json::{Map, Value};

/// Limits and switches for [`check`].
#[derive(Debug, Clone)]
pub struct GateOptions {
    pub allow_placeholders: bool,
    pub max_sql_bytes: usize,
}

impl Default for GateOptions {
    fn default() -> Self {
        Self {
            allow_placeholders: false,
            max_sql_bytes: 100 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementKind {
    Select,
    Explain { analyze: bool },
    Show { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub kind: StatementKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub code: &'static str,
    pub message: String,
}

/// Stack for the parser thread: the C parser, the protobuf decoder and serde all recurse.
const PARSE_STACK_BYTES: usize = 64 * 1024 * 1024;
/// Maximum nesting of the serialized parse tree, counted in JSON levels.
const MAX_DEPTH: usize = 5000;

/// Settings whose values can expose credentials or local paths.
pub const SECRET_SETTINGS: &[&str] = &[
    "primary_conninfo",
    "ssl_passphrase_command",
    "ssl_key_file",
    "archive_command",
    "restore_command",
    "archive_cleanup_command",
    "recovery_end_command",
    "krb_server_keyfile",
];

/// Relations that expose credentials, matched by lowercased name when unqualified or in pg_catalog or
/// information_schema. pg_roles and pg_user show `********` for passwords and stay readable.
const CREDENTIAL_RELATIONS: &[&str] = &[
    "pg_authid",
    "pg_shadow",
    "pg_user_mapping",
    "pg_user_mappings",
    "_pg_user_mappings",
    "user_mapping_options",
    "pg_subscription",
    "pg_settings",
    "pg_file_settings",
    "pg_hba_file_rules",
    "pg_ident_file_mappings",
    "pg_config",
    "pg_db_role_setting",
    "pg_statistic",
    "pg_statistic_ext_data",
];

/// The relations of CREDENTIAL_RELATIONS that hold server settings; their message names server_info.
const SETTINGS_RELATIONS: &[&str] = &["pg_settings", "pg_file_settings"];

/// Schemas whose functions are TimescaleDB internals; a call qualified with one is denied.
const INTERNAL_SCHEMAS: &[&str] = &[
    "_timescaledb_functions",
    "_timescaledb_internal",
    "_timescaledb_catalog",
];

const EXPLAIN_OPTIONS: &[&str] = &[
    "analyze",
    "verbose",
    "costs",
    "settings",
    "generic_plan",
    "buffers",
    "serialize",
    "wal",
    "timing",
    "summary",
    "memory",
    "format",
    "io",
];

/// Parse-tree node variants that may appear in a read-only statement.
const ALLOWED_NODES: &[&str] = &[
    "SelectStmt",
    "ExplainStmt",
    "VariableShowStmt",
    "DefElem",
    "ResTarget",
    "ColumnRef",
    "AStar",
    "AConst",
    "AExpr",
    "BoolExpr",
    "NullTest",
    "BooleanTest",
    "SubLink",
    "CaseExpr",
    "CaseWhen",
    "CoalesceExpr",
    "MinMaxExpr",
    "NullIfExpr",
    "RowExpr",
    "TypeCast",
    "TypeName",
    "CollateClause",
    "FuncCall",
    "NamedArgExpr",
    "WindowDef",
    "SortBy",
    "RangeVar",
    "RangeSubselect",
    "RangeFunction",
    "RangeTableFunc",
    "RangeTableFuncCol",
    "RangeTableSample",
    "JoinExpr",
    "Alias",
    "WithClause",
    "CommonTableExpr",
    "CtesearchClause",
    "CtecycleClause",
    "AIndices",
    "AIndirection",
    "AArrayExpr",
    "GroupingSet",
    "GroupingFunc",
    "ParamRef",
    "SqlvalueFunction",
    "XmlExpr",
    "XmlSerialize",
    "String",
    "Integer",
    "Float",
    "Boolean",
    "BitString",
    "List",
    "ColumnDef",
    "JsonObjectConstructor",
    "JsonArrayConstructor",
    "JsonArrayQueryConstructor",
    "JsonObjectAgg",
    "JsonArrayAgg",
    "JsonAggConstructor",
    "JsonKeyValue",
    "JsonValueExpr",
    "JsonFormat",
    "JsonOutput",
    "JsonReturning",
    "JsonIsPredicate",
    "JsonFuncExpr",
    "JsonParseExpr",
    "JsonScalarExpr",
    "JsonSerializeExpr",
    "JsonTable",
    "JsonTableColumn",
    "JsonTablePathSpec",
    "JsonArgument",
    "JsonBehavior",
];

const CRON_JOB_FUNCTIONS: &[&str] = &[
    "schedule",
    "schedule_in_database",
    "unschedule",
    "alter_job",
];

const R_CONTROL: &str = "it controls the server or other sessions";
const R_STATS: &str = "it changes statistics";
const R_SESSION: &str = "it changes session state that pooled connections would leak";
const R_SEQUENCE: &str = "it consumes a sequence value or transaction id";
const R_LARGE_OBJECT: &str = "it writes or exports large objects";
const R_OTHER_SQL: &str = "it executes SQL text the gate cannot inspect";
const R_WAL: &str = "it writes WAL or changes replication state";
const R_FILES: &str = "it reads or writes server files";
const R_MAINTENANCE: &str = "it performs maintenance work";
const R_SETTINGS: &str = "it can expose credentials; use the server_info tool";
const R_TIMESCALE: &str = "it changes TimescaleDB objects";
const R_CRON: &str = "it changes scheduled jobs";
const R_RAW_PAGES: &str = "it changes or reads table pages directly";
const R_EXTENSION: &str = "it is an extension routine the gate does not allow";
const R_NETWORK: &str = "it makes network requests";
const R_TIMESCALE_INTERNAL: &str = "it calls TimescaleDB internals the gate cannot classify";
const R_LOG_HELPERS: &str =
    "the server log helper functions are reserved for the read_server_log tool";

/// Function names denied by name or prefix (a trailing `*`); matched on the last name part.
const DENIED_FUNCTIONS: &[(&str, &str)] = &[
    ("pg_terminate_backend", R_CONTROL),
    ("pg_cancel_backend", R_CONTROL),
    ("pg_reload_conf", R_CONTROL),
    ("pg_rotate_logfile", R_CONTROL),
    // adminpack's pre-9.1 alias, still installed on PostgreSQL 15.
    ("pg_rotate_logfile_old", R_CONTROL),
    ("pg_switch_wal", R_CONTROL),
    ("pg_create_restore_point", R_CONTROL),
    ("pg_promote", R_CONTROL),
    ("pg_wal_replay_*", R_CONTROL),
    ("pg_backup_*", R_CONTROL),
    ("pg_log_backend_memory_contexts", R_CONTROL),
    ("pg_log_standby_snapshot", R_CONTROL),
    ("pg_import_system_collations", R_CONTROL),
    ("binary_upgrade_*", R_CONTROL),
    ("pg_stat_reset*", R_STATS),
    ("pg_stat_statements_reset", R_STATS),
    ("pg_stat_force_next_flush", R_STATS),
    ("pg_stat_clear_snapshot", R_STATS),
    ("pg_restore_*", R_STATS),
    ("pg_clear_*", R_STATS),
    ("pg_advisory_*", R_SESSION),
    ("pg_try_advisory_*", R_SESSION),
    ("set_config", R_SESSION),
    ("pg_notify", R_SESSION),
    ("setseed", R_SESSION),
    ("pg_export_snapshot", R_SESSION),
    ("nextval", R_SEQUENCE),
    ("setval", R_SEQUENCE),
    ("txid_current", R_SEQUENCE),
    ("pg_current_xact_id", R_SEQUENCE),
    ("lo_import", R_LARGE_OBJECT),
    ("lo_export", R_LARGE_OBJECT),
    ("lo_unlink", R_LARGE_OBJECT),
    ("lo_create", R_LARGE_OBJECT),
    ("lo_creat", R_LARGE_OBJECT),
    ("lo_put", R_LARGE_OBJECT),
    ("lo_from_bytea", R_LARGE_OBJECT),
    ("lowrite", R_LARGE_OBJECT),
    ("lo_open", R_LARGE_OBJECT),
    ("lo_truncate", R_LARGE_OBJECT),
    ("lo_truncate64", R_LARGE_OBJECT),
    ("dblink*", R_OTHER_SQL),
    ("query_to_xml*", R_OTHER_SQL),
    ("cursor_to_xml*", R_OTHER_SQL),
    ("table_to_xml*", R_OTHER_SQL),
    ("schema_to_xml*", R_OTHER_SQL),
    ("database_to_xml*", R_OTHER_SQL),
    ("ts_stat", R_OTHER_SQL),
    ("ts_rewrite", R_OTHER_SQL),
    ("crosstab*", R_OTHER_SQL),
    ("connectby", R_OTHER_SQL),
    ("xpath_table", R_OTHER_SQL),
    ("pg_logical_emit_message", R_WAL),
    ("pg_logical_slot_*", R_WAL),
    ("pg_replication_slot_*", R_WAL),
    ("pg_create_logical_replication_slot", R_WAL),
    ("pg_create_physical_replication_slot", R_WAL),
    ("pg_drop_replication_slot", R_WAL),
    ("pg_copy_logical_replication_slot", R_WAL),
    ("pg_copy_physical_replication_slot", R_WAL),
    ("pg_replication_origin_*", R_WAL),
    ("pg_sync_replication_slots", R_WAL),
    ("pg_read_file", R_FILES),
    // adminpack's pre-9.1 aliases, still installed on PostgreSQL 15.
    ("pg_read_file_old", R_FILES),
    ("pg_read_binary_file", R_FILES),
    // pg_ls_dir takes any path; the fixed-directory pg_ls_*dir listings stay with PostgreSQL privileges.
    ("pg_ls_dir", R_FILES),
    ("pg_stat_file", R_FILES),
    ("pg_file_*", R_FILES),
    ("pg_prewarm", R_MAINTENANCE),
    ("brin_summarize_*", R_MAINTENANCE),
    ("brin_desummarize_range", R_MAINTENANCE),
    ("gin_clean_pending_list", R_MAINTENANCE),
    ("pg_buffercache_evict*", R_MAINTENANCE),
    ("pg_show_all_settings", R_SETTINGS),
    ("pg_show_all_file_settings", R_SETTINGS),
    ("pg_hba_file_rules", R_SETTINGS),
    ("pg_ident_file_mappings", R_SETTINGS),
    ("add_columnstore_policy", R_TIMESCALE),
    ("add_compaction_policy", R_TIMESCALE),
    ("add_compression_policy", R_TIMESCALE),
    ("add_continuous_aggregate_policy", R_TIMESCALE),
    ("add_dimension", R_TIMESCALE),
    ("add_job", R_TIMESCALE),
    ("add_policies", R_TIMESCALE),
    ("add_reorder_policy", R_TIMESCALE),
    ("add_retention_policy", R_TIMESCALE),
    ("alter_job", R_TIMESCALE),
    ("alter_policies", R_TIMESCALE),
    ("attach_chunk", R_TIMESCALE),
    ("attach_tablespace", R_TIMESCALE),
    ("cagg_migrate", R_TIMESCALE),
    ("compress_chunk", R_TIMESCALE),
    ("convert_to_columnstore", R_TIMESCALE),
    ("convert_to_rowstore", R_TIMESCALE),
    ("copy_chunk", R_TIMESCALE),
    ("create_chunk", R_TIMESCALE),
    ("create_distributed_hypertable", R_TIMESCALE),
    ("create_hypertable", R_TIMESCALE),
    ("decompress_chunk", R_TIMESCALE),
    ("delete_job", R_TIMESCALE),
    ("detach_chunk", R_TIMESCALE),
    ("detach_tablespace", R_TIMESCALE),
    ("detach_tablespaces", R_TIMESCALE),
    ("disable_chunk_skipping", R_TIMESCALE),
    ("drop_chunks", R_TIMESCALE),
    ("enable_chunk_skipping", R_TIMESCALE),
    ("merge_chunks", R_TIMESCALE),
    ("merge_chunks_concurrently", R_TIMESCALE),
    ("move_chunk", R_TIMESCALE),
    ("recompress_chunk", R_TIMESCALE),
    ("refresh_continuous_aggregate", R_TIMESCALE),
    ("remove_all_policies", R_TIMESCALE),
    ("remove_columnstore_policy", R_TIMESCALE),
    ("remove_compaction_policy", R_TIMESCALE),
    ("remove_compression_policy", R_TIMESCALE),
    ("remove_continuous_aggregate_policy", R_TIMESCALE),
    ("remove_policies", R_TIMESCALE),
    ("remove_reorder_policy", R_TIMESCALE),
    ("remove_retention_policy", R_TIMESCALE),
    ("reorder_chunk", R_TIMESCALE),
    ("run_job", R_TIMESCALE),
    ("set_adaptive_chunking", R_TIMESCALE),
    ("set_chunk_time_interval", R_TIMESCALE),
    ("set_integer_now_func", R_TIMESCALE),
    ("set_number_partitions", R_TIMESCALE),
    ("set_partitioning_interval", R_TIMESCALE),
    ("set_replication_factor", R_TIMESCALE),
    ("split_chunk", R_TIMESCALE),
    ("timescaledb_post_restore", R_TIMESCALE),
    ("timescaledb_pre_restore", R_TIMESCALE),
    ("heap_force_kill", R_RAW_PAGES),
    ("heap_force_freeze", R_RAW_PAGES),
    ("pg_truncate_visibility_map", R_RAW_PAGES),
    ("get_raw_page", R_RAW_PAGES),
    ("autoprewarm_dump_now", R_MAINTENANCE),
    ("autoprewarm_start_worker", R_MAINTENANCE),
    ("pg_logdir_ls", R_FILES),
    ("pg_background_launch", R_OTHER_SQL),
    ("pg_background_result", R_OTHER_SQL),
    ("pg_background_detach", R_OTHER_SQL),
    ("http", R_NETWORK),
    ("http_get", R_NETWORK),
    ("http_post", R_NETWORK),
    ("http_put", R_NETWORK),
    ("http_patch", R_NETWORK),
    ("http_delete", R_NETWORK),
    ("http_head", R_NETWORK),
    ("http_set_curlopt", R_NETWORK),
    ("http_reset_curlopt", R_NETWORK),
    ("postgres_fdw_disconnect", R_CONTROL),
    ("postgres_fdw_disconnect_all", R_CONTROL),
    ("hypopg_create_index", R_SESSION),
    ("hypopg_drop_index", R_SESSION),
    ("hypopg_reset", R_SESSION),
    ("hypopg_reset_index", R_SESSION),
    ("hypopg_hide_index", R_SESSION),
    ("hypopg_unhide_index", R_SESSION),
    ("hypopg_unhide_all_indexes", R_SESSION),
    ("pg_stat_kcache_reset", R_STATS),
    ("pg_qualstats_reset", R_STATS),
    ("pg_wait_sampling_reset_profile", R_STATS),
    ("pg_stat_monitor_reset", R_STATS),
    ("pgr_*", R_EXTENSION),
    ("read_log_file", R_LOG_HELPERS),
    ("list_log_files", R_LOG_HELPERS),
];

/// Functions that stay allowed even where a deny prefix would match them.
const ALLOWED_FUNCTIONS: &[&str] = &["pg_current_xact_id_if_assigned", "pg_stat_get_*", "lo_get"];

/// The function deny list as (name or `prefix*`, reason); the tests generate cases from it.
#[doc(hidden)]
pub fn denied_functions() -> &'static [(&'static str, &'static str)] {
    DENIED_FUNCTIONS
}

/// Checks one SQL string and accepts it only when it is a single read-only statement.
pub fn check(sql: &str, opts: &GateOptions) -> Result<Accepted, Rejection> {
    if sql.trim().is_empty() {
        return Err(reject("empty", "SQL text is empty."));
    }
    if sql.len() > opts.max_sql_bytes {
        let message = format!(
            "SQL text is {} bytes; the limit is {} bytes.",
            sql.len(),
            opts.max_sql_bytes
        );
        return Err(reject("too_long", message));
    }
    if sql.contains('\0') {
        return Err(reject("nul_byte", "SQL text contains a NUL byte."));
    }
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .stack_size(PARSE_STACK_BYTES)
            .spawn_scoped(scope, || analyse(sql, opts));
        match worker {
            Err(error) => Err(parse_failed(format!(
                "could not start the parser thread: {error}"
            ))),
            Ok(handle) => handle
                .join()
                .unwrap_or_else(|_| Err(parse_failed("internal parser failure"))),
        }
    })
}

/// Parses, serializes and walks the statement; runs on the big-stack thread.
fn analyse(sql: &str, opts: &GateOptions) -> Result<Accepted, Rejection> {
    let parsed = pg_query::parse(sql, pg_query::ParserOptions::DEFAULT).map_err(parse_error_of)?;
    let statement = match parsed.protobuf.stmts.as_slice() {
        [] => return Err(reject("empty", "SQL text is empty.")),
        [single] => single,
        many => {
            let message = format!("Send exactly one statement per call; found {}.", many.len());
            return Err(reject("multiple_statements", message));
        }
    };
    let Some(node) = statement.stmt.as_deref() else {
        return Err(malformed());
    };
    let tree = serde_json::to_value(node).map_err(|error| parse_failed(error.to_string()))?;
    let kind = classify(&tree)?;
    walk(&tree, opts)?;
    Ok(Accepted { kind })
}

fn classify(tree: &Value) -> Result<StatementKind, Rejection> {
    let Some((variant, body)) = node_of(tree) else {
        return Err(malformed());
    };
    match variant {
        "SelectStmt" => Ok(StatementKind::Select),
        "ExplainStmt" => classify_explain(body),
        "VariableShowStmt" => {
            let name = str_field(body, "name")
                .unwrap_or_default()
                .to_ascii_lowercase();
            Ok(StatementKind::Show { name })
        }
        other => Err(statement_not_allowed(other)),
    }
}

fn classify_explain(body: &Value) -> Result<StatementKind, Rejection> {
    let Some((inner, _)) = body.get("query").and_then(node_of) else {
        return Err(malformed());
    };
    if inner != "SelectStmt" {
        return Err(statement_not_allowed(inner));
    }
    let mut analyze = false;
    for option in items(body, "options") {
        let Some(("DefElem", def)) = node_of(option) else {
            return Err(malformed());
        };
        let name = str_field(def, "defname")
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !EXPLAIN_OPTIONS.contains(&name.as_str()) {
            return Err(reject(
                "explain_option",
                format!("EXPLAIN option {name} is not allowed."),
            ));
        }
        if name == "analyze" && !is_false_value(def.get("arg")) {
            analyze = true;
        }
    }
    Ok(StatementKind::Explain { analyze })
}

/// True for an explicit `false`, `off` or `0` option argument; a missing argument is not false.
fn is_false_value(arg: Option<&Value>) -> bool {
    let Some((variant, body)) = arg.and_then(node_of) else {
        return false;
    };
    match variant {
        "Boolean" => body.get("boolval").and_then(Value::as_bool) == Some(false),
        "Integer" => body.get("ival").and_then(Value::as_i64) == Some(0),
        "String" => str_field(body, "sval")
            .is_some_and(|s| matches!(s.to_ascii_lowercase().as_str(), "false" | "off" | "0")),
        _ => false,
    }
}

/// Visits every object and array of the tree without recursion.
fn walk(root: &Value, opts: &GateOptions) -> Result<(), Rejection> {
    let mut pending: Vec<(&Value, usize)> = vec![(root, 1)];
    while let Some((value, depth)) = pending.pop() {
        if depth > MAX_DEPTH {
            return Err(reject(
                "too_deep",
                "The query is nested too deeply for the read-only gate.",
            ));
        }
        match value {
            Value::Object(map) => {
                check_fields(map)?;
                if let Some((variant, body)) = node_of(value) {
                    check_node(variant, body, opts)?;
                }
                pending.extend(map.values().map(|child| (child, depth + 1)));
            }
            Value::Array(list) => pending.extend(list.iter().map(|child| (child, depth + 1))),
            _ => {}
        }
    }
    Ok(())
}

fn check_fields(map: &Map<String, Value>) -> Result<(), Rejection> {
    if map.get("into_clause").is_some_and(|value| !value.is_null()) {
        let message = "SELECT ... INTO creates a table and is not allowed. Remove the INTO clause.";
        return Err(reject("select_into", message));
    }
    if map
        .get("locking_clause")
        .and_then(Value::as_array)
        .is_some_and(|list| !list.is_empty())
    {
        let message =
            "FOR UPDATE / FOR SHARE takes row locks and is not allowed. Remove the locking clause.";
        return Err(reject("row_locking", message));
    }
    Ok(())
}

fn check_node(variant: &str, body: &Value, opts: &GateOptions) -> Result<(), Rejection> {
    if !ALLOWED_NODES.contains(&variant) {
        let message =
            format!("This query uses a construct the read-only gate does not allow: {variant}.");
        return Err(reject("node_not_allowed", message));
    }
    match variant {
        "ParamRef" if !opts.allow_placeholders => Err(reject(
            "placeholder",
            "Parameter placeholders ($1) are not supported. Inline the value.",
        )),
        "CommonTableExpr" => check_cte(body),
        "FuncCall" => check_function(body),
        "AIndirection" => check_indirection(body),
        "ColumnRef" => check_column_ref(body),
        "RangeVar" => check_relation(body),
        "VariableShowStmt" => check_setting(str_field(body, "name").unwrap_or_default()),
        _ => Ok(()),
    }
}

/// Only SELECT may appear in WITH; data-modifying statements get their own code.
fn check_cte(body: &Value) -> Result<(), Rejection> {
    match body.get("ctequery").and_then(node_of) {
        Some(("SelectStmt", _)) => Ok(()),
        Some(_) => {
            let message = "Data-modifying statements inside WITH (INSERT, UPDATE, DELETE, MERGE) are not allowed.";
            Err(reject("data_modifying_cte", message))
        }
        None => Err(malformed()),
    }
}

fn check_function(body: &Value) -> Result<(), Rejection> {
    let names: Vec<&str> = items(body, "funcname")
        .iter()
        .filter_map(node_of)
        .filter_map(|(variant, part)| {
            if variant == "String" {
                str_field(part, "sval")
            } else {
                None
            }
        })
        .collect();
    let Some(&last) = names.last() else {
        return Err(malformed());
    };
    let lowered = last.to_ascii_lowercase();
    let qualifier = names.iter().rev().nth(1).map(|q| q.to_ascii_lowercase());
    if qualifier.as_deref() == Some("cron") && CRON_JOB_FUNCTIONS.contains(&lowered.as_str()) {
        return Err(function_denied(last, R_CRON));
    }
    if qualifier.as_deref() == Some("pgmcp") {
        return Err(function_denied(last, R_LOG_HELPERS));
    }
    if let Some(qualifier) = qualifier.as_deref()
        && INTERNAL_SCHEMAS.contains(&qualifier)
    {
        return Err(function_denied(last, R_TIMESCALE_INTERNAL));
    }
    if let Some(reason) = deny_reason(&lowered) {
        return Err(function_denied(last, reason));
    }
    if lowered == "current_setting" {
        check_current_setting(body)?;
    }
    Ok(())
}

/// `(expr).name` calls name(expr) when no field has that name, so every name after the dot is checked.
fn check_indirection(body: &Value) -> Result<(), Rejection> {
    items(body, "indirection")
        .iter()
        .try_for_each(check_dotted_name)
}

/// `rel.name` calls name(rel) when rel has no column of that name; the last name is the one called.
fn check_column_ref(body: &Value) -> Result<(), Rejection> {
    let fields = items(body, "fields");
    if fields.len() < 2 {
        return Ok(());
    }
    fields.last().map_or(Ok(()), check_dotted_name)
}

/// Applies the function rules to one name after a dot; a non-string item is not a name.
fn check_dotted_name(part: &Value) -> Result<(), Rejection> {
    let Some(("String", body)) = node_of(part) else {
        return Ok(());
    };
    let Some(name) = str_field(body, "sval") else {
        return Ok(());
    };
    let lowered = name.to_ascii_lowercase();
    if let Some(reason) = deny_reason(&lowered) {
        return Err(dotted_denied(name, reason));
    }
    if lowered == "current_setting" {
        let message = "\"current_setting\" after a dot would call current_setting() with a computed name, which is not allowed. Use current_setting('name') with a literal name. If it is a column of yours, give it another name with AS in a subquery.";
        return Err(reject("setting_denied", message));
    }
    Ok(())
}

/// current_setting() takes a bare string literal naming the setting; the optional missing_ok may be any constant.
fn check_current_setting(body: &Value) -> Result<(), Rejection> {
    let args = items(body, "args");
    let literal = args.first().and_then(string_constant);
    let missing_ok_is_constant = args.get(1).is_none_or(is_constant);
    match literal {
        Some(name) if args.len() <= 2 && missing_ok_is_constant => check_setting(name),
        _ => {
            let message = "current_setting() takes a literal setting name here; computed names are not allowed.";
            Err(reject("setting_denied", message))
        }
    }
}

fn check_relation(body: &Value) -> Result<(), Rejection> {
    let relname = str_field(body, "relname")
        .unwrap_or_default()
        .to_ascii_lowercase();
    let schema = str_field(body, "schemaname")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if CREDENTIAL_RELATIONS.contains(&relname.as_str())
        && matches!(schema.as_str(), "" | "pg_catalog" | "information_schema")
    {
        let message = if SETTINGS_RELATIONS.contains(&relname.as_str()) {
            format!(
                "{relname} can expose credentials and is not readable through this server. Use the server_info tool for settings."
            )
        } else {
            format!(
                "Relation {relname} is not readable through this server. It can expose credentials."
            )
        };
        return Err(reject("relation_denied", message));
    }
    Ok(())
}

fn check_setting(name: &str) -> Result<(), Rejection> {
    let lowered = name.to_ascii_lowercase();
    if SECRET_SETTINGS.contains(&lowered.as_str()) {
        let message = format!(
            "The setting {lowered} can expose credentials or local paths and is not readable through this server. Use the server_info tool for settings."
        );
        return Err(reject("setting_denied", message));
    }
    Ok(())
}

fn deny_reason(name: &str) -> Option<&'static str> {
    if ALLOWED_FUNCTIONS
        .iter()
        .any(|pattern| matches_pattern(pattern, name))
    {
        return None;
    }
    DENIED_FUNCTIONS
        .iter()
        .find(|entry| matches_pattern(entry.0, name))
        .map(|entry| entry.1)
}

fn matches_pattern(pattern: &str, name: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => pattern == name,
    }
}

fn dotted_denied(name: &str, reason: &str) -> Rejection {
    let message = format!(
        "\"{name}\" after a dot would call the function {name}(), which is not allowed: {reason}. If it is a column of yours, give it another name with AS in a subquery."
    );
    reject("function_denied", message)
}

fn function_denied(name: &str, reason: &str) -> Rejection {
    reject(
        "function_denied",
        format!("Function {name}() is not allowed: {reason}."),
    )
}

/// Human name of a top-level statement variant, used in the rejection message.
fn statement_kind_name(variant: &str) -> String {
    let known = match variant {
        "InsertStmt" => "INSERT",
        "UpdateStmt" => "UPDATE",
        "DeleteStmt" => "DELETE",
        "MergeStmt" => "MERGE",
        "VariableSetStmt" => "SET",
        "TransactionStmt" => "transaction control",
        "CopyStmt" => "COPY",
        "DoStmt" => "DO",
        "CallStmt" => "CALL",
        "CreateStmt" | "CreateTableAsStmt" => "CREATE",
        "DropStmt" => "DROP",
        "AlterTableStmt" => "ALTER",
        "TruncateStmt" => "TRUNCATE",
        "GrantStmt" | "GrantRoleStmt" => "GRANT/REVOKE",
        "ListenStmt" => "LISTEN",
        "NotifyStmt" => "NOTIFY",
        "PrepareStmt" => "PREPARE",
        "ExecuteStmt" => "EXECUTE",
        "DeclareCursorStmt" => "DECLARE",
        "FetchStmt" => "FETCH",
        "LockStmt" => "LOCK",
        "DiscardStmt" => "DISCARD",
        "VacuumStmt" => "VACUUM/ANALYZE",
        "RefreshMatViewStmt" => "REFRESH MATERIALIZED VIEW",
        "SecLabelStmt" => "SECURITY LABEL",
        other => {
            return other
                .strip_suffix("Stmt")
                .unwrap_or(other)
                .to_ascii_uppercase();
        }
    };
    known.to_string()
}

fn statement_not_allowed(variant: &str) -> Rejection {
    let message = format!(
        "Only read-only statements are accepted (SELECT, WITH, VALUES, TABLE, EXPLAIN, SHOW). This is a {} statement.",
        statement_kind_name(variant)
    );
    reject("statement_not_allowed", message)
}

fn parse_error_of(error: pg_query::Error) -> Rejection {
    match error {
        pg_query::Error::Parse(message) => {
            reject("parse_error", format!("SQL syntax error: {message}"))
        }
        other => parse_failed(other.to_string()),
    }
}

fn parse_failed(detail: impl std::fmt::Display) -> Rejection {
    reject("parse_error", format!("SQL could not be parsed: {detail}"))
}

fn malformed() -> Rejection {
    parse_failed("unexpected parse tree")
}

fn reject(code: &'static str, message: impl Into<String>) -> Rejection {
    Rejection {
        code,
        message: message.into(),
    }
}

/// Returns the variant name and body of a `{"node": {"Variant": body}}` wrapper.
fn node_of(wrapper: &Value) -> Option<(&str, &Value)> {
    let map = wrapper.as_object()?;
    if map.len() != 1 {
        return None;
    }
    let inner = map.get("node")?.as_object()?;
    if inner.len() != 1 {
        return None;
    }
    let (variant, body) = inner.iter().next()?;
    Some((variant.as_str(), body))
}

fn items<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    match value.get(key) {
        Some(Value::Array(list)) => list.as_slice(),
        _ => &[],
    }
}

fn str_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

/// True for a literal constant node such as 'x', 1, true or NULL.
fn is_constant(arg: &Value) -> bool {
    node_of(arg).is_some_and(|(variant, _)| variant == "AConst")
}

/// The string of a string-literal argument, such as `'work_mem'`.
fn string_constant(arg: &Value) -> Option<&str> {
    let (variant, body) = node_of(arg)?;
    if variant != "AConst" {
        return None;
    }
    str_field(body.get("val")?.get("Sval")?, "sval")
}
