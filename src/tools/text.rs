//! Every string an MCP client reads: tool titles, descriptions and server instructions.
//! Changing a tool's behaviour means changing its text here and in README.md.

pub const DATABASE_PARAM: &str = "Name of a configured database connection, as returned by list_databases. \
     Optional when exactly one database is configured.";

pub const LIST_DATABASES_TITLE: &str = "List databases";
pub const LIST_DATABASES: &str = "List the database connections this server is configured for. For each one: its name (the value \
     every other tool takes as 'database'), whether it is reachable, the PostgreSQL version, and whether \
     TimescaleDB is installed. Connection details and credentials are never returned.";

pub const EXECUTE_QUERY_TITLE: &str = "Run a read-only SQL query";
pub const EXECUTE_QUERY: &str = "Run ONE read-only SQL statement and return its rows.\n\
     ACCEPTED: SELECT (including WITH, set operations, VALUES and TABLE), EXPLAIN of such a statement, \
     and SHOW. One trailing ';' is fine.\n\
     REJECTED before it runs: anything that writes or changes state (INSERT, UPDATE, DELETE, MERGE, DDL, \
     SET, COPY, DO, CALL, LISTEN/NOTIFY, PREPARE/EXECUTE, transaction control), SELECT ... INTO, \
     FOR UPDATE/FOR SHARE, data-modifying CTEs, more than one statement, $1 placeholders, and functions \
     with side effects (nextval, set_config, pg_advisory_lock, pg_terminate_backend, dblink, \
     query_to_xml, lo_import, pg_read_file and similar). The rejection message names the construct. \
     Catalogs that hold credentials (pg_authid, pg_shadow, pg_settings) are not readable here; use \
     server_info for settings. The statistics views pg_stats, pg_stats_ext and pg_stats_ext_exprs never \
     return rows for the catalogs that hold credentials. Name them directly in FROM or JOIN; a correlated subquery over one scans the whole view once per outer row.\n\
     The statement runs in a READ ONLY transaction that is always rolled back, under a server-side \
     time limit. Each call is independent: no session state survives between calls.\n\
     ROWS: at most the server row cap is returned (default 1000). Apart from the statistics views named above, the SQL runs as written. \
     \"truncated\": true means more rows existed or the response size budget was reached; add a LIMIT, \
     aggregate, or select fewer columns. Use ORDER BY for a stable page.\n\
     RESULT: {database, columns, rows, rowCount, truncated, truncatedReason?, truncatedValues, \
     rawFallbacks, redactedHashes, executionTimeMs}.\n\
     - columns: [{name, type, typeOid, originalName?}] in SELECT order, present even with zero rows. \
     rows: one {column: value} object per row. Duplicate column names become \"id__2\", \"id__3\" with \
     originalName set.\n\
     VALUES:\n\
     - boolean: true/false. smallint, integer, oid: number.\n\
     - bigint (and COUNT(*)): number while |v| <= 9007199254740991, otherwise an exact decimal string.\n\
     - numeric/decimal: ALWAYS a string with exact digits and scale (\"1.50\"); also \"NaN\", \
     \"Infinity\", \"-Infinity\". Parse before doing arithmetic.\n\
     - real, double precision: number; \"NaN\", \"Infinity\", \"-Infinity\" as strings.\n\
     - date, time, timestamp: ISO strings (\"2024-02-29 13:00:00.123456\"). timestamptz is always \
     shown in UTC and ends in \"+00\". \"infinity\", \"-infinity\" and a \" BC\" suffix can appear.\n\
     - interval: ISO 8601 duration (\"P1Y2M3DT4H5M6.789S\"; parts can be negative, \"P-1M2DT-3H\").\n\
     - json, jsonb: inlined as real JSON, numbers kept exact. A json value with duplicate keys comes \
     back as its original text.\n\
     - arrays: nested JSON arrays with elements encoded by the same rules, NULL as null. An array \
     with non-default lower bounds is {\"lowerBounds\": [...], \"elements\": [...]}.\n\
     - ranges: {\"lower\", \"upper\", \"lowerInc\", \"upperInc\"} (null bound = unbounded) or \
     {\"empty\": true}; multiranges are arrays of those.\n\
     - bytea: \"\\x\" followed by hex, capped with a truncation marker.\n\
     - everything else (uuid, inet, money, enum, composite, geometric, tsvector, hstore, vector, \
     PostGIS geometry, any extension type): the text PostgreSQL itself prints. A domain is encoded \
     as its base type. Use to_jsonb(col), \
     ST_AsGeoJSON(col) or col::text when you want another shape.\n\
     - Oversized text is cut and ends with \"…[truncated: X of Y bytes]\"; truncatedValues counts \
     them. Re-query with substr() for the rest. rawFallbacks counts values returned as raw text \
     because they did not parse as their type. SQL NULL is null. Text shaped like a PostgreSQL password hash is replaced with [redacted password hash] in every result, and redactedHashes counts the replacements.";

pub const EXECUTE_QUERY_SQL_PARAM: &str = "One read-only SQL statement: SELECT, WITH, VALUES, TABLE, EXPLAIN or SHOW. No placeholders; \
     inline the values.";

pub fn server_instructions(databases: &[String]) -> String {
    format!(
        "Read-only access to {} PostgreSQL database(s): {}. Nothing here can write: every statement runs \
         in a READ ONLY transaction that is rolled back. Start with list_databases, then search_schema \
         or list_objects to find tables, describe_table for columns, keys and comments, and \
         execute_query for SQL. Every tool takes a 'database' name (optional when only one is \
         configured). Read execute_query's description before interpreting values: numeric is always a \
         string, bigint becomes a string past 2^53-1, timestamptz is UTC, and results are capped \
         (check 'truncated'). Monitoring tools (list_activity, query_stats, read_server_log) and \
         TimescaleDB tools report what is missing when a grant or extension is absent.",
        databases.len(),
        databases.join(", ")
    )
}

pub const LIMIT_PARAM: &str = "Maximum number of entries to return (default 100, at most 500).";
pub const CURSOR_PARAM: &str =
    "Opaque cursor from a previous call's nextCursor, to fetch the next page.";
pub const SCHEMA_PARAM: &str = "Schema name. Omit to cover every schema except the system ones.";

pub const SERVER_INFO_TITLE: &str = "Server and connection info";
pub const SERVER_INFO: &str = "Describe one database server as this connection sees it: PostgreSQL version, uptime, whether it is a \
     replica, database name, encoding and size, the connected role with its attributes and role \
     memberships, installed extensions with versions (and newer versions available), TimescaleDB version if \
     present, and a set of settings relevant to reading data (timeouts, time zone, search_path, logging). \
     Settings that can hold credentials are never shown. Call this first when you need to know what the \
     server supports.";

pub const EXPLAIN_QUERY_TITLE: &str = "Explain a query plan";
pub const EXPLAIN_QUERY: &str = "Return PostgreSQL's execution plan for ONE read-only statement (the same statements execute_query \
     accepts; pass the bare query without the EXPLAIN keyword). Options: format (text, json, yaml, xml), \
     analyze, buffers, verbose, settings, wal, memory, serialize and generic_plan; options the server \
     version does not have are reported, not silently dropped. analyze=true really executes the query, \
     inside the same rolled-back READ ONLY transaction and time limit, and returns actual timings. \
     generic_plan=true lets the query contain $1 placeholders. The plan is returned as text, or as parsed \
     JSON when format is json.";

pub const LIST_SCHEMAS_TITLE: &str = "List schemas";
pub const LIST_SCHEMAS: &str = "List the schemas of a database with owner, comment, and how many tables, views and functions \
     each holds. System schemas (pg_catalog, information_schema, pg_toast, TimescaleDB internals) are left \
     out unless include_system is true.";

pub const LIST_OBJECTS_TITLE: &str = "List tables, views and other objects";
pub const LIST_OBJECTS: &str = "List objects in a database, optionally limited to one schema and to some kinds: table, \
     partitioned_table, view, materialized_view, foreign_table, sequence, function, procedure, type (enums, \
     domains, composites, ranges). Each entry has schema, name, kind, owner and comment. Tables and \
     materialized views add an estimated row count (the planner's estimate, not an exact count; -1 means \
     never analyzed) and total size in bytes; partitions name their parent; functions show their \
     arguments and return type; enums list their labels. Paged: pass nextCursor back as cursor.";

pub const DESCRIBE_TABLE_TITLE: &str = "Describe a table or view";
pub const DESCRIBE_TABLE: &str = "Full definition of one table, partitioned table, view, materialized view or foreign table. \
     Give 'table' as a bare name with 'schema', or as schema.name; a bare name found in several schemas \
     is an error that lists them. Returns: columns in order (type, \
     nullability, default, identity, generated expression, collation, comment), primary key, unique and \
     check constraints, foreign keys in both directions (what it references and what references it), \
     indexes (definition, uniqueness, validity, size, number of scans), triggers, row-level security \
     policies, partitioning (key, parent, and up to 200 partitions, with partitionsTruncated when there \
     are more), inheritance, the view definition for views, owner, \
     comment, sizes in bytes, the estimated row count and when it was last vacuumed and analyzed. A section \
     the role may not read is null with a matching '<section>Error', never silently empty.";

pub const DESCRIBE_FUNCTION_TITLE: &str = "Describe a function or procedure";
pub const DESCRIBE_FUNCTION: &str = "Details of the functions or procedures with a given name (all overloads): argument names and \
     types, return type, language, volatility, parallel safety, strictness, SECURITY DEFINER, owner, \
     comment, and the source text when the role may read it.";

pub const SEARCH_SCHEMA_TITLE: &str = "Search the schema by name or comment";
pub const SEARCH_SCHEMA: &str = "Find tables, views, columns and functions whose name or comment contains the given text \
     (case-insensitive). Use it to locate where a concept lives before describing a table, e.g. query \
     'invoice' or 'email'. Each hit names the object, its kind, where the text matched (name or comment) \
     and, for columns, the column's type. System schemas are excluded.";

pub const GET_PRIVILEGES_TITLE: &str = "What this connection may read";
pub const GET_PRIVILEGES: &str = "Report what the connected role is allowed to do: role attributes, the predefined roles it is a \
     member of (pg_read_all_data, pg_monitor, ...), per-schema USAGE, a count of tables it can and cannot \
     SELECT per schema, and which monitoring features will work (other sessions' query text, \
     pg_stat_statements, the server log reader) with the exact GRANT that is missing when one will not. \
     Also flags anything beyond read access (ability to write, create, or superuser), which a read-only \
     deployment should not have.";

pub const LIST_ACTIVITY_TITLE: &str = "Current sessions and locks";
pub const LIST_ACTIVITY: &str = "Show what the server is doing now, from pg_stat_activity: each session's pid, user, database, \
     application, client address, state, wait event, how long its transaction and current query have been \
     running, the query text (cut to a preview), and blocked_by: the pids holding locks it waits for. \
     Filter by state, minimum duration or user; all_databases widens it beyond the current database; \
     set only_blocked to see lock waits and their blockers. Background workers are left out unless include_background is true. Without \
     pg_read_all_stats (or pg_monitor) PostgreSQL hides other users' query text, application and state, \
     which then show as null. Passwords in query text are masked on a best-effort basis.";

pub const QUERY_STATS_TITLE: &str = "Statement statistics";
pub const QUERY_STATS: &str = "Top statements from pg_stat_statements: normalized query text, calls, total and mean execution \
     time, rows, shared blocks hit and read, and temp blocks written. order_by chooses the ranking \
     (total_time, mean_time, calls, rows, io, temp); min_calls and contains narrow it, and all_databases \
     includes statements from other databases. Reports clearly when the extension is not installed, not \
     in shared_preload_libraries, or when the role may not see other users' statements.";

pub const DATABASE_STATS_TITLE: &str = "Database and server statistics";
pub const DATABASE_STATS: &str = "Cumulative statistics, one section per call or several at once: database (commits, rollbacks, \
     deadlocks, conflicts, temp files, cache hit ratio, sessions), io (pg_stat_io, PostgreSQL 16+), wal, \
     checkpointer (bgwriter on older versions), progress (running VACUUM, ANALYZE, CREATE INDEX, COPY, base \
     backup) and wait_events (what active sessions wait on). A section the server version or the role's \
     grants do not provide is returned as unavailable with the reason. On PostgreSQL 17 and newer each wait event carries its description.";

pub const TABLE_STATS_TITLE: &str = "Table and index usage statistics";
pub const TABLE_STATS: &str = "Per-table activity from pg_stat_user_tables and pg_statio_user_tables: sequential and index \
     scans, rows inserted, updated and deleted since the last reset, live and dead row estimates, last \
     vacuum and analyze times, sizes, and each index's scan count (unused indexes have 0). Limit it to a \
     schema or a table; order_by picks the ranking (size, seq_scan, idx_scan, dead_rows, writes, last_autovacuum).";

pub const REPLICATION_STATUS_TITLE: &str = "Replication status";
pub const REPLICATION_STATUS: &str = "Replication state of this server: whether it is in recovery, connected standbys with their lag, \
     replication slots and how much WAL they retain, the WAL receiver when this is a standby, and logical \
     subscriptions and publications. Connection strings are never returned. replayLagSeconds is the time since the last replayed transaction and is null when the standby has replayed everything it received.";

pub const READ_SERVER_LOG_TITLE: &str = "Read the PostgreSQL server log";
pub const READ_SERVER_LOG: &str = "Read entries from the PostgreSQL server log files, newest first. Without filters it returns the \
     latest entries; filter with since/until (ISO timestamps), min_severity (DEBUG, INFO, NOTICE, WARNING, \
     ERROR, FATAL, PANIC), contains (case-insensitive text), entry_database, user and pid. Each entry has \
     timestamp, severity, message and, when the log format provides them, user, database, pid, SQLSTATE, \
     detail, hint and the statement. jsonlog and csvlog files are parsed into fields; plain stderr logs are \
     returned line by line with the severity parsed from the line prefix when possible. Set list_files to \
     see the log files and the logging settings instead of entries. Paged with nextCursor; one call scans \
     a bounded amount of log, so 'scannedToEnd': false with zero entries means: continue with the cursor. \
     pgaudit entries live in this log: use contains 'AUDIT:'. Requires the setup function \
     pgmcp.read_log_file (see README) and logging_collector = on; when either is missing the result says \
     exactly what to change. Passwords in logged statements are masked on a best-effort basis.";

pub const LIST_HYPERTABLES_TITLE: &str = "List TimescaleDB hypertables";
pub const LIST_HYPERTABLES: &str = "List TimescaleDB hypertables with their time dimension, chunk interval, number of chunks, \
     whether the columnstore (compression) is enabled, total size, approximate row count and comment. \
     Returns timescaledb: false with a note when the extension is not installed in this database.";

pub const DESCRIBE_HYPERTABLE_TITLE: &str = "Describe a TimescaleDB hypertable";
pub const DESCRIBE_HYPERTABLE: &str = "One hypertable in detail: dimensions, chunk interval, columnstore settings (segment by, order \
     by) and size before and after conversion, the policies attached to it (columnstore, retention, \
     reorder, refresh), and its chunks with time range, size and whether each is in the columnstore \
     (newest first, paged). Use describe_table for its columns and indexes.";

pub const LIST_CAGGS_TITLE: &str = "List TimescaleDB continuous aggregates";
pub const LIST_CAGGS: &str = "List continuous aggregates: the view, the hypertable it reads, its defining query, whether it is \
     real-time (materialized_only false) or materialized only, its refresh policy (schedule, start and end \
     offsets), and the watermark up to which data is materialized.";

pub const LIST_JOBS_TITLE: &str = "TimescaleDB jobs and their history";
pub const LIST_JOBS: &str = "TimescaleDB background jobs (policies and custom jobs): procedure, schedule, configuration, next \
     start, last run status, and totals of runs, successes and failures. Set history to true (optionally \
     with job_id and only_failures) to get recent runs with start, finish, duration, and the SQLSTATE and \
     error message of failed ones.";

pub const NOT_INSTALLED_TIMESCALE: &str = "TimescaleDB is not installed in this database. Hypertable and job tools need the timescaledb \
     extension; ordinary tables are available through list_objects and describe_table.";

// Parameter descriptions moved from the tool modules; each is one client-facing string.
pub const READ_SERVER_LOG_LIST_FILES_PARAM: &str =
    "Return the log files and logging settings instead of log entries.";
pub const READ_SERVER_LOG_SINCE_PARAM: &str =
    "Only entries at or after this time (ISO 8601, e.g. 2026-01-31T14:00:00Z).";
pub const READ_SERVER_LOG_UNTIL_PARAM: &str = "Only entries before this time (ISO 8601).";
pub const READ_SERVER_LOG_MIN_SEVERITY_PARAM: &str = "Lowest severity to return: DEBUG, INFO, NOTICE, WARNING, ERROR, FATAL or PANIC. LOG lines rank as INFO.";
pub const READ_SERVER_LOG_CONTAINS_PARAM: &str =
    "Case-insensitive text that must appear in the message, detail or statement.";
pub const READ_SERVER_LOG_USER_PARAM: &str =
    "Only entries of this database role (structured formats only).";
pub const READ_SERVER_LOG_ENTRY_DATABASE_PARAM: &str =
    "Only entries of this database name (structured formats only).";
pub const READ_SERVER_LOG_PID_PARAM: &str = "Only entries of this backend process id.";
pub const READ_SERVER_LOG_FILE_PARAM: &str =
    "Read this log file instead of the newest ones (a name from list_files).";
pub const DESCRIBE_HYPERTABLE_HYPERTABLE_PARAM: &str = "Hypertable name, bare or as schema.name.";
pub const DESCRIBE_HYPERTABLE_SCHEMA_PARAM: &str =
    "Schema of the hypertable. Optional when the name is unique.";
pub const DESCRIBE_HYPERTABLE_CHUNK_LIMIT_PARAM: &str =
    "Chunks to list, newest first (default 20, at most 500).";
pub const DESCRIBE_HYPERTABLE_CHUNK_CURSOR_PARAM: &str =
    "Cursor from a previous call's nextChunkCursor.";
pub const LIST_JOBS_JOB_ID_PARAM: &str = "Only this job.";
pub const LIST_JOBS_HISTORY_PARAM: &str = "Return recent runs instead of the job list.";
pub const LIST_JOBS_ONLY_FAILURES_PARAM: &str = "With history: only failed runs.";
pub const LIST_ACTIVITY_STATE_PARAM: &str = "Only sessions in this state: active, idle, idle in transaction, idle in transaction (aborted).";
pub const LIST_ACTIVITY_MIN_DURATION_MS_PARAM: &str = "Only sessions whose current query (or transaction, when idle in transaction) has run at least this long.";
pub const LIST_ACTIVITY_USER_PARAM: &str = "Only sessions of this role.";
pub const LIST_ACTIVITY_ALL_DATABASES_PARAM: &str = "Include sessions connected to other databases of the server. Default false: this database only.";
pub const LIST_ACTIVITY_ONLY_BLOCKED_PARAM: &str =
    "Only sessions waiting on a lock, plus the sessions blocking them.";
pub const LIST_ACTIVITY_INCLUDE_BACKGROUND_PARAM: &str = "Include background workers (autovacuum, WAL writer, extension workers). Default false: client backends only.";
pub const LIST_ACTIVITY_QUERY_CHARS_PARAM: &str =
    "Characters of query text to return per session, 0 to 4000. Default 500.";
pub const QUERY_STATS_ORDER_BY_PARAM: &str = "Ranking: total_time (default), mean_time, calls, rows, io (blocks read), temp (temp blocks written).";
pub const QUERY_STATS_MIN_CALLS_PARAM: &str = "Only statements called at least this many times.";
pub const QUERY_STATS_CONTAINS_PARAM: &str = "Case-insensitive text the statement must contain.";
pub const QUERY_STATS_ALL_DATABASES_PARAM: &str =
    "Include statements from other databases. Default false.";
pub const QUERY_STATS_QUERY_CHARS_PARAM: &str =
    "Characters of statement text per entry, 0 to 4000. Default 500.";
pub const QUERY_STATS_LIMIT_PARAM: &str =
    "Maximum number of statements to return (default 20, at most 500).";
pub const DATABASE_STATS_SECTIONS_PARAM: &str = "Sections to return: database, io, wal, checkpointer, progress, wait_events. Default: database, checkpointer and progress.";
pub const TABLE_STATS_TABLE_PARAM: &str = "Only this table (bare name, combine with schema).";
pub const TABLE_STATS_ORDER_BY_PARAM: &str =
    "Ranking: size (default), seq_scan, idx_scan, dead_rows, writes, last_autovacuum.";
pub const TABLE_STATS_INCLUDE_INDEXES_PARAM: &str = "Add each table's indexes with their scan counts and sizes. Default true when a single table is requested, else false.";
pub const TABLE_STATS_UNUSED_INDEXES_PARAM: &str = "Return only indexes never scanned since the last statistics reset (primary keys and unique indexes excluded).";
pub const EXPLAIN_QUERY_SQL_PARAM: &str = "The statement to explain, without the EXPLAIN keyword.";
pub const EXPLAIN_QUERY_FORMAT_PARAM: &str = "Plan format: text (default), json, yaml or xml.";
pub const EXPLAIN_QUERY_ANALYZE_PARAM: &str =
    "Execute the statement and report actual times and row counts.";
pub const EXPLAIN_QUERY_BUFFERS_PARAM: &str = "Include shared, local and temporary buffer usage.";
pub const EXPLAIN_QUERY_VERBOSE_PARAM: &str = "Include output columns and schema-qualified names.";
pub const EXPLAIN_QUERY_SETTINGS_PARAM: &str =
    "Include configuration settings that differ from the defaults (PostgreSQL 12 or newer).";
pub const EXPLAIN_QUERY_WAL_PARAM: &str =
    "Include WAL usage; needs analyze (PostgreSQL 13 or newer).";
pub const EXPLAIN_QUERY_MEMORY_PARAM: &str =
    "Include planner memory usage (PostgreSQL 17 or newer).";
pub const EXPLAIN_QUERY_SERIALIZE_PARAM: &str =
    "Measure the time to convert the output for transfer; needs analyze (PostgreSQL 17 or newer).";
pub const EXPLAIN_QUERY_GENERIC_PLAN_PARAM: &str = "Plan with generic parameters so the statement may contain $1 placeholders (PostgreSQL 16 or newer); not with analyze.";

pub const RESOURCE_DATABASE_TITLE: &str = "Database";
pub const RESOURCE_DATABASE_DESCRIPTION: &str = "Summary of this database: PostgreSQL version, TimescaleDB version when installed, schemas with their object counts, and installed extensions.";
pub const RESOURCE_SCHEMA_TITLE: &str = "Schema";
pub const RESOURCE_SCHEMA_DESCRIPTION: &str = "Tables, views, materialized views, sequences and functions of one schema, with comments, estimated rows and sizes. Same content as the list_objects tool.";
pub const RESOURCE_TABLE_TITLE: &str = "Table or view";
pub const RESOURCE_TABLE_DESCRIPTION: &str = "Full definition of one table or view: columns, keys, indexes, policies and statistics. Same content as the describe_table tool.";
pub const UNKNOWN_RESOURCE_URI: &str = "Unknown resource URI. Use postgres://<database>, postgres://<database>/<schema> or postgres://<database>/<schema>/<table>.";
