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
     server_info for settings.\n\
     The statement runs in a READ ONLY transaction that is always rolled back, under a server-side \
     time limit. Each call is independent: no session state survives between calls.\n\
     ROWS: at most the server row cap is returned (default 1000) and the SQL is not rewritten. \
     \"truncated\": true means more rows existed or the response size budget was reached; add a LIMIT, \
     aggregate, or select fewer columns. Use ORDER BY for a stable page.\n\
     RESULT: {database, columns, rows, rowCount, truncated, truncatedReason?, truncatedValues, \
     rawFallbacks, executionTimeMs}.\n\
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
     - interval: ISO 8601 duration (\"P1Y2M3DT4H5M6S\").\n\
     - json, jsonb: inlined as real JSON, numbers kept exact. A json value with duplicate keys comes \
     back as its original text.\n\
     - arrays: nested JSON arrays with elements encoded by the same rules, NULL as null. An array \
     with non-default lower bounds is {\"lowerBounds\": [...], \"elements\": [...]}.\n\
     - ranges: {\"lower\", \"upper\", \"lowerInc\", \"upperInc\"} (null bound = unbounded) or \
     {\"empty\": true}; multiranges are arrays of those.\n\
     - bytea: \"\\x\" followed by hex, capped with a truncation marker.\n\
     - everything else (uuid, inet, money, enum, composite, geometric, tsvector, hstore, vector, \
     PostGIS geometry, any extension type): the text PostgreSQL itself prints. Use to_jsonb(col), \
     ST_AsGeoJSON(col) or col::text when you want another shape.\n\
     - Oversized text is cut and ends with \"…[truncated: X of Y bytes]\"; truncatedValues counts \
     them. Re-query with substr() for the rest. rawFallbacks counts values returned as raw text \
     because they did not parse as their type. SQL NULL is null.";

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
