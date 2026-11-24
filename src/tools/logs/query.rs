//! Database access for read_server_log: setup check, file listing, logging settings, time bounds and chunk reads.

use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::parse::Format;
use crate::pg::wire::FetchLimits;
use crate::server::AppState;
use crate::tools::{Runner, Statement, ToolError};

/// Bytes requested per read_log_file call.
pub const READ_LEN: usize = 1_048_576;

/// Three log reader flags in one select list: installed, allowed, authentic. The functions are found in pg_proc,
/// so a role without USAGE on pgmcp gets false, not an error. read_server_log and get_privileges both use it.
pub fn log_reader_flags() -> String {
    let read = "(SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
        WHERE n.nspname = 'pgmcp' AND p.proname = 'read_log_file' AND p.proargtypes::text = '25 20 23')";
    let list = "(SELECT p.oid FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
        WHERE n.nspname = 'pgmcp' AND p.proname = 'list_log_files' AND p.proargtypes::text = '')";
    format!(
        "COALESCE({read} IS NOT NULL AND {list} IS NOT NULL, false) AS installed, \
        COALESCE(has_schema_privilege(pg_catalog.to_regnamespace('pgmcp')::oid, 'USAGE') \
        AND has_function_privilege({read}, 'EXECUTE') AND has_function_privilege({list}, 'EXECUTE'), false) AS allowed, \
        COALESCE((SELECT bool_and(p.prosecdef AND (o.rolname = 'pgmcp_log_reader' OR o.rolsuper)) \
        FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_roles o ON o.oid = p.proowner \
        WHERE p.oid IN ({read}, {list})), false) AS authentic"
    )
}

fn setup_sql() -> String {
    format!(
        "SELECT {}, pg_catalog.current_user() AS role",
        log_reader_flags()
    )
}
const FILES_SQL: &str = "SELECT l.name AS name, l.size AS size, l.modification::text AS modified \
    FROM pgmcp.list_log_files() AS l ORDER BY l.modification DESC, l.name DESC";
const BOUNDS_SQL: &str = "SELECT \
    pg_catalog.to_char($1::timestamptz AT TIME ZONE pg_catalog.current_setting('log_timezone'), 'YYYY-MM-DD HH24:MI:SS.MS') AS since_bound, \
    pg_catalog.to_char($2::timestamptz AT TIME ZONE pg_catalog.current_setting('log_timezone'), 'YYYY-MM-DD HH24:MI:SS.MS') AS until_bound";
const BOUND_SQL: &str = "SELECT \
    pg_catalog.to_char($1::timestamptz AT TIME ZONE pg_catalog.current_setting('log_timezone'), 'YYYY-MM-DD HH24:MI:SS.MS') AS bound";
const READ_SQL: &str = "SELECT pgmcp.read_log_file($1::text, $2::bigint, $3::int)";
const SETTINGS_SQL: &str = "SELECT s.name::text AS name, pg_catalog.current_setting(s.name) AS value \
    FROM pg_catalog.pg_settings AS s WHERE s.name = ANY($1::text[])";

/// Logging settings reported by list_files: (setting name, result key).
pub const SETTINGS: &[(&str, &str)] = &[
    ("logging_collector", "loggingCollector"),
    ("log_destination", "logDestination"),
    ("log_directory", "logDirectory"),
    ("log_filename", "logFilename"),
    ("log_timezone", "logTimezone"),
    ("log_line_prefix", "logLinePrefix"),
    ("log_min_duration_statement", "logMinDurationStatement"),
    ("log_statement", "logStatement"),
    ("log_min_messages", "logMinMessages"),
    ("log_connections", "logConnections"),
];

/// Whether the log reader functions exist and the connected role may run them.
pub struct Setup {
    pub installed: bool,
    /// Both functions are SECURITY DEFINER and owned by pgmcp_log_reader or a superuser.
    pub authentic: bool,
    pub allowed: bool,
    pub role: String,
}

/// One file in the log directory.
#[derive(Debug, Clone)]
pub struct LogFile {
    pub name: String,
    pub size: u64,
    pub modified: String,
    pub format: Format,
}

pub async fn setup(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Setup, ToolError> {
    let envelope = Runner::new(state)
        .internal_query(database, &setup_sql(), &[], ct)
        .await?;
    let row = envelope
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no setup row".to_owned()))?;
    Ok(Setup {
        installed: flag(row, "installed"),
        authentic: flag(row, "authentic"),
        allowed: flag(row, "allowed"),
        role: text_of(row, "role").unwrap_or_default(),
    })
}

/// The files in the log directory, newest first.
pub async fn files(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Vec<LogFile>, ToolError> {
    let envelope = Runner::new(state)
        .internal_query(database, FILES_SQL, &[], ct)
        .await?;
    Ok(envelope
        .rows
        .iter()
        .filter_map(|row| {
            let name = text_of(row, "name")?;
            let format = Format::of_file(&name);
            Some(LogFile {
                size: row.get("size").and_then(Value::as_u64).unwrap_or_default(),
                modified: text_of(row, "modified").unwrap_or_default(),
                format,
                name,
            })
        })
        .collect())
}

/// The logging settings, each as its text value or null when the role cannot read it.
/// pg_settings lists only the settings this role may examine, so restricted ones are never passed to current_setting.
pub async fn settings(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Map<String, Value>, ToolError> {
    let names = format!(
        "{{{}}}",
        SETTINGS
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(",")
    );
    let envelope = Runner::new(state)
        .internal_query(database, SETTINGS_SQL, &[Some(names.as_str())], ct)
        .await?;
    let mut out = Map::new();
    for (name, key) in SETTINGS {
        let value = envelope
            .rows
            .iter()
            .find(|row| text_of(row, "name").as_deref() == Some(name))
            .and_then(|row| row.get("value").cloned())
            .unwrap_or(Value::Null);
        out.insert((*key).to_owned(), value);
    }
    Ok(out)
}

/// The `since` and `until` bounds as they compare with entry timestamps; each None when not given.
pub async fn bounds(
    state: &AppState,
    database: Option<&str>,
    since: Option<&str>,
    until: Option<&str>,
    ct: &CancellationToken,
) -> Result<(Option<String>, Option<String>), ToolError> {
    let runner = Runner::new(state);
    let both = runner
        .internal_query(database, BOUNDS_SQL, &[since, until], ct)
        .await;
    match both {
        Ok(envelope) => {
            let row = envelope.rows.first();
            Ok((
                row.and_then(|r| text_of(r, "since_bound"))
                    .filter(|_| since.is_some()),
                row.and_then(|r| text_of(r, "until_bound"))
                    .filter(|_| until.is_some()),
            ))
        }
        Err(ToolError::Db(_)) => {
            // Attribute the error to the bound that is not a valid timestamp.
            let since_bound = match since {
                Some(value) => Some(one_bound(state, database, value, ct).await.map_err(|_| {
                    ToolError::Rejected("since is not a valid timestamp.".to_owned())
                })?),
                None => None,
            };
            let until_bound = match until {
                Some(value) => Some(one_bound(state, database, value, ct).await.map_err(|_| {
                    ToolError::Rejected("until is not a valid timestamp.".to_owned())
                })?),
                None => None,
            };
            Ok((since_bound, until_bound))
        }
        Err(other) => Err(other),
    }
}

async fn one_bound(
    state: &AppState,
    database: Option<&str>,
    value: &str,
    ct: &CancellationToken,
) -> Result<String, ToolError> {
    let envelope = Runner::new(state)
        .internal_query(database, BOUND_SQL, &[Some(value)], ct)
        .await?;
    envelope
        .rows
        .first()
        .and_then(|row| text_of(row, "bound"))
        .ok_or_else(|| ToolError::Internal("the server returned no timestamp".to_owned()))
}

/// Reads `len` bytes of a log file at `offset` through pgmcp.read_log_file.
pub async fn read_chunk(
    state: &AppState,
    database: Option<&str>,
    name: &str,
    offset: u64,
    len: usize,
    ct: &CancellationToken,
) -> Result<Vec<u8>, ToolError> {
    let offset_text = offset.to_string();
    let len_text = len.to_string();
    let params = [
        Some(name),
        Some(offset_text.as_str()),
        Some(len_text.as_str()),
    ];
    let statement = Statement {
        sql: READ_SQL,
        params: &params,
        user_sql: false,
        fetch: FetchLimits {
            max_rows: 1,
            max_bytes: 8 * 1_048_576,
            max_value_bytes: 2 * READ_LEN + 2,
        },
        offset: 0,
        search_path_catalog_only: true,
    };
    let (_, output) = Runner::new(state)
        .internal_raw(database, statement, ct)
        .await?;
    let cell = output
        .result
        .rows
        .first()
        .and_then(|row| row.first())
        .and_then(Option::as_ref);
    match cell {
        None => Ok(Vec::new()),
        Some(field) if field.full_len > field.data.len() => Err(ToolError::Internal(
            "a log read was cut short by the value limit".to_owned(),
        )),
        Some(field) => decode_bytea(&field.data),
    }
}

/// Decodes bytea hex output (`\x` followed by hex pairs).
pub fn decode_bytea(text: &[u8]) -> Result<Vec<u8>, ToolError> {
    let hex = text.strip_prefix(b"\\x").ok_or_else(|| {
        ToolError::Internal("the log read returned an unexpected encoding".to_owned())
    })?;
    if hex.len() % 2 != 0 {
        return Err(ToolError::Internal(
            "the log read returned an odd hex length".to_owned(),
        ));
    }
    hex.chunks(2)
        .map(|pair| {
            let high = hex_digit(pair[0]);
            let low = hex_digit(pair[1]);
            match (high, low) {
                (Some(h), Some(l)) => Ok(h << 4 | l),
                _ => Err(ToolError::Internal(
                    "the log read returned a non-hex byte".to_owned(),
                )),
            }
        })
        .collect()
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn text_of(row: &Map<String, Value>, key: &str) -> Option<String> {
    row.get(key).and_then(Value::as_str).map(str::to_owned)
}

fn flag(row: &Map<String, Value>, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or_default()
}
