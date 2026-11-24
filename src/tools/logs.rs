//! read_server_log: entries from the PostgreSQL server log, or the log files and logging settings.

mod parse;
pub(crate) mod query;
mod scan;

use rmcp::ErrorData as McpError;
use rmcp::model::Tool;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::core::tool;
use super::mask;
use super::{Call, ToolError, Toolset, parse_args, text, value_of};
use crate::server::AppState;
use parse::{Entry, Format, rank};
use query::LogFile;
use scan::{Backward, WINDOW};

const NOT_INSTALLED: &str = "The log reader functions are not installed in this database.";
const NOT_AUTHENTIC: &str = "The pgmcp log reader functions in this database were not installed by sql/log_reader.sql (unexpected owner or not SECURITY DEFINER).";
const NO_PRIVILEGE: &str = "The connected role may not execute pgmcp.read_log_file.";
const NO_FILES: &str =
    "No log files found: logging_collector is off or the log directory is empty.";
const ENABLE_LOGGING: &str = "Set logging_collector = on (restart required) and log_destination = 'jsonlog' (PostgreSQL 15+).";
/// Log bytes read per call before the scan stops and returns a cursor.
const BUDGET_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_LIMIT: i64 = 100;
const SEVERITY_NAMES: &[&str] = &[
    "DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "FATAL", "PANIC",
];
const TRUNCATED_MARK: &str = "…[truncated]";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReadArgs {
    pub database: Option<String>,
    pub list_files: Option<bool>,
    pub since: Option<String>,
    pub until: Option<String>,
    pub min_severity: Option<String>,
    pub contains: Option<String>,
    pub user: Option<String>,
    pub entry_database: Option<String>,
    pub pid: Option<i64>,
    pub file: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

/// The reply: unavailable (with the reason and the setup), the file listing, or the entries of one scan.
#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogOutput {
    pub database: String,
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how_to_enable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<Vec<FileInfo>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entries: Option<Vec<LogEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_to_end: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanned_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files_read: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_messages: Option<u64>,
}

impl LogOutput {
    /// A reply with only the database and availability set.
    fn bare(database: String, available: bool) -> LogOutput {
        LogOutput {
            database,
            available,
            reason: None,
            how_to_enable: None,
            format: None,
            files: None,
            settings: None,
            entries: None,
            next_cursor: None,
            scanned_to_end: None,
            scanned_bytes: None,
            files_read: None,
            truncated_messages: None,
        }
    }
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FileInfo {
    pub name: String,
    pub size_bytes: u64,
    pub modified: String,
    pub format: &'static str,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EntriesResult {
    pub database: String,
    pub available: bool,
    pub format: &'static str,
    pub entries: Vec<LogEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub scanned_to_end: bool,
    pub scanned_bytes: u64,
    pub files_read: Vec<String>,
    pub truncated_messages: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LogEntry {
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sqlstate: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub statement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub file: String,
}

/// Every log tool with its toolset tag.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    vec![(
        Toolset::Logs,
        tool::<ReadArgs, LogOutput>(
            "read_server_log",
            text::READ_SERVER_LOG_TITLE,
            text::READ_SERVER_LOG,
            &[
                ("database", text::DATABASE_PARAM),
                ("list_files", text::READ_SERVER_LOG_LIST_FILES_PARAM),
                ("since", text::READ_SERVER_LOG_SINCE_PARAM),
                ("until", text::READ_SERVER_LOG_UNTIL_PARAM),
                ("min_severity", text::READ_SERVER_LOG_MIN_SEVERITY_PARAM),
                ("contains", text::READ_SERVER_LOG_CONTAINS_PARAM),
                ("user", text::READ_SERVER_LOG_USER_PARAM),
                ("entry_database", text::READ_SERVER_LOG_ENTRY_DATABASE_PARAM),
                ("pid", text::READ_SERVER_LOG_PID_PARAM),
                ("file", text::READ_SERVER_LOG_FILE_PARAM),
                ("limit", text::LIMIT_PARAM),
                ("cursor", text::CURSOR_PARAM),
            ],
        ),
    )]
}

/// Runs read_server_log, or returns None when the name is not this module's tool.
pub async fn dispatch(
    state: &AppState,
    name: &str,
    args: Value,
    ct: &CancellationToken,
) -> Option<Result<Call, McpError>> {
    if name != "read_server_log" {
        return None;
    }
    let args: ReadArgs = match parse_args(args) {
        Ok(args) => args,
        Err(error) => return Some(Err(error)),
    };
    Some(Ok(read_server_log(state, args, ct).await))
}

async fn read_server_log(state: &AppState, args: ReadArgs, ct: &CancellationToken) -> Call {
    let result = read(state, &args, ct).await;
    let database = match &result {
        Ok(outcome) => Some(outcome.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    let rows = result.as_ref().ok().and_then(|outcome| outcome.entries);
    Call {
        result: result.and_then(|outcome| value_of(&outcome.output)),
        database,
        rows,
        sql: None,
    }
}

struct Outcome {
    database: String,
    output: LogOutput,
    /// Number of entries returned, for entry replies.
    entries: Option<usize>,
}

/// A validated request, with the filters in the form the scan needs.
struct Plan {
    limit: usize,
    min_rank: Option<u8>,
    contains: Option<String>,
    user: Option<String>,
    entry_database: Option<String>,
    pid: Option<i64>,
    since: Option<String>,
    until: Option<String>,
    /// Files to read, newest first, in the chosen format group.
    files: Vec<LogFile>,
    /// Index into `files` where the scan starts.
    first: usize,
    /// Byte offset in `files[first]` where the scan starts; None means its end.
    offset: Option<u64>,
    format: Format,
}

async fn read(
    state: &AppState,
    args: &ReadArgs,
    ct: &CancellationToken,
) -> Result<Outcome, ToolError> {
    let db = args.database.as_deref();
    let database = state.pool(db)?.0.name.clone();
    let setup = query::setup(state, db, ct).await?;
    if let Some(reason) = setup_reason(&setup) {
        return Ok(unavailable(database, reason, grant_text(&setup.role)));
    }
    let listing = query::files(state, db, ct).await?;
    if let Some(reason) = listing_reason(listing.len()) {
        return Ok(unavailable(database, reason, ENABLE_LOGGING.to_owned()));
    }
    if args.list_files.unwrap_or(false) {
        let settings = query::settings(state, db, ct).await?;
        let files = listing
            .iter()
            .map(|f| FileInfo {
                name: f.name.clone(),
                size_bytes: f.size,
                modified: f.modified.clone(),
                format: f.format.name(),
            })
            .collect();
        return Ok(Outcome {
            database: database.clone(),
            output: LogOutput {
                files: Some(files),
                settings: Some(settings),
                ..LogOutput::bare(database, true)
            },
            entries: None,
        });
    }
    let plan = plan(state, args, &listing, db, ct).await?;
    let scanned = scan_entries(state, db, &plan, ct).await?;
    let count = scanned.entries.len();
    Ok(Outcome {
        database: database.clone(),
        output: scanned.into_result(&database, plan.format),
        entries: Some(count),
    })
}

/// The reason the log reader cannot be used, checked in order; None when the setup allows it.
fn setup_reason(setup: &query::Setup) -> Option<&'static str> {
    if !setup.installed {
        Some(NOT_INSTALLED)
    } else if !setup.authentic {
        Some(NOT_AUTHENTIC)
    } else if !setup.allowed {
        Some(NO_PRIVILEGE)
    } else {
        None
    }
}

/// The reason there is nothing to read when the log directory lists `files` files; None when it has some.
fn listing_reason(files: usize) -> Option<&'static str> {
    if files == 0 { Some(NO_FILES) } else { None }
}

/// The setup steps for the connected role.
fn grant_text(role: &str) -> String {
    format!(
        "Run sql/log_reader.sql as a superuser, then: GRANT USAGE ON SCHEMA pgmcp TO {role}; \
         GRANT EXECUTE ON FUNCTION pgmcp.read_log_file(text, bigint, integer), pgmcp.list_log_files() TO {role};"
    )
}

fn unavailable(database: String, reason: &str, how: String) -> Outcome {
    let output = LogOutput {
        reason: Some(reason.to_owned()),
        how_to_enable: Some(how),
        ..LogOutput::bare(database.clone(), false)
    };
    Outcome {
        database,
        output,
        entries: None,
    }
}

/// Validates the arguments and resolves the files and the start position.
async fn plan(
    state: &AppState,
    args: &ReadArgs,
    listing: &[LogFile],
    db: Option<&str>,
    ct: &CancellationToken,
) -> Result<Plan, ToolError> {
    let limit = args.limit.unwrap_or(DEFAULT_LIMIT);
    if !(1..=500).contains(&limit) {
        return Err(ToolError::Rejected(
            "limit must be between 1 and 500.".to_owned(),
        ));
    }
    let min_rank = match args.min_severity.as_deref() {
        None => None,
        Some(name) => {
            let upper = name.to_ascii_uppercase();
            match rank(&upper) {
                Some(value) if SEVERITY_NAMES.contains(&upper.as_str()) => Some(value),
                _ => {
                    return Err(ToolError::Rejected(format!(
                        "min_severity must be one of {}.",
                        SEVERITY_NAMES.join(", ")
                    )));
                }
            }
        }
    };
    let (since, until) =
        query::bounds(state, db, args.since.as_deref(), args.until.as_deref(), ct).await?;
    let group = file_group(listing, args.file.as_deref())?;
    let format = group.first().map_or(Format::Stderr, |file| file.format);
    let (first, offset) = match args.cursor.as_deref() {
        None => (0, None),
        Some(text) => {
            let (index, offset) = decode_cursor(text, listing, &group, args.file.as_deref())?;
            (index, Some(offset))
        }
    };
    Ok(Plan {
        limit: usize::try_from(limit).unwrap_or(DEFAULT_LIMIT as usize),
        min_rank,
        contains: args.contains.as_ref().map(|s| s.to_lowercase()),
        user: args.user.clone(),
        entry_database: args.entry_database.clone(),
        pid: args.pid,
        since,
        until,
        files: group,
        first,
        offset,
        format,
    })
}

/// The files read: the named file, else the jsonlog files, else the csvlog files, else all stderr files.
fn file_group(listing: &[LogFile], file: Option<&str>) -> Result<Vec<LogFile>, ToolError> {
    if let Some(name) = file {
        return match listing.iter().find(|f| f.name == name) {
            Some(found) => Ok(vec![found.clone()]),
            None => Err(ToolError::Rejected(format!("Unknown log file \"{name}\"."))),
        };
    }
    for format in [Format::Jsonlog, Format::Csvlog, Format::Stderr] {
        let group: Vec<LogFile> = listing
            .iter()
            .filter(|f| f.format == format)
            .cloned()
            .collect();
        if !group.is_empty() {
            return Ok(group);
        }
    }
    Ok(listing.to_vec())
}

/// Checks a cursor of the form `name|offset|format` against the listing; returns its index in `group`.
fn decode_cursor(
    text: &str,
    listing: &[LogFile],
    group: &[LogFile],
    file: Option<&str>,
) -> Result<(usize, u64), ToolError> {
    let invalid = || ToolError::Rejected("Invalid cursor.".to_owned());
    let parts: Vec<&str> = text.split('|').collect();
    let [name, offset, format] = parts.as_slice() else {
        return Err(invalid());
    };
    let offset: u64 = offset.parse().map_err(|_| invalid())?;
    let known = listing
        .iter()
        .find(|f| f.name == *name)
        .ok_or_else(invalid)?;
    if offset > known.size || *format != known.format.name() {
        return Err(invalid());
    }
    if file.is_some_and(|wanted| wanted != *name) {
        return Err(invalid());
    }
    let index = group
        .iter()
        .position(|f| f.name == *name)
        .ok_or_else(invalid)?;
    Ok((index, offset))
}

fn encode_cursor(file: &str, offset: u64, format: Format) -> String {
    format!("{file}|{offset}|{}", format.name())
}

/// What a scan produced before any cursor is attached.
#[derive(Default)]
struct Scanned {
    entries: Vec<LogEntry>,
    scanned_bytes: u64,
    files_read: Vec<String>,
    truncated: u64,
    /// Where the next call resumes, as (file, offset); None when the scan ended.
    next: Option<(String, u64)>,
    scanned_to_end: bool,
    response_bytes: usize,
}

impl Scanned {
    fn into_result(self, database: &str, format: Format) -> LogOutput {
        let next_cursor = self
            .next
            .as_ref()
            .map(|(file, offset)| encode_cursor(file, *offset, format));
        LogOutput {
            format: Some(format.name()),
            entries: Some(self.entries),
            next_cursor,
            scanned_to_end: Some(self.scanned_to_end),
            scanned_bytes: Some(self.scanned_bytes),
            files_read: Some(self.files_read),
            truncated_messages: Some(self.truncated),
            ..LogOutput::bare(database.to_owned(), true)
        }
    }
}

/// Scans the planned files backwards until the limit, the response size, the byte budget or the
/// since bound stops it, or the oldest file is reached.
async fn scan_entries(
    state: &AppState,
    db: Option<&str>,
    plan: &Plan,
    ct: &CancellationToken,
) -> Result<Scanned, ToolError> {
    let limits = &state.config.limits;
    let mut scanned = Scanned::default();
    // Start of the last returned entry, the point a cursor resumes from.
    let mut last: Option<(String, u64)> = None;
    for (index, file) in plan.files.iter().enumerate().skip(plan.first) {
        let end = match plan.offset {
            Some(offset) if index == plan.first => offset,
            _ => file.size,
        };
        let mut backward = Backward::new(file.format, end, WINDOW);
        while let Some(read) = backward.request() {
            if scanned.scanned_bytes >= BUDGET_BYTES {
                scanned.next = Some((file.name.clone(), backward.end()));
                return Ok(scanned);
            }
            if scanned.files_read.last() != Some(&file.name) {
                scanned.files_read.push(file.name.clone());
            }
            let bytes = query::read_chunk(state, db, &file.name, read.offset, read.len, ct).await?;
            scanned.scanned_bytes += bytes.len() as u64;
            let Some(records) = backward.feed(read.offset, bytes) else {
                continue;
            };
            for (at, entry) in records {
                let stamped = !entry.timestamp.is_empty();
                if let Some(since) = &plan.since
                    && stamped
                    && stamp(&entry.timestamp) < since.as_str()
                {
                    scanned.scanned_to_end = true;
                    return Ok(scanned);
                }
                if let Some(until) = &plan.until
                    && stamped
                    && stamp(&entry.timestamp) >= until.as_str()
                {
                    continue;
                }
                let entry = mask_entry(entry);
                if !matches(plan, &entry) {
                    continue;
                }
                let output = to_output(
                    entry,
                    &file.name,
                    limits.max_value_bytes,
                    &mut scanned.truncated,
                );
                let size = serde_json::to_string(&output)
                    .map_err(|e| ToolError::Internal(e.to_string()))?
                    .len();
                if !scanned.entries.is_empty()
                    && scanned.response_bytes + size > limits.max_response_bytes
                {
                    scanned.next = last;
                    return Ok(scanned);
                }
                scanned.response_bytes += size;
                scanned.entries.push(output);
                last = Some((file.name.clone(), at));
                if scanned.entries.len() >= plan.limit {
                    scanned.next = last;
                    return Ok(scanned);
                }
            }
        }
    }
    scanned.scanned_to_end = true;
    Ok(scanned)
}

/// The first 23 characters of a timestamp, comparable with the bound text.
fn stamp(timestamp: &str) -> &str {
    timestamp.get(..23).unwrap_or(timestamp)
}

fn mask_entry(mut entry: Entry) -> Entry {
    entry.message = mask::mask(&entry.message);
    entry.detail = entry.detail.as_deref().map(mask::mask);
    entry.statement = entry.statement.as_deref().map(mask::mask);
    entry.context = entry.context.as_deref().map(mask::mask);
    entry
}

/// The filters, applied to a masked entry.
fn matches(plan: &Plan, entry: &Entry) -> bool {
    if let Some(min) = plan.min_rank {
        match rank(&entry.severity) {
            Some(value) if value >= min => {}
            _ => return false,
        }
    }
    if let Some(needle) = &plan.contains {
        let found = [
            Some(entry.message.as_str()),
            entry.detail.as_deref(),
            entry.statement.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(|text| text.to_lowercase().contains(needle.as_str()));
        if !found {
            return false;
        }
    }
    if let Some(user) = &plan.user
        && entry.user.as_deref() != Some(user.as_str())
    {
        return false;
    }
    if let Some(database) = &plan.entry_database
        && entry.database.as_deref() != Some(database.as_str())
    {
        return false;
    }
    if let Some(pid) = plan.pid
        && entry.pid != Some(pid)
    {
        return false;
    }
    true
}

/// Cuts a text field to `max` bytes on a character boundary, counting each cut.
fn cut(text: String, max: usize, truncated: &mut u64) -> String {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    *truncated += 1;
    format!("{}{TRUNCATED_MARK}", &text[..end])
}

fn to_output(entry: Entry, file: &str, max_value_bytes: usize, truncated: &mut u64) -> LogEntry {
    let message = cut(entry.message, max_value_bytes, truncated);
    let detail = entry
        .detail
        .map(|text| cut(text, max_value_bytes, truncated));
    let context = entry
        .context
        .map(|text| cut(text, max_value_bytes, truncated));
    let statement = entry
        .statement
        .map(|text| cut(text, max_value_bytes, truncated));
    LogEntry {
        timestamp: entry.timestamp,
        severity: entry.severity,
        message,
        pid: entry.pid,
        user: entry.user,
        database: entry.database,
        application: entry.application,
        client_addr: entry.client_addr,
        sqlstate: entry.sqlstate,
        detail,
        hint: entry.hint,
        context,
        statement,
        backend_type: entry.backend_type,
        query_id: entry.query_id,
        session_id: entry.session_id,
        file: file.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::query::{LogFile, Setup, decode_bytea};
    use super::*;

    fn setup(installed: bool, authentic: bool, allowed: bool) -> Setup {
        Setup {
            installed,
            authentic,
            allowed,
            role: "mcp_min".to_owned(),
        }
    }

    #[test]
    fn setup_reason_checks_installed_then_authentic_then_allowed() {
        assert_eq!(
            setup_reason(&setup(false, false, false)),
            Some(NOT_INSTALLED)
        );
        assert_eq!(
            setup_reason(&setup(true, false, false)),
            Some(NOT_AUTHENTIC)
        );
        assert_eq!(setup_reason(&setup(true, true, false)), Some(NO_PRIVILEGE));
        assert_eq!(setup_reason(&setup(true, true, true)), None);
    }

    #[test]
    fn empty_log_directory_is_no_files_and_any_file_is_readable() {
        assert_eq!(listing_reason(0), Some(NO_FILES));
        assert_eq!(listing_reason(1), None);
        assert_eq!(listing_reason(3), None);
    }

    fn listed(name: &str, size: u64, format: Format) -> LogFile {
        LogFile {
            name: name.to_owned(),
            size,
            modified: String::new(),
            format,
        }
    }

    fn cursor_error(text: &str, file: Option<&str>) -> String {
        let listing = vec![
            listed("a.json", 100, Format::Jsonlog),
            listed("b.csv", 50, Format::Csvlog),
        ];
        let group = listing[..1].to_vec();
        match decode_cursor(text, &listing, &group, file) {
            Ok(found) => format!("ok {found:?}"),
            Err(error) => error.message(),
        }
    }

    #[test]
    fn cut_leaves_short_text_and_counts_nothing() {
        let mut truncated = 0;
        assert_eq!(cut("abc".to_owned(), 5, &mut truncated), "abc");
        assert_eq!(truncated, 0);
    }

    #[test]
    fn cut_stops_on_a_character_boundary() {
        let mut truncated = 0;
        assert_eq!(cut("héllo".to_owned(), 2, &mut truncated), "h…[truncated]");
        assert_eq!(cut("héllo".to_owned(), 3, &mut truncated), "hé…[truncated]");
        assert_eq!(truncated, 2);
    }

    #[test]
    fn cursor_must_name_a_listed_file_in_range_and_format() {
        assert_eq!(cursor_error("a.json|10|jsonlog", None), "ok (0, 10)");
        assert_eq!(cursor_error("a.json|100|jsonlog", None), "ok (0, 100)");
        for bad in [
            "a.json|101|jsonlog",
            "a.json|10|csvlog",
            "a.json|10",
            "zz.json|1|jsonlog",
            "a.json|x|jsonlog",
            "garbage",
        ] {
            assert_eq!(cursor_error(bad, None), "Invalid cursor.", "{bad}");
        }
        assert_eq!(
            cursor_error("a.json|10|jsonlog", Some("b.csv")),
            "Invalid cursor."
        );
    }

    #[test]
    fn file_argument_selects_one_file_or_errors() {
        let listing = vec![listed("a.json", 1, Format::Jsonlog)];
        assert_eq!(
            file_group(&listing, Some("a.json")).map(|g| g.len()).ok(),
            Some(1)
        );
        let error = file_group(&listing, Some("x.log"))
            .err()
            .map(|e| e.message());
        assert_eq!(error.as_deref(), Some("Unknown log file \"x.log\"."));
    }

    #[test]
    fn bytea_hex_decodes_and_rejects_bad_input() {
        assert_eq!(decode_bytea(b"\\x48690a").ok(), Some(b"Hi\n".to_vec()));
        assert_eq!(decode_bytea(b"\\x").ok(), Some(Vec::new()));
        assert!(decode_bytea(b"48").is_err());
        assert!(decode_bytea(b"\\x4").is_err());
        assert!(decode_bytea(b"\\xzz").is_err());
    }
}
