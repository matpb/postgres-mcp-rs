//! Log entry parsing for the three PostgreSQL log formats: jsonlog, csvlog and plain stderr.

use serde_json::{Map, Value};

/// One log entry as read from the file, before masking and truncation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Entry {
    pub timestamp: String,
    pub severity: String,
    pub message: String,
    pub pid: Option<i64>,
    pub user: Option<String>,
    pub database: Option<String>,
    pub application: Option<String>,
    pub client_addr: Option<String>,
    pub sqlstate: Option<String>,
    pub detail: Option<String>,
    pub hint: Option<String>,
    pub context: Option<String>,
    pub statement: Option<String>,
    pub backend_type: Option<String>,
    pub query_id: Option<i64>,
    pub session_id: Option<String>,
}

/// The layout of a log file, chosen from its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Jsonlog,
    Csvlog,
    Stderr,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Jsonlog => "jsonlog",
            Format::Csvlog => "csvlog",
            Format::Stderr => "stderr",
        }
    }

    /// `.json` is jsonlog, `.csv` is csvlog, anything else is plain stderr.
    pub fn of_file(name: &str) -> Format {
        let lower = name.to_ascii_lowercase();
        if lower.ends_with(".json") {
            Format::Jsonlog
        } else if lower.ends_with(".csv") {
            Format::Csvlog
        } else {
            Format::Stderr
        }
    }
}

/// Severity rank for min_severity filters; None for severities that are not ranked (UNKNOWN, DETAIL, ...).
pub fn rank(severity: &str) -> Option<u8> {
    match severity {
        "DEBUG" | "DEBUG1" | "DEBUG2" | "DEBUG3" | "DEBUG4" | "DEBUG5" => Some(1),
        "INFO" | "LOG" => Some(2),
        "NOTICE" => Some(3),
        "WARNING" => Some(4),
        "ERROR" => Some(5),
        "FATAL" => Some(6),
        "PANIC" => Some(7),
        _ => None,
    }
}

/// Stderr severities that attach to the preceding entry instead of starting one.
const ATTACHED: &[&str] = &[
    "DETAIL",
    "HINT",
    "CONTEXT",
    "STATEMENT",
    "QUERY",
    "LOCATION",
];
/// Every severity word a stderr prefix can carry.
const SEVERITIES: &[&str] = &[
    "DEBUG1",
    "DEBUG2",
    "DEBUG3",
    "DEBUG4",
    "DEBUG5",
    "LOG",
    "INFO",
    "NOTICE",
    "WARNING",
    "ERROR",
    "FATAL",
    "PANIC",
    "DETAIL",
    "HINT",
    "CONTEXT",
    "STATEMENT",
    "QUERY",
    "LOCATION",
];

/// True when the bytes at the start of a line begin a record in this format. Stderr continuation
/// records (DETAIL, HINT, ...) are not record starts, so a chunk never begins with an attached line.
pub fn record_start(format: Format, line: &[u8]) -> bool {
    match format {
        Format::Jsonlog => line.first() == Some(&b'{'),
        Format::Csvlog => csv_record_start(line),
        Format::Stderr => match parse_stderr_line(line) {
            Some(parsed) => !parsed
                .severity
                .as_deref()
                .is_some_and(|s| ATTACHED.contains(&s)),
            None => false,
        },
    }
}

/// Parses the records of a buffer that starts at a record start. Each result carries the record's
/// byte offset within the buffer.
pub fn parse_records(format: Format, bytes: &[u8]) -> Vec<(usize, Entry)> {
    match format {
        Format::Jsonlog => parse_jsonlog(bytes),
        Format::Csvlog => parse_csvlog(bytes),
        Format::Stderr => parse_stderr(bytes),
    }
}

fn parse_jsonlog(bytes: &[u8]) -> Vec<(usize, Entry)> {
    let mut out = Vec::new();
    let mut offset = 0;
    for raw in bytes.split_inclusive(|&b| b == b'\n') {
        let start = offset;
        offset += raw.len();
        let line = String::from_utf8_lossy(raw);
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            continue;
        }
        let entry = match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(map)) => entry_from_json(&map),
            _ => unknown_entry(line),
        };
        out.push((start, entry));
    }
    out
}

fn entry_from_json(map: &Map<String, Value>) -> Entry {
    let text = |key: &str| {
        map.get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    };
    Entry {
        timestamp: text("timestamp").unwrap_or_default(),
        severity: text("error_severity").unwrap_or_else(|| "UNKNOWN".to_owned()),
        message: text("message").unwrap_or_default(),
        pid: map.get("pid").and_then(Value::as_i64),
        user: text("user"),
        database: text("dbname"),
        application: text("application_name"),
        client_addr: text("remote_host"),
        sqlstate: text("state_code"),
        detail: text("detail"),
        hint: text("hint"),
        context: text("context"),
        statement: text("statement"),
        backend_type: text("backend_type"),
        query_id: map.get("query_id").and_then(Value::as_i64),
        session_id: text("session_id"),
    }
}

/// An entry for a line that could not be parsed: its raw text as the message.
fn unknown_entry(line: &str) -> Entry {
    Entry {
        severity: "UNKNOWN".to_owned(),
        message: line.to_owned(),
        ..Entry::default()
    }
}

/// True when the line starts with `YYYY-MM-DD HH:MM:SS.mmm ZZZ,`, the start of a csvlog record.
fn csv_record_start(line: &[u8]) -> bool {
    if !matches_pattern(line, b"dddd-dd-dd dd:dd:dd.ddd ") {
        return false;
    }
    let zone = &line[24..];
    match zone.iter().position(|&b| b == b',') {
        Some(comma) => {
            comma > 0
                && zone[..comma]
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'/' | b'_'))
        }
        None => false,
    }
}

/// Splits one csv record starting at `start`: its fields and the index after its line end.
fn csv_record(bytes: &[u8], start: usize) -> (Vec<Vec<u8>>, usize) {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut quoted = false;
    let mut i = start;
    while let Some(&b) = bytes.get(i) {
        if quoted {
            if b == b'"' {
                if bytes.get(i + 1) == Some(&b'"') {
                    field.push(b'"');
                    i += 2;
                    continue;
                }
                quoted = false;
            } else {
                field.push(b);
            }
            i += 1;
            continue;
        }
        match b {
            b'"' => quoted = true,
            b',' => fields.push(std::mem::take(&mut field)),
            b'\r' => {}
            b'\n' => {
                fields.push(field);
                return (fields, i + 1);
            }
            _ => field.push(b),
        }
        i += 1;
    }
    fields.push(field);
    (fields, bytes.len())
}

fn parse_csvlog(bytes: &[u8]) -> Vec<(usize, Entry)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let (fields, next) = csv_record(bytes, pos);
        out.push((pos, entry_from_csv(&fields)));
        pos = next;
    }
    out
}

/// Maps csv columns by position; a missing or empty column is absent. Columns past the known set are ignored.
fn entry_from_csv(fields: &[Vec<u8>]) -> Entry {
    let col = |index: usize| {
        fields
            .get(index)
            .map(|f| String::from_utf8_lossy(f).into_owned())
            .filter(|s| !s.is_empty())
    };
    Entry {
        timestamp: col(0).unwrap_or_default(),
        user: col(1),
        database: col(2),
        pid: col(3).and_then(|s| s.parse().ok()),
        client_addr: col(4),
        session_id: col(5),
        severity: col(11).unwrap_or_else(|| "UNKNOWN".to_owned()),
        sqlstate: col(12),
        message: col(13).unwrap_or_default(),
        detail: col(14),
        hint: col(15),
        context: col(18),
        statement: col(19),
        application: col(22),
        backend_type: col(23),
        query_id: col(25).and_then(|s| s.parse().ok()),
    }
}

/// One stderr line split into its prefix parts and text.
struct StderrLine {
    timestamp: String,
    pid: Option<i64>,
    /// None when no known severity follows the prefix; then `text` is the whole line.
    severity: Option<String>,
    text: String,
}

/// Parses a stderr line that starts with a timestamp; None when it does not.
fn parse_stderr_line(line: &[u8]) -> Option<StderrLine> {
    if !matches_pattern(line, b"dddd-dd-dd dd:dd:dd") {
        return None;
    }
    let mut end = 19;
    if line.get(end) == Some(&b'.') {
        end += 1;
        while line.get(end).is_some_and(u8::is_ascii_digit) {
            end += 1;
        }
    }
    if let Some(zone_end) = zone_token_end(line, end) {
        end = zone_end;
    }
    let timestamp = String::from_utf8_lossy(&line[..end]).into_owned();
    let rest = String::from_utf8_lossy(&line[end..]).into_owned();
    let Some((at, name)) = find_severity(&rest) else {
        return Some(StderrLine {
            timestamp,
            pid: None,
            severity: None,
            text: String::from_utf8_lossy(line).into_owned(),
        });
    };
    let prefix = &rest[..at];
    let text = rest[at + name.len() + 3..].to_owned();
    Some(StderrLine {
        timestamp,
        pid: bracket_pid(prefix),
        severity: Some(name.to_owned()),
        text,
    })
}

/// End index of the zone token that follows the timestamp, if one is there.
fn zone_token_end(line: &[u8], from: usize) -> Option<usize> {
    if line.get(from) != Some(&b' ') {
        return None;
    }
    let start = from + 1;
    let len = line[start.min(line.len())..]
        .iter()
        .take_while(|b| !b.is_ascii_whitespace())
        .count();
    let token = &line[start.min(line.len())..start.min(line.len()) + len];
    let plausible = !token.is_empty()
        && token[0] != b'['
        && token.last() != Some(&b':')
        && token
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'/' | b'_'));
    plausible.then_some(start + len)
}

/// The earliest `SEVERITY:  ` at a token start in `rest`, as its byte index and name.
fn find_severity(rest: &str) -> Option<(usize, &'static str)> {
    let mut best: Option<(usize, &'static str)> = None;
    for name in SEVERITIES {
        let pattern = format!("{name}:  ");
        let mut from = 0;
        while let Some(found) = rest.get(from..).and_then(|s| s.find(&pattern)) {
            let at = from + found;
            let token_start = at == 0 || matches!(rest.as_bytes().get(at - 1), Some(b' ' | b']'));
            if token_start {
                if best.is_none_or(|(b, _)| at < b) {
                    best = Some((at, name));
                }
                break;
            }
            from = at + 1;
        }
    }
    best
}

/// The number inside the first `[...]` of a stderr prefix (the backend pid).
fn bracket_pid(prefix: &str) -> Option<i64> {
    let open = prefix.find('[')?;
    let close = prefix[open..].find(']')? + open;
    prefix[open + 1..close].trim().parse().ok()
}

fn parse_stderr(bytes: &[u8]) -> Vec<(usize, Entry)> {
    // Index in `out` of the last main entry, and the field continuation lines extend.
    let mut out: Vec<(usize, Entry)> = Vec::new();
    let mut main: Option<usize> = None;
    let mut current: Option<(usize, Field)> = None;
    let mut offset = 0;
    for raw in bytes.split_inclusive(|&b| b == b'\n') {
        let start = offset;
        offset += raw.len();
        let line = raw.strip_suffix(b"\n").unwrap_or(raw);
        let Some(parsed) = parse_stderr_line(line) else {
            match current {
                Some((index, field)) => {
                    append(&mut out[index].1, field, &String::from_utf8_lossy(line))
                }
                None => out.push((start, unknown_entry(&String::from_utf8_lossy(line)))),
            }
            continue;
        };
        let severity = parsed.severity.clone();
        match severity.as_deref() {
            Some(name) if ATTACHED.contains(&name) => match (main, field_of(name)) {
                (Some(index), Some(field)) => {
                    append(&mut out[index].1, field, &parsed.text);
                    current = Some((index, field));
                }
                (Some(index), None) => current = Some((index, Field::Discard)),
                (None, _) => out.push((start, unknown_entry(&String::from_utf8_lossy(line)))),
            },
            _ => {
                let entry = Entry {
                    timestamp: parsed.timestamp,
                    severity: severity.unwrap_or_else(|| "UNKNOWN".to_owned()),
                    message: parsed.text,
                    pid: parsed.pid,
                    ..Entry::default()
                };
                let index = out.len();
                out.push((start, entry));
                main = Some(index);
                current = Some((index, Field::Message));
            }
        }
    }
    out
}

/// The entry field a continuation line extends.
#[derive(Clone, Copy)]
enum Field {
    Message,
    Detail,
    Hint,
    Context,
    Statement,
    /// LOCATION lines are read and dropped.
    Discard,
}

fn field_of(severity: &str) -> Option<Field> {
    match severity {
        "DETAIL" => Some(Field::Detail),
        "HINT" => Some(Field::Hint),
        "CONTEXT" => Some(Field::Context),
        "STATEMENT" | "QUERY" => Some(Field::Statement),
        _ => None,
    }
}

/// Appends a line to a field, with a newline before it when the field already has text.
fn append(entry: &mut Entry, field: Field, text: &str) {
    let slot = match field {
        Field::Message => {
            entry.message.push('\n');
            entry.message.push_str(text);
            return;
        }
        Field::Discard => return,
        Field::Detail => &mut entry.detail,
        Field::Hint => &mut entry.hint,
        Field::Context => &mut entry.context,
        Field::Statement => &mut entry.statement,
    };
    match slot {
        Some(existing) => {
            existing.push('\n');
            existing.push_str(text);
        }
        None => *slot = Some(text.to_owned()),
    }
}

/// True when `bytes` starts with `pattern`, where `d` in the pattern matches an ASCII digit.
fn matches_pattern(bytes: &[u8], pattern: &[u8]) -> bool {
    bytes.len() >= pattern.len()
        && pattern.iter().zip(bytes).all(|(p, b)| match p {
            b'd' => b.is_ascii_digit(),
            other => other == b,
        })
}

#[cfg(test)]
mod tests {
    use super::{Format, parse_records, rank, record_start};

    fn entries(format: Format, text: &str) -> Vec<(usize, super::Entry)> {
        parse_records(format, text.as_bytes())
    }

    #[test]
    fn jsonlog_line_maps_keys() {
        let line = r#"{"timestamp":"2026-01-31 14:00:00.123 UTC","user":"mcp_ro","dbname":"appdb","pid":42,"remote_host":"127.0.0.1","session_id":"6a.1","error_severity":"ERROR","state_code":"22012","message":"division by zero","statement":"SELECT 1/0","application_name":"psql","backend_type":"client backend","query_id":-5}"#;
        let parsed = entries(Format::Jsonlog, &format!("{line}\n"));
        assert_eq!(parsed.len(), 1);
        let (start, entry) = &parsed[0];
        assert_eq!(*start, 0);
        assert_eq!(entry.timestamp, "2026-01-31 14:00:00.123 UTC");
        assert_eq!(entry.severity, "ERROR");
        assert_eq!(entry.message, "division by zero");
        assert_eq!(entry.pid, Some(42));
        assert_eq!(entry.user.as_deref(), Some("mcp_ro"));
        assert_eq!(entry.database.as_deref(), Some("appdb"));
        assert_eq!(entry.client_addr.as_deref(), Some("127.0.0.1"));
        assert_eq!(entry.sqlstate.as_deref(), Some("22012"));
        assert_eq!(entry.statement.as_deref(), Some("SELECT 1/0"));
        assert_eq!(entry.application.as_deref(), Some("psql"));
        assert_eq!(entry.backend_type.as_deref(), Some("client backend"));
        assert_eq!(entry.query_id, Some(-5));
        assert_eq!(entry.session_id.as_deref(), Some("6a.1"));
        assert_eq!(entry.detail, None);
    }

    #[test]
    fn jsonlog_missing_keys_are_absent() {
        let line =
            r#"{"timestamp":"2026-01-31 14:00:01.000 UTC","error_severity":"LOG","message":"x"}"#;
        let parsed = entries(Format::Jsonlog, &format!("{line}\n"));
        let entry = &parsed[0].1;
        assert_eq!(entry.severity, "LOG");
        assert_eq!(entry.pid, None);
        assert_eq!(entry.user, None);
        assert_eq!(entry.database, None);
        assert_eq!(entry.sqlstate, None);
        assert_eq!(entry.query_id, None);
    }

    #[test]
    fn jsonlog_broken_line_is_unknown_with_raw_text() {
        let text = "{\"timestamp\": oops\n{\"error_severity\":\"LOG\",\"message\":\"ok\"}\n";
        let parsed = entries(Format::Jsonlog, text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].1.severity, "UNKNOWN");
        assert_eq!(parsed[0].1.message, "{\"timestamp\": oops");
        assert_eq!(parsed[0].1.timestamp, "");
        assert_eq!(parsed[1].0, 19);
        assert_eq!(parsed[1].1.message, "ok");
    }

    #[test]
    fn csv_row_with_quotes_newlines_and_23_columns() {
        let row = "2026-01-31 14:00:00.123 UTC,mcp_ro,appdb,42,127.0.0.1:5555,6a1b.2c,1,SELECT,\
            2026-01-31 13:59:00 UTC,3/4,0,ERROR,22012,\"division, by \"\"zero\"\"\",\
            \"detail line 1\ndetail line 2\",,,,,\"SELECT 1/0\",,,psql\n";
        let parsed = entries(Format::Csvlog, row);
        assert_eq!(parsed.len(), 1);
        let entry = &parsed[0].1;
        assert_eq!(entry.timestamp, "2026-01-31 14:00:00.123 UTC");
        assert_eq!(entry.user.as_deref(), Some("mcp_ro"));
        assert_eq!(entry.database.as_deref(), Some("appdb"));
        assert_eq!(entry.pid, Some(42));
        assert_eq!(entry.client_addr.as_deref(), Some("127.0.0.1:5555"));
        assert_eq!(entry.session_id.as_deref(), Some("6a1b.2c"));
        assert_eq!(entry.severity, "ERROR");
        assert_eq!(entry.sqlstate.as_deref(), Some("22012"));
        assert_eq!(entry.message, "division, by \"zero\"");
        assert_eq!(
            entry.detail.as_deref(),
            Some("detail line 1\ndetail line 2")
        );
        assert_eq!(entry.statement.as_deref(), Some("SELECT 1/0"));
        assert_eq!(entry.application.as_deref(), Some("psql"));
        assert_eq!(entry.backend_type, None);
        assert_eq!(entry.query_id, None);
    }

    #[test]
    fn csv_26_column_row_reads_backend_and_query_id() {
        let row = "2026-01-31 14:00:00.123 UTC,u,d,7,,s,1,,,,,LOG,00000,\"m\",,,,,,,,,app,client backend,0,-1234\n";
        let parsed = entries(Format::Csvlog, row);
        let entry = &parsed[0].1;
        assert_eq!(entry.message, "m");
        assert_eq!(entry.application.as_deref(), Some("app"));
        assert_eq!(entry.backend_type.as_deref(), Some("client backend"));
        assert_eq!(entry.query_id, Some(-1234));
        assert_eq!(entry.client_addr, None);
    }

    #[test]
    fn csv_records_report_their_offsets() {
        let first = "2026-01-31 14:00:00.123 UTC,,,1,,,1,,,,,LOG,00000,\"a\nb\",,,,,,,,,\"\",,,\n";
        let second = "2026-01-31 14:00:01.123 UTC,,,2,,,1,,,,,LOG,00000,\"c\",,,,,,,,,\"\",,,\n";
        let parsed = entries(Format::Csvlog, &format!("{first}{second}"));
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].0, 0);
        assert_eq!(parsed[0].1.message, "a\nb");
        assert_eq!(parsed[1].0, first.len());
        assert_eq!(parsed[1].1.pid, Some(2));
    }

    #[test]
    fn stderr_real_line_with_prefix() {
        let text = "2026-11-24 17:18:30.124 UTC [86] LOG:  duration: 54.831 ms  statement: CREATE DATABASE \"appdb\" ;\n";
        let parsed = entries(Format::Stderr, text);
        assert_eq!(parsed.len(), 1);
        let entry = &parsed[0].1;
        assert_eq!(entry.timestamp, "2026-11-24 17:18:30.124 UTC");
        assert_eq!(entry.pid, Some(86));
        assert_eq!(entry.severity, "LOG");
        assert_eq!(
            entry.message,
            "duration: 54.831 ms  statement: CREATE DATABASE \"appdb\" ;"
        );
    }

    #[test]
    fn stderr_attaches_detail_hint_and_statement() {
        let text = "2026-01-31 14:00:00.000 UTC [7] ERROR:  division by zero\n\
            2026-01-31 14:00:00.000 UTC [7] DETAIL:  detail one\n\
            continuation\n\
            2026-01-31 14:00:00.000 UTC [7] HINT:  try x\n\
            2026-01-31 14:00:00.000 UTC [7] STATEMENT:  SELECT 1/0\n\
            2026-01-31 14:00:01.000 UTC [8] LOG:  next\n\
            multi line\n";
        let parsed = entries(Format::Stderr, text);
        assert_eq!(parsed.len(), 2);
        let first = &parsed[0].1;
        assert_eq!(first.severity, "ERROR");
        assert_eq!(first.message, "division by zero");
        assert_eq!(first.pid, Some(7));
        assert_eq!(first.detail.as_deref(), Some("detail one\ncontinuation"));
        assert_eq!(first.hint.as_deref(), Some("try x"));
        assert_eq!(first.statement.as_deref(), Some("SELECT 1/0"));
        let second = &parsed[1].1;
        assert_eq!(second.severity, "LOG");
        assert_eq!(second.message, "next\nmulti line");
        assert_eq!(second.pid, Some(8));
        assert_eq!(parsed[1].0, text.find("2026-01-31 14:00:01").unwrap_or(0));
    }

    #[test]
    fn stderr_prefix_with_extra_tokens_keeps_severity_and_message() {
        let text = "2026-01-31 14:00:00.000 UTC [7] alice@appdb ERROR:  boom\n";
        let parsed = entries(Format::Stderr, text);
        let entry = &parsed[0].1;
        assert_eq!(entry.severity, "ERROR");
        assert_eq!(entry.message, "boom");
        assert_eq!(entry.pid, Some(7));
    }

    #[test]
    fn stderr_unparseable_lines_are_unknown() {
        let text = "no timestamp here\n2026-01-31 14:00:00.000 UTC [7] no severity here\n";
        let parsed = entries(Format::Stderr, text);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].1.severity, "UNKNOWN");
        assert_eq!(parsed[0].1.message, "no timestamp here");
        assert_eq!(parsed[1].1.severity, "UNKNOWN");
        assert_eq!(
            parsed[1].1.message,
            "2026-01-31 14:00:00.000 UTC [7] no severity here"
        );
    }

    #[test]
    fn record_start_rules() {
        assert!(record_start(Format::Jsonlog, b"{\"a\":1}"));
        assert!(!record_start(Format::Jsonlog, b"  {"));
        assert!(record_start(
            Format::Csvlog,
            b"2026-01-31 14:00:00.123 UTC,u,d"
        ));
        assert!(!record_start(Format::Csvlog, b"2026-01-31 14:00:00 UTC,u"));
        assert!(record_start(
            Format::Stderr,
            b"2026-01-31 14:00:00.000 UTC [7] LOG:  x"
        ));
        assert!(!record_start(
            Format::Stderr,
            b"2026-01-31 14:00:00.000 UTC [7] DETAIL:  x"
        ));
        assert!(!record_start(Format::Stderr, b"continuation"));
    }

    #[test]
    fn severity_ranks() {
        assert_eq!(rank("LOG"), rank("INFO"));
        assert!(rank("DEBUG3") < rank("LOG"));
        assert!(rank("LOG") < rank("NOTICE"));
        assert!(rank("ERROR") < rank("FATAL"));
        assert!(rank("FATAL") < rank("PANIC"));
        assert_eq!(rank("UNKNOWN"), None);
    }
}
