//! Audit log: one `audit` target line per tool call, with no SQL text, values or error detail.

use std::time::Duration;

use sha2::{Digest, Sha256};

/// What one tool call records.
pub struct Record<'a> {
    pub tool: &'a str,
    pub database: Option<&'a str>,
    pub ok: bool,
    pub duration: Duration,
    pub rows: Option<usize>,
    pub sqlstate: Option<&'a str>,
    /// The SQL text; only its digest is logged.
    pub sql: Option<&'a str>,
}

/// Writes the audit line when the audit log is enabled.
pub fn record(enabled: bool, record: &Record<'_>) {
    if !enabled {
        return;
    }
    let sql_sha256 = record.sql.map(sql_digest);
    let duration_ms = u64::try_from(record.duration.as_millis()).unwrap_or(u64::MAX);
    let rows = record.rows.map(|n| u64::try_from(n).unwrap_or(u64::MAX));
    tracing::info!(
        target: "audit",
        tool = record.tool,
        database = record.database,
        ok = record.ok,
        duration_ms,
        rows,
        sqlstate = record.sqlstate,
        sql_sha256 = sql_sha256.as_deref(),
        "tool call"
    );
}

/// The first 16 hex characters of the SHA-256 of the SQL text.
pub fn sql_digest(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
