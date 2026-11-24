//! Runs one statement on a pooled connection inside a READ ONLY transaction, then resets the session.
// RunError holds DbError and WireError by value, which are large (fixed by the wire interface).
#![allow(clippy::result_large_err)]

use std::time::{Duration, Instant};

use tokio_util::sync::CancellationToken;

use crate::encode::TypeInfo;
use crate::pg::pool::{Lease, Pool, PoolError};
use crate::pg::wire::{
    CancelHandle, Connection, DbError, FetchLimits, QueryResult, TxStatus, WireError,
};
use crate::typeinfo::TypeCache;

/// Grace added to the server statement timeout before the client stops waiting for the query.
const CLIENT_GRACE_MS: u64 = 5_000;
/// Values the session check must see, in the column order of SESSION_CHECK.
const SESSION_EXPECTED: [&str; 8] = [
    "on", "ISO, MDY", "iso_8601", "UTC", "hex", "on", "UTF8", "true",
];
const SESSION_CHECK: &str = "SELECT pg_catalog.current_setting('transaction_read_only'), \
    pg_catalog.current_setting('DateStyle'), pg_catalog.current_setting('IntervalStyle'), \
    pg_catalog.current_setting('TimeZone'), pg_catalog.current_setting('bytea_output'), \
    pg_catalog.current_setting('standard_conforming_strings'), \
    pg_catalog.current_setting('client_encoding'), (current_user = session_user)::text";

#[derive(Debug, Clone)]
pub struct SessionSettings {
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    pub fetch: FetchLimits,
    pub pool_wait: Duration,
    /// Sets search_path to pg_catalog for the transaction; true for the server's own catalog SQL.
    pub search_path_catalog_only: bool,
}

#[derive(Debug)]
pub struct RunOutput {
    pub result: QueryResult,
    /// One per result column, same order.
    pub types: Vec<TypeInfo>,
    pub server_version_num: u32,
    /// Time spent in the execute step only.
    pub elapsed: Duration,
}

#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    Refused(String),
    #[error("{}", .0.message)]
    Db(DbError),
    #[error("the query exceeded the {0} ms time limit and was cancelled")]
    Timeout(u64),
    #[error("the request was cancelled")]
    Cancelled,
    #[error("database unavailable: {0}")]
    Unavailable(String),
    #[error("internal error: {0}")]
    Internal(String),
}

/// Why a run stopped. Keep means the connection is still in a known state and gets reset.
enum Failure {
    Keep(RunError),
    Drop(RunError),
    /// The session check hit an I/O error; a reused connection may just have gone stale.
    Stale(RunError),
}

enum Race {
    Cancelled,
    Deadline,
    Done(Result<QueryResult, WireError>),
}

/// What one session runs inside its read-only transaction.
enum Body<'a> {
    /// `user_sql` true: the server must report zero parameters. `params` are text-format values.
    Bound {
        sql: &'a str,
        params: &'a [Option<&'a str>],
        user_sql: bool,
    },
    /// An EXPLAIN text with no bind values; see `explain_unbound`.
    Generic { sql: &'a str },
}

/// `user_sql` true: the server must report zero parameters. `params` are text-format values.
pub async fn run_readonly(
    pool: &Pool,
    sql: &str,
    params: &[Option<&str>],
    user_sql: bool,
    settings: &SessionSettings,
    cancel: &CancellationToken,
) -> Result<RunOutput, RunError> {
    let body = Body::Bound {
        sql,
        params,
        user_sql,
    };
    run_session(pool, body, settings, cancel).await
}

/// Runs an EXPLAIN GENERIC_PLAN text through the simple protocol behind a server-side preflight.
/// Bind values would make PostgreSQL plan the value, so the text is sent with none.
pub async fn run_readonly_explain_generic(
    pool: &Pool,
    sql: &str,
    settings: &SessionSettings,
    cancel: &CancellationToken,
) -> Result<RunOutput, RunError> {
    run_session(pool, Body::Generic { sql }, settings, cancel).await
}

/// Checkout, BEGIN READ ONLY with the session check, the body, then reset or close.
async fn run_session(
    pool: &Pool,
    body: Body<'_>,
    settings: &SessionSettings,
    cancel: &CancellationToken,
) -> Result<RunOutput, RunError> {
    let mut lease = pool
        .checkout(settings.pool_wait)
        .await
        .map_err(pool_failure)?;
    let mut checked = verify_session(&mut lease, settings).await;
    if matches!(checked, Err(Failure::Stale(_))) && lease.reused() {
        drop(lease);
        lease = pool
            .checkout_fresh(settings.pool_wait)
            .await
            .map_err(pool_failure)?;
        checked = verify_session(&mut lease, settings).await;
    }
    let outcome = match checked {
        Ok(()) => run_held(lease.conn(), body, settings, cancel, pool.type_cache()).await,
        Err(failure) => Err(failure),
    };
    match outcome {
        Ok(output) => {
            reset_and_release(lease).await;
            Ok(output)
        }
        Err(Failure::Keep(e)) => {
            reset_and_release(lease).await;
            Err(e)
        }
        Err(Failure::Drop(e) | Failure::Stale(e)) => {
            drop(lease);
            Err(e)
        }
    }
}

/// BEGIN READ ONLY with the server-side time limits, as a statement list ending in a semicolon.
fn begin_sql(settings: &SessionSettings, server_version_num: u32) -> String {
    let st = settings.statement_timeout_ms;
    let mut parts = vec![
        "BEGIN READ ONLY".to_string(),
        format!("SET LOCAL statement_timeout = {st}"),
        format!("SET LOCAL lock_timeout = {}", settings.lock_timeout_ms),
        format!(
            "SET LOCAL idle_in_transaction_session_timeout = {}",
            st.saturating_add(10_000)
        ),
    ];
    if server_version_num >= 170_000 {
        parts.push(format!(
            "SET LOCAL transaction_timeout = {}",
            st.saturating_add(5_000)
        ));
    }
    if settings.search_path_catalog_only {
        parts.push("SET LOCAL search_path = pg_catalog".to_string());
    }
    format!("{};", parts.join("; "))
}

/// Opens the read-only transaction and checks the session settings before anything else is sent.
async fn verify_session(lease: &mut Lease<'_>, settings: &SessionSettings) -> Result<(), Failure> {
    let conn = lease.conn();
    let sql = format!(
        "{} {SESSION_CHECK}",
        begin_sql(settings, conn.server_version_num())
    );
    let result = match conn.simple_query(&sql).await {
        Ok(result) => result,
        Err(WireError::Io(e)) => return Err(Failure::Stale(RunError::Unavailable(e.to_string()))),
        Err(e) => return Err(wire_failure(e)),
    };
    if result.status != TxStatus::InTransaction || !session_ok(&result.rows) {
        tracing::warn!(status = ?result.status, values = ?result.rows, "session check failed");
        return Err(Failure::Drop(RunError::Internal(
            "session check failed".into(),
        )));
    }
    Ok(())
}

fn session_ok(rows: &[Vec<Option<String>>]) -> bool {
    match rows {
        [row] => {
            row.len() == SESSION_EXPECTED.len()
                && row
                    .iter()
                    .zip(SESSION_EXPECTED)
                    .all(|(got, want)| got.as_deref() == Some(want))
        }
        _ => false,
    }
}

/// Execute, type resolution. Runs inside the transaction opened by `verify_session`.
async fn run_held(
    conn: &mut Connection,
    body: Body<'_>,
    settings: &SessionSettings,
    cancel: &CancellationToken,
    types: &TypeCache,
) -> Result<RunOutput, Failure> {
    let cancel_handle = conn.cancel_handle();
    let statement_ms = settings.statement_timeout_ms;
    let deadline = Duration::from_millis(statement_ms.saturating_add(CLIENT_GRACE_MS));
    let generic = matches!(body, Body::Generic { .. });
    let started = Instant::now();
    let race = tokio::select! {
        biased;
        _ = cancel.cancelled() => Race::Cancelled,
        _ = tokio::time::sleep(deadline) => Race::Deadline,
        r = fetch_rows(conn, body, settings) => Race::Done(r),
    };
    let elapsed = started.elapsed();
    let result = match race {
        Race::Done(Ok(result)) => result,
        Race::Done(Err(e)) if conn.is_poisoned() => {
            return Err(close_on(query_failure(e, statement_ms)));
        }
        Race::Done(Err(e)) => return Err(query_failure(e, statement_ms)),
        Race::Cancelled => {
            stop_query(&cancel_handle).await;
            return Err(Failure::Drop(RunError::Cancelled));
        }
        Race::Deadline => {
            stop_query(&cancel_handle).await;
            return Err(Failure::Drop(RunError::Timeout(statement_ms)));
        }
    };
    // The generic path has no truncation exception: its plan is never cut short.
    if (generic || result.truncated.is_none()) && result.status != TxStatus::InTransaction {
        return Err(Failure::Drop(RunError::Internal(
            "unexpected transaction state".into(),
        )));
    }
    if let Some(tag) = &result.command_tag
        && !allowed_tag(tag)
    {
        return Err(Failure::Drop(RunError::Internal(
            "unexpected command tag".into(),
        )));
    }
    let oids: Vec<u32> = result.columns.iter().map(|c| c.type_oid).collect();
    let types = resolve_types(conn, types, result.status, &oids, settings).await?;
    Ok(RunOutput {
        result,
        types,
        server_version_num: conn.server_version_num(),
        elapsed,
    })
}

async fn fetch_rows(
    conn: &mut Connection,
    body: Body<'_>,
    settings: &SessionSettings,
) -> Result<QueryResult, WireError> {
    match body {
        Body::Bound {
            sql,
            params,
            user_sql,
        } => conn.query(sql, params, user_sql, &settings.fetch).await,
        Body::Generic { sql } => conn.explain_unbound(sql, settings.fetch.max_bytes).await,
    }
}

/// The same failure, with the connection closed afterwards.
fn close_on(failure: Failure) -> Failure {
    match failure {
        Failure::Keep(e) | Failure::Drop(e) | Failure::Stale(e) => Failure::Drop(e),
    }
}

/// Command tags of the statements the gate lets run: `SELECT n`, `EXPLAIN` and `SHOW`.
fn allowed_tag(tag: &str) -> bool {
    match tag {
        "EXPLAIN" | "SHOW" => true,
        _ => tag
            .strip_prefix("SELECT ")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())),
    }
}

/// Asks the server to cancel the running query. A failed cancel request is only logged.
async fn stop_query(handle: &CancelHandle) {
    if let Err(e) = handle.cancel().await {
        tracing::debug!(error = %e, "cancel request failed");
    }
}

async fn resolve_types(
    conn: &mut Connection,
    types: &TypeCache,
    status: TxStatus,
    oids: &[u32],
    settings: &SessionSettings,
) -> Result<Vec<TypeInfo>, Failure> {
    if status != TxStatus::InTransaction {
        // A cancelled fetch aborted the transaction: end it, then open a new read-only one for the lookups.
        simple_expect(conn, "ROLLBACK", TxStatus::Idle)
            .await
            .map_err(wire_failure)?;
        let begin = begin_sql(settings, conn.server_version_num());
        simple_expect(conn, &begin, TxStatus::InTransaction)
            .await
            .map_err(wire_failure)?;
    }
    types.resolve(conn, oids).await.map_err(wire_failure)
}

/// Runs one statement and requires the resulting transaction status.
async fn simple_expect(
    conn: &mut Connection,
    sql: &str,
    status: TxStatus,
) -> Result<(), WireError> {
    let result = conn.simple_query(sql).await?;
    if result.status != status {
        return Err(WireError::Protocol("unexpected transaction state".into()));
    }
    Ok(())
}

/// ROLLBACK, then DISCARD ALL, as two calls. The session must end idle.
async fn reset(conn: &mut Connection) -> Result<(), WireError> {
    simple_expect(conn, "ROLLBACK", TxStatus::Idle).await?;
    simple_expect(conn, "DISCARD ALL", TxStatus::Idle).await
}

async fn reset_and_release(mut lease: Lease<'_>) {
    match reset(lease.conn()).await {
        Ok(()) => lease.release(true),
        Err(e) => tracing::warn!(error = %e, "session reset failed; closing the connection"),
    }
}

fn query_failure(e: WireError, statement_ms: u64) -> Failure {
    match e {
        WireError::Db(db) if db.code == "57014" && db.message.contains("statement timeout") => {
            Failure::Keep(RunError::Timeout(statement_ms))
        }
        other => wire_failure(other),
    }
}

/// Server-reported errors and refusals leave the connection resettable; anything else closes it.
fn wire_failure(e: WireError) -> Failure {
    match e {
        WireError::Refused(m) => Failure::Keep(RunError::Refused(m)),
        WireError::Db(db) => Failure::Keep(RunError::Db(db)),
        WireError::Protocol(m) => Failure::Drop(RunError::Internal(m)),
        other => Failure::Drop(RunError::Unavailable(other.to_string())),
    }
}

fn pool_failure(e: PoolError) -> RunError {
    match e {
        PoolError::Busy => RunError::Unavailable("all connections are busy, retry shortly".into()),
        PoolError::Closed => RunError::Unavailable("the pool is closed".into()),
        PoolError::Connect(message) => RunError::Unavailable(message),
    }
}
