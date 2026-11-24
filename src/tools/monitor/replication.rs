//! replication_status: primary or standby state, standbys, slots, the WAL receiver, publications and subscriptions.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{fail, present_columns, wide_rows};
use crate::server::AppState;
use crate::tools::{Call, ToolError, value_of};

const CORE_SQL: &str = "SELECT pg_catalog.current_database()::text AS \"database\", \
    pg_catalog.pg_is_in_recovery() AS \"inRecovery\", \
    CASE WHEN NOT pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_current_wal_lsn()::text END AS \"currentLsn\", \
    CASE WHEN pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_last_wal_receive_lsn()::text END AS \"receiveLsn\", \
    CASE WHEN pg_catalog.pg_is_in_recovery() THEN pg_catalog.pg_last_wal_replay_lsn()::text END AS \"replayLsn\", \
    CASE WHEN pg_catalog.pg_is_in_recovery() THEN \
    ROUND(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp() - pg_catalog.pg_last_xact_replay_timestamp())::numeric, 3)::float8 \
    END AS \"replayLagSeconds\"";
const STANDBYS_SQL: &str = "SELECT r.pid, r.usename AS \"user\", r.application_name AS \"application\", \
    r.client_addr::text AS \"clientAddr\", r.state, r.sync_state AS \"syncState\", \
    r.sent_lsn::text AS \"sentLsn\", r.write_lsn::text AS \"writeLsn\", r.flush_lsn::text AS \"flushLsn\", \
    r.replay_lsn::text AS \"replayLsn\", \
    ROUND((EXTRACT(EPOCH FROM r.write_lag) * 1000)::numeric, 3)::float8 AS \"writeLagMs\", \
    ROUND((EXTRACT(EPOCH FROM r.flush_lag) * 1000)::numeric, 3)::float8 AS \"flushLagMs\", \
    ROUND((EXTRACT(EPOCH FROM r.replay_lag) * 1000)::numeric, 3)::float8 AS \"replayLagMs\", \
    CASE WHEN NOT pg_catalog.pg_is_in_recovery() \
    THEN pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_lsn(), r.replay_lsn)::bigint END AS \"lagBytes\" \
    FROM pg_catalog.pg_stat_replication r ORDER BY r.pid";
const WAL_RECEIVER_SQL: &str = "SELECT w.status, w.sender_host AS \"senderHost\", \
    w.sender_port AS \"senderPort\", w.slot_name AS \"slotName\", w.flushed_lsn::text AS \"flushedLsn\", \
    w.latest_end_lsn::text AS \"latestEndLsn\", w.last_msg_receipt_time AS \"lastMsgReceiptTime\" \
    FROM pg_catalog.pg_stat_wal_receiver w";
const PUBLICATIONS_SQL: &str = "SELECT p.pubname AS \"name\", pg_catalog.pg_get_userbyid(p.pubowner)::text AS \"owner\", \
    p.puballtables AS \"allTables\", p.pubinsert AS \"insert\", p.pubupdate AS \"update\", \
    p.pubdelete AS \"delete\", p.pubtruncate AS \"truncate\", \
    CASE WHEN p.puballtables THEN (SELECT count(*) FROM pg_catalog.pg_class c \
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE c.relkind IN ('r', 'p') AND n.nspname NOT IN ('pg_catalog', 'information_schema') \
    AND NOT starts_with(n.nspname, 'pg_toast')) \
    ELSE (SELECT count(*) FROM pg_catalog.pg_publication_rel pr WHERE pr.prpubid = p.oid) END AS \"tables\" \
    FROM pg_catalog.pg_publication p ORDER BY p.pubname";
const SUBSCRIPTIONS_SQL: &str = "SELECT s.subname AS \"name\", pg_catalog.pg_get_userbyid(s.subowner)::text AS \"owner\", \
    s.subenabled AS \"enabled\", s.subpublications AS \"publications\", s.subslotname::text AS \"slotName\" \
    FROM pg_catalog.pg_subscription s \
    WHERE s.subdbid = (SELECT db.oid FROM pg_catalog.pg_database db WHERE db.datname = pg_catalog.current_database()) \
    ORDER BY s.subname";
/// Columns of pg_replication_slots that only some server versions have.
const SLOT_OPTIONAL: [&str; 3] = ["two_phase", "failover", "invalidation_reason"];

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplicationArgs {
    pub database: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReplicationResult {
    pub database: String,
    pub in_recovery: bool,
    pub role: String,
    pub current_lsn: Option<String>,
    pub receive_lsn: Option<String>,
    pub replay_lsn: Option<String>,
    pub replay_lag_seconds: Option<f64>,
    pub standbys: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub standbys_error: Option<String>,
    pub slots: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slots_error: Option<String>,
    pub wal_receiver: Option<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wal_receiver_error: Option<String>,
    pub publications: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publications_error: Option<String>,
    pub subscriptions: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subscriptions_error: Option<String>,
    pub warnings: Vec<String>,
}

pub async fn replication_status(
    state: &AppState,
    args: ReplicationArgs,
    ct: &CancellationToken,
) -> Call {
    match replication_of(state, &args, ct).await {
        Ok(result) => {
            let database = Some(result.database.clone());
            Call {
                result: value_of(&result),
                database,
                rows: None,
                sql: None,
            }
        }
        Err(error) => fail(error, state, args.database.as_deref()),
    }
}

async fn replication_of(
    state: &AppState,
    args: &ReplicationArgs,
    ct: &CancellationToken,
) -> Result<ReplicationResult, ToolError> {
    let database = args.database.as_deref();
    let core = wide_rows(state, database, CORE_SQL, &[], ct).await?;
    let row = core
        .rows
        .first()
        .ok_or_else(|| ToolError::Internal("the server returned no replication row".to_owned()))?;
    let in_recovery = row
        .get("inRecovery")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let text = |key: &str| row.get(key).and_then(Value::as_str).map(str::to_owned);
    let replay_lag_seconds = row.get("replayLagSeconds").and_then(Value::as_f64);
    let (current_lsn, receive_lsn, replay_lsn) =
        (text("currentLsn"), text("receiveLsn"), text("replayLsn"));
    let database_name = core.database.clone();

    let (standbys, standbys_error) = optional_rows(state, database, STANDBYS_SQL, ct).await?;
    let (slots, slots_error) = slots_section(state, database, ct).await?;
    let (wal_receiver, wal_receiver_error) =
        match optional_rows(state, database, WAL_RECEIVER_SQL, ct).await? {
            (Some(rows), error) => (rows.into_iter().next(), error),
            (None, error) => (None, error),
        };
    let (publications, publications_error) =
        optional_rows(state, database, PUBLICATIONS_SQL, ct).await?;
    let (subscriptions, subscriptions_error) =
        optional_rows(state, database, SUBSCRIPTIONS_SQL, ct).await?;

    let warnings = slots.as_deref().map(slot_warnings).unwrap_or_default();
    Ok(ReplicationResult {
        database: database_name,
        in_recovery,
        role: if in_recovery { "standby" } else { "primary" }.to_owned(),
        current_lsn,
        receive_lsn,
        replay_lsn,
        replay_lag_seconds,
        standbys,
        standbys_error,
        slots,
        slots_error,
        wal_receiver,
        wal_receiver_error,
        publications,
        publications_error,
        subscriptions,
        subscriptions_error,
        warnings,
    })
}

/// The rows of a section that some roles may not read: None with the error text when PostgreSQL refuses.
async fn optional_rows(
    state: &AppState,
    database: Option<&str>,
    sql: &str,
    ct: &CancellationToken,
) -> Result<(Option<Vec<Map<String, Value>>>, Option<String>), ToolError> {
    match wide_rows(state, database, sql, &[], ct).await {
        Ok(envelope) => Ok((Some(envelope.rows), None)),
        Err(error) if matches!(error, ToolError::Db(_)) => Ok((None, Some(error.message()))),
        Err(error) => Err(error),
    }
}

async fn slots_section(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<(Option<Vec<Map<String, Value>>>, Option<String>), ToolError> {
    let present = present_columns(
        state,
        database,
        "pg_catalog.pg_replication_slots",
        &SLOT_OPTIONAL,
        ct,
    )
    .await?;
    let has = |name: &str| present.iter().any(|column| column == name);
    let mut items = vec![
        "s.slot_name AS \"name\"".to_owned(),
        "s.slot_type AS \"type\"".to_owned(),
        "s.plugin".to_owned(),
        "s.database".to_owned(),
        "s.active".to_owned(),
        "s.temporary".to_owned(),
        "s.restart_lsn::text AS \"restartLsn\"".to_owned(),
        "s.confirmed_flush_lsn::text AS \"confirmedFlushLsn\"".to_owned(),
        "s.wal_status AS \"walStatus\"".to_owned(),
        "s.safe_wal_size::bigint AS \"safeWalSize\"".to_owned(),
        "CASE WHEN NOT pg_catalog.pg_is_in_recovery() AND s.restart_lsn IS NOT NULL \
        THEN pg_catalog.pg_wal_lsn_diff(pg_catalog.pg_current_wal_lsn(), s.restart_lsn)::bigint END AS \"retainedBytes\""
            .to_owned(),
    ];
    for (column, alias) in [
        ("two_phase", "twoPhase"),
        ("failover", "failover"),
        ("invalidation_reason", "invalidationReason"),
    ] {
        if has(column) {
            items.push(format!("s.{column} AS \"{alias}\""));
        }
    }
    let sql = format!(
        "SELECT {} FROM pg_catalog.pg_replication_slots s ORDER BY s.slot_name",
        items.join(", ")
    );
    optional_rows(state, database, &sql, ct).await
}

/// Warnings for inactive slots that hold WAL and for slots whose WAL is at risk or lost.
fn slot_warnings(slots: &[Map<String, Value>]) -> Vec<String> {
    let mut warnings = Vec::new();
    for slot in slots {
        let name = slot.get("name").and_then(Value::as_str).unwrap_or_default();
        let retained = slot
            .get("retainedBytes")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if slot.get("active").and_then(Value::as_bool) == Some(false) && retained > 0 {
            warnings.push(format!(
                "replication slot {name} is inactive and retains {retained} bytes of WAL."
            ));
        }
        if let Some(status) = slot.get("walStatus").and_then(Value::as_str)
            && matches!(status, "unreserved" | "lost")
        {
            warnings.push(format!("replication slot {name} has walStatus {status}."));
        }
        if let Some(reason) = slot.get("invalidationReason").and_then(Value::as_str) {
            warnings.push(format!(
                "replication slot {name} was invalidated: {reason}."
            ));
        }
    }
    warnings
}
