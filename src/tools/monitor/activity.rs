//! list_activity: sessions from pg_stat_activity with lock waits and the query text policy.

use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::{
    bool_text, bounded, fail, flag, hidden_text_note, shape_query, text_visibility, wide_rows,
};
use crate::server::AppState;
use crate::tools::{Call, ToolError, value_of};

const STATES: [&str; 4] = [
    "active",
    "idle",
    "idle in transaction",
    "idle in transaction (aborted)",
];

/// Sessions of this database, with lock waits resolved; one row per session.
const ACTIVITY_SQL: &str = "WITH base AS (\
    SELECT a.pid, a.usename, a.datname, a.application_name, a.client_addr, a.backend_type, a.state, \
    a.wait_event_type, a.wait_event, a.backend_start, a.xact_start, a.query_start, a.state_change, \
    a.query, a.query_id, pg_catalog.pg_blocking_pids(a.pid) AS blocked_by \
    FROM pg_catalog.pg_stat_activity a \
    WHERE ($1::boolean OR a.datname = pg_catalog.current_database() OR a.datname IS NULL) \
    AND ($2::boolean OR a.backend_type = 'client backend') \
    AND ($3::text IS NULL OR a.state = $3::text) \
    AND ($4::bigint IS NULL OR EXTRACT(EPOCH FROM pg_catalog.clock_timestamp() - \
    CASE WHEN pg_catalog.starts_with(a.state, 'idle in transaction') THEN a.xact_start ELSE a.query_start END) * 1000 >= $4::bigint) \
    AND ($5::text IS NULL OR a.usename = $5::text)), \
    kept AS (SELECT b.* FROM base b WHERE NOT $6::boolean OR pg_catalog.cardinality(b.blocked_by) > 0 \
    OR b.pid IN (SELECT pg_catalog.unnest(x.blocked_by) FROM base x)) \
    SELECT k.pid, k.usename AS \"user\", k.datname AS \"database\", k.application_name AS \"application\", \
    k.client_addr::text AS \"clientAddr\", k.backend_type AS \"backendType\", k.state, \
    k.wait_event_type AS \"waitEventType\", k.wait_event AS \"waitEvent\", k.backend_start AS \"backendStart\", \
    k.xact_start AS \"xactStart\", k.query_start AS \"queryStart\", k.state_change AS \"stateChange\", \
    pg_catalog.FLOOR(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp() - k.xact_start) * 1000)::bigint AS \"xactAgeMs\", \
    pg_catalog.FLOOR(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp() - k.query_start) * 1000)::bigint AS \"queryAgeMs\", \
    k.query, NULL::boolean AS \"queryTruncated\", k.query_id::text AS \"queryId\", \
    k.blocked_by AS \"blockedBy\", NULL::int[] AS blocking, \
    (k.pid = pg_catalog.pg_backend_pid()) AS \"isSelf\", pg_catalog.count(*) OVER () AS total \
    FROM kept k ORDER BY (k.state = 'active') DESC NULLS LAST, \"queryAgeMs\" DESC NULLS LAST, k.pid";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListActivityArgs {
    pub database: Option<String>,
    pub state: Option<String>,
    pub min_duration_ms: Option<i64>,
    pub user: Option<String>,
    pub all_databases: Option<bool>,
    pub only_blocked: Option<bool>,
    pub include_background: Option<bool>,
    pub query_chars: Option<i64>,
    pub limit: Option<i64>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListActivityResult {
    pub database: String,
    pub sessions: Vec<Map<String, Value>>,
    pub total: i64,
    pub query_text_visible: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub async fn list_activity(
    state: &AppState,
    args: ListActivityArgs,
    ct: &CancellationToken,
) -> Call {
    match activity_of(state, &args, ct).await {
        Ok(result) => {
            let rows = result.sessions.len();
            let database = Some(result.database.clone());
            Call {
                result: value_of(&result),
                database,
                rows: Some(rows),
                sql: None,
            }
        }
        Err(error) => fail(error, state, args.database.as_deref()),
    }
}

async fn activity_of(
    state: &AppState,
    args: &ListActivityArgs,
    ct: &CancellationToken,
) -> Result<ListActivityResult, ToolError> {
    if let Some(name) = &args.state
        && !STATES.contains(&name.as_str())
    {
        return Err(ToolError::Rejected(format!(
            "Invalid state \"{name}\". Valid states: {}.",
            STATES.join(", ")
        )));
    }
    let query_chars =
        usize::try_from(bounded("query_chars", args.query_chars, 500, 0, 4000)?).unwrap_or(0);
    let limit = bounded("limit", args.limit, 100, 1, 500)?;
    let min_duration = args.min_duration_ms.map(|ms| ms.to_string());
    let params: [Option<&str>; 6] = [
        Some(bool_text(flag(args.all_databases))),
        Some(bool_text(flag(args.include_background))),
        args.state.as_deref(),
        min_duration.as_deref(),
        args.user.as_deref(),
        Some(bool_text(flag(args.only_blocked))),
    ];
    let sql = format!("{ACTIVITY_SQL} LIMIT {limit}");
    let envelope = wide_rows(state, args.database.as_deref(), &sql, &params, ct).await?;
    let visibility = text_visibility(state, args.database.as_deref(), ct).await?;

    let total = envelope
        .rows
        .first()
        .and_then(|row| row.get("total"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let mut sessions = envelope.rows;
    let blocking = blocking_map(&sessions);
    for row in &mut sessions {
        row.remove("total");
        shape_query(row, query_chars);
        let pid = row.get("pid").and_then(Value::as_i64);
        let blocks = pid
            .and_then(|pid| blocking.get(&pid))
            .map(|pids| pids.iter().copied().map(Value::from).collect())
            .unwrap_or_default();
        row.insert("blocking".to_owned(), Value::Array(blocks));
    }
    Ok(ListActivityResult {
        database: envelope.database,
        sessions,
        total,
        query_text_visible: visibility.visible,
        note: (!visibility.visible).then(|| hidden_text_note(&visibility.role)),
    })
}

/// For each session pid, the pids of the listed sessions it blocks, ascending.
fn blocking_map(sessions: &[Map<String, Value>]) -> BTreeMap<i64, Vec<i64>> {
    let mut blocking: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for row in sessions {
        let Some(pid) = row.get("pid").and_then(Value::as_i64) else {
            continue;
        };
        let blockers = row
            .get("blockedBy")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_i64);
        for blocker in blockers {
            blocking.entry(blocker).or_default().push(pid);
        }
    }
    for pids in blocking.values_mut() {
        pids.sort_unstable();
    }
    blocking
}
