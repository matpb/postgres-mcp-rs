//! list_jobs: TimescaleDB background jobs, and with history their recent runs or failed runs.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::probe::{self, Sources};
use super::{
    DEFAULT_LIMIT, ERRORS_COLUMNS, HISTORY_COLUMNS, JOB_COLUMNS, JOB_STATS_COLUMNS, Page,
    job_kind_sql, query,
};
use crate::server::AppState;
use crate::tools::text;
use crate::tools::{Call, ToolError, value_of};

const VISIBILITY_NOTE: &str =
    "Job history is visible only to the job owner, members of its role, or the database owner.";
const FAILURES_ONLY_NOTE: &str = "This TimescaleDB version records failed runs only.";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    pub database: Option<String>,
    /// Only this job.
    pub job_id: Option<i32>,
    /// Return recent runs instead of the job list.
    pub history: Option<bool>,
    /// With history: only failed runs.
    pub only_failures: Option<bool>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListResult {
    pub database: String,
    pub timescaledb: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(flatten)]
    pub detail: Option<ListDetail>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListDetail {
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jobs: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runs: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl ListResult {
    fn absent(database: String) -> ListResult {
        ListResult {
            database,
            timescaledb: false,
            note: Some(text::NOT_INSTALLED_TIMESCALE.to_owned()),
            detail: None,
        }
    }
}

/// The job list: one row per job with its procedure, schedule, configuration and run totals.
fn jobs_sql(sources: &Sources, window: &str) -> String {
    let fixed = if sources.job_fixed_schedule {
        "j.fixed_schedule AS \"fixedSchedule\", "
    } else {
        ""
    };
    format!(
        "SELECT j.job_id AS \"jobId\", j.application_name::text AS \"applicationName\", {kind} AS \"kind\", \
         j.proc_schema::text || '.' || j.proc_name::text AS \"procedure\", j.owner::text AS \"owner\", \
         j.scheduled AS \"scheduled\", j.schedule_interval::text AS \"schedule\", j.max_runtime::text AS \"maxRuntime\", \
         j.max_retries AS \"maxRetries\", j.retry_period::text AS \"retryPeriod\", {fixed}j.config AS \"config\", \
         j.hypertable_schema::text || '.' || j.hypertable_name::text AS \"hypertable\", j.next_start::text AS \"nextStart\", \
         s.last_run_started_at::text AS \"lastRunStartedAt\", s.last_run_status::text AS \"lastRunStatus\", \
         s.last_successful_finish::text AS \"lastSuccessfulFinish\", s.last_run_duration::text AS \"lastRunDuration\", \
         s.total_runs AS \"totalRuns\", s.total_successes AS \"totalSuccesses\", s.total_failures AS \"totalFailures\" \
         FROM timescaledb_information.jobs j \
         LEFT JOIN timescaledb_information.job_stats s ON s.job_id = j.job_id \
         WHERE ($1::integer IS NULL OR j.job_id = $1::integer) \
         ORDER BY j.job_id {window}",
        kind = job_kind_sql("j")
    )
}

/// Runs from job_history, which holds successes and failures; $2 true keeps only runs that did not succeed.
fn history_sql(window: &str) -> String {
    format!(
        "SELECT h.job_id AS \"jobId\", h.proc_schema::text || '.' || h.proc_name::text AS \"procedure\", \
         h.pid AS \"pid\", h.start_time::text AS \"startedAt\", h.finish_time::text AS \"finishedAt\", \
         (EXTRACT(EPOCH FROM (h.finish_time - h.start_time)) * 1000)::bigint AS \"durationMs\", \
         h.succeeded AS \"succeeded\", h.sqlerrcode::text AS \"sqlstate\", h.err_message AS \"errorMessage\" \
         FROM timescaledb_information.job_history h \
         WHERE ($1::integer IS NULL OR h.job_id = $1::integer) \
         AND (NOT $2::boolean OR h.succeeded IS NOT TRUE) \
         ORDER BY h.start_time DESC, h.id DESC {window}"
    )
}

/// Runs from job_errors on versions without job_history: failed runs only.
fn errors_sql(window: &str) -> String {
    format!(
        "SELECT e.job_id AS \"jobId\", e.proc_schema::text || '.' || e.proc_name::text AS \"procedure\", \
         e.pid AS \"pid\", e.start_time::text AS \"startedAt\", e.finish_time::text AS \"finishedAt\", \
         (EXTRACT(EPOCH FROM (e.finish_time - e.start_time)) * 1000)::bigint AS \"durationMs\", \
         false AS \"succeeded\", e.sqlerrcode::text AS \"sqlstate\", e.err_message AS \"errorMessage\" \
         FROM timescaledb_information.job_errors e \
         WHERE ($1::integer IS NULL OR e.job_id = $1::integer) \
         ORDER BY e.start_time DESC, e.job_id DESC, e.pid DESC {window}"
    )
}

pub async fn list(state: &AppState, args: ListArgs, ct: &CancellationToken) -> Call {
    let result = list_of(state, &args, ct).await;
    let database = match &result {
        Ok(listed) => Some(listed.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    let rows = result
        .as_ref()
        .ok()
        .and_then(|listed| listed.detail.as_ref())
        .and_then(|detail| detail.jobs.as_ref().or(detail.runs.as_ref()))
        .map(Vec::len);
    Call {
        result: result.and_then(|listed| value_of(&listed)),
        database,
        rows,
        sql: None,
    }
}

async fn list_of(
    state: &AppState,
    args: &ListArgs,
    ct: &CancellationToken,
) -> Result<ListResult, ToolError> {
    let history = args.history.unwrap_or(false);
    let only_failures = history && args.only_failures.unwrap_or(false);
    let page = Page::new(args.limit, DEFAULT_LIMIT, "limit", args.cursor.as_deref())?;
    let features = probe::load(state, args.database.as_deref(), ct).await?;
    if !features.installed() {
        return Ok(ListResult::absent(features.database));
    }
    let database = features.database.clone();
    let target = Some(database.as_str());
    let version = features.version.clone().unwrap_or_default();
    let job_id = args.job_id.map(|id| id.to_string());
    let job_param = job_id.as_deref();
    let sources = Sources::choose(&features);

    if !history {
        features.require("jobs", JOB_COLUMNS)?;
        features.require("job_stats", JOB_STATS_COLUMNS)?;
        let sql = jobs_sql(&sources, &page.window());
        let mut rows = query(state, target, &sql, &[job_param], ct).await?.rows;
        let next_cursor = page.trim(&mut rows);
        return Ok(ListResult {
            database,
            timescaledb: true,
            note: None,
            detail: Some(ListDetail {
                version,
                jobs: Some(rows),
                source: None,
                runs: None,
                next_cursor,
            }),
        });
    }

    let window = page.window();
    let (source, mut runs, mut notes) = if features.has_all("job_history", HISTORY_COLUMNS) {
        let sql = history_sql(&window);
        let rows = query(
            state,
            target,
            &sql,
            &[job_param, Some(bool_text(only_failures))],
            ct,
        )
        .await?
        .rows;
        ("job_history", rows, Vec::new())
    } else {
        features.require("job_errors", ERRORS_COLUMNS)?;
        let sql = errors_sql(&window);
        let rows = query(state, target, &sql, &[job_param], ct).await?.rows;
        ("job_errors", rows, vec![FAILURES_ONLY_NOTE])
    };
    let next_cursor = page.trim(&mut runs);
    if runs.is_empty() {
        notes.push(VISIBILITY_NOTE);
    }
    let note = (!notes.is_empty()).then(|| notes.join(" "));
    Ok(ListResult {
        database,
        timescaledb: true,
        note,
        detail: Some(ListDetail {
            version,
            jobs: None,
            source: Some(source),
            runs: Some(runs),
            next_cursor,
        }),
    })
}

/// The text of a boolean bind value.
fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}
