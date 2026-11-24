//! list_continuous_aggregates: each continuous aggregate with its source, definition, refresh policy and watermark.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio_util::sync::CancellationToken;

use super::probe::{self, Sources};
use super::{
    CAGG_COLUMNS, DEFAULT_LIMIT, JOB_COLUMNS, JOB_STATS_COLUMNS, Page, first_row, query, section,
    text_of, unavailable,
};
use crate::server::AppState;
use crate::tools::text;
use crate::tools::{Call, ToolError, value_of};

/// Schema of the TimescaleDB internal functions that report the watermark.
const FUNCTIONS_SCHEMA: &str = "_timescaledb_functions";

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListResult {
    pub database: String,
    pub timescaledb: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    #[serde(flatten)]
    pub detail: Option<ListDetail>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListDetail {
    pub version: String,
    pub continuous_aggregates: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub warnings: Vec<String>,
}

impl ListResult {
    fn absent(database: String) -> ListResult {
        ListResult {
            database,
            timescaledb: false,
            note: Some(text::NOT_INSTALLED_TIMESCALE),
            detail: None,
        }
    }
}

/// The page of aggregates. The refresh policy is one jsonb object built in SQL; the materialization
/// schema and name are returned for the watermark call and removed from the rows afterwards.
fn list_sql(sources: &Sources, window: &str) -> String {
    let flag = sources
        .cagg_flag
        .map(|column| {
            let key = if column == "columnstore_enabled" {
                "columnstoreEnabled"
            } else {
                "compressionEnabled"
            };
            format!(", ca.{column} AS \"{key}\"")
        })
        .unwrap_or_default();
    let finalized = if sources.cagg_finalized {
        ", ca.finalized AS \"finalized\""
    } else {
        ""
    };
    format!(
        "SELECT ca.view_schema::text AS \"schema\", ca.view_name::text AS \"name\", \
         ca.view_owner::text AS \"owner\", pg_catalog.obj_description(vc.oid, 'pg_class') AS \"comment\", \
         ca.hypertable_schema::text || '.' || ca.hypertable_name::text AS \"hypertable\", \
         ca.materialized_only AS \"materializedOnly\", NOT ca.materialized_only AS \"realTime\"{flag}{finalized}, \
         ca.view_definition AS \"definition\", \
         ca.materialization_hypertable_schema::text || '.' || ca.materialization_hypertable_name::text AS \"materializationHypertable\", \
         ca.materialization_hypertable_schema::text AS \"materializationSchema\", \
         ca.materialization_hypertable_name::text AS \"materializationName\", \
         CASE WHEN rp.job_id IS NULL THEN NULL ELSE pg_catalog.jsonb_build_object('jobId', rp.job_id, \
           'schedule', rp.schedule, 'startOffset', rp.config ->> 'start_offset', 'endOffset', rp.config ->> 'end_offset', \
           'nextStart', rp.next_start, 'lastRunStatus', rp.last_run_status) END AS \"refreshPolicy\" \
         FROM timescaledb_information.continuous_aggregates ca \
         JOIN pg_catalog.pg_namespace vn ON vn.nspname = ca.view_schema \
         JOIN pg_catalog.pg_class vc ON vc.relnamespace = vn.oid AND vc.relname = ca.view_name \
         LEFT JOIN LATERAL (SELECT j.job_id, j.schedule_interval::text AS schedule, j.config, \
           j.next_start::text AS next_start, s.last_run_status::text AS last_run_status \
           FROM timescaledb_information.jobs j \
           LEFT JOIN timescaledb_information.job_stats s ON s.job_id = j.job_id \
           WHERE j.proc_name = 'policy_refresh_continuous_aggregate' \
           AND j.hypertable_schema = ca.view_schema AND j.hypertable_name = ca.view_name \
           ORDER BY j.job_id LIMIT 1) rp ON true \
         WHERE ($1::text IS NULL OR ca.view_schema::text = $1::text) \
         ORDER BY ca.view_schema, ca.view_name {window}"
    )
}

/// The watermark of one aggregate as text: a timestamp for timestamptz time, the integer otherwise.
/// Takes the materialization schema and name as $1 and $2.
fn watermark_sql(cagg_watermark: &str, hypertable_info: &str) -> String {
    format!(
        "WITH mat AS (SELECT c.oid FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = $1::text AND c.relname = $2::text), \
         wm AS (SELECT {cagg_watermark}(({hypertable_info}(mat.oid)).hypertable_id) AS w FROM mat) \
         SELECT CASE WHEN d.column_type::text = 'timestamp with time zone' \
           THEN pg_catalog.to_timestamp(wm.w::float8 / 1000000.0)::text \
           WHEN d.column_type::text IN ('smallint', 'integer', 'bigint') THEN wm.w::text END AS \"watermark\" \
         FROM wm LEFT JOIN timescaledb_information.dimensions d \
         ON d.hypertable_schema::text = $1::text AND d.hypertable_name::text = $2::text AND d.dimension_number = 1"
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
        .map(|detail| detail.continuous_aggregates.len());
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
    let page = Page::new(args.limit, DEFAULT_LIMIT, "limit", args.cursor.as_deref())?;
    let features = probe::load(state, args.database.as_deref(), ct).await?;
    if !features.installed() {
        return Ok(ListResult::absent(features.database));
    }
    features.require("continuous_aggregates", CAGG_COLUMNS)?;
    features.require("jobs", JOB_COLUMNS)?;
    features.require("job_stats", JOB_STATS_COLUMNS)?;
    let sources = Sources::choose(&features);
    let database = features.database.clone();
    let target = Some(database.as_str());
    let sql = list_sql(&sources, &page.window());
    let mut rows = query(state, target, &sql, &[args.schema.as_deref()], ct)
        .await?
        .rows;
    let next_cursor = page.trim(&mut rows);

    let mut warnings = Vec::new();
    let watermark = match (
        features.function(FUNCTIONS_SCHEMA, "cagg_watermark"),
        features.function(FUNCTIONS_SCHEMA, "get_hypertable_info"),
    ) {
        (Some(cagg_watermark), Some(hypertable_info)) => {
            Some(watermark_sql(&cagg_watermark, &hypertable_info))
        }
        _ => {
            unavailable(&mut warnings, "cagg_watermark");
            None
        }
    };
    for row in rows.iter_mut() {
        let label = format!(
            "{}.{} watermark",
            text_of(row, "schema").unwrap_or_default(),
            text_of(row, "name").unwrap_or_default()
        );
        let materialized = (
            take_text(row, "materializationSchema"),
            take_text(row, "materializationName"),
        );
        let value = match (&watermark, materialized) {
            (Some(sql), (Some(schema), Some(name))) => {
                let params = [Some(schema.as_str()), Some(name.as_str())];
                let found = section(state, target, sql, &params, &label, ct, &mut warnings).await?;
                first_row(found)
                    .and_then(|found| found.get("watermark").cloned())
                    .unwrap_or(Value::Null)
            }
            _ => Value::Null,
        };
        row.insert("watermark".to_owned(), value);
    }

    Ok(ListResult {
        database,
        timescaledb: true,
        note: None,
        detail: Some(ListDetail {
            version: features.version.clone().unwrap_or_default(),
            continuous_aggregates: rows,
            next_cursor,
            warnings,
        }),
    })
}

/// Removes a key from a row and returns its text value.
fn take_text(row: &mut Map<String, Value>, key: &str) -> Option<String> {
    row.remove(key)?.as_str().map(str::to_owned)
}
