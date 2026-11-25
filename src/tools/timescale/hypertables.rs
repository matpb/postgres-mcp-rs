//! list_hypertables and describe_hypertable: the hypertables of a database and one hypertable in detail.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use super::parse::{parse_name_list, parse_orderby};
use super::probe::{self, Features, Sources};
use super::{
    CAGG_COLUMNS, CHUNK_COLUMNS, DEFAULT_CHUNK_LIMIT, DEFAULT_LIMIT, DIMENSION_COLUMNS,
    JOB_COLUMNS, JOB_STATS_COLUMNS, Page, RELATION_OID_SQL, add_per_relation, cell,
    checked_section, first_row, job_kind_sql, query, section, text_of, unavailable,
};
use crate::server::AppState;
use crate::tools::text;
use crate::tools::{Call, ToolError, value_of};

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ListArgs {
    pub database: Option<String>,
    pub schema: Option<String>,
    pub limit: Option<i64>,
    pub cursor: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescribeArgs {
    pub database: Option<String>,
    pub hypertable: String,
    pub schema: Option<String>,
    pub chunk_limit: Option<i64>,
    pub chunk_cursor: Option<String>,
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
    pub hypertables: Vec<Map<String, Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DescribeResult {
    pub database: String,
    pub timescaledb: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<&'static str>,
    #[serde(flatten)]
    pub detail: Option<DescribeDetail>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DescribeDetail {
    pub version: String,
    pub schema: String,
    pub name: String,
    pub owner: String,
    pub comment: Option<String>,
    pub dimensions: Option<Vec<Map<String, Value>>>,
    pub columnstore: Option<Value>,
    pub sizes: Value,
    pub approximate_rows: Value,
    pub policies: Option<Vec<Map<String, Value>>>,
    pub continuous_aggregates: Option<Vec<String>>,
    pub chunks: Option<Vec<Map<String, Value>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_chunk_cursor: Option<String>,
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

impl DescribeResult {
    fn absent(database: String) -> DescribeResult {
        DescribeResult {
            database,
            timescaledb: false,
            note: Some(text::NOT_INSTALLED_TIMESCALE),
            detail: None,
        }
    }
}

const DIMENSION_SQL: &str = "SELECT d.column_name::text AS \"column\", d.column_type::text AS \"type\", \
    CASE WHEN d.dimension_type = 'Time' THEN 'time' ELSE 'space' END AS \"kind\", \
    COALESCE(pg_catalog.to_jsonb(d.time_interval::text), pg_catalog.to_jsonb(d.integer_interval)) AS \"interval\", \
    d.num_partitions AS \"partitions\" \
    FROM timescaledb_information.dimensions d \
    WHERE d.hypertable_schema::text = $1::text AND d.hypertable_name::text = $2::text \
    ORDER BY d.dimension_number";
const CAGG_LIST_SQL: &str = "SELECT ca.view_schema::text || '.' || ca.view_name::text AS \"view\" \
    FROM timescaledb_information.continuous_aggregates ca \
    WHERE ca.hypertable_schema::text = $1::text AND ca.hypertable_name::text = $2::text \
    ORDER BY ca.view_schema, ca.view_name";
const REGULAR_TABLE_SQL: &str = "SELECT n.nspname::text AS \"schema\", c.relname::text AS \"name\" \
    FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE c.relname = $1::text AND ($2::text IS NULL OR n.nspname = $2::text) \
    AND c.relkind IN ('r', 'p') AND NOT pg_catalog.starts_with(n.nspname::text, 'pg_') \
    AND n.nspname <> 'information_schema' AND NOT pg_catalog.starts_with(n.nspname::text, '_timescaledb_') \
    ORDER BY n.nspname LIMIT 1";
/// Hypertables are the relations that have a dimension: timescaledb_information.hypertables omits the
/// storage of continuous aggregates in this version, dimensions does not.
const RESOLVE_SQL: &str = "SELECT DISTINCT d.hypertable_schema::text AS \"schema\", d.hypertable_name::text AS \"name\" \
    FROM timescaledb_information.dimensions d \
    WHERE d.hypertable_name::text = $1::text AND ($2::text IS NULL OR d.hypertable_schema::text = $2::text) \
    ORDER BY 1, 2";

/// The `hypertables` join that supplies the columnstore flag, and the flag expression; both empty when the version has no flag.
fn flag_join(sources: &Sources, schema: &str, name: &str) -> (String, Option<String>) {
    match sources.hypertable_flag {
        Some(flag) => (
            format!(
                " LEFT JOIN timescaledb_information.hypertables h ON h.hypertable_schema = {schema} \
                 AND h.hypertable_name = {name}"
            ),
            Some(format!("COALESCE(h.{flag}, false)")),
        ),
        None => (String::new(), None),
    }
}

/// The list rows: hypertables ordered by schema and name, internal storage excluded unless its schema is named.
fn list_sql(sources: &Sources, window: &str) -> String {
    let (join, flag) = flag_join(sources, "ht.hypertable_schema", "ht.hypertable_name");
    let enabled = flag
        .map(|expr| format!("{expr} AS \"columnstoreEnabled\", "))
        .unwrap_or_default();
    format!(
        "SELECT ht.hypertable_schema::text AS \"schema\", ht.hypertable_name::text AS \"name\", \
         pg_catalog.pg_get_userbyid(c.relowner)::text AS \"owner\", pg_catalog.obj_description(c.oid, 'pg_class') AS \"comment\", \
         td.column_name::text AS \"timeColumn\", td.column_type::text AS \"timeColumnType\", \
         COALESCE(pg_catalog.to_jsonb(td.time_interval::text), pg_catalog.to_jsonb(td.integer_interval)) AS \"chunkInterval\", \
         (SELECT pg_catalog.count(*) FROM timescaledb_information.dimensions dd \
           WHERE dd.hypertable_schema = ht.hypertable_schema AND dd.hypertable_name = ht.hypertable_name) AS \"dimensions\", \
         (SELECT pg_catalog.count(*) FROM timescaledb_information.chunks ch \
           WHERE ch.hypertable_schema = ht.hypertable_schema AND ch.hypertable_name = ht.hypertable_name) AS \"chunks\", \
         {enabled}EXISTS (SELECT 1 FROM timescaledb_information.continuous_aggregates ca \
           WHERE ca.materialization_hypertable_schema = ht.hypertable_schema \
           AND ca.materialization_hypertable_name = ht.hypertable_name) AS \"isContinuousAggregateStorage\" \
         FROM (SELECT DISTINCT d0.hypertable_schema, d0.hypertable_name FROM timescaledb_information.dimensions d0) ht \
         JOIN pg_catalog.pg_namespace n ON n.nspname = ht.hypertable_schema \
         JOIN pg_catalog.pg_class c ON c.relnamespace = n.oid AND c.relname = ht.hypertable_name \
         LEFT JOIN timescaledb_information.dimensions td ON td.hypertable_schema = ht.hypertable_schema \
           AND td.hypertable_name = ht.hypertable_name AND td.dimension_type = 'Time'{join} \
         WHERE ($1::text IS NULL AND NOT pg_catalog.starts_with(ht.hypertable_schema::text, '_timescaledb_')) \
           OR ht.hypertable_schema::text = $1::text \
         ORDER BY ht.hypertable_schema, ht.hypertable_name {window}"
    )
}

/// One hypertable's own facts: owner, comment and whether its columnstore is on.
fn details_sql(sources: &Sources) -> String {
    let (join, flag) = flag_join(sources, "n.nspname", "c.relname");
    let enabled = flag
        .map(|expr| format!(", {expr} AS \"enabled\""))
        .unwrap_or_else(|| ", false AS \"enabled\"".to_owned());
    format!(
        "SELECT pg_catalog.pg_get_userbyid(c.relowner)::text AS \"owner\", pg_catalog.obj_description(c.oid, 'pg_class') AS \"comment\"{enabled} \
         FROM pg_catalog.pg_class c \
         JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace{join} \
         WHERE n.nspname = $1::text AND c.relname = $2::text"
    )
}

/// The policies attached to one hypertable, with their kind and last run status.
fn policies_sql() -> String {
    format!(
        "SELECT j.job_id AS \"jobId\", {kind} AS \"kind\", j.proc_schema::text || '.' || j.proc_name::text AS \"procedure\", \
         j.schedule_interval::text AS \"schedule\", j.config AS \"config\", j.next_start::text AS \"nextStart\", \
         s.last_run_status::text AS \"lastRunStatus\" \
         FROM timescaledb_information.jobs j \
         LEFT JOIN timescaledb_information.job_stats s ON s.job_id = j.job_id \
         WHERE j.hypertable_schema::text = $1::text AND j.hypertable_name::text = $2::text \
         ORDER BY j.job_id",
        kind = job_kind_sql("j")
    )
}

/// The chunk page, newest first. With `sizes` the size function is joined once for the whole hypertable.
fn chunks_sql(sources: &Sources, sizes: Option<&str>, window: &str) -> String {
    let (with, total, join) = match sizes {
        Some(function) => (
            format!(
                "WITH ht AS ({RELATION_OID_SQL}), \
                 sz AS (SELECT s.chunk_schema, s.chunk_name, s.total_bytes FROM ht, {function}(ht.oid) s) "
            ),
            "sz.total_bytes",
            " LEFT JOIN sz ON sz.chunk_schema = c.chunk_schema AND sz.chunk_name = c.chunk_name",
        ),
        None => (String::new(), "NULL::bigint", ""),
    };
    let flag = sources
        .chunk_flag
        .map(|flag| format!(", c.{flag} AS \"isColumnstore\""))
        .unwrap_or_default();
    let tablespace = if sources.chunk_tablespace {
        ", c.chunk_tablespace::text AS \"tablespace\""
    } else {
        ""
    };
    format!(
        "{with}SELECT c.chunk_schema::text AS \"schema\", c.chunk_name::text AS \"name\", \
         COALESCE(c.range_start::text, c.range_start_integer::text) AS \"rangeStart\", \
         COALESCE(c.range_end::text, c.range_end_integer::text) AS \"rangeEnd\"{flag}, \
         {total} AS \"totalBytes\"{tablespace} \
         FROM timescaledb_information.chunks c{join} \
         WHERE c.hypertable_schema::text = $1::text AND c.hypertable_name::text = $2::text \
         ORDER BY c.range_start DESC NULLS LAST, c.range_start_integer DESC NULLS LAST, c.chunk_schema, c.chunk_name {window}"
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
        .map(|detail| detail.hypertables.len());
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
    features.require("dimensions", DIMENSION_COLUMNS)?;
    features.require("continuous_aggregates", CAGG_COLUMNS)?;
    let sources = Sources::choose(&features);
    let database = features.database.clone();
    let target = Some(database.as_str());
    let sql = list_sql(&sources, &page.window());
    let mut hypertables = query(state, target, &sql, &[args.schema.as_deref()], ct)
        .await?
        .rows;
    let next_cursor = page.trim(&mut hypertables);
    let mut warnings = Vec::new();
    match features.extension_function("hypertable_size") {
        Some(function) => {
            add_per_relation(
                state,
                &database,
                &mut hypertables,
                "totalBytes",
                &function,
                ct,
                &mut warnings,
            )
            .await?
        }
        None => unavailable(&mut warnings, "hypertable_size"),
    }
    match features.extension_function("approximate_row_count") {
        Some(function) => {
            add_per_relation(
                state,
                &database,
                &mut hypertables,
                "approximateRows",
                &function,
                ct,
                &mut warnings,
            )
            .await?
        }
        None => unavailable(&mut warnings, "approximate_row_count"),
    }
    Ok(ListResult {
        database,
        timescaledb: true,
        note: None,
        detail: Some(ListDetail {
            version: features.version.clone().unwrap_or_default(),
            hypertables,
            next_cursor,
            warnings,
        }),
    })
}

pub async fn describe(state: &AppState, args: DescribeArgs, ct: &CancellationToken) -> Call {
    let result = describe_of(state, &args, ct).await;
    let database = match &result {
        Ok(described) => Some(described.database.clone()),
        Err(_) => state.resolve_name(args.database.as_deref()),
    };
    let rows = result
        .as_ref()
        .ok()
        .and_then(|described| described.detail.as_ref())
        .and_then(|detail| detail.chunks.as_ref())
        .map(Vec::len);
    Call {
        result: result.and_then(|described| value_of(&described)),
        database,
        rows,
        sql: None,
    }
}

async fn describe_of(
    state: &AppState,
    args: &DescribeArgs,
    ct: &CancellationToken,
) -> Result<DescribeResult, ToolError> {
    let page = Page::new(
        args.chunk_limit,
        DEFAULT_CHUNK_LIMIT,
        "chunk_limit",
        args.chunk_cursor.as_deref(),
    )?;
    let features = probe::load(state, args.database.as_deref(), ct).await?;
    if !features.installed() {
        return Ok(DescribeResult::absent(features.database));
    }
    let database = features.database.clone();
    let target = Some(database.as_str());
    let (schema, name) =
        resolve(state, target, &args.hypertable, args.schema.as_deref(), ct).await?;
    let params = [Some(schema.as_str()), Some(name.as_str())];
    let sources = Sources::choose(&features);
    let mut warnings = Vec::new();

    let details = first_row(Some(
        query(state, target, &details_sql(&sources), &params, ct)
            .await?
            .rows,
    ))
    .unwrap_or_default();
    let dimensions = checked_section(
        state,
        target,
        &features,
        &[("dimensions", DIMENSION_COLUMNS)],
        DIMENSION_SQL,
        &params,
        "dimensions",
        ct,
        &mut warnings,
    )
    .await?;
    let columnstore = match sources.settings_view {
        Some(view) => {
            columnstore_of(
                state,
                target,
                &features,
                &sources,
                view,
                &params,
                details
                    .get("enabled")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                ct,
                &mut warnings,
            )
            .await?
        }
        None => None,
    };
    // TimescaleDB's table_bytes is the heap alone; tableBytes adds TOAST, as pg_table_size does.
    let sizes = match features.extension_function("hypertable_detailed_size") {
        Some(function) => {
            let sql = format!(
                "WITH ht AS ({RELATION_OID_SQL}) SELECT s.total_bytes AS \"totalBytes\", \
                 s.table_bytes + s.toast_bytes AS \"tableBytes\", s.index_bytes AS \"indexBytes\", s.toast_bytes AS \"toastBytes\" \
                 FROM ht, {function}(ht.oid) s"
            );
            first_row(section(state, target, &sql, &params, "sizes", ct, &mut warnings).await?)
        }
        None => {
            unavailable(&mut warnings, "hypertable_detailed_size");
            None
        }
    };
    let approximate = match features.extension_function("approximate_row_count") {
        Some(function) => {
            let sql = format!(
                "WITH ht AS ({RELATION_OID_SQL}) SELECT {function}(ht.oid) AS \"value\" FROM ht"
            );
            first_row(
                section(
                    state,
                    target,
                    &sql,
                    &params,
                    "approximateRows",
                    ct,
                    &mut warnings,
                )
                .await?,
            )
        }
        None => {
            unavailable(&mut warnings, "approximate_row_count");
            None
        }
    };
    let policies = checked_section(
        state,
        target,
        &features,
        &[("jobs", JOB_COLUMNS), ("job_stats", JOB_STATS_COLUMNS)],
        &policies_sql(),
        &params,
        "policies",
        ct,
        &mut warnings,
    )
    .await?;
    let caggs: Option<Vec<String>> = checked_section(
        state,
        target,
        &features,
        &[("continuous_aggregates", CAGG_COLUMNS)],
        CAGG_LIST_SQL,
        &params,
        "continuousAggregates",
        ct,
        &mut warnings,
    )
    .await?
    .map(|rows| rows.iter().filter_map(|row| text_of(row, "view")).collect());
    let (chunks, next_chunk_cursor) = chunks_of(
        state,
        target,
        &features,
        &sources,
        &params,
        &page,
        ct,
        &mut warnings,
    )
    .await?;

    Ok(DescribeResult {
        database,
        timescaledb: true,
        note: None,
        detail: Some(DescribeDetail {
            version: features.version.clone().unwrap_or_default(),
            schema,
            name,
            owner: text_of(&details, "owner").unwrap_or_default(),
            comment: text_of(&details, "comment"),
            dimensions,
            columnstore,
            sizes: json!({
                "totalBytes": cell(&sizes, "totalBytes"),
                "tableBytes": cell(&sizes, "tableBytes"),
                "indexBytes": cell(&sizes, "indexBytes"),
                "toastBytes": cell(&sizes, "toastBytes"),
            }),
            approximate_rows: cell(&approximate, "value"),
            policies,
            continuous_aggregates: caggs,
            chunks,
            next_chunk_cursor,
            warnings,
        }),
    })
}

/// Finds the hypertable a caller named, as (schema, name). Errors quote the name as given.
async fn resolve(
    state: &AppState,
    target: Option<&str>,
    hypertable: &str,
    schema: Option<&str>,
    ct: &CancellationToken,
) -> Result<(String, String), ToolError> {
    let (inline_schema, name) = match hypertable.split_once('.') {
        Some((inline, name)) => (Some(inline), name),
        None => (None, hypertable),
    };
    let wanted = match (schema, inline_schema) {
        (Some(given), Some(inline)) if given != inline => {
            return Err(not_found(hypertable, None));
        }
        (Some(given), _) => Some(given),
        (None, inline) => inline,
    };
    let found = query(state, target, RESOLVE_SQL, &[Some(name), wanted], ct)
        .await?
        .rows;
    match found.as_slice() {
        [row] => Ok((
            text_of(row, "schema").unwrap_or_default(),
            text_of(row, "name").unwrap_or_default(),
        )),
        [] => {
            let tables = query(state, target, REGULAR_TABLE_SQL, &[Some(name), wanted], ct)
                .await?
                .rows;
            let regular = tables
                .first()
                .and_then(|row| Some((text_of(row, "schema")?, text_of(row, "name")?)));
            Err(not_found(hypertable, regular))
        }
        _ => Err(ToolError::Rejected(format!(
            "Hypertable \"{hypertable}\" exists in more than one schema: pass schema."
        ))),
    }
}

fn not_found(hypertable: &str, regular: Option<(String, String)>) -> ToolError {
    let mut message = format!("Hypertable \"{hypertable}\" not found.");
    if let Some((schema, name)) = regular {
        message.push_str(&format!(
            " \"{schema}.{name}\" is a regular table, not a hypertable: use describe_table."
        ));
    }
    ToolError::Rejected(message)
}

/// The columnstore section: segmentby and orderby from the settings view, totals from the stats function.
/// None when the settings cannot be read; a failing stats call leaves only its fields null.
#[allow(clippy::too_many_arguments)]
async fn columnstore_of(
    state: &AppState,
    target: Option<&str>,
    features: &Features,
    sources: &Sources,
    view: &str,
    params: &[Option<&str>],
    enabled: bool,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Result<Option<Value>, ToolError> {
    let settings_sql = format!(
        "WITH ht AS ({RELATION_OID_SQL}) SELECT s.segmentby::text AS \"segmentBy\", s.orderby::text AS \"orderBy\" \
         FROM ht JOIN timescaledb_information.{view} s ON s.hypertable::oid = ht.oid"
    );
    let Some(settings) = section(
        state,
        target,
        &settings_sql,
        params,
        "columnstore",
        ct,
        warnings,
    )
    .await?
    else {
        return Ok(None);
    };
    let settings = settings.first();
    let stats = match sources
        .stats_function
        .and_then(|name| features.extension_function(name))
    {
        Some(function) => {
            let sql = format!(
                "WITH ht AS ({RELATION_OID_SQL}) SELECT s.total_chunks AS \"totalChunks\", \
                 s.number_compressed_chunks AS \"columnstoreChunks\", \
                 s.before_compression_total_bytes AS \"beforeBytes\", \
                 s.after_compression_total_bytes AS \"afterBytes\" \
                 FROM ht, {function}(ht.oid) s"
            );
            first_row(
                section(
                    state,
                    target,
                    &sql,
                    params,
                    "columnstore totals",
                    ct,
                    warnings,
                )
                .await?,
            )
        }
        None => {
            unavailable(warnings, "hypertable_columnstore_stats");
            None
        }
    };
    let before = cell(&stats, "beforeBytes").as_i64();
    let after = cell(&stats, "afterBytes").as_i64();
    let ratio = match (before, after) {
        (Some(before), Some(after)) if after > 0 => json!(before as f64 / after as f64),
        _ => Value::Null,
    };
    Ok(Some(json!({
        "enabled": enabled,
        "segmentBy": settings
            .and_then(|row| text_of(row, "segmentBy"))
            .map(|text| parse_name_list(&text))
            .unwrap_or_default(),
        "orderBy": settings
            .and_then(|row| text_of(row, "orderBy"))
            .map(|text| parse_orderby(&text))
            .unwrap_or_default(),
        "totalChunks": cell(&stats, "totalChunks"),
        "columnstoreChunks": cell(&stats, "columnstoreChunks"),
        "beforeBytes": cell(&stats, "beforeBytes"),
        "afterBytes": cell(&stats, "afterBytes"),
        "ratio": ratio,
    })))
}

/// The chunk page and the cursor of the next one. Sizes come from one set-returning call joined in SQL;
/// when that call fails, the page is read again without sizes and totalBytes is null.
#[allow(clippy::too_many_arguments)]
async fn chunks_of(
    state: &AppState,
    target: Option<&str>,
    features: &Features,
    sources: &Sources,
    params: &[Option<&str>],
    page: &Page,
    ct: &CancellationToken,
    warnings: &mut Vec<String>,
) -> Result<(Option<Vec<Map<String, Value>>>, Option<String>), ToolError> {
    if let Err(error) = features.require("chunks", CHUNK_COLUMNS) {
        warnings.push(format!("chunks: {}", error.message()));
        return Ok((None, None));
    }
    let window = page.window();
    let mut rows = match features.extension_function("chunks_detailed_size") {
        None => {
            unavailable(warnings, "chunks_detailed_size");
            None
        }
        Some(function) => {
            let sql = chunks_sql(sources, Some(function.as_str()), &window);
            match query(state, target, &sql, params, ct).await {
                Ok(envelope) => Some(envelope.rows),
                Err(error @ ToolError::Cancelled) => return Err(error),
                Err(error) => {
                    warnings.push(format!("chunks totalBytes: {}", error.message()));
                    None
                }
            }
        }
    };
    if rows.is_none() {
        let sql = chunks_sql(sources, None, &window);
        rows = section(state, target, &sql, params, "chunks", ct, warnings).await?;
    }
    let next = rows.as_mut().and_then(|rows| page.trim(rows));
    Ok((rows, next))
}
