//! Probes which TimescaleDB views, columns and extension functions a database has, so queries name only what exists.

use std::collections::HashSet;

use tokio_util::sync::CancellationToken;

use super::parse::quote_ident;
use super::{query, text_of};
use crate::server::AppState;
use crate::tools::ToolError;

const EXTENSION_SQL: &str = "SELECT e.extversion::text AS version, n.nspname::text AS schema \
    FROM pg_catalog.pg_extension e JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace \
    WHERE e.extname = 'timescaledb'";
const COLUMNS_SQL: &str = "SELECT c.relname::text AS relation, a.attname::text AS column_name \
    FROM pg_catalog.pg_attribute a \
    JOIN pg_catalog.pg_class c ON c.oid = a.attrelid \
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace \
    WHERE n.nspname = 'timescaledb_information' AND a.attnum > 0 AND NOT a.attisdropped";
const FUNCTIONS_SQL: &str = "SELECT n.nspname::text AS schema, p.proname::text AS name \
    FROM pg_catalog.pg_proc p \
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace \
    JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_proc'::regclass::oid AND d.objid = p.oid AND d.deptype = 'e' \
    JOIN pg_catalog.pg_extension e ON e.oid = d.refobjid AND e.extname = 'timescaledb'";

/// What one database offers: the TimescaleDB version, its functions and the columns of its information views.
#[derive(Debug, Clone)]
pub struct Features {
    pub database: String,
    pub version: Option<String>,
    pub extension_schema: Option<String>,
    columns: HashSet<(String, String)>,
    functions: HashSet<(String, String)>,
}

impl Features {
    /// Features from probed names; `version` and `extension_schema` are None when TimescaleDB is absent.
    pub fn new(
        database: &str,
        version: Option<&str>,
        extension_schema: Option<&str>,
        columns: &[(&str, &str)],
        functions: &[(&str, &str)],
    ) -> Features {
        Features {
            database: database.to_owned(),
            version: version.map(str::to_owned),
            extension_schema: extension_schema.map(str::to_owned),
            columns: columns
                .iter()
                .map(|(view, column)| ((*view).to_owned(), (*column).to_owned()))
                .collect(),
            functions: functions
                .iter()
                .map(|(schema, name)| ((*schema).to_owned(), (*name).to_owned()))
                .collect(),
        }
    }

    pub fn installed(&self) -> bool {
        self.version.is_some()
    }

    /// True when the timescaledb_information view has the column.
    pub fn has(&self, view: &str, column: &str) -> bool {
        self.columns.contains(&(view.to_owned(), column.to_owned()))
    }

    /// True when the timescaledb_information view has every listed column.
    pub fn has_all(&self, view: &str, columns: &[&str]) -> bool {
        columns.iter().all(|column| self.has(view, column))
    }

    /// Fails with an internal error naming the first view column the query needs and this version lacks.
    pub fn require(&self, view: &str, columns: &[&str]) -> Result<(), ToolError> {
        match columns.iter().find(|column| !self.has(view, column)) {
            None => Ok(()),
            Some(column) => Err(ToolError::Internal(format!(
                "TimescaleDB {} has no {view}.{column}, which this tool needs.",
                self.version.as_deref().unwrap_or("(absent)")
            ))),
        }
    }

    /// The function as a qualified call prefix when the schema holds it.
    pub fn function(&self, schema: &str, name: &str) -> Option<String> {
        self.functions
            .contains(&(schema.to_owned(), name.to_owned()))
            .then(|| format!("{}.{name}", quote_ident(schema)))
    }

    /// The function as a qualified call prefix when the extension's schema holds it.
    pub fn extension_function(&self, name: &str) -> Option<String> {
        let schema = self.extension_schema.as_deref()?;
        self.function(schema, name)
    }
}

/// Which catalog sources this database offers for each concept, newest name first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sources {
    /// hypertables column that says whether the columnstore is on.
    pub hypertable_flag: Option<&'static str>,
    /// chunks column that says whether a chunk is in the columnstore.
    pub chunk_flag: Option<&'static str>,
    /// continuous_aggregates column that says whether the columnstore is on.
    pub cagg_flag: Option<&'static str>,
    /// View of columnstore settings: segmentby and orderby per hypertable.
    pub settings_view: Option<&'static str>,
    /// Function with columnstore totals per hypertable.
    pub stats_function: Option<&'static str>,
    pub cagg_finalized: bool,
    pub chunk_tablespace: bool,
    pub job_fixed_schedule: bool,
}

impl Sources {
    pub fn choose(features: &Features) -> Sources {
        Sources {
            hypertable_flag: first_column(
                features,
                "hypertables",
                &["columnstore_enabled", "compression_enabled"],
            ),
            chunk_flag: first_column(features, "chunks", &["is_columnstore", "is_compressed"]),
            cagg_flag: first_column(
                features,
                "continuous_aggregates",
                &["columnstore_enabled", "compression_enabled"],
            ),
            settings_view: first_settings_view(
                features,
                &[
                    "hypertable_columnstore_settings",
                    "hypertable_compression_settings",
                ],
            ),
            stats_function: first_function(
                features,
                &[
                    "hypertable_columnstore_stats",
                    "hypertable_compression_stats",
                ],
            ),
            cagg_finalized: features.has("continuous_aggregates", "finalized"),
            chunk_tablespace: features.has("chunks", "chunk_tablespace"),
            job_fixed_schedule: features.has("jobs", "fixed_schedule"),
        }
    }
}

fn first_column(
    features: &Features,
    view: &str,
    candidates: &[&'static str],
) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|column| features.has(view, column))
}

fn first_settings_view(features: &Features, candidates: &[&'static str]) -> Option<&'static str> {
    candidates.iter().copied().find(|view| {
        ["hypertable", "segmentby", "orderby"]
            .iter()
            .all(|column| features.has(view, column))
    })
}

fn first_function(features: &Features, candidates: &[&'static str]) -> Option<&'static str> {
    candidates
        .iter()
        .copied()
        .find(|name| features.extension_function(name).is_some())
}

/// Probes one database: the extension, the columns of timescaledb_information and the extension's functions.
/// Without the extension the result is not installed and holds nothing else.
pub async fn load(
    state: &AppState,
    database: Option<&str>,
    ct: &CancellationToken,
) -> Result<Features, ToolError> {
    let extension = query(state, database, EXTENSION_SQL, &[], ct).await?;
    let name = extension.database.clone();
    let Some(row) = extension.rows.first() else {
        return Ok(Features::new(&name, None, None, &[], &[]));
    };
    let version = text_of(row, "version");
    let schema = text_of(row, "schema");
    let target = Some(name.as_str());
    let columns = query(state, target, COLUMNS_SQL, &[], ct).await?;
    let functions = query(state, target, FUNCTIONS_SQL, &[], ct).await?;
    let column_pairs: Vec<(&str, &str)> = columns
        .rows
        .iter()
        .filter_map(|row| {
            Some((
                row.get("relation")?.as_str()?,
                row.get("column_name")?.as_str()?,
            ))
        })
        .collect();
    let function_pairs: Vec<(&str, &str)> = functions
        .rows
        .iter()
        .filter_map(|row| Some((row.get("schema")?.as_str()?, row.get("name")?.as_str()?)))
        .collect();
    Ok(Features::new(
        &name,
        version.as_deref(),
        schema.as_deref(),
        &column_pairs,
        &function_pairs,
    ))
}
