//! Result envelope shared by the query tools: typed columns, JSON rows and truncation flags.

use std::time::Duration;

use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::config::Limits;
use crate::encode::{EncodeLimits, EncodeStats, dedup_columns, encode_value};
use crate::gate::SECRET_SETTINGS;
use crate::pg::session::RunOutput;
use crate::pg::wire::{Field, Truncation};

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct QueryEnvelope {
    pub database: String,
    pub columns: Vec<ColumnInfo>,
    pub rows: Vec<Map<String, Value>>,
    pub row_count: usize,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncated_reason: Option<&'static str>,
    pub truncated_values: u64,
    pub raw_fallbacks: u64,
    /// Password hash texts replaced in the values of this result.
    pub redacted_hashes: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ColumnInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub type_oid: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_name: Option<String>,
}

/// Builds the envelope from a fetched result. `hide_secret_rows` drops `SHOW ALL` rows for secret settings.
pub fn build(
    database: &str,
    output: RunOutput,
    limits: &Limits,
    hide_secret_rows: bool,
) -> QueryEnvelope {
    let RunOutput {
        result,
        types,
        elapsed,
        ..
    } = output;
    let raw_names: Vec<String> = result.columns.iter().map(|c| c.name.clone()).collect();
    let deduped = dedup_columns(&raw_names);
    let columns = result
        .columns
        .iter()
        .zip(&types)
        .zip(&deduped)
        .map(|((column, ty), (name, original))| ColumnInfo {
            name: name.clone(),
            type_name: ty.name.clone(),
            type_oid: column.type_oid,
            original_name: original.clone(),
        })
        .collect::<Vec<_>>();

    let limits_encode = EncodeLimits {
        max_value_bytes: limits.max_value_bytes,
        max_binary_preview_bytes: limits.max_binary_preview_bytes,
    };
    let mut stats = EncodeStats::default();
    let mut rows = Vec::with_capacity(result.rows.len());
    for row in result.rows {
        if hide_secret_rows && is_secret_row(&row) {
            continue;
        }
        let mut object = Map::with_capacity(row.len());
        for (index, cell) in row.into_iter().enumerate() {
            let value = match cell {
                Some(field) => encode_value(
                    &field.data,
                    field.full_len,
                    &types[index],
                    &limits_encode,
                    &mut stats,
                ),
                None => Value::Null,
            };
            object.insert(deduped[index].0.clone(), value);
        }
        rows.push(object);
    }

    let (truncated, truncated_reason) = match result.truncated {
        None => (false, None),
        Some(Truncation::Rows) => (true, Some("row_limit")),
        Some(Truncation::Bytes) => (true, Some("response_size")),
    };
    QueryEnvelope {
        database: database.to_owned(),
        columns,
        row_count: rows.len(),
        rows,
        truncated,
        truncated_reason,
        truncated_values: stats.truncated_values,
        raw_fallbacks: stats.raw_fallbacks,
        redacted_hashes: stats.redacted_hashes,
        execution_time_ms: elapsed_ms(elapsed),
    }
}

/// Whole milliseconds, saturating.
pub fn elapsed_ms(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

/// True when the first column (a setting name) is a secret-bearing setting.
fn is_secret_row(row: &[Option<Field>]) -> bool {
    match row.first() {
        Some(Some(field)) => std::str::from_utf8(&field.data).is_ok_and(|name| {
            SECRET_SETTINGS
                .iter()
                .any(|secret| secret.eq_ignore_ascii_case(name))
        }),
        _ => false,
    }
}
