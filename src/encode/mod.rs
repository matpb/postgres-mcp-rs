//! Decodes PostgreSQL TEXT-format values into JSON, lossless or capped.

mod array;
mod columns;
mod json;
mod range;
mod types;

use serde_json::Value;

pub use columns::dedup_columns;
pub use types::{TypeInfo, TypeKind, builtin_type};

/// Size caps for one encoded value.
#[derive(Debug, Clone, Copy)]
pub struct EncodeLimits {
    pub max_value_bytes: usize,
    pub max_binary_preview_bytes: usize,
}

/// Counters for values that were cut or fell back to raw text.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EncodeStats {
    pub truncated_values: u64,
    pub raw_fallbacks: u64,
}

const MAX_SAFE_INTEGER: u128 = 9_007_199_254_740_991;

/// Encodes one non-NULL value. `raw` may be a prefix of the value; `full_len` is its real length.
pub fn encode_value(
    raw: &[u8],
    full_len: usize,
    ty: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Value {
    if full_len > raw.len() {
        return wire_truncated(raw, full_len, stats);
    }
    let Ok(text) = std::str::from_utf8(raw) else {
        stats.raw_fallbacks += 1;
        return hex_capped(raw, limits, stats);
    };
    match decode(text, ty, limits, stats) {
        Some(value) => value,
        None => {
            stats.raw_fallbacks += 1;
            text_value(text, limits, stats)
        }
    }
}

/// Decodes valid UTF-8 text by kind; None means the text did not parse.
fn decode(
    text: &str,
    ty: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    match &ty.kind {
        TypeKind::Bool => match text {
            "t" => Some(Value::Bool(true)),
            "f" => Some(Value::Bool(false)),
            _ => None,
        },
        TypeKind::Int => text.parse::<i64>().ok().map(Value::from),
        TypeKind::BigInt => {
            let v: i128 = text.parse().ok()?;
            if v.unsigned_abs() <= MAX_SAFE_INTEGER {
                Some(Value::from(i64::try_from(v).ok()?))
            } else {
                Some(text_value(text, limits, stats))
            }
        }
        TypeKind::Float => float(text, limits, stats),
        TypeKind::Numeric | TypeKind::Text => Some(text_value(text, limits, stats)),
        TypeKind::Json => json::decode(text, limits, stats),
        TypeKind::Bytea => bytea(text, limits, stats),
        TypeKind::Array { elem, delim } => array::decode(text, elem, *delim, limits, stats),
        TypeKind::Range { sub } => range::decode(text, sub, limits, stats),
        TypeKind::Multirange { sub } => range::decode_multirange(text, sub, limits, stats),
    }
}

fn float(text: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Option<Value> {
    match text {
        "NaN" | "Infinity" | "-Infinity" => Some(text_value(text, limits, stats)),
        _ => {
            let f: f64 = text.parse().ok()?;
            if !f.is_finite() {
                return None;
            }
            match serde_json::from_str::<Value>(text) {
                Ok(v @ Value::Number(_)) => Some(v),
                _ => None,
            }
        }
    }
}

fn bytea(text: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Option<Value> {
    let hex = text.strip_prefix("\\x")?;
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let decoded_len = hex.len() / 2;
    let cap = limits.max_binary_preview_bytes;
    if decoded_len <= cap {
        return Some(Value::String(format!("\\x{hex}")));
    }
    stats.truncated_values += 1;
    Some(Value::String(format!(
        "\\x{}…[truncated: {cap} of {decoded_len} bytes]",
        &hex[..cap * 2]
    )))
}

/// Text is cut on a char boundary, with the marker, when longer than max_value_bytes.
pub(super) fn text_value(s: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Value {
    let max = limits.max_value_bytes;
    if s.len() <= max {
        return Value::String(s.to_string());
    }
    let mut cut = max;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    stats.truncated_values += 1;
    Value::String(format!(
        "{}…[truncated: {cut} of {} bytes]",
        &s[..cut],
        s.len()
    ))
}

/// Adds the counters of a nested decode that succeeded.
pub(super) fn absorb(stats: &mut EncodeStats, other: &EncodeStats) {
    stats.truncated_values += other.truncated_values;
    stats.raw_fallbacks += other.raw_fallbacks;
}

/// The wire cut the value: keep the valid prefix, lossy-decoded, with the marker.
fn wire_truncated(raw: &[u8], full_len: usize, stats: &mut EncodeStats) -> Value {
    let cut = match std::str::from_utf8(raw) {
        Ok(_) => raw.len(),
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => raw.len(),
    };
    stats.truncated_values += 1;
    Value::String(format!(
        "{}…[truncated: {cut} of {full_len} bytes]",
        String::from_utf8_lossy(&raw[..cut])
    ))
}

/// Non-UTF-8 bytes as `\x` hex, capped like bytea.
fn hex_capped(raw: &[u8], limits: &EncodeLimits, stats: &mut EncodeStats) -> Value {
    let cap = limits.max_binary_preview_bytes;
    if raw.len() <= cap {
        return Value::String(format!("\\x{}", hex(raw)));
    }
    stats.truncated_values += 1;
    Value::String(format!(
        "\\x{}…[truncated: {cap} of {} bytes]",
        hex(&raw[..cap]),
        raw.len()
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}
