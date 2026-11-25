//! Decodes PostgreSQL TEXT-format values into JSON, lossless or capped.

mod array;
mod columns;
mod json;
mod range;
mod types;

use std::borrow::Cow;

use serde_json::Value;

use crate::scrub;

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
/// Password hashes in the kept bytes are replaced before the value is decoded or cut again.
pub fn encode_value(
    raw: &[u8],
    full_len: usize,
    ty: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Value {
    let complete = full_len <= raw.len();
    if let (false, TypeKind::Bytea, Some(hex_text)) = (complete, &ty.kind, raw.strip_prefix(b"\\x"))
    {
        return wire_truncated_bytea(hex_text, full_len, limits, stats);
    }
    let (raw, _) = scrub_raw(raw, ty);
    if !complete {
        // The cut may split an md5 hash, in text or inside a hex run; the fragment is replaced here.
        let (hex_tail, _) = scrub::scrub_hex_tail(&raw);
        let (tail, _) = scrub::scrub_cut_tail(&hex_tail);
        let keep = scrub::cut_index(&tail, limits.max_value_bytes);
        return wire_truncated(&tail[..keep], full_len, stats);
    }
    let Ok(text) = std::str::from_utf8(&raw) else {
        stats.raw_fallbacks += 1;
        return hex_capped(&raw, limits, stats);
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

/// A bytea value cut by the wire. Its kept bytes are scrubbed and cut again, so an md5 hash that straddles
/// the cut is replaced in the bytes it is made of. The result stays hex, so the marker reads as hex bytes.
fn wire_truncated_bytea(
    hex_text: &[u8],
    full_len: usize,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Value {
    let bytes = unhex_pairs(hex_text);
    let (scrubbed, _) = scrub::scrub_bytes(&bytes);
    let (tail, _) = scrub::scrub_cut_tail(&scrubbed);
    let keep = scrub::cut_index(&tail, limits.max_value_bytes);
    stats.truncated_values += 1;
    let decoded_len = full_len.saturating_sub(2) / 2;
    Value::String(format!(
        "\\x{}…[truncated: {keep} of {decoded_len} bytes]",
        hex(&tail[..keep])
    ))
}

/// Replaces password hashes in a raw value. A bytea value is scrubbed as the bytes its hex text stands for.
fn scrub_raw<'a>(raw: &'a [u8], ty: &TypeInfo) -> (Cow<'a, [u8]>, usize) {
    match ty.kind {
        TypeKind::Bytea => scrub_bytea_text(raw),
        _ => scrub::scrub_bytes(raw),
    }
}

/// Scrubs the bytes of a `\x` hex text. Returns the text unchanged when no hash is found.
fn scrub_bytea_text(raw: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let Some(hex_text) = raw.strip_prefix(b"\\x") else {
        return (Cow::Borrowed(raw), 0);
    };
    let bytes = unhex_pairs(hex_text);
    let (scrubbed, found) = scrub::scrub_bytes(&bytes);
    if found == 0 {
        return (Cow::Borrowed(raw), 0);
    }
    let mut text = b"\\x".to_vec();
    text.extend_from_slice(hex(&scrubbed).as_bytes());
    (Cow::Owned(text), found)
}

/// The bytes of each complete pair of hex digits, stopping at the first character that is not a digit.
fn unhex_pairs(hex_text: &[u8]) -> Vec<u8> {
    let digit = |b: u8| char::from(b).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(hex_text.len() / 2);
    for pair in hex_text.chunks_exact(2) {
        match (digit(pair[0]), digit(pair[1])) {
            (Some(high), Some(low)) => out.push(high << 4 | low),
            _ => break,
        }
    }
    out
}

fn bytea(text: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Option<Value> {
    let hex = text.strip_prefix("\\x")?;
    if !hex.len().is_multiple_of(2) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (scrubbed, found) = scrub_bytea_text(text.as_bytes());
    if found > 0 {
        let replaced = String::from_utf8_lossy(&scrubbed).into_owned();
        return bytea(&replaced, limits, stats);
    }
    let decoded_len = hex.len() / 2;
    let cap = limits.max_binary_preview_bytes;
    if decoded_len <= cap {
        return Some(Value::String(format!("\\x{hex}")));
    }
    let decoded = unhex_pairs(hex.as_bytes());
    let keep = scrub::cut_index(&decoded, cap);
    stats.truncated_values += 1;
    Some(Value::String(format!(
        "\\x{}…[truncated: {keep} of {decoded_len} bytes]",
        self::hex(&decoded[..keep])
    )))
}

/// Text is cut on a char boundary, with the marker, when longer than max_value_bytes.
pub(super) fn text_value(s: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Value {
    let max = limits.max_value_bytes;
    if s.len() <= max {
        return Value::String(s.to_string());
    }
    let mut cut = crate::scrub::cut_index(s.as_bytes(), max);
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
    let valid = match std::str::from_utf8(raw) {
        Ok(_) => raw.len(),
        Err(e) if e.error_len().is_none() => e.valid_up_to(),
        Err(_) => raw.len(),
    };
    let cut = scrub::cut_index(raw, valid);
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
    let keep = scrub::cut_index(raw, cap);
    stats.truncated_values += 1;
    Value::String(format!(
        "\\x{}…[truncated: {keep} of {} bytes]",
        hex(&raw[..keep]),
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
