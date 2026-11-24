use std::borrow::Cow;

use serde_json::{Value, json};

use super::{EncodeLimits, EncodeStats, TypeInfo, absorb, encode_value};

/// Decodes one range such as `[1,5)` or `empty`; None when it does not parse.
pub(super) fn decode(
    text: &str,
    sub: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    let mut scratch = EncodeStats::default();
    let value = range_value(text, sub, limits, &mut scratch)?;
    absorb(stats, &scratch);
    Some(value)
}

/// Decodes a multirange such as `{[1,3),[5,8)}` into an array of ranges.
pub(super) fn decode_multirange(
    text: &str,
    sub: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() {
        return Some(Value::Array(Vec::new()));
    }
    let mut scratch = EncodeStats::default();
    let mut items = Vec::new();
    for piece in split_multirange(inner)? {
        items.push(range_value(piece, sub, limits, &mut scratch)?);
    }
    absorb(stats, &scratch);
    Some(Value::Array(items))
}

fn range_value(
    text: &str,
    sub: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    if text == "empty" {
        return Some(json!({"empty": true}));
    }
    let first = text.chars().next()?;
    let last = text.chars().next_back()?;
    let lower_inc = match first {
        '[' => true,
        '(' => false,
        _ => return None,
    };
    let upper_inc = match last {
        ']' => true,
        ')' => false,
        _ => return None,
    };
    let inner = text.get(1..text.len() - 1)?;
    let comma = bound_comma(inner)?;
    let lower = bound_value(&inner[..comma], sub, limits, stats)?;
    let upper = bound_value(&inner[comma + 1..], sub, limits, stats)?;
    Some(json!({
        "lower": lower,
        "upper": upper,
        "lowerInc": lower_inc,
        "upperInc": upper_inc
    }))
}

/// Byte index of the single comma outside double quotes; None if there is not exactly one.
fn bound_comma(inner: &str) -> Option<usize> {
    let mut found = None;
    let mut in_quote = false;
    let mut chars = inner.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if in_quote {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    if matches!(chars.peek(), Some((_, '"'))) {
                        chars.next();
                    } else {
                        in_quote = false;
                    }
                }
                _ => {}
            }
        } else if c == '"' {
            in_quote = true;
        } else if c == ',' {
            if found.is_some() {
                return None;
            }
            found = Some(i);
        }
    }
    if in_quote { None } else { found }
}

/// Splits a multirange body at commas that sit outside both quotes and range brackets.
fn split_multirange(inner: &str) -> Option<Vec<&str>> {
    let mut parts = Vec::new();
    let mut in_range = false;
    let mut in_quote = false;
    let mut start = 0;
    let mut chars = inner.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if in_quote {
            match c {
                '\\' => {
                    chars.next();
                }
                '"' => {
                    if matches!(chars.peek(), Some((_, '"'))) {
                        chars.next();
                    } else {
                        in_quote = false;
                    }
                }
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_quote = true,
            '[' | '(' => in_range = true,
            ']' | ')' => in_range = false,
            ',' if !in_range => {
                parts.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if in_quote || in_range {
        return None;
    }
    parts.push(&inner[start..]);
    Some(parts)
}

/// Encodes one bound with the subtype; an empty bound is unbounded (null).
fn bound_value(
    raw: &str,
    sub: &TypeInfo,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    if raw.is_empty() {
        return Some(Value::Null);
    }
    let content: Cow<str> = if raw.starts_with('"') {
        Cow::Owned(unquote(raw)?)
    } else {
        Cow::Borrowed(raw)
    };
    Some(encode_value(
        content.as_bytes(),
        content.len(),
        sub,
        limits,
        stats,
    ))
}

/// Removes the surrounding quotes and resolves `\x` and `""` escapes.
fn unquote(raw: &str) -> Option<String> {
    let mut chars = raw.strip_prefix('"')?.chars();
    let mut out = String::new();
    loop {
        match chars.next()? {
            '\\' => out.push(chars.next()?),
            '"' => match chars.next() {
                None => return Some(out),
                Some('"') => out.push('"'),
                Some(_) => return None,
            },
            c => out.push(c),
        }
    }
}
