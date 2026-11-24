use serde_json::{Value, json};

use super::{EncodeLimits, EncodeStats, TypeInfo, absorb, encode_value, text_value};

/// Parses PostgreSQL array text into nested JSON arrays; None when the grammar does not hold.
pub(super) fn decode(
    text: &str,
    elem: &TypeInfo,
    delim: char,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    if text.len() > limits.max_value_bytes.saturating_mul(16) {
        return Some(text_value(text, limits, stats));
    }
    let (lowers, body) = split_dims(text)?;
    let mut scratch = EncodeStats::default();
    let value = parse_body(body, elem, delim, limits, &mut scratch)?;
    absorb(stats, &scratch);
    if lowers.iter().all(|&l| l == 1) {
        Some(value)
    } else {
        Some(json!({"lowerBounds": lowers, "elements": value}))
    }
}

/// Splits an optional `[l:u]...=` decoration from the `{...}` body; returns the lower bounds.
fn split_dims(text: &str) -> Option<(Vec<i64>, &str)> {
    let mut rest = text;
    let mut lowers = Vec::new();
    while let Some(after) = rest.strip_prefix('[') {
        let (lo, after) = after.split_once(':')?;
        let (hi, after) = after.split_once(']')?;
        lowers.push(lo.parse::<i64>().ok()?);
        hi.parse::<i64>().ok()?;
        rest = after;
    }
    let body = if lowers.is_empty() {
        rest
    } else {
        rest.strip_prefix('=')?
    };
    Some((lowers, body))
}

fn peek(s: &str, i: usize) -> Option<char> {
    s.get(i..)?.chars().next()
}

fn skip_ws(s: &str, i: &mut usize) {
    while let Some(c) = peek(s, *i) {
        if !c.is_ascii_whitespace() {
            break;
        }
        *i += c.len_utf8();
    }
}

/// Iterative parser: an explicit stack of open braces, so nesting depth never recurses.
fn parse_body(
    body: &str,
    elem: &TypeInfo,
    delim: char,
    limits: &EncodeLimits,
    stats: &mut EncodeStats,
) -> Option<Value> {
    if peek(body, 0)? != '{' {
        return None;
    }
    let mut stack: Vec<Vec<Value>> = vec![Vec::new()];
    let mut i = 1;
    // True where an element or a closing brace may appear, i.e. after '{' or a delimiter.
    let mut expect_elem = true;
    loop {
        skip_ws(body, &mut i);
        let c = peek(body, i)?;
        if c == '}' {
            if expect_elem && !stack.last()?.is_empty() {
                return None;
            }
            i += 1;
            let arr = Value::Array(stack.pop()?);
            match stack.last_mut() {
                Some(parent) => parent.push(arr),
                None => {
                    skip_ws(body, &mut i);
                    return if i == body.len() { Some(arr) } else { None };
                }
            }
            expect_elem = false;
        } else if c == delim {
            if expect_elem {
                return None;
            }
            i += c.len_utf8();
            expect_elem = true;
        } else if c == '{' && expect_elem {
            stack.push(Vec::new());
            i += 1;
        } else if !expect_elem {
            return None;
        } else {
            let (value, next) = read_element(body, i, delim)?;
            if !value.quoted && value.text.is_empty() {
                return None;
            }
            let item = if !value.quoted && value.text.eq_ignore_ascii_case("NULL") {
                Value::Null
            } else {
                encode_value(value.text.as_bytes(), value.text.len(), elem, limits, stats)
            };
            stack.last_mut()?.push(item);
            i = next;
            expect_elem = false;
        }
    }
}

struct Element {
    text: String,
    quoted: bool,
}

/// Reads one element starting at `i`; returns it and the index just after it.
fn read_element(body: &str, i: usize, delim: char) -> Option<(Element, usize)> {
    if peek(body, i)? == '"' {
        let mut out = String::new();
        let mut j = i + 1;
        loop {
            let c = peek(body, j)?;
            j += c.len_utf8();
            match c {
                '\\' => {
                    let e = peek(body, j)?;
                    j += e.len_utf8();
                    out.push(e);
                }
                '"' => break,
                _ => out.push(c),
            }
        }
        return Some((
            Element {
                text: out,
                quoted: true,
            },
            j,
        ));
    }
    let mut j = i;
    while let Some(c) = peek(body, j) {
        if c == delim || c == '}' {
            break;
        }
        j += c.len_utf8();
    }
    let token = body[i..j].trim_end();
    Some((
        Element {
            text: token.to_string(),
            quoted: false,
        },
        j,
    ))
}
