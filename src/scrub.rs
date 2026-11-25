//! Password hash scrubber: replaces text shaped like a PostgreSQL password hash wherever text leaves the server.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Map, Value};

/// What a password-hash match is replaced with.
pub const REDACTED: &str = "[redacted password hash]";

const SCRAM_PREFIX: &[u8] = b"SCRAM-SHA-256$";
const MD5_PREFIX: &[u8] = b"md5";
const MD5_HEX_LEN: usize = 32;

/// Characters of a SCRAM verifier. A truncated verifier runs up to the first character outside them.
fn scram_char(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b':' | b'$')
}

/// The end of the hash that starts at `at`, when one starts there.
fn hash_end(bytes: &[u8], at: usize, after_marker: bool) -> Option<usize> {
    let rest = bytes.get(at..)?;
    if rest.starts_with(SCRAM_PREFIX) {
        let mut end = at + SCRAM_PREFIX.len();
        loop {
            if bytes[end..].starts_with(SCRAM_PREFIX) {
                end += SCRAM_PREFIX.len();
            } else if end < bytes.len() && scram_char(bytes[end]) {
                end += 1;
            } else {
                break;
            }
        }
        return Some(end);
    }
    if rest.starts_with(MD5_PREFIX) {
        let digits_start = at + MD5_PREFIX.len();
        let digits_end = digits_start + MD5_HEX_LEN;
        let digits = bytes.get(digits_start..digits_end)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        let before_ok = after_marker || at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let rest_after = bytes.get(digits_end..).unwrap_or_default();
        let after_ok = !rest_after.first().is_some_and(u8::is_ascii_alphanumeric)
            || rest_after.starts_with(SCRAM_PREFIX)
            || rest_after.starts_with(MD5_PREFIX);
        return (before_ok && after_ok).then_some(digits_end);
    }
    None
}

/// Replaces every password hash in the bytes and returns the count. Borrows the input when there is none.
/// The loop repeats only as a backstop; one pass normally leaves nothing.
pub fn scrub_bytes(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let mut count = 0;
    let mut owned: Option<Vec<u8>> = None;
    loop {
        let input = owned.as_deref().unwrap_or(bytes);
        let (plain, found) = scrub_pass(input);
        let (escaped, more) = hex_stage(&plain);
        if found + more == 0 {
            break;
        }
        count += found + more;
        let next = escaped.into_owned();
        owned = Some(next);
    }
    match owned {
        Some(buffer) => (Cow::Owned(buffer), count),
        None => (Cow::Borrowed(bytes), 0),
    }
}

/// Replaces hashes that sit in `\x` hex escapes, as a bytea value inside a record's text does. Each escape is
/// decoded and matched; the digits around a replacement are written back as they were.
fn hex_stage(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    let mut count = 0;
    let mut at = 1;
    while at < bytes.len() {
        if bytes[at] != b'x' || bytes[at - 1] != b'\\' {
            at += 1;
            continue;
        }
        let start = at + 1;
        let run = bytes[start..]
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        let even = run & !1;
        let digits = &bytes[start..start + even];
        let spans = hash_spans(&unhex_hex(digits));
        if spans.is_empty() {
            at = start + even;
            continue;
        }
        let buffer = out.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
        buffer.extend_from_slice(&bytes[copied..start]);
        buffer.extend_from_slice(&hex_keeping_case(digits, &spans));
        count += spans.len();
        copied = start + even;
        at = copied;
    }
    match out {
        None => (Cow::Borrowed(bytes), 0),
        Some(mut buffer) => {
            buffer.extend_from_slice(&bytes[copied..]);
            (Cow::Owned(buffer), count)
        }
    }
}

/// The hex digits of `digits` with each span (in decoded byte positions) written as the marker's hex; the other
/// digits keep their letter case.
fn hex_keeping_case(digits: &[u8], spans: &[(usize, usize)]) -> Vec<u8> {
    let marker = hex_text(REDACTED.as_bytes());
    let mut out = Vec::with_capacity(digits.len());
    let mut byte = 0;
    let mut spans = spans.iter().peekable();
    while byte < digits.len() / 2 {
        match spans.peek() {
            Some(&&(start, end)) if start == byte => {
                out.extend_from_slice(marker.as_bytes());
                byte = end;
                spans.next();
            }
            _ => {
                out.extend_from_slice(&digits[2 * byte..2 * byte + 2]);
                byte += 1;
            }
        }
    }
    out
}

/// Replaces an md5 hash that a value cut short inside a `\x` hex run. When the run reaches the end, its even
/// prefix is decoded, the tail rule is applied to the bytes, and the run is written back in hex.
pub fn scrub_hex_tail(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let mut run_start = bytes.len();
    while run_start > 0 && bytes[run_start - 1].is_ascii_hexdigit() {
        run_start -= 1;
    }
    if run_start < 2 || bytes[run_start - 1] != b'x' || bytes[run_start - 2] != b'\\' {
        return (Cow::Borrowed(bytes), 0);
    }
    let run = &bytes[run_start..];
    let even = run.len() & !1;
    let decoded = unhex_hex(&run[..even]);
    let (tail, found) = scrub_cut_tail(&decoded);
    if found == 0 {
        return (Cow::Borrowed(bytes), 0);
    }
    let mut out = bytes[..run_start].to_vec();
    out.extend_from_slice(hex_text(&tail).as_bytes());
    out.extend_from_slice(&run[even..]);
    (Cow::Owned(out), found)
}

/// The bytes of hex digit pairs; the caller passes an even number of hex digits.
fn unhex_hex(digits: &[u8]) -> Vec<u8> {
    digits
        .chunks_exact(2)
        .map(|pair| {
            let high = char::from(pair[0]).to_digit(16).unwrap_or(0) as u8;
            let low = char::from(pair[1]).to_digit(16).unwrap_or(0) as u8;
            high << 4 | low
        })
        .collect()
}

/// Lower-case hex of the bytes.
fn hex_text(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// One left-to-right pass of `scrub_bytes`.
fn scrub_pass(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let spans = hash_spans(bytes);
    if spans.is_empty() {
        return (Cow::Borrowed(bytes), 0);
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut copied = 0;
    for &(start, end) in &spans {
        out.extend_from_slice(&bytes[copied..start]);
        out.extend_from_slice(REDACTED.as_bytes());
        copied = end;
    }
    out.extend_from_slice(&bytes[copied..]);
    (Cow::Owned(out), spans.len())
}

/// The spans of the hashes, left to right. A hash that starts where the previous one ended may follow it with
/// no separator, so a run of packed hashes is one pass.
fn hash_spans(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut at = 0;
    let mut last_end = None;
    while at < bytes.len() {
        match hash_end(bytes, at, last_end == Some(at)) {
            Some(end) => {
                spans.push((at, end));
                last_end = Some(end);
                at = end;
            }
            None => at += 1,
        }
    }
    spans
}

/// Replaces an md5 hash that a value cut short: `md5` and one to 31 hex digits run to the end of the bytes.
pub fn scrub_cut_tail(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let first = bytes
        .len()
        .saturating_sub(MD5_PREFIX.len() + MD5_HEX_LEN - 1);
    for at in first..bytes.len() {
        let Some(digits) = bytes.get(at + MD5_PREFIX.len()..) else {
            continue;
        };
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        if bytes[at..].starts_with(MD5_PREFIX)
            && before_ok
            && !digits.is_empty()
            && digits.len() < MD5_HEX_LEN
            && digits.iter().all(u8::is_ascii_hexdigit)
        {
            let mut out = bytes[..at].to_vec();
            out.extend_from_slice(REDACTED.as_bytes());
            return (Cow::Owned(out), 1);
        }
    }
    (Cow::Borrowed(bytes), 0)
}

/// The longest prefix of `text` within `max` bytes that does not end inside a marker: a marker that the cut
/// would split starts the cut instead.
pub fn cut_index(text: &[u8], max: usize) -> usize {
    if max >= text.len() {
        return text.len();
    }
    let from = (max + 1).saturating_sub(REDACTED.len());
    for start in from..max {
        if text[start..].starts_with(REDACTED.as_bytes()) {
            return start;
        }
    }
    max
}

/// `text` with a hash cut at its end replaced, when one is there.
pub fn scrub_tail(text: &str) -> Cow<'_, str> {
    match scrub_cut_tail(text.as_bytes()) {
        (Cow::Owned(bytes), _) => Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
        (Cow::Borrowed(_), _) => Cow::Borrowed(text),
    }
}

/// The markers in a returned value, as text and as the hex of their bytes (a bytea value shows them as hex).
pub fn count_markers(value: &Value) -> u64 {
    let text = value.to_string();
    let hex: String = REDACTED.bytes().map(|b| format!("{b:02x}")).collect();
    (text.matches(REDACTED).count() + text.matches(hex.as_str()).count()) as u64
}

/// Replaces every password hash in the text; the count is the number of replacements.
pub fn scrub_counting(text: &str) -> (Cow<'_, str>, usize) {
    match scrub_bytes(text.as_bytes()) {
        (Cow::Borrowed(_), _) => (Cow::Borrowed(text), 0),
        // Matches are ASCII and sit on char boundaries, so the output is still UTF-8.
        (Cow::Owned(bytes), count) => (
            Cow::Owned(String::from_utf8_lossy(&bytes).into_owned()),
            count,
        ),
    }
}

/// Replaces every password hash in the text.
pub fn scrub(text: &str) -> Cow<'_, str> {
    scrub_counting(text).0
}

tokio::task_local! {
    /// The replacements made so far by the call that runs on this task.
    static CALL_REDACTIONS: Arc<AtomicU64>;
}

/// Runs one call's future with its own replacement counter. Returns the output and the total of the call.
pub async fn counted<F: Future>(future: F) -> (F::Output, u64) {
    let counter = Arc::new(AtomicU64::new(0));
    let output = CALL_REDACTIONS.scope(counter.clone(), future).await;
    (output, counter.load(Ordering::Relaxed))
}

/// The counter of the running call, for work the call hands to another task.
pub fn call_counter() -> Option<Arc<AtomicU64>> {
    CALL_REDACTIONS.try_with(Arc::clone).ok()
}

/// Runs a future under a call's counter, when the call has one.
pub async fn under_counter<F: Future>(counter: Option<Arc<AtomicU64>>, future: F) -> F::Output {
    match counter {
        Some(counter) => CALL_REDACTIONS.scope(counter, future).await,
        None => future.await,
    }
}

/// Adds replacements to the running call. Outside a call nothing is counted.
pub fn record(count: usize) {
    if count > 0 {
        let _ =
            CALL_REDACTIONS.try_with(|counter| counter.fetch_add(count as u64, Ordering::Relaxed));
    }
}

/// Sets the running call's count to the markers in what it returns; zero outside a call.
pub fn set_total(count: u64) {
    let _ = CALL_REDACTIONS.try_with(|counter| counter.store(count, Ordering::Relaxed));
}

/// The running call's count so far; zero outside a call.
pub fn total() -> u64 {
    CALL_REDACTIONS
        .try_with(|counter| counter.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Scrubs every string of a JSON value and every object key, without recursion. Returns the count of replacements.
pub fn scrub_value(value: &mut Value) -> usize {
    let mut count = 0;
    let mut pending: Vec<&mut Value> = vec![value];
    while let Some(node) = pending.pop() {
        match node {
            Value::String(text) => {
                let (scrubbed, found) = scrub_counting(text.as_str());
                let replacement = (found > 0).then(|| scrubbed.into_owned());
                if let Some(replacement) = replacement {
                    *text = replacement;
                    count += found;
                }
            }
            Value::Array(items) => pending.extend(items.iter_mut()),
            Value::Object(map) => {
                rebuild_keys(map, &mut count);
                pending.extend(map.values_mut());
            }
            _ => {}
        }
    }
    count
}

/// Replaces hashes in the keys of one object. A changed key takes its replacement name, or that name with
/// `__2`, `__3` and so on when the name is taken. The object is rebuilt only when a key changes.
fn rebuild_keys(map: &mut Map<String, Value>, count: &mut usize) {
    let changed: Vec<(String, String, usize)> = map
        .keys()
        .filter_map(|key| {
            let (fixed, found) = scrub_counting(key);
            (found > 0).then(|| (key.clone(), fixed.into_owned(), found))
        })
        .collect();
    if changed.is_empty() {
        return;
    }
    let mut taken: HashSet<String> = map
        .keys()
        .filter(|key| scrub_counting(key).1 == 0)
        .cloned()
        .collect();
    let mut renamed: HashMap<String, String> = HashMap::new();
    for (original, fixed, found) in changed {
        *count += found;
        let mut name = fixed.clone();
        let mut suffix = 2;
        while taken.contains(&name) {
            name = format!("{fixed}__{suffix}");
            suffix += 1;
        }
        taken.insert(name.clone());
        renamed.insert(original, name);
    }
    let entries: Vec<(String, Value)> = std::mem::take(map).into_iter().collect();
    for (key, child) in entries {
        let name = renamed.remove(&key).unwrap_or(key);
        map.insert(name, child);
    }
}
