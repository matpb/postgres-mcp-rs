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
fn hash_end(bytes: &[u8], at: usize) -> Option<usize> {
    let rest = bytes.get(at..)?;
    if rest.starts_with(SCRAM_PREFIX) {
        let mut end = at + SCRAM_PREFIX.len();
        while end < bytes.len() && scram_char(bytes[end]) {
            end += 1;
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
        let before_ok = at == 0 || !bytes[at - 1].is_ascii_alphanumeric();
        let after_ok = bytes
            .get(digits_end)
            .is_none_or(|byte| !byte.is_ascii_alphanumeric());
        return (before_ok && after_ok).then_some(digits_end);
    }
    None
}

/// Replaces every password hash in the bytes. Borrows the input when there is none; returns the count.
pub fn scrub_bytes(bytes: &[u8]) -> (Cow<'_, [u8]>, usize) {
    let mut out: Option<Vec<u8>> = None;
    let mut copied = 0;
    let mut count = 0;
    let mut at = 0;
    while at < bytes.len() {
        match hash_end(bytes, at) {
            Some(end) => {
                let buffer = out.get_or_insert_with(|| Vec::with_capacity(bytes.len()));
                buffer.extend_from_slice(&bytes[copied..at]);
                buffer.extend_from_slice(REDACTED.as_bytes());
                count += 1;
                copied = end;
                at = end;
            }
            None => at += 1,
        }
    }
    match out {
        None => (Cow::Borrowed(bytes), 0),
        Some(mut buffer) => {
            buffer.extend_from_slice(&bytes[copied..]);
            (Cow::Owned(buffer), count)
        }
    }
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

/// The replacements the running call has made so far; zero outside a call.
pub fn total() -> u64 {
    CALL_REDACTIONS
        .try_with(|counter| counter.load(Ordering::Relaxed))
        .unwrap_or(0)
}

/// Scrubs every string of a JSON value and every object key, without recursion. Returns the count, which
/// is also added to the running call.
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
    record(count);
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
