use std::collections::HashSet;

use serde_json::Value;

use super::{EncodeLimits, EncodeStats, text_value};

/// Inlines a JSON document. None when it is malformed or repeats a key in any object.
/// A document over max_value_bytes is never parsed; it becomes capped text.
pub(super) fn decode(text: &str, limits: &EncodeLimits, stats: &mut EncodeStats) -> Option<Value> {
    if text.len() > limits.max_value_bytes {
        return Some(text_value(text, limits, stats));
    }
    let value: Value = serde_json::from_str(text).ok()?;
    if has_duplicate_keys(text) {
        return None;
    }
    Some(value)
}

enum Frame {
    Object {
        keys: HashSet<String>,
        expect_key: bool,
    },
    Array,
}

/// Streams over valid JSON with an explicit stack; true when any object repeats a key.
fn has_duplicate_keys(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut stack: Vec<Frame> = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'{' => {
                stack.push(Frame::Object {
                    keys: HashSet::new(),
                    expect_key: true,
                });
                i += 1;
            }
            b'[' => {
                stack.push(Frame::Array);
                i += 1;
            }
            b'}' | b']' => {
                stack.pop();
                i += 1;
            }
            b',' => {
                if let Some(Frame::Object { expect_key, .. }) = stack.last_mut() {
                    *expect_key = true;
                }
                i += 1;
            }
            b'"' => {
                let end = string_end(bytes, i);
                match stack.last_mut() {
                    Some(Frame::Object { keys, expect_key }) if *expect_key => {
                        let Ok(key) = serde_json::from_str::<String>(&text[i..end]) else {
                            return true;
                        };
                        if !keys.insert(key) {
                            return true;
                        }
                        *expect_key = false;
                    }
                    _ => {}
                }
                i = end;
            }
            _ => i += 1,
        }
    }
    false
}

/// Index just past the closing quote of the string starting at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut j = start + 1;
    while j < bytes.len() {
        match bytes[j] {
            b'\\' => j += 2,
            b'"' => return j + 1,
            _ => j += 1,
        }
    }
    bytes.len()
}
