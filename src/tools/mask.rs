//! Best-effort masking of secrets in log text: SQL PASSWORD literals, connection-string keys and URL passwords.

use std::borrow::Cow;

use crate::encode::TRUNCATION_MARK;

/// Replacement for a masked secret.
const MASK: &str = "***";
/// Keys whose value is masked when written as `key=value` or `key = 'value'`.
const KEYS: &[&[u8]] = &[b"password", b"sslpassword", b"passfile"];

/// The final pass over a value that leaves the server: hashes are replaced, then the PASSWORD literal mask runs on
/// every string. Keys in `pre_masked` were masked by their tool already; `statement_text` keys also lose a hash cut at their end.
pub fn scrub_and_mask(value: &mut serde_json::Value, pre_masked: &[&str], statement_text: &[&str]) {
    crate::scrub::scrub_value(value);
    let mut pending: Vec<(&mut serde_json::Value, bool, bool)> = vec![(value, false, false)];
    while let Some((node, skip, statement)) = pending.pop() {
        match node {
            serde_json::Value::String(text) => {
                let masked = if skip {
                    None
                } else {
                    owned_or_none(mask_password_literals(text))
                };
                let tailed = if statement {
                    owned_or_none(crate::scrub::scrub_tail(masked.as_deref().unwrap_or(text)))
                } else {
                    None
                };
                if let Some(replaced) = tailed.or(masked) {
                    *text = replaced;
                }
            }
            serde_json::Value::Array(items) => {
                pending.extend(items.iter_mut().map(|item| (item, skip, statement)));
            }
            serde_json::Value::Object(map) => {
                pending.extend(map.iter_mut().map(|(key, child)| {
                    (
                        child,
                        skip || pre_masked.contains(&key.as_str()),
                        statement || statement_text.contains(&key.as_str()),
                    )
                }));
            }
            _ => {}
        }
    }
}

fn owned_or_none(text: Cow<'_, str>) -> Option<String> {
    match text {
        Cow::Owned(owned) => Some(owned),
        Cow::Borrowed(_) => None,
    }
}

/// Returns `text` with each quoted literal after the keyword PASSWORD replaced by `'***'`; other text is unchanged.
pub fn mask_password_literals(text: &str) -> Cow<'_, str> {
    let (body, marker) = split_truncation(text);
    let masked = mask_keyed(body.as_bytes(), true);
    if masked == body.as_bytes() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(format!("{}{marker}", String::from_utf8_lossy(&masked)))
    }
}

/// Returns `text` with secrets replaced by `***`; text without secrets comes back unchanged.
pub fn mask(text: &str) -> String {
    let (body, marker) = split_truncation(text);
    let keyed = mask_keyed(body.as_bytes(), false);
    let masked = mask_urls(&keyed);
    format!("{}{marker}", String::from_utf8_lossy(&masked))
}

/// The text before a truncation marker that ends it, and the marker (empty when there is none). A literal that the value
/// limit cut ends where the text ends, so the marker is not an input to the masks.
fn split_truncation(text: &str) -> (&str, &str) {
    if let Some(at) = text.rfind(TRUNCATION_MARK)
        && is_truncation_counts(&text[at + TRUNCATION_MARK.len()..])
    {
        return (&text[..at], &text[at..]);
    }
    (text, "")
}

/// True for the `X of Y bytes]` that ends a truncation marker.
fn is_truncation_counts(rest: &str) -> bool {
    let Some(counts) = rest.strip_suffix(" bytes]") else {
        return false;
    };
    let Some((cut, full)) = counts.split_once(" of ") else {
        return false;
    };
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    digits(cut) && digits(full)
}

/// The lexical state of a scan: inside a quoted literal (an E'' literal reads backslash escapes), inside a comment, or
/// in plain statement text.
#[derive(Default)]
struct Lex {
    pos: usize,
    quote: bool,
    escape: bool,
    line: bool,
    block: bool,
}

impl Lex {
    /// Reads the bytes before `to` as plain statement text.
    fn read_to(&mut self, text: &[u8], to: usize) {
        while self.pos < to {
            self.pos = self.step(text, self.pos);
        }
    }

    /// Reads the bytes before `to` of a masked literal. A dollar-quoted body in them is skipped, so the state is unchanged.
    fn read_masked(&mut self, text: &[u8], to: usize) {
        while self.pos < to {
            if !(self.quote || self.line || self.block)
                && text[self.pos] == b'$'
                && let Some(open) = dollar_open(text, self.pos)
            {
                let tag = &text[self.pos..open];
                self.pos = find_bytes(text, open, tag)
                    .map_or(to, |at| at + tag.len())
                    .min(to);
                continue;
            }
            self.pos = self.step(text, self.pos);
        }
    }

    /// Reads the token at `pos` and returns the index after it.
    fn step(&mut self, text: &[u8], pos: usize) -> usize {
        let b = text[pos];
        let next = text.get(pos + 1).copied();
        if self.line {
            self.line = b != b'\n';
        } else if self.block {
            if b == b'*' && next == Some(b'/') {
                self.block = false;
                return pos + 2;
            }
        } else if self.quote {
            if self.escape && b == b'\\' {
                return (pos + 2).min(text.len());
            }
            if b == b'\'' {
                if next == Some(b'\'') {
                    return pos + 2;
                }
                self.quote = false;
            }
        } else if b == b'\'' {
            self.quote = true;
            self.escape = pos > 0
                && matches!(text[pos - 1], b'E' | b'e')
                && (pos < 2 || !is_word(text[pos - 2]));
        } else if b == b'-' && next == Some(b'-') {
            self.line = true;
            return pos + 2;
        } else if b == b'/' && next == Some(b'*') {
            self.block = true;
            return pos + 2;
        }
        pos + 1
    }
}

/// Masks every keyed secret. With `literal_only`, only a PASSWORD literal is masked.
fn mask_keyed(text: &[u8], literal_only: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut lex = Lex::default();
    let mut i = 0;
    while i < text.len() {
        lex.read_to(text, i);
        let masked = if literal_only {
            password_literal(text, i, lex.quote, &mut out)
        } else {
            keyed_secret(text, i, lex.quote, &mut out)
        };
        match masked {
            Some(next) => {
                lex.read_masked(text, next);
                i = next;
            }
            None => {
                out.push(text[i]);
                i += 1;
            }
        }
    }
    out
}

/// Masks the literal after the keyword PASSWORD at `start`, keeping the text before it; `in_quote` says whether the
/// keyword is inside a quoted literal. Whitespace or a comment must separate the keyword from the literal.
fn password_literal(text: &[u8], start: usize, in_quote: bool, out: &mut Vec<u8>) -> Option<usize> {
    if start > 0 && is_word(text[start - 1]) {
        return None;
    }
    let after_quote = start > 0 && matches!(text[start - 1], b'\'' | b'"');
    let end = start + b"password".len();
    if !text.get(start..end)?.eq_ignore_ascii_case(b"password")
        || text.get(end).is_some_and(|&b| is_word(b))
    {
        return None;
    }
    let k = skip_blanks(text, end)?;
    if k == end {
        return None;
    }
    let (keep, replacement, literal_end): (usize, &[u8], usize) = match text.get(k)? {
        b'\'' => match empty_or_nested(text, k, in_quote) {
            Some((replacement, literal_end)) => (k, replacement, literal_end),
            None if after_quote => return None,
            None => (k, b"'***'", quoted_end(text, k)),
        },
        _ if after_quote => return None,
        b'E' | b'e' if text.get(k + 1) == Some(&b'\'') => {
            match empty_or_nested(text, k + 1, in_quote) {
                Some((replacement, literal_end)) => (k + 1, replacement, literal_end),
                None => (k, b"'***'", escape_end(text, k + 1)),
            }
        }
        b'U' | b'u' if text.get(k + 1..k + 3) == Some(b"&'".as_slice()) => {
            match empty_or_nested(text, k + 2, in_quote) {
                Some((replacement, literal_end)) => (k + 2, replacement, literal_end),
                None => (k, b"'***'", quoted_end(text, k + 2)),
            }
        }
        b'$' => {
            let open = dollar_open(text, k)?;
            let tag = &text[k..open];
            let close = find_bytes(text, open, tag).map_or(text.len(), |at| at + tag.len());
            // A quote right after the literal would pair with the mask quotes on a second pass.
            let stray = close + text[close..].iter().take_while(|&&b| b == b'\'').count();
            (k, b"'***'", stray)
        }
        _ => return None,
    };
    out.extend_from_slice(&text[start..keep]);
    out.extend_from_slice(replacement);
    Some(literal_end)
}

/// The mask and end of an empty or nested literal at quote `q`. Outside a quoted literal, `''` before a separator is
/// empty unless a quote run follows before the next `;`; inside one, four or five quotes are a nested empty literal.
fn empty_or_nested(text: &[u8], q: usize, in_quote: bool) -> Option<(&'static [u8], usize)> {
    if in_quote {
        let run = text[q..].iter().take_while(|&&b| b == b'\'').count();
        if run == 4 || run == 5 {
            return Some((&b"''***''"[..], q + 4));
        }
    } else if text.get(q + 1) == Some(&b'\'')
        && ends_empty_literal(text, q + 2)
        && !has_nested_run(text, q + 2)
    {
        return Some((&b"'***'"[..], q + 2));
    }
    nested_open(text, q).then(|| (&b"''***''"[..], nested_close(text, q + 2)))
}

/// True when the first quote before the next `;` or `,` at `at` starts a run of two or more quotes.
fn has_nested_run(text: &[u8], at: usize) -> bool {
    let rest = &text[at..];
    let limit = rest
        .iter()
        .position(|&b| matches!(b, b';' | b','))
        .unwrap_or(rest.len());
    match rest[..limit].iter().position(|&b| b == b'\'') {
        Some(first) => rest[first..].iter().take_while(|&&b| b == b'\'').count() >= 2,
        None => false,
    }
}

/// True when the text at `at` ends a statement fragment: the end of the text, whitespace, `;`, `,`, `)` or a comment.
fn ends_empty_literal(text: &[u8], at: usize) -> bool {
    match text.get(at..) {
        None | Some([]) => true,
        Some(rest) => {
            rest[0].is_ascii_whitespace()
                || matches!(rest[0], b';' | b',' | b')')
                || rest.starts_with(b"/*")
                || rest.starts_with(b"--")
        }
    }
}

/// The most bytes of comments read after the keyword before its literal. Whitespace is not counted.
const COMMENT_BUDGET: usize = 256;

/// Index past the whitespace and comments at `i`. None when the comments hold more than `COMMENT_BUDGET` bytes.
fn skip_blanks(text: &[u8], mut i: usize) -> Option<usize> {
    let mut budget = COMMENT_BUDGET;
    loop {
        match text.get(i) {
            Some(b) if b.is_ascii_whitespace() => i += 1,
            Some(b'/') if text.get(i + 1) == Some(&b'*') => {
                let limit = text.len().min(i + budget);
                let next = find_bytes(&text[..limit], i + 2, b"*/")? + 2;
                budget -= next - i;
                i = next;
            }
            Some(b'-') if text.get(i + 1) == Some(&b'-') => {
                let limit = text.len().min(i + budget);
                let next = find_bytes(&text[..limit], i, b"\n")? + 1;
                budget -= next - i;
                i = next;
            }
            _ => return Some(i),
        }
    }
}

/// True when the quote at `k` and the one after it open a literal nested in a quoted one. The run of quotes after
/// them decides: two or more, or a single one that ends the text, make the literal nested.
fn nested_open(text: &[u8], k: usize) -> bool {
    if text.get(k + 1) != Some(&b'\'') {
        return false;
    }
    let rest = &text[k + 2..];
    if matches!(rest.first(), None | Some(b'\'')) {
        return false;
    }
    match rest.iter().position(|&b| b == b'\'') {
        None => true,
        Some(at) => {
            let run = rest[at..].iter().take_while(|&&b| b == b'\'').count();
            run >= 2 || at + run == rest.len()
        }
    }
}

/// Masks the secret of the keyword at `start`, appends the result to `out` and returns the index after it.
fn keyed_secret(text: &[u8], start: usize, in_quote: bool, out: &mut Vec<u8>) -> Option<usize> {
    if start > 0 && is_word(text[start - 1]) {
        return None;
    }
    for key in KEYS {
        let end = start + key.len();
        let Some(word) = text.get(start..end) else {
            continue;
        };
        if !word.eq_ignore_ascii_case(key) || text.get(end).is_some_and(|&b| is_word(b)) {
            continue;
        }
        let k = skip_blanks(text, end)?;
        return match text.get(k) {
            Some(b'=') => {
                let v = skip_spaces(text, k + 1);
                let value_end = keyed_value_end(text, v);
                out.extend_from_slice(&text[start..end]);
                // The blanks before `=` are dropped; a comment among them is kept.
                let comment = text[end..k].trim_ascii();
                if !comment.is_empty() {
                    out.push(b' ');
                    out.extend_from_slice(comment);
                }
                out.push(b'=');
                out.extend_from_slice(MASK.as_bytes());
                Some(value_end)
            }
            Some(b'\'') if *key == b"password" => {
                out.extend_from_slice(&text[start..k]);
                match empty_or_nested(text, k, in_quote) {
                    Some((replacement, literal_end)) => {
                        out.extend_from_slice(replacement);
                        Some(literal_end)
                    }
                    None => {
                        out.extend_from_slice(b"'***'");
                        Some(quoted_end(text, k))
                    }
                }
            }
            // Escape string E'...': backslash escapes and doubled quotes.
            Some(b'E' | b'e') if *key == b"password" && text.get(k + 1) == Some(&b'\'') => {
                out.extend_from_slice(&text[start..=k]);
                match empty_or_nested(text, k + 1, in_quote) {
                    Some((replacement, literal_end)) => {
                        out.extend_from_slice(replacement);
                        Some(literal_end)
                    }
                    None => {
                        out.extend_from_slice(b"'***'");
                        Some(escape_end(text, k + 1))
                    }
                }
            }
            // Unicode escape string U&'...': doubled quotes only.
            Some(b'U' | b'u')
                if *key == b"password" && text.get(k + 1..k + 3) == Some(b"&'".as_slice()) =>
            {
                out.extend_from_slice(&text[start..k + 2]);
                match empty_or_nested(text, k + 2, in_quote) {
                    Some((replacement, literal_end)) => {
                        out.extend_from_slice(replacement);
                        Some(literal_end)
                    }
                    None => {
                        out.extend_from_slice(b"'***'");
                        Some(quoted_end(text, k + 2))
                    }
                }
            }
            // Dollar-quoted $tag$...$tag$, where the empty tag is $$.
            Some(b'$') if *key == b"password" => {
                let open = dollar_open(text, k)?;
                let tag = &text[k..open];
                let end = match find_bytes(text, open, tag) {
                    Some(close) => close + tag.len(),
                    None => text.len(),
                };
                out.extend_from_slice(&text[start..k]);
                out.extend_from_slice(tag);
                out.extend_from_slice(MASK.as_bytes());
                out.extend_from_slice(tag);
                Some(end)
            }
            _ => None,
        };
    }
    None
}

/// Index after the quotes that close a literal nested in a quoted one, whose content starts at `from`.
/// An odd count of inner quotes in a run closes the literal, and an odd run ends with the outer quote.
fn nested_close(text: &[u8], from: usize) -> usize {
    let mut i = from;
    loop {
        let Some(offset) = text
            .get(i..)
            .and_then(|rest| rest.iter().position(|&b| b == b'\''))
        else {
            return text.len();
        };
        let at = i + offset;
        let run = text[at..].iter().take_while(|&&b| b == b'\'').count();
        let inner = run / 2;
        match (run % 2, inner % 2) {
            (1, 1) => return at + run - 1,
            (1, _) => return at + run,
            (_, 1) => return at + run,
            _ => i = at + run,
        }
    }
}

/// Index just past the closing quote of the literal opened at `open`, or the end of the text when unterminated.
fn quoted_end(text: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    while let Some(&b) = text.get(i) {
        if b == b'\'' {
            if text.get(i + 1) == Some(&b'\'') {
                i += 2;
                continue;
            }
            return i + 1;
        }
        i += 1;
    }
    text.len()
}

/// Index just past the closing quote of the escape string opened at `open`; a backslash escapes the next byte.
fn escape_end(text: &[u8], open: usize) -> usize {
    let mut i = open + 1;
    while let Some(&b) = text.get(i) {
        match b {
            b'\\' => i += 2,
            b'\'' if text.get(i + 1) == Some(&b'\'') => i += 2,
            b'\'' => return i + 1,
            _ => i += 1,
        }
    }
    text.len()
}

/// Index just past the opening `$tag$` delimiter that starts at `start`, or None when no delimiter starts there.
fn dollar_open(text: &[u8], start: usize) -> Option<usize> {
    if text.get(start) != Some(&b'$') {
        return None;
    }
    let mut i = start + 1;
    match text.get(i) {
        Some(b'$') => return Some(i + 1),
        Some(&b) if b.is_ascii_alphabetic() || b == b'_' || b >= 0x80 => {}
        _ => return None,
    }
    while let Some(&b) = text.get(i) {
        if b == b'$' {
            return Some(i + 1);
        }
        if !(b.is_ascii_alphanumeric() || b == b'_' || b >= 0x80) {
            return None;
        }
        i += 1;
    }
    None
}

/// Index of the first occurrence of `needle` at or after `from`.
fn find_bytes(text: &[u8], from: usize, needle: &[u8]) -> Option<usize> {
    text.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|p| from + p)
}

/// Index just past the value of `key=value` that starts at `v`: a quoted, escape or unicode literal, or a bare token.
fn keyed_value_end(text: &[u8], v: usize) -> usize {
    match text.get(v..) {
        Some([b'\'', ..]) => quoted_end(text, v),
        Some([b'E' | b'e', b'\'', ..]) => escape_end(text, v + 1),
        Some([b'U' | b'u', b'&', b'\'', ..]) => quoted_end(text, v + 2),
        _ => token_end(text, v),
    }
}

/// Index of the first byte that ends an unquoted value starting at `from`.
fn token_end(text: &[u8], from: usize) -> usize {
    match text.get(from..) {
        Some(rest) => {
            from + rest
                .iter()
                .position(|&b| is_token_end(b))
                .unwrap_or(rest.len())
        }
        None => text.len(),
    }
}

/// Index of the first byte at or after `i` that is not whitespace, newlines included.
fn skip_spaces(text: &[u8], mut i: usize) -> usize {
    while text.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_token_end(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b'\'' | b'"' | b';' | b',' | b')')
}

fn is_authority_end(b: u8) -> bool {
    b.is_ascii_whitespace()
        || matches!(
            b,
            b'/' | b'\'' | b'"' | b'?' | b'#' | b')' | b',' | b';' | b'<' | b'>'
        )
}

fn mask_urls(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match url_secret(text, i, &mut out) {
            Some(next) => i = next,
            None => {
                out.push(text[i]);
                i += 1;
            }
        }
    }
    out
}

/// At a `://` after a scheme, masks the password in the userinfo; returns the index of its closing `@`.
fn url_secret(text: &[u8], start: usize, out: &mut Vec<u8>) -> Option<usize> {
    if start == 0 || !text[start - 1].is_ascii_alphanumeric() {
        return None;
    }
    if text.get(start..start + 3) != Some(b"://".as_slice()) {
        return None;
    }
    let auth = start + 3;
    let stop = match text.get(auth..) {
        Some(rest) => {
            auth + rest
                .iter()
                .position(|&b| is_authority_end(b))
                .unwrap_or(rest.len())
        }
        None => return None,
    };
    let at = auth + text.get(auth..stop)?.iter().rposition(|&b| b == b'@')?;
    let colon = auth + text.get(auth..at)?.iter().position(|&b| b == b':')?;
    out.extend_from_slice(&text[start..=colon]);
    out.extend_from_slice(MASK.as_bytes());
    Some(at)
}

#[cfg(test)]
mod tests {
    use super::{mask, mask_password_literals};
    use crate::encode::TRUNCATION_MARK;
    use proptest::prelude::*;

    #[test]
    fn a_nested_literal_after_password_is_masked_without_any_password_character() {
        for (text, expected) in [
            (
                "DO $$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''hunter2'''; END $$",
                "DO $$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD ''***'''; END $$",
            ),
            (
                "SELECT 1 AS a, 'ALTER ROLE app PASSWORD ''hunter2'''",
                "SELECT 1 AS a, 'ALTER ROLE app PASSWORD ''***'''",
            ),
            ("'PASSWORD ''hunter2-m'''", "'PASSWORD ''***'''"),
            (
                "'ALTER ROLE app PASSWORD ''it''''s'''",
                "'ALTER ROLE app PASSWORD ''***'''",
            ),
        ] {
            let masked = mask_password_literals(text);
            assert_eq!(masked, expected, "{text}");
        }
    }

    #[test]
    fn a_keyword_inside_quoted_text_before_a_closing_quote_is_rewritten_as_documented() {
        assert_eq!(
            mask_password_literals("'reset password ' || name || ' now'"),
            "'reset password '***' now'"
        );
    }

    #[test]
    fn a_literal_after_a_comment_longer_than_the_window_is_left_unmasked() {
        let text = format!("ALTER ROLE x PASSWORD /*{}*/ 'secret'", "c".repeat(300));
        assert_eq!(mask_password_literals(&text), text);
    }

    #[test]
    fn a_literal_after_a_100_byte_comment_is_masked() {
        let comment = "c".repeat(100);
        assert_eq!(
            mask_password_literals(&format!("ALTER ROLE x PASSWORD /*{comment}*/ 'secret'")),
            format!("ALTER ROLE x PASSWORD /*{comment}*/ '***'")
        );
    }

    #[test]
    fn long_comment_heavy_text_after_the_keyword_is_scanned_in_linear_time() {
        let cases = [
            "password /*".repeat(95_000),
            "password --".repeat(95_000),
            "password /**/ /* ".repeat(60_000),
            ("password /* ".repeat(300) + "*/ /* ").repeat(280),
        ];
        for text in cases {
            let started = std::time::Instant::now();
            let masked = mask_password_literals(&text).into_owned();
            let elapsed = started.elapsed();
            // A generous bound: a wall-clock limit can flake on a loaded machine.
            assert!(elapsed < std::time::Duration::from_secs(5), "{elapsed:?}");
            assert_eq!(masked, text);
        }
    }

    /// The text left visible by a masked text, with the replacement literals removed.
    fn visible(text: &str) -> String {
        text.replace("''***''", "").replace("'***'", "")
    }

    /// True when every character of `part` appears in `whole` in the same order.
    fn is_subsequence(part: &str, whole: &str) -> bool {
        let mut rest = whole.chars();
        part.chars().all(|c| rest.any(|w| w == c))
    }

    /// A masked literal can remove the `*/` that closed a comment, so a second pass masks one more literal.
    #[test]
    fn a_second_pass_masks_more_after_a_comment() {
        let once = mask_password_literals("PASSWORD/* PASSWORD '*/\\' */'").into_owned();
        assert_eq!(once, "PASSWORD/* PASSWORD '***' */'");
        assert_eq!(
            mask_password_literals(&once),
            "PASSWORD/* PASSWORD '***' */'***'"
        );
    }

    /// Both masks of `text`: the literal-only mask, then the broad mask.
    fn both_masks(text: &str) -> (String, String) {
        (mask_password_literals(text).into_owned(), mask(text))
    }

    /// Checks each (input, expected) pair in both masks.
    fn check_both(cases: &[(&str, &str)]) {
        for (input, expected) in cases {
            let (literal, broad) = both_masks(input);
            assert_eq!(literal, *expected, "literal mask of {input:?}");
            assert_eq!(broad, *expected, "broad mask of {input:?}");
        }
    }

    #[test]
    fn an_empty_literal_at_statement_level_hides_no_later_password_and_loses_no_text() {
        check_both(&[
            (
                "ALTER ROLE a PASSWORD ''; SELECT ''''; ALTER ROLE b PASSWORD 'hunter2'",
                "ALTER ROLE a PASSWORD '***'; SELECT ''''; ALTER ROLE b PASSWORD '***'",
            ),
            (
                "ALTER ROLE a PASSWORD '' NOLOGIN",
                "ALTER ROLE a PASSWORD '***' NOLOGIN",
            ),
            (
                "ALTER ROLE a PASSWORD '' NOLOGIN; DROP TABLE audit_trail",
                "ALTER ROLE a PASSWORD '***' NOLOGIN; DROP TABLE audit_trail",
            ),
            (
                "CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'u', password ''); GRANT x TO y",
                "CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'u', password '***'); GRANT x TO y",
            ),
            (
                "ALTER ROLE a PASSWORD ''; ALTER ROLE b PASSWORD '''hunter2'",
                "ALTER ROLE a PASSWORD '***'; ALTER ROLE b PASSWORD '***'",
            ),
        ]);
    }

    #[test]
    fn a_nested_empty_literal_does_not_hide_the_next_password() {
        check_both(&[
            (
                "EXECUTE 'ALTER ROLE a PASSWORD '''''; ALTER ROLE b PASSWORD 'hunter2'",
                "EXECUTE 'ALTER ROLE a PASSWORD ''***'''; ALTER ROLE b PASSWORD '***'",
            ),
            (
                "EXECUTE 'ALTER ROLE a PASSWORD /* c */ '''''; ALTER ROLE b PASSWORD 'hunter2'",
                "EXECUTE 'ALTER ROLE a PASSWORD /* c */ ''***'''; ALTER ROLE b PASSWORD '***'",
            ),
        ]);
    }

    #[test]
    fn a_nested_literal_cut_by_the_value_limit_is_masked_and_the_marker_kept() {
        let marker = format!("{TRUNCATION_MARK}4096 of 4103 bytes]");
        let input = format!("EXECUTE 'ALTER ROLE a PASSWORD ''hunter2'{marker}");
        let expected = format!("EXECUTE 'ALTER ROLE a PASSWORD ''***''{marker}");
        check_both(&[(input.as_str(), expected.as_str())]);
    }

    /// A quoted statement held in a comment still has its nested literal masked, in both masks.
    #[test]
    fn a_nested_literal_inside_a_comment_is_masked() {
        check_both(&[
            (
                "SELECT 1 /* EXECUTE 'ALTER ROLE app PASSWORD '')hunter2''' */",
                "SELECT 1 /* EXECUTE 'ALTER ROLE app PASSWORD ''***''' */",
            ),
            (
                "SELECT 1 /* EXECUTE 'ALTER ROLE app PASSWORD '' hunter2''' */",
                "SELECT 1 /* EXECUTE 'ALTER ROLE app PASSWORD ''***''' */",
            ),
        ]);
    }

    /// A statement-level empty literal before a separator stays empty when no quote run follows it before the separator.
    #[test]
    fn an_empty_literal_followed_by_a_later_quote_run_past_a_separator_stays_empty() {
        check_both(&[(
            "ALTER ROLE a PASSWORD '' NOLOGIN; SELECT ''''",
            "ALTER ROLE a PASSWORD '***' NOLOGIN; SELECT ''''",
        )]);
    }

    #[test]
    fn the_truncation_marker_is_the_encoder_marker_constant() {
        assert_eq!(TRUNCATION_MARK, "…[truncated: ");
    }

    /// Documented limit: a fragment with no outer quote reads `''` before `)` as an empty literal.
    #[test]
    fn a_fragment_with_no_outer_quote_is_read_as_an_empty_literal() {
        check_both(&[(
            "ALTER ROLE app PASSWORD '')hunter2",
            "ALTER ROLE app PASSWORD '***')hunter2",
        )]);
    }

    #[test]
    fn a_nested_unicode_literal_is_masked_with_its_prefix_kept() {
        check_both(&[(
            "EXECUTE 'ALTER ROLE a PASSWORD U&''hunter2'''",
            "EXECUTE 'ALTER ROLE a PASSWORD U&''***'''",
        )]);
    }

    #[test]
    fn a_nested_escape_literal_keeps_the_case_of_its_prefix() {
        check_both(&[(
            "EXECUTE 'ALTER ROLE a PASSWORD e''hunter2'''",
            "EXECUTE 'ALTER ROLE a PASSWORD e''***'''",
        )]);
    }

    #[test]
    fn a_comment_between_the_keyword_and_the_equals_sign_is_kept() {
        assert_eq!(
            mask("password /* keep */ = hunter2"),
            "password /* keep */=***"
        );
    }

    #[test]
    fn a_comment_of_exactly_256_bytes_before_the_literal_is_within_the_budget() {
        let comment = format!("/*{}*/", "c".repeat(252));
        assert_eq!(comment.len(), 256);
        let text = format!("ALTER ROLE x PASSWORD {comment} 'hunter2'");
        let expected = format!("ALTER ROLE x PASSWORD {comment} '***'");
        check_both(&[(text.as_str(), expected.as_str())]);
    }

    #[test]
    fn a_comment_of_257_bytes_before_the_literal_is_over_the_budget() {
        let comment = format!("/*{}*/", "c".repeat(253));
        assert_eq!(comment.len(), 257);
        let text = format!("ALTER ROLE x PASSWORD {comment} 'hunter2'");
        let (literal, broad) = both_masks(&text);
        assert_eq!(literal, text);
        assert_eq!(broad, text);
    }

    proptest! {
        /// Masking a masked text reveals no text that the first pass hid: the visible text after a second pass is a
        /// subsequence of the visible text after the first. Exact idempotence fails, see `a_second_pass_masks_more_after_a_comment`.
        #[test]
        fn masking_twice_reveals_nothing_the_first_pass_hid(
            parts in proptest::collection::vec(
                prop_oneof![
                    Just("PASSWORD"), Just("password"), Just(" "), Just("'"), Just("''"),
                    Just("$$"), Just("$a$"), Just("x"), Just("/*"), Just("*/"), Just("--"),
                    Just("\n"), Just("E'"), Just("U&"), Just("\\"), Just("("), Just(")"),
                    Just(";"), Just("'ab'"), Just("''cd''"), Just("\""), Just("_"), Just("é"),
                    Just("/* '"), Just("' */"), Just("-- '\n"), Just("*/ '"), Just("'/*"),
                    Just("--'"), Just("E''"), Just("$$'"), Just("$a$'"), Just("''''"),
                    Just(" PASSWORD '"), Just("'' hunter2'''"),
                ],
                0..40,
            ),
        ) {
            let text: String = parts.concat();
            let once = mask_password_literals(&text).into_owned();
            let twice = mask_password_literals(&once).into_owned();
            prop_assert!(
                is_subsequence(&visible(&twice), &visible(&once)),
                "{:?} -> {:?} -> {:?}", text, once, twice
            );
        }
    }

    #[test]
    fn ordinary_sql_text_with_the_word_password_is_unchanged() {
        for text in [
            "ARRAY['password'::text, 'token'::text]",
            "IF NOT ok THEN RAISE EXCEPTION 'wrong password'; END IF; RETURN 1; END",
            "SELECT * FROM creds WHERE kind = 'password' AND v = 'x'",
            "CHECK (kind IN ('password', 'token', 'key'))",
            "host=h password=secret",
            "Forgot your password = reset it via the portal",
            "a message that ends in the word password",
        ] {
            assert_eq!(mask_password_literals(text), text, "{text}");
        }
    }

    #[test]
    fn a_literal_after_the_keyword_is_masked_in_every_quoting_form() {
        for (text, expected) in [
            (
                "ALTER ROLE x PASSWORD 'secret'",
                "ALTER ROLE x PASSWORD '***'",
            ),
            (
                "CREATE ROLE x ENCRYPTED PASSWORD 'secret'",
                "CREATE ROLE x ENCRYPTED PASSWORD '***'",
            ),
            (
                "ALTER ROLE x PASSWORD 'p''w'",
                "ALTER ROLE x PASSWORD '***'",
            ),
            (
                "CREATE ROLE x PASSWORD $$secret$$",
                "CREATE ROLE x PASSWORD '***'",
            ),
            (
                "CREATE ROLE x PASSWORD $tag$se'cret$tag$",
                "CREATE ROLE x PASSWORD '***'",
            ),
            (
                "CREATE ROLE x PASSWORD E'se\\'cret'",
                "CREATE ROLE x PASSWORD '***'",
            ),
            ("ALTER ROLE x PASSWORD U&'x'", "ALTER ROLE x PASSWORD '***'"),
        ] {
            assert_eq!(mask_password_literals(text), expected, "{text}");
        }
    }

    #[test]
    fn a_literal_that_starts_with_a_doubled_quote_leaves_nothing_of_the_password() {
        assert_eq!(
            mask_password_literals("ALTER ROLE x PASSWORD '''abc'"),
            "ALTER ROLE x PASSWORD '***'"
        );
    }

    #[test]
    fn an_empty_literal_is_masked_and_the_rest_of_the_statement_kept() {
        assert_eq!(
            mask_password_literals("ALTER ROLE x PASSWORD '' VALID UNTIL 'infinity'"),
            "ALTER ROLE x PASSWORD '***' VALID UNTIL 'infinity'"
        );
    }

    #[test]
    fn a_comment_between_the_keyword_and_the_literal_is_masked() {
        assert_eq!(
            mask_password_literals("ALTER ROLE x PASSWORD /* c */ 'x'"),
            "ALTER ROLE x PASSWORD /* c */ '***'"
        );
    }

    #[test]
    fn a_dollar_tag_with_a_non_ascii_letter_is_masked() {
        assert_eq!(
            mask_password_literals("CREATE ROLE x PASSWORD $é$secret$é$"),
            "CREATE ROLE x PASSWORD '***'"
        );
    }

    #[test]
    fn the_keyword_inside_an_identifier_or_a_quote_is_not_a_match() {
        for text in [
            "SELECT \"password\" FROM t",
            "SELECT 'x' || 'password' FROM t",
            "SELECT mypassword 'x'",
        ] {
            assert_eq!(mask_password_literals(text), text, "{text}");
        }
    }

    #[test]
    fn alter_role_password_literal_is_masked() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD 'p''w'"),
            "ALTER ROLE x PASSWORD '***'"
        );
    }

    #[test]
    fn escape_string_connection_value_with_spaces_is_masked() {
        assert_eq!(
            mask("host=h password=E'my secret' dbname=d"),
            "host=h password=*** dbname=d"
        );
    }

    #[test]
    fn quoted_connection_value_with_spaces_around_equals_is_masked() {
        assert_eq!(
            mask("host=h password = 'my secret' dbname=d"),
            "host=h password=*** dbname=d"
        );
    }

    #[test]
    fn password_keyword_then_newline_before_literal_is_masked() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD\n'hunter2'"),
            "ALTER ROLE x PASSWORD\n'***'"
        );
    }

    #[test]
    fn user_mapping_password_option_is_masked() {
        assert_eq!(
            mask("CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'u', password 'secret')"),
            "CREATE USER MAPPING FOR u SERVER s OPTIONS (user 'u', password '***')"
        );
    }

    #[test]
    fn connection_string_password_is_masked() {
        assert_eq!(
            mask("host=h password=abc dbname=d"),
            "host=h password=*** dbname=d"
        );
        assert_eq!(mask("passfile = '/tmp/x y' host=h"), "passfile=*** host=h");
        assert_eq!(mask("host=h sslpassword=k2 x"), "host=h sslpassword=*** x");
    }

    #[test]
    fn url_password_is_masked() {
        assert_eq!(mask("postgres://u:pw@h/db"), "postgres://u:***@h/db");
        assert_eq!(
            mask("connect to postgres://u@h/db"),
            "connect to postgres://u@h/db"
        );
    }

    #[test]
    fn text_without_secrets_is_unchanged() {
        for text in [
            "SELECT 1 AS passwordless",
            "ALTER ROLE x PASSWORD NULL",
            "ALTER ROLE x PASSWORD",
            "ALTER ROLE x PASSWORD $1",
            "ALTER ROLE x PASSWORD E",
            "ALTER ROLE x PASSWORD U&",
            "plain message with = and : and ://",
            "",
        ] {
            assert_eq!(mask(text), text);
        }
    }

    #[test]
    fn unterminated_literal_is_masked_to_end() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD 'abc"),
            "ALTER ROLE x PASSWORD '***'"
        );
    }

    #[test]
    fn nested_password_literal_is_masked() {
        assert_eq!(
            mask("SELECT 'x' AS a WHERE 'PASSWORD ''hunter2-m'''"),
            "SELECT 'x' AS a WHERE 'PASSWORD ''***'''"
        );
    }

    #[test]
    fn escape_string_password_is_masked() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD E'it\\'s'"),
            "ALTER ROLE x PASSWORD E'***'"
        );
        assert_eq!(
            mask("ALTER ROLE x PASSWORD e'a''b\\\\c' AND 1"),
            "ALTER ROLE x PASSWORD e'***' AND 1"
        );
    }

    #[test]
    fn unterminated_escape_string_is_masked_to_end() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD E'abc\\'d"),
            "ALTER ROLE x PASSWORD E'***'"
        );
    }

    #[test]
    fn dollar_quoted_password_is_masked() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD $$hunter2$$"),
            "ALTER ROLE x PASSWORD $$***$$"
        );
        assert_eq!(
            mask("ALTER ROLE x PASSWORD $tag$p'w$tag$ x"),
            "ALTER ROLE x PASSWORD $tag$***$tag$ x"
        );
    }

    #[test]
    fn unterminated_dollar_quote_is_masked_to_end() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD $tag$abc"),
            "ALTER ROLE x PASSWORD $tag$***$tag$"
        );
        assert_eq!(
            mask("ALTER ROLE x PASSWORD $$abc $tag$"),
            "ALTER ROLE x PASSWORD $$***$$"
        );
    }

    #[test]
    fn unicode_string_password_is_masked() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD U&'d\\0061'"),
            "ALTER ROLE x PASSWORD U&'***'"
        );
        assert_eq!(
            mask("ALTER ROLE x PASSWORD U&'abc"),
            "ALTER ROLE x PASSWORD U&'***'"
        );
    }

    #[test]
    fn a_quote_after_a_dollar_literal_is_masked_so_a_second_pass_changes_nothing() {
        let once = mask_password_literals("password $$a$$'");
        assert_eq!(once, "password '***'");
        assert_eq!(mask_password_literals(&once), once);
    }

    #[test]
    fn a_quote_after_a_dollar_literal_in_a_do_block_deletes_no_text() {
        assert_eq!(
            mask_password_literals(
                "DO $do$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD $$x1$$'; ALTER ROLE b PASSWORD 'hunter2'; END $do$"
            ),
            "DO $do$ BEGIN EXECUTE 'ALTER ROLE a PASSWORD '***'; ALTER ROLE b PASSWORD '***'; END $do$"
        );
        assert_eq!(
            mask_password_literals(
                "DO $do$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD $$x1$$'; EXECUTE 'GRANT a TO b'; END $do$"
            ),
            "DO $do$ BEGIN EXECUTE 'ALTER ROLE app PASSWORD '***'; EXECUTE 'GRANT a TO b'; END $do$"
        );
    }

    #[test]
    fn a_nested_literal_starting_with_a_parenthesis_or_space_is_masked() {
        assert_eq!(
            mask_password_literals("EXECUTE 'ALTER ROLE app PASSWORD '')hunter2'''"),
            "EXECUTE 'ALTER ROLE app PASSWORD ''***'''"
        );
        assert_eq!(
            mask_password_literals("EXECUTE 'ALTER ROLE app PASSWORD '' hunter2'''"),
            "EXECUTE 'ALTER ROLE app PASSWORD ''***'''"
        );
    }

    #[test]
    fn an_empty_literal_before_a_comment_is_not_nested() {
        assert_eq!(
            mask_password_literals(
                "ALTER ROLE a PASSWORD ''/* none */; ALTER ROLE b PASSWORD 'hunter2';"
            ),
            "ALTER ROLE a PASSWORD '***'/* none */; ALTER ROLE b PASSWORD '***';"
        );
    }

    #[test]
    fn an_empty_literal_before_a_semicolon_is_masked_and_the_rest_kept() {
        assert_eq!(
            mask_password_literals("ALTER ROLE a PASSWORD ''; COMMENT ON ROLE a IS ''"),
            "ALTER ROLE a PASSWORD '***'; COMMENT ON ROLE a IS ''"
        );
    }

    #[test]
    fn any_amount_of_whitespace_before_the_literal_is_accepted() {
        let text = format!("ALTER ROLE x PASSWORD{}'hunter2'", " ".repeat(300));
        assert_eq!(
            mask_password_literals(&text),
            format!("ALTER ROLE x PASSWORD{}'***'", " ".repeat(300))
        );
    }

    #[test]
    fn a_literal_after_a_comment_is_masked_in_the_broad_mask() {
        assert_eq!(
            mask("ALTER ROLE x PASSWORD /* c */ 'hunter2'"),
            "ALTER ROLE x PASSWORD /* c */ '***'"
        );
    }

    #[test]
    fn a_nested_escape_string_literal_is_masked_with_its_quotes_kept() {
        assert_eq!(
            mask_password_literals("EXECUTE 'ALTER ROLE a PASSWORD E''hunter2'''"),
            "EXECUTE 'ALTER ROLE a PASSWORD E''***'''"
        );
        assert_eq!(
            mask("EXECUTE 'ALTER ROLE a PASSWORD E''hunter2'''"),
            "EXECUTE 'ALTER ROLE a PASSWORD E''***'''"
        );
    }

    #[test]
    fn a_keyword_followed_by_spaces_scans_linearly() {
        let spaced = format!("password{}", " ".repeat(1_000_000));
        let repeated = "password ".repeat(125_000);
        let started = std::time::Instant::now();
        assert_eq!(mask_password_literals(&spaced), spaced);
        assert_eq!(mask_password_literals(&repeated), repeated);
        assert_eq!(mask(&spaced), spaced);
        // A generous bound: a wall-clock limit can flake on a loaded machine.
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn many_keywords_with_long_spacing_are_each_masked_exactly() {
        let text = ("password".to_owned() + &" ".repeat(300) + "'x' ").repeat(3000);
        let expected = ("password".to_owned() + &" ".repeat(300) + "'***' ").repeat(3000);
        let started = std::time::Instant::now();
        assert_eq!(mask_password_literals(&text), expected);
        // A generous bound: a wall-clock limit can flake on a loaded machine.
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    /// Documented limit: a nested literal whose value starts with a quote is not masked in full.
    #[test]
    fn a_nested_password_starting_with_a_quote_is_a_documented_limit() {
        assert_eq!(
            mask_password_literals("EXECUTE 'ALTER ROLE a PASSWORD ''''''hunter2'''''''"),
            "EXECUTE 'ALTER ROLE a PASSWORD '***'hunter2'''''''"
        );
    }

    /// Documented limit: a password built by concatenation is masked only up to its first quote.
    #[test]
    fn a_password_built_with_concatenation_is_a_documented_limit() {
        assert_eq!(
            mask_password_literals("ALTER ROLE a PASSWORD ' || quote_literal('hunter2')"),
            "ALTER ROLE a PASSWORD '***'hunter2')"
        );
    }

    #[test]
    fn long_input_is_masked_at_the_end() {
        let input = "a ".repeat(50_000) + "PASSWORD 'hunter2'";
        let masked = mask(&input);
        assert!(
            masked.ends_with("PASSWORD '***'"),
            "{}",
            &masked[masked.len() - 40..]
        );
        assert!(!masked.contains("hunter2"));
    }

    proptest! {
        #[test]
        fn never_panics(s in ".*") {
            let _ = mask(&s);
        }

        #[test]
        fn plain_text_is_unchanged(s in "[a-z0-9 ,.;=()]{0,120}") {
            let lower = s.to_ascii_lowercase();
            prop_assume!(!lower.contains("password") && !lower.contains("passfile") && !lower.contains("://"));
            prop_assert_eq!(mask(&s), s);
        }
    }
}
