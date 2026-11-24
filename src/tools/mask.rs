//! Best-effort masking of secrets in log text: SQL PASSWORD literals, connection-string keys and URL passwords.

/// Replacement for a masked secret.
const MASK: &str = "***";
/// Keys whose value is masked when written as `key=value` or `key = 'value'`.
const KEYS: &[&[u8]] = &[b"password", b"sslpassword", b"passfile"];

/// Returns `text` with secrets replaced by `***`; text without secrets comes back unchanged.
pub fn mask(text: &str) -> String {
    let keyed = mask_keyed(text.as_bytes());
    let masked = mask_urls(&keyed);
    String::from_utf8_lossy(&masked).into_owned()
}

fn mask_keyed(text: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    let mut i = 0;
    while i < text.len() {
        match keyed_secret(text, i, &mut out) {
            Some(next) => i = next,
            None => {
                out.push(text[i]);
                i += 1;
            }
        }
    }
    out
}

/// Masks the secret of the keyword at `start`, appends the result to `out` and returns the index after it.
fn keyed_secret(text: &[u8], start: usize, out: &mut Vec<u8>) -> Option<usize> {
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
        let k = skip_spaces(text, end);
        return match text.get(k) {
            Some(b'=') => {
                let v = skip_spaces(text, k + 1);
                let value_end = keyed_value_end(text, v);
                out.extend_from_slice(&text[start..end]);
                out.push(b'=');
                out.extend_from_slice(MASK.as_bytes());
                Some(value_end)
            }
            Some(b'\'') if *key == b"password" => {
                out.extend_from_slice(&text[start..k]);
                if text.get(k + 1) == Some(&b'\'') {
                    // A doubled quote opens a literal nested in an outer one; its content ends at the next quote pair.
                    Some(nested_end(text, k + 2, out))
                } else {
                    out.extend_from_slice(b"'***'");
                    Some(quoted_end(text, k))
                }
            }
            // Escape string E'...': backslash escapes and doubled quotes.
            Some(b'E' | b'e') if *key == b"password" && text.get(k + 1) == Some(&b'\'') => {
                out.extend_from_slice(&text[start..=k]);
                out.extend_from_slice(b"'***'");
                Some(escape_end(text, k + 1))
            }
            // Unicode escape string U&'...': doubled quotes only.
            Some(b'U' | b'u')
                if *key == b"password" && text.get(k + 1..k + 3) == Some(b"&'".as_slice()) =>
            {
                out.extend_from_slice(&text[start..k + 2]);
                out.extend_from_slice(b"'***'");
                Some(quoted_end(text, k + 2))
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

/// Writes `'***'` for a nested literal whose content starts at `from`; returns the index after its closing quotes.
fn nested_end(text: &[u8], from: usize, out: &mut Vec<u8>) -> usize {
    out.extend_from_slice(b"'***'");
    match text
        .get(from..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\''))
    {
        None => text.len(),
        Some(p) if text.get(from + p + 1) == Some(&b'\'') => from + p + 2,
        Some(p) => from + p + 1,
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
        Some(&b) if b.is_ascii_alphabetic() || b == b'_' => {}
        _ => return None,
    }
    while let Some(&b) = text.get(i) {
        if b == b'$' {
            return Some(i + 1);
        }
        if !(b.is_ascii_alphanumeric() || b == b'_') {
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
    use super::mask;
    use proptest::prelude::*;

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
            "SELECT 'x' AS a WHERE 'PASSWORD '***''"
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
