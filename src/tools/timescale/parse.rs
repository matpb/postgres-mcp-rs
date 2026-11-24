//! Pure helpers for the TimescaleDB tools: identifier quoting and the catalog's list text.

use serde_json::{Value, json};

/// A schema or relation name as a quoted identifier, with embedded double quotes doubled.
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// A comma-separated list of column names, as the catalog prints segmentby.
pub fn parse_name_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(|part| unquote(part.trim()))
        .filter(|name| !name.is_empty())
        .collect()
}

/// The catalog's orderby text as {column, descending, nullsFirst} objects; PostgreSQL's NULLS defaults apply.
pub fn parse_orderby(text: &str) -> Vec<Value> {
    text.split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let words: Vec<&str> = part.split_whitespace().collect();
            let column = words.first().map(|word| unquote(word)).unwrap_or_default();
            let rest = words.get(1..).unwrap_or(&[]);
            let descending = rest.iter().any(|word| word.eq_ignore_ascii_case("DESC"));
            let nulls = rest
                .windows(2)
                .find(|pair| pair[0].eq_ignore_ascii_case("NULLS"))
                .map(|pair| pair[1].eq_ignore_ascii_case("FIRST"));
            json!({
                "column": column,
                "descending": descending,
                "nullsFirst": nulls.unwrap_or(descending),
            })
        })
        .collect()
}

/// Removes the double quotes around a catalog identifier and undoes their doubling.
fn unquote(name: &str) -> String {
    match name
        .strip_prefix('"')
        .and_then(|inner| inner.strip_suffix('"'))
    {
        Some(inner) => inner.replace("\"\"", "\""),
        None => name.to_owned(),
    }
}
