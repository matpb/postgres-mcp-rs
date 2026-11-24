//! Every function call in the SQL the server runs itself is schema-qualified. The string literals of `src/` are
//! parsed with PostgreSQL's parser, and each FuncCall node must name its schema.

use std::path::{Path, PathBuf};

use serde_json::Value;

/// Schemas a call may be qualified with: the catalog, this server's functions, TimescaleDB's, and the
/// placeholder that stands for a schema or function name supplied by a format argument.
const QUALIFYING_SCHEMAS: &[&str] = &[
    "pg_catalog",
    "pgmcp",
    "_timescaledb_functions",
    "timescaledb_information",
    "pgmcp_arg",
];

/// Name a dynamic function name is replaced with: `features.function` returns it qualified at run time.
const DYNAMIC_FUNCTION: &str = "pgmcp_dynamic";

/// SQL keywords and syntax forms written with parentheses that are not function calls. `substring` and
/// `position` are listed because their FROM and IN forms are only accepted unqualified by PostgreSQL's grammar.
const SYNTAX_KEYWORDS: &[&str] = &[
    "all",
    "and",
    "any",
    "array",
    "as",
    "asc",
    "between",
    "by",
    "case",
    "cast",
    "coalesce",
    "desc",
    "distinct",
    "else",
    "end",
    "except",
    "exists",
    "extract",
    "filter",
    "first",
    "from",
    "greatest",
    "group",
    "having",
    "ilike",
    "in",
    "intersect",
    "interval",
    "is",
    "join",
    "lateral",
    "last",
    "least",
    "like",
    "limit",
    "not",
    "nulls",
    "nullif",
    "offset",
    "on",
    "or",
    "order",
    "over",
    "returning",
    "row",
    "select",
    "some",
    "then",
    "union",
    "using",
    "values",
    "when",
    "where",
    "with",
    "substring",
    "position",
];

/// Identifiers followed by `(` in SQL text that are function calls without a schema. Aliases (`AS u(a, b)`),
/// CTE column lists (`name(a) AS (...)`), keywords and placeholders are not calls.
fn unqualified_text_calls(sql: &str) -> Vec<String> {
    // Single-quoted SQL strings and double-quoted identifiers are blanked so their contents are not read as code.
    let mut code = String::new();
    let mut quote: Option<char> = None;
    for c in sql.chars() {
        match quote {
            Some(q) if c == q => {
                quote = None;
                code.push(' ');
            }
            Some(_) => code.push(' '),
            None if c == '\'' || c == '"' => {
                quote = Some(c);
                code.push(' ');
            }
            None => code.push(c),
        }
    }
    let chars: Vec<char> = code.chars().collect();
    let word_at = |from: usize| -> Option<(usize, usize)> {
        let mut start = from;
        while start < chars.len() && chars[start] == ' ' {
            start += 1;
        }
        if start >= chars.len() || !(chars[start].is_ascii_alphabetic() || chars[start] == '_') {
            return None;
        }
        let mut end = start;
        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
            end += 1;
        }
        Some((start, end))
    };
    let text = |(a, b): (usize, usize)| -> String {
        chars[a..b].iter().collect::<String>().to_ascii_lowercase()
    };
    let mut found = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let Some((start, end)) = word_at(i) else {
            i += 1;
            continue;
        };
        i = end;
        let word = text((start, end));
        let before = chars[..start].iter().rev().find(|c| **c != ' ').copied();
        if matches!(before, Some('.') | Some(':')) {
            continue;
        }
        let previous_word = {
            let mut back = start;
            while back > 0 && chars[back - 1] == ' ' {
                back -= 1;
            }
            let mut from = back;
            while from > 0 && (chars[from - 1].is_ascii_alphanumeric() || chars[from - 1] == '_') {
                from -= 1;
            }
            (from < back).then(|| text((from, back)))
        };
        let mut open = end;
        while open < chars.len() && chars[open] == ' ' {
            open += 1;
        }
        if chars.get(open) != Some(&'(') {
            continue;
        }
        if previous_word.as_deref() == Some("as") || word.starts_with("pgmcp_") {
            continue;
        }
        // A CTE column list: the parenthesis closes and `AS` follows.
        let mut depth = 0;
        let mut close = open;
        while close < chars.len() {
            match chars[close] {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        break;
                    }
                }
                _ => {}
            }
            close += 1;
        }
        if word_at(close + 1).is_some_and(|w| text(w) == "as") {
            continue;
        }
        if !SYNTAX_KEYWORDS.contains(&word.as_str()) {
            found.push(word);
        }
    }
    found
}

/// Every `.rs` file under `dir`, sorted.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out.sort();
}

/// The contents of every ordinary string literal in Rust source, with comments and char literals skipped.
fn string_literals(source: &str) -> Vec<String> {
    let chars: Vec<char> = source.chars().collect();
    let mut literals = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '/' if chars.get(i + 1) == Some(&'/') => {
                while i < chars.len() && chars[i] != '\n' {
                    i += 1;
                }
            }
            '/' if chars.get(i + 1) == Some(&'*') => {
                i += 2;
                while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                    i += 1;
                }
                i += 2;
            }
            '\'' => {
                if chars.get(i + 1) == Some(&'\\') {
                    i += 2;
                    while i < chars.len() && chars[i] != '\'' {
                        i += 1;
                    }
                    i += 1;
                } else if chars.get(i + 2) == Some(&'\'') {
                    i += 3;
                } else {
                    i += 1;
                }
            }
            '"' => {
                let mut text = String::new();
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                        match chars.get(i) {
                            Some('\n') => {
                                while i < chars.len() && chars[i].is_whitespace() {
                                    i += 1;
                                }
                                continue;
                            }
                            Some('n') => text.push('\n'),
                            Some('t') => text.push('\t'),
                            Some(&c) => text.push(c),
                            None => break,
                        }
                    } else {
                        text.push(chars[i]);
                    }
                    i += 1;
                }
                i += 1;
                literals.push(text);
            }
            _ => i += 1,
        }
    }
    literals
}

/// The SQL text with format placeholders replaced: a placeholder in function position is DYNAMIC_FUNCTION,
/// any other placeholder is `pgmcp_arg`. Doubled braces become single braces.
fn sql_with_placeholders(literal: &str) -> String {
    let mut out = String::new();
    let mut chars = literal.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                out.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                out.push('}');
            }
            '{' => {
                let mut name = String::new();
                for n in chars.by_ref() {
                    if n == '}' {
                        break;
                    }
                    name.push(n);
                }
                let in_function_position = chars.peek() == Some(&'(');
                out.push_str(if in_function_position {
                    DYNAMIC_FUNCTION
                } else {
                    "pgmcp_arg"
                });
            }
            other => out.push(other),
        }
    }
    out
}

/// Names of every FuncCall node in a serialized parse tree, with the number of name parts it has.
fn function_calls(tree: &Value, found: &mut Vec<Vec<String>>) {
    let mut stack = vec![tree];
    while let Some(node) = stack.pop() {
        match node {
            Value::Object(map) => {
                if let Some(call) = map.get("FuncCall") {
                    let names: Vec<String> = call["funcname"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|part| {
                            part["node"]["String"]["sval"].as_str().map(str::to_owned)
                        })
                        .collect();
                    found.push(names);
                }
                stack.extend(map.values());
            }
            Value::Array(items) => stack.extend(items.iter()),
            _ => {}
        }
    }
}

/// Every unqualified function call in the SQL literals of `src`, as "file: name", plus how many literals parsed.
fn unqualified_calls() -> (Vec<String>, usize, usize) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    let mut violations = Vec::new();
    let mut parsed = 0;
    let mut sql_literals = 0;
    for file in &files {
        let source = std::fs::read_to_string(file).expect("source is readable");
        for literal in string_literals(&source) {
            let sql = sql_with_placeholders(&literal);
            let looks_like_sql = sql.split_whitespace().next().is_some_and(|w| {
                matches!(
                    w.to_ascii_uppercase().as_str(),
                    "SELECT" | "WITH" | "VALUES" | "TABLE" | "SHOW"
                )
            });
            if !looks_like_sql {
                continue;
            }
            sql_literals += 1;
            for name in unqualified_text_calls(&sql) {
                let location = file.strip_prefix(&root).unwrap_or(file).display();
                violations.push(format!("{location}: {name}"));
            }
            let Ok(tree) = pg_query::parse(&sql, pg_query::ParserOptions::DEFAULT) else {
                continue;
            };
            parsed += 1;
            let serialized = serde_json::to_value(&tree.protobuf).expect("parse tree serializes");
            let mut calls = Vec::new();
            function_calls(&serialized, &mut calls);
            for names in calls {
                let qualified = names.len() >= 2 && QUALIFYING_SCHEMAS.contains(&names[0].as_str());
                let dynamic = names.len() == 1 && names[0] == DYNAMIC_FUNCTION;
                if !qualified && !dynamic {
                    let name = names.join(".");
                    let location = file.strip_prefix(&root).unwrap_or(file).display();
                    violations.push(format!("{location}: {name}"));
                }
            }
        }
    }
    violations.sort();
    violations.dedup();
    (violations, sql_literals, parsed)
}

#[test]
fn every_function_call_in_internal_sql_is_schema_qualified() {
    let (violations, sql_literals, parsed) = unqualified_calls();
    eprintln!("internal SQL literals: {sql_literals}, parsed: {parsed}");
    assert!(parsed > 50, "only {parsed} SQL literals parsed");
    assert_eq!(violations, Vec::<String>::new(), "unqualified calls");
}
