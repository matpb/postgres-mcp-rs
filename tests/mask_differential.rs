//! Corpus check of the PASSWORD masks: every generated statement keeps its secrets hidden and its own text.

use postgres_mcp::encode::TRUNCATION_MARK;
use postgres_mcp::tools::mask::{mask, mask_password_literals};
use std::time::{Duration, Instant};

/// Documented limits. A limit's forms are generated only when its flag is on; the corpus test turns them all off.
#[derive(Clone, Copy)]
enum Limit {
    SeparatorLess,
    LongComment,
    TwoLevels,
    EscapedNested,
    QuoteStart,
    NoOuterQuote,
    Concat,
}

struct Limits {
    separatorless: bool,
    long_comment: bool,
    two_levels: bool,
    escaped_nested: bool,
    quote_start: bool,
    no_outer_quote: bool,
    concat: bool,
}

impl Limits {
    /// Every documented limit off: the corpus holds only forms that must be fully masked.
    const OFF: Limits = Limits {
        separatorless: false,
        long_comment: false,
        two_levels: false,
        escaped_nested: false,
        quote_start: false,
        no_outer_quote: false,
        concat: false,
    };
    fn allows(&self, limit: Option<Limit>) -> bool {
        match limit {
            None => true,
            Some(Limit::SeparatorLess) => self.separatorless,
            Some(Limit::LongComment) => self.long_comment,
            Some(Limit::TwoLevels) => self.two_levels,
            Some(Limit::EscapedNested) => self.escaped_nested,
            Some(Limit::QuoteStart) => self.quote_start,
            Some(Limit::NoOuterQuote) => self.no_outer_quote,
            Some(Limit::Concat) => self.concat,
        }
    }
}

/// A literal after the keyword, holding the secret token `t`, and the limit it belongs to (if any).
struct Form {
    build: fn(&str) -> String,
    limit: Option<Limit>,
}

fn form(build: fn(&str) -> String, limit: Option<Limit>) -> Form {
    Form { build, limit }
}

/// Literals in statement text (outside any quoted literal).
fn statement_forms() -> Vec<Form> {
    vec![
        form(|t| format!("'{t}'"), None),
        form(|t| format!("$${t}$$"), None),
        form(|t| format!("$t${t}$t$"), None),
        form(|t| format!("E'{t}'"), None),
        form(|t| format!("e'{t}'"), None),
        form(|t| format!("U&'{t}'"), None),
        form(|t| format!("'''{t}'"), None),
        form(
            |t| format!("' || quote_literal('{t}')"),
            Some(Limit::Concat),
        ),
        form(|t| format!("'')x{t}"), Some(Limit::NoOuterQuote)),
    ]
}

/// Literals nested in a quoted statement, which the corpus places inside `EXECUTE '...'`.
fn nested_forms() -> Vec<Form> {
    vec![
        form(|t| format!("''{t}'''"), None),
        form(|t| format!("E''{t}'''"), None),
        form(|t| format!("U&''{t}'''"), None),
        form(|t| format!("'' {t}'''"), None),
        form(|t| format!("'')x{t}'''"), None),
        form(|t| format!("''''''{t}'''''''''"), Some(Limit::TwoLevels)),
        form(|t| format!("E''x\\'{t}'''"), Some(Limit::EscapedNested)),
        form(|t| format!("''''{t}'''''"), Some(Limit::QuoteStart)),
    ]
}

/// Separators between the keyword and its literal: whitespace, comments up to the budget, and the limit cases.
fn separators(limits: &Limits) -> Vec<(String, Option<Limit>)> {
    let block = |n: usize| format!("/*{}*/", "c".repeat(n));
    let mut seps = vec![
        (" ".to_owned(), None),
        ("\n".to_owned(), None),
        ("/* c */".to_owned(), None),
        ("-- c\n".to_owned(), None),
        (block(98), None),
        (block(252), None),
    ];
    if limits.long_comment {
        seps.push((block(253), Some(Limit::LongComment)));
    }
    if limits.separatorless {
        seps.push((String::new(), Some(Limit::SeparatorLess)));
    }
    seps.retain(|(_, limit)| limits.allows(*limit));
    seps
}

const KEYWORDS: &[&str] = &["PASSWORD", "password", "Password"];
const PADS: &[usize] = &[0, 1, 255, 400];
/// Text before a statement that holds a password, with no quote open at the keyword.
const STATEMENT_PREFIXES: &[&str] = &["", "SELECT 1; ", "-- note\n", "/* c */ ", "x = 'y'; "];
const STATEMENT_SUFFIXES: &[&str] = &[
    "",
    "; SELECT 'a'",
    " ) ",
    "\n-- tail\n",
    "; ALTER ROLE b PASSWORD 'z'",
];
/// Empty literals before a statement, with no secret in them.
const EMPTY_BEFORE: &[&str] = &[
    "",
    "ALTER ROLE e PASSWORD ''; ",
    "ALTER ROLE e PASSWORD '' NOLOGIN; ",
    "CREATE USER MAPPING FOR u SERVER s OPTIONS (password ''); ",
];
/// The statement that opens an `EXECUTE` literal, and the one that closes it.
const QUOTED_PREFIX: &str = "DO $do$ BEGIN EXECUTE 'ALTER ROLE app ";
const QUOTED_SUFFIX: &str = "; END $do$";

/// The statement-level texts, one per combination of the grammar, each with its secret token.
fn statements(limits: &Limits, next_token: &mut usize) -> Vec<(String, Vec<String>)> {
    let seps = separators(limits);
    let mut out = Vec::new();
    for prefix in STATEMENT_PREFIXES {
        for kw in KEYWORDS {
            for (sep, _) in &seps {
                for pad in PADS {
                    for f in statement_forms().iter().filter(|f| limits.allows(f.limit)) {
                        for suffix in STATEMENT_SUFFIXES {
                            for before in EMPTY_BEFORE {
                                let token = format!("tok{:07}", *next_token);
                                *next_token += 1;
                                let literal = (f.build)(&token);
                                let text = format!(
                                    "{before}{prefix}ALTER ROLE a {kw}{sep}{}{literal}{suffix}",
                                    " ".repeat(*pad)
                                );
                                out.push((text, vec![token]));
                            }
                        }
                    }
                }
            }
        }
    }
    out
}

/// The texts with a password literal nested in `EXECUTE '...'`, one per combination of the grammar.
fn nested_statements(limits: &Limits, next_token: &mut usize) -> Vec<(String, Vec<String>)> {
    let seps = separators(limits);
    let mut out = Vec::new();
    for kw in KEYWORDS {
        for (sep, _) in &seps {
            for pad in PADS {
                for f in nested_forms().iter().filter(|f| limits.allows(f.limit)) {
                    let token = format!("tok{:07}", *next_token);
                    *next_token += 1;
                    let literal = (f.build)(&token);
                    let text = format!(
                        "{QUOTED_PREFIX}{kw}{sep}{}{literal}{QUOTED_SUFFIX}",
                        " ".repeat(*pad)
                    );
                    out.push((text, vec![token]));
                }
            }
        }
    }
    out
}

/// Two passwords in one text, with markers outside every literal: before, between and after the statements.
fn multi_statements(
    limits: &Limits,
    next_token: &mut usize,
) -> Vec<(String, Vec<String>, Vec<String>)> {
    let seps = separators(limits);
    let mut out = Vec::new();
    for before in EMPTY_BEFORE {
        for f1 in statement_forms().iter().filter(|f| limits.allows(f.limit)) {
            for (sep1, _) in &seps {
                for f2 in statement_forms().iter().filter(|f| limits.allows(f.limit)) {
                    for (sep2, _) in &seps {
                        let (t1, t2) = (
                            format!("tok{:07}", *next_token),
                            format!("tok{:07}", *next_token + 1),
                        );
                        *next_token += 2;
                        let text = format!(
                            "SELECT keepA; {before}ALTER ROLE a PASSWORD{sep1}{}; SELECT keepB; ALTER ROLE b PASSWORD{sep2}{} ; SELECT keepC",
                            (f1.build)(&t1),
                            (f2.build)(&t2),
                        );
                        out.push((
                            text,
                            vec![t1, t2],
                            vec!["keepA".into(), "keepB".into(), "keepC".into()],
                        ));
                    }
                }
            }
        }
    }
    out
}

/// Asserts that each token of `secrets` is hidden and each marker of `keeps` survives, in both masks.
fn check(text: &str, secrets: &[String], keeps: &[String]) {
    for masked in [mask_password_literals(text).into_owned(), mask(text)] {
        for token in secrets {
            assert!(
                !masked.contains(token),
                "{token} visible: {text:?} -> {masked:?}"
            );
        }
        for keep in keeps {
            assert!(masked.contains(keep), "{keep} lost: {text:?} -> {masked:?}");
        }
    }
}

#[test]
fn every_generated_statement_hides_its_secrets_and_keeps_its_text() {
    let started = Instant::now();
    let limits = Limits::OFF;
    let mut next_token = 0;
    let mut cases = 0usize;

    let single: Vec<_> = statements(&limits, &mut next_token)
        .into_iter()
        .chain(nested_statements(&limits, &mut next_token))
        .collect();
    for (text, secrets) in &single {
        check(text, secrets, &[]);
        cases += 1;
    }

    let multi = multi_statements(&limits, &mut next_token);
    for (text, secrets, keeps) in &multi {
        check(text, secrets, keeps);
        cases += 1;
    }

    // Every byte offset of a sample of statements, cut with and without the marker the encoder appends.
    let mut cuts = 0usize;
    for (text, secrets) in single.iter().step_by(50) {
        cuts += cut_all(text, secrets, &[]);
    }
    for (text, secrets, keeps) in multi.iter().step_by(40) {
        cuts += cut_all(text, secrets, keeps);
    }

    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "corpus took {elapsed:?} over {cases} cases and {cuts} cuts"
    );
}

/// Checks `text` cut at each byte offset, with and without a marker; returns the number of cuts checked.
fn cut_all(text: &str, secrets: &[String], keeps: &[String]) -> usize {
    let mut count = 0;
    for cut in 0..=text.len() {
        let body = &text[..cut];
        let visible: Vec<String> = secrets
            .iter()
            .filter(|t| body.contains(t.as_str()))
            .cloned()
            .collect();
        let kept: Vec<String> = keeps
            .iter()
            .filter(|k| body.contains(k.as_str()))
            .cloned()
            .collect();
        check(body, &visible, &kept);
        let marked = format!("{body}{TRUNCATION_MARK}{cut} of {} bytes]", text.len());
        check(&marked, &visible, &kept);
        count += 2;
    }
    count
}

/// Each documented limit is real: each limit form leaves its secret visible in a mask, and so does each limit separator.
#[test]
fn each_documented_limit_leaks_as_documented() {
    let mut leaks = Vec::new();
    let statement = statement_forms();
    for (i, f) in statement.iter().enumerate() {
        if f.limit.is_some() {
            let token = format!("tok{i:07}");
            leaks.push((
                format!("ALTER ROLE a PASSWORD {}", (f.build)(&token)),
                token,
            ));
        }
    }
    for (i, f) in nested_forms().iter().enumerate() {
        if f.limit.is_some() {
            let token = format!("tok{:07}", 100 + i);
            let text = format!(
                "{QUOTED_PREFIX}PASSWORD {}{QUOTED_SUFFIX}",
                (f.build)(&token)
            );
            leaks.push((text, token));
        }
    }
    assert_eq!(leaks.len(), 5);
    for (text, token) in leaks {
        let visible =
            mask_password_literals(&text).contains(&token) || mask(&text).contains(&token);
        assert!(visible, "a documented limit no longer leaks: {text:?}");
    }
    let block = format!("/*{}*/", "c".repeat(253));
    let long = format!("ALTER ROLE a PASSWORD{block}'tok9999991'");
    assert!(mask_password_literals(&long).contains("tok9999991"));
    assert!(mask(&long).contains("tok9999991"));
    // Results use the literal-only mask, which needs whitespace or a comment before the literal.
    let bare = "ALTER ROLE a PASSWORD'tok9999992'";
    assert!(mask_password_literals(bare).contains("tok9999992"));
}
