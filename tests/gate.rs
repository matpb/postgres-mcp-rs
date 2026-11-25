//! Tests for the read-only query gate: corpus files, exact messages and property checks.

use postgres_mcp::gate::{Accepted, GateOptions, Rejection, SECRET_SETTINGS, StatementKind, check};
use proptest::prelude::*;

fn gate(sql: &str) -> Result<Accepted, Rejection> {
    check(sql, &GateOptions::default())
}

fn code_of(sql: &str) -> &'static str {
    match gate(sql) {
        Err(rejection) => rejection.code,
        Ok(accepted) => panic!("expected a rejection, accepted as {accepted:?}: {sql}"),
    }
}

/// Splits a corpus file into blocks at lines that contain only `--;;`.
fn read_corpus(name: &str) -> Vec<String> {
    let path = format!("{}/tests/gate_corpus/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).expect("corpus file is readable");
    let mut blocks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        if line == "--;;" {
            blocks.push(std::mem::take(&mut current));
        } else {
            current.push_str(line);
            current.push('\n');
        }
    }
    blocks.push(current);
    blocks
        .into_iter()
        .map(|block| block.trim().to_string())
        .filter(|block| !block.is_empty())
        .collect()
}

fn expected_code(block: &str) -> &str {
    block
        .lines()
        .next()
        .and_then(|line| line.strip_prefix("-- code: "))
        .expect("deny block starts with a '-- code: ' line")
}

#[test]
fn allow_corpus_is_accepted() {
    let blocks = read_corpus("allow.sql");
    assert!(
        blocks.len() >= 50,
        "allow corpus has {} blocks",
        blocks.len()
    );
    for block in blocks {
        if let Err(rejection) = gate(&block) {
            panic!("allowed block rejected: {rejection:?}\n{block}");
        }
    }
}

#[test]
fn deny_corpus_is_rejected_with_expected_code() {
    let blocks = read_corpus("deny.sql");
    assert!(
        blocks.len() >= 100,
        "deny corpus has {} blocks",
        blocks.len()
    );
    for block in blocks {
        let expected = expected_code(&block);
        match gate(&block) {
            Err(rejection) => {
                assert_eq!(rejection.code, expected, "{}\n{block}", rejection.message)
            }
            Ok(accepted) => panic!("expected {expected}, accepted as {accepted:?}:\n{block}"),
        }
    }
}

#[test]
fn options_too_long() {
    let opts = GateOptions {
        allow_placeholders: false,
        max_sql_bytes: 10,
    };
    let rejection =
        check("SELECT 1234567890", &opts).expect_err("17 bytes is over the 10 byte limit");
    assert_eq!(rejection.code, "too_long");
    assert_eq!(
        rejection.message,
        "SQL text is 17 bytes; the limit is 10 bytes."
    );
    assert_eq!(
        check("SELECT 123", &opts).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn default_limit_is_100_kib() {
    let opts = GateOptions::default();
    assert_eq!(opts.max_sql_bytes, 100 * 1024);
    assert!(!opts.allow_placeholders);
    let padded = format!("SELECT 1{}", " ".repeat(100 * 1024 - 8));
    assert_eq!(padded.len(), 100 * 1024);
    assert_eq!(
        check(&padded, &opts).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
    let too_big = format!("{padded} ");
    assert_eq!(
        check(&too_big, &opts).expect_err("over the limit").code,
        "too_long"
    );
}

#[test]
fn nul_byte() {
    let rejection = gate("SELECT 1\0").expect_err("NUL is rejected");
    assert_eq!(rejection.code, "nul_byte");
    assert_eq!(rejection.message, "SQL text contains a NUL byte.");
}

#[test]
fn empty_inputs_are_empty() {
    for sql in ["", "   \n\t ", "-- only a comment", "/* block */", ";"] {
        let rejection = gate(sql).expect_err("no statement to accept");
        assert_eq!(rejection.code, "empty", "input {sql:?}");
        assert_eq!(rejection.message, "SQL text is empty.");
    }
}

#[test]
fn zero_limit_empty_input_is_still_empty() {
    let opts = GateOptions {
        allow_placeholders: false,
        max_sql_bytes: 0,
    };
    assert_eq!(check("", &opts).expect_err("empty").code, "empty");
    assert_eq!(check("1", &opts).expect_err("too long").code, "too_long");
}

#[test]
fn parse_error_uses_the_parser_message() {
    let rejection = gate("SELECT FROM WHERE").expect_err("syntax error");
    assert_eq!(rejection.code, "parse_error");
    assert!(
        rejection.message.starts_with("SQL syntax error: "),
        "message was {:?}",
        rejection.message
    );
    assert!(
        rejection.message.contains("WHERE"),
        "message was {:?}",
        rejection.message
    );
}

#[test]
fn explain_generic_plan_allows_placeholder() {
    let with = GateOptions {
        allow_placeholders: true,
        max_sql_bytes: 100 * 1024,
    };
    let accepted = check("EXPLAIN (GENERIC_PLAN) SELECT $1", &with).expect("accepted");
    assert_eq!(accepted.kind, StatementKind::Explain { analyze: false });
    assert_eq!(code_of("EXPLAIN (GENERIC_PLAN) SELECT $1"), "placeholder");
    let rejection = gate("SELECT $1").expect_err("placeholder");
    assert_eq!(
        rejection.message,
        "Parameter placeholders ($1) are not supported. Inline the value."
    );
    assert_eq!(
        check("SELECT $1", &with).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn kinds() {
    let kind = |sql: &str| gate(sql).expect("accepted").kind;
    assert_eq!(kind("SELECT 1"), StatementKind::Select);
    assert_eq!(kind("VALUES (1)"), StatementKind::Select);
    assert_eq!(kind("TABLE t"), StatementKind::Select);
    assert_eq!(
        kind("EXPLAIN ANALYZE SELECT 1"),
        StatementKind::Explain { analyze: true }
    );
    assert_eq!(
        kind("EXPLAIN (ANALYZE false) SELECT 1"),
        StatementKind::Explain { analyze: false }
    );
    assert_eq!(
        kind("EXPLAIN (ANALYZE 0) SELECT 1"),
        StatementKind::Explain { analyze: false }
    );
    assert_eq!(
        kind("EXPLAIN (ANALYZE off) SELECT 1"),
        StatementKind::Explain { analyze: false }
    );
    assert_eq!(
        kind("EXPLAIN (ANALYZE true) SELECT 1"),
        StatementKind::Explain { analyze: true }
    );
    assert_eq!(
        kind("EXPLAIN (Analyze, Buffers) SELECT 1"),
        StatementKind::Explain { analyze: true }
    );
    assert_eq!(
        kind("EXPLAIN SELECT 1"),
        StatementKind::Explain { analyze: false }
    );
    assert_eq!(
        kind("SHOW ALL"),
        StatementKind::Show {
            name: "all".to_string()
        }
    );
    assert_eq!(
        kind("SHOW Server_Version"),
        StatementKind::Show {
            name: "server_version".to_string()
        }
    );
}

#[test]
fn constructs_report_exact_messages() {
    let cases = [
        (
            "SELECT 1 INTO x",
            "select_into",
            "SELECT ... INTO creates a table and is not allowed. Remove the INTO clause.",
        ),
        (
            "SELECT * FROM t FOR UPDATE",
            "row_locking",
            "FOR UPDATE / FOR SHARE takes row locks and is not allowed. Remove the locking clause.",
        ),
        (
            "WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d",
            "data_modifying_cte",
            "Data-modifying statements inside WITH (INSERT, UPDATE, DELETE, MERGE) are not allowed.",
        ),
        (
            "SELECT $1",
            "placeholder",
            "Parameter placeholders ($1) are not supported. Inline the value.",
        ),
        (
            "SHOW primary_conninfo",
            "setting_denied",
            "The setting primary_conninfo can expose credentials or local paths and is not readable through this server. Use the server_info tool for settings.",
        ),
        (
            "SELECT cron.schedule('* * * * *', 'select 1')",
            "function_denied",
            "Function schedule() is not allowed: it changes scheduled jobs.",
        ),
        (
            "SELECT 1; SELECT 2",
            "multiple_statements",
            "Send exactly one statement per call; found 2.",
        ),
        (
            "EXPLAIN DELETE FROM t",
            "statement_not_allowed",
            "Only read-only statements are accepted (SELECT, WITH, VALUES, TABLE, EXPLAIN, SHOW). This is a DELETE statement.",
        ),
    ];
    for (sql, code, message) in cases {
        let rejection = gate(sql).expect_err(sql);
        assert_eq!(
            (rejection.code, rejection.message.as_str()),
            (code, message),
            "{sql}"
        );
    }
}

#[test]
fn explain_option_outside_allow_list_is_rejected() {
    let rejection = gate("EXPLAIN (FOO) SELECT 1").expect_err("unknown option");
    assert_eq!(rejection.code, "explain_option");
    assert_eq!(rejection.message, "EXPLAIN option foo is not allowed.");
}

#[test]
fn messages_name_the_construct() {
    let rejection = gate("INSERT INTO t VALUES (1)").expect_err("insert");
    assert_eq!(rejection.code, "statement_not_allowed");
    assert_eq!(
        rejection.message,
        "Only read-only statements are accepted (SELECT, WITH, VALUES, TABLE, EXPLAIN, SHOW). This is a INSERT statement."
    );
    assert!(rejection.message.contains("INSERT"));

    let rejection = gate("SELECT pg_terminate_backend(1)").expect_err("function");
    assert_eq!(
        rejection.message,
        "Function pg_terminate_backend() is not allowed: it controls the server or other sessions."
    );
    assert!(rejection.message.contains("pg_terminate_backend"));
}

#[test]
fn schedule_unqualified_is_allowed() {
    assert_eq!(
        gate("SELECT schedule(1)").map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn secret_settings_are_exported() {
    let mut names = SECRET_SETTINGS.to_vec();
    names.sort_unstable();
    assert_eq!(
        names,
        vec![
            "archive_cleanup_command",
            "archive_command",
            "krb_server_keyfile",
            "primary_conninfo",
            "recovery_end_command",
            "restore_command",
            "ssl_key_file",
            "ssl_passphrase_command",
        ]
    );
}

#[test]
fn secret_settings_are_denied_by_show_and_current_setting() {
    assert_eq!(code_of("SHOW primary_conninfo"), "setting_denied");
    assert_eq!(code_of("SHOW SSL_KEY_FILE"), "setting_denied");
    assert_eq!(
        code_of("SELECT current_setting('restore_command')"),
        "setting_denied"
    );
    assert_eq!(
        gate("SHOW work_mem").map(|a| a.kind),
        Ok(StatementKind::Show {
            name: "work_mem".to_string()
        })
    );
}

#[test]
fn relation_denied_message_is_exact() {
    let rejection = gate("SELECT * FROM pg_catalog.pg_shadow").expect_err("credentials view");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        "Relation pg_shadow is not readable through this server. It can expose credentials."
    );
    assert_eq!(
        gate("SELECT * FROM pg_roles").map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn settings_relations_keep_the_server_info_message() {
    for name in ["pg_settings", "pg_file_settings"] {
        let rejection = gate(&format!("SELECT * FROM pg_catalog.{name}")).expect_err(name);
        assert_eq!(rejection.code, "relation_denied", "{name}");
        assert_eq!(
            rejection.message,
            format!(
                "{name} can expose credentials and is not readable through this server. Use the server_info tool for settings."
            ),
            "{name}"
        );
    }
}

#[test]
fn user_mappings_underscore_view_is_denied_with_exact_message() {
    let rejection = gate("SELECT umoptions FROM information_schema._pg_user_mappings")
        .expect_err("user mapping view with passwords");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        "Relation _pg_user_mappings is not readable through this server. It can expose credentials."
    );
}

#[test]
fn function_denied_is_case_insensitive_and_checks_quoted_names() {
    assert_eq!(code_of("SELECT PG_TERMINATE_BACKEND(1)"), "function_denied");
    assert_eq!(code_of("SELECT \"pg_advisory_lock\"(1)"), "function_denied");
    assert_eq!(
        gate("SELECT PG_Sleep(0)").map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn allowed_names_that_look_like_denied_ones() {
    for sql in [
        "SELECT pg_sleep(1), lo_get(123), currval('s'), lastval()",
        "SELECT pg_ls_logdir(), pg_ls_waldir(), pg_current_xact_id_if_assigned()",
        "SELECT pg_stat_get_activity(NULL)",
        "SELECT time_bucket('1 hour', ts), hypertable_size('t'), show_chunks('t')",
        "SELECT approximate_row_count('t'), now(), count(*), set_bit(b, 1, 1), replace(a, 'x', 'y')",
        "SELECT overlay(a placing 'x' from 1), \"insert\" FROM t",
    ] {
        assert!(gate(sql).is_ok(), "should be accepted: {sql}");
    }
}

/// Deep trees hit either the walker cap (`too_deep`) or pg_query's own nesting limits, which depend on the build profile.
#[test]
fn deep_nesting_is_rejected_not_crashed() {
    let chain = (0..2000).map(|_| "1").collect::<Vec<_>>().join("+");
    let nested = format!(
        "SELECT * FROM {}t{}",
        "(SELECT * FROM ".repeat(800),
        ") s".repeat(800)
    );
    let opts = GateOptions {
        allow_placeholders: false,
        max_sql_bytes: 1024 * 1024,
    };
    for sql in [format!("SELECT {chain}"), nested] {
        let rejection = check(&sql, &opts).expect_err("deep tree is rejected");
        let too_deep = rejection.code == "too_deep"
            && rejection.message == "The query is nested too deeply for the read-only gate.";
        let parser_limit = rejection.code == "parse_error"
            && rejection.message.starts_with("SQL syntax error: ")
            && (rejection.message.ends_with("stack depth limit exceeded")
                || rejection
                    .message
                    .ends_with("nested too deeply to serialize to protobuf"));
        assert!(
            too_deep || parser_limit,
            "unexpected rejection: {rejection:?}"
        );
    }
}

#[test]
fn nesting_below_the_depth_cap_is_accepted() {
    let chain = (0..400).map(|_| "1").collect::<Vec<_>>().join("+");
    assert_eq!(
        gate(&format!("SELECT {chain}")).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
    let nested = format!(
        "SELECT * FROM {}t{}",
        "(SELECT * FROM ".repeat(250),
        ") s".repeat(250)
    );
    assert_eq!(gate(&nested).map(|a| a.kind), Ok(StatementKind::Select));
}

#[test]
fn huge_numbers_and_long_chains_are_accepted() {
    let digits = "9".repeat(1000);
    assert_eq!(
        gate(&format!("SELECT {digits}")).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
    let chain = (0..200).map(|_| "1").collect::<Vec<_>>().join("+");
    assert_eq!(
        gate(&format!("SELECT {chain}")).map(|a| a.kind),
        Ok(StatementKind::Select)
    );
}

#[test]
fn arguments_are_unchanged() {
    let opts = GateOptions {
        allow_placeholders: true,
        max_sql_bytes: 4096,
    };
    let before = format!("{opts:?}");
    let sql = String::from("SELECT $1, lo_get(1)");
    let _ = check(&sql, &opts);
    let _ = check("INSERT INTO t VALUES (1)", &opts);
    assert_eq!(format!("{opts:?}"), before);
    assert_eq!(sql, "SELECT $1, lo_get(1)");
}

const COMPUTED_SETTING: &str =
    "current_setting() takes a literal setting name here; computed names are not allowed.";

#[test]
fn current_setting_takes_only_a_literal_name() {
    for sql in [
        "SELECT current_setting('primary_conninfo'::text)",
        "SELECT current_setting('primary_' || 'conninfo')",
        "SELECT current_setting(lower('X'))",
        "SELECT current_setting(n) FROM unnest(ARRAY['primary_conninfo']) AS n",
        "SELECT pg_catalog.current_setting('archive_command'::text)",
        "SELECT current_setting((SELECT 'primary_conninfo'))",
        "SELECT current_setting(VARIADIC ARRAY['primary_conninfo'])",
        "SELECT \"current_setting\"('ssl_passphrase_command'::name)",
        "SELECT current_setting('work_mem'::text)",
        "SELECT current_setting(1)",
        "SELECT current_setting(NULL)",
        "SELECT current_setting('work_mem', current_setting('work_mem'))",
        "SELECT current_setting()",
    ] {
        let rejection = gate(sql).expect_err(sql);
        assert_eq!(rejection.code, "setting_denied", "{sql}");
        assert_eq!(rejection.message, COMPUTED_SETTING, "{sql}");
    }
}

#[test]
fn current_setting_literal_secret_uses_the_secret_message() {
    let rejection = gate("SELECT pg_catalog.current_setting('Primary_Conninfo', true)")
        .expect_err("secret literal");
    assert_eq!(rejection.code, "setting_denied");
    assert_eq!(
        rejection.message,
        "The setting primary_conninfo can expose credentials or local paths and is not readable through this server. Use the server_info tool for settings."
    );
}

#[test]
fn current_setting_literal_names_are_accepted() {
    for sql in [
        "SELECT current_setting('work_mem')",
        "SELECT pg_catalog.current_setting('TimeZone', true)",
        "SELECT current_setting('work_mem', 1)",
    ] {
        assert_eq!(
            gate(sql).map(|a| a.kind),
            Ok(StatementKind::Select),
            "{sql}"
        );
    }
}

#[test]
fn catalog_config_relation_is_denied_with_exact_message() {
    let rejection = gate("SELECT * FROM pg_config").expect_err("build configuration view");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        "Relation pg_config is not readable through this server. It can expose credentials."
    );
}

/// Every function name the gate denies by name, with the reason the message must give.
const DENIED_BY_NAME: &[(&str, &str)] = &[
    (
        "heap_force_kill",
        "it changes or reads table pages directly",
    ),
    (
        "heap_force_freeze",
        "it changes or reads table pages directly",
    ),
    (
        "pg_truncate_visibility_map",
        "it changes or reads table pages directly",
    ),
    ("get_raw_page", "it changes or reads table pages directly"),
    ("autoprewarm_dump_now", "it performs maintenance work"),
    ("autoprewarm_start_worker", "it performs maintenance work"),
    ("pg_prewarm", "it performs maintenance work"),
    ("pg_logdir_ls", "it reads or writes server files"),
    ("add_policies", "it changes TimescaleDB objects"),
    ("alter_policies", "it changes TimescaleDB objects"),
    ("remove_policies", "it changes TimescaleDB objects"),
    ("remove_all_policies", "it changes TimescaleDB objects"),
    ("enable_chunk_skipping", "it changes TimescaleDB objects"),
    ("disable_chunk_skipping", "it changes TimescaleDB objects"),
    ("attach_chunk", "it changes TimescaleDB objects"),
    ("detach_chunk", "it changes TimescaleDB objects"),
    ("create_chunk", "it changes TimescaleDB objects"),
    ("copy_chunk", "it changes TimescaleDB objects"),
    ("cagg_migrate", "it changes TimescaleDB objects"),
    ("set_number_partitions", "it changes TimescaleDB objects"),
    ("set_replication_factor", "it changes TimescaleDB objects"),
    ("set_adaptive_chunking", "it changes TimescaleDB objects"),
    (
        "create_distributed_hypertable",
        "it changes TimescaleDB objects",
    ),
    (
        "pg_background_launch",
        "it executes SQL text the gate cannot inspect",
    ),
    (
        "pg_background_result",
        "it executes SQL text the gate cannot inspect",
    ),
    (
        "pg_background_detach",
        "it executes SQL text the gate cannot inspect",
    ),
    ("http", "it makes network requests"),
    ("http_get", "it makes network requests"),
    ("http_post", "it makes network requests"),
    ("http_put", "it makes network requests"),
    ("http_patch", "it makes network requests"),
    ("http_delete", "it makes network requests"),
    ("http_head", "it makes network requests"),
    ("http_set_curlopt", "it makes network requests"),
    ("http_reset_curlopt", "it makes network requests"),
    (
        "postgres_fdw_disconnect",
        "it controls the server or other sessions",
    ),
    (
        "postgres_fdw_disconnect_all",
        "it controls the server or other sessions",
    ),
    (
        "hypopg_create_index",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_drop_index",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_reset",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_reset_index",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_hide_index",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_unhide_index",
        "it changes session state that pooled connections would leak",
    ),
    (
        "hypopg_unhide_all_indexes",
        "it changes session state that pooled connections would leak",
    ),
    ("pg_stat_kcache_reset", "it changes statistics"),
    ("pg_qualstats_reset", "it changes statistics"),
    ("pg_wait_sampling_reset_profile", "it changes statistics"),
    ("pg_stat_monitor_reset", "it changes statistics"),
    (
        "pgr_dijkstra",
        "it is an extension routine the gate does not allow",
    ),
    (
        "pgr_createtopology",
        "it is an extension routine the gate does not allow",
    ),
];

#[test]
fn extension_functions_are_denied_by_name() {
    for (name, reason) in DENIED_BY_NAME {
        let upper = name.to_uppercase();
        for (sql, shown) in [
            (format!("SELECT {name}()"), name.to_string()),
            (
                format!("SELECT pg_catalog.{name}(1, 'x')"),
                name.to_string(),
            ),
            (format!("SELECT \"{upper}\"()"), upper.clone()),
        ] {
            let rejection = gate(&sql).expect_err(&sql);
            assert_eq!(rejection.code, "function_denied", "{sql}");
            assert_eq!(
                rejection.message,
                format!("Function {shown}() is not allowed: {reason}."),
                "{sql}"
            );
        }
    }
}

#[test]
fn calls_qualified_with_timescaledb_internal_schemas_are_denied() {
    for schema in [
        "_timescaledb_functions",
        "_timescaledb_internal",
        "_timescaledb_catalog",
    ] {
        for name in ["hypertable_size", "time_bucket", "anything_at_all"] {
            let sql = format!("SELECT {schema}.{name}('t')");
            let rejection = gate(&sql).expect_err(&sql);
            assert_eq!(rejection.code, "function_denied", "{sql}");
            assert_eq!(
                rejection.message,
                format!(
                    "Function {name}() is not allowed: it calls TimescaleDB internals the gate cannot classify."
                ),
                "{sql}"
            );
        }
    }
}

#[test]
fn timescaledb_read_functions_stay_allowed() {
    for sql in [
        "SELECT time_bucket('1 hour', ts), first(v, ts), last(v, ts) FROM t",
        "SELECT hypertable_size('t'), hypertable_detailed_size('t'), show_chunks('t')",
        "SELECT approximate_row_count('t'), chunks_detailed_size('t')",
        "SELECT histogram(v, 0, 10, 5), locf(v), interpolate(v)",
    ] {
        assert_eq!(
            gate(sql).map(|a| a.kind),
            Ok(StatementKind::Select),
            "{sql}"
        );
    }
}

/// Marks which characters are code, so mutations never touch strings or comments.
fn code_mask(chars: &[char]) -> Vec<bool> {
    let mut mask = vec![false; chars.len()];
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let end = if c == '-' && next == Some('-') {
            find_from(chars, i, &['\n']).map_or(chars.len(), |p| p + 1)
        } else if c == '/' && next == Some('*') {
            find_from(chars, i + 2, &['*', '/']).map_or(chars.len(), |p| p + 2)
        } else if c == '\'' || c == '"' {
            find_from(chars, i + 1, &[c]).map_or(chars.len(), |p| p + 1)
        } else if c == '$' {
            match dollar_quote_end(chars, i) {
                Some(end) => end,
                None => {
                    mask[i] = true;
                    i += 1;
                    continue;
                }
            }
        } else {
            mask[i] = true;
            i += 1;
            continue;
        };
        i = end;
    }
    mask
}

fn find_from(chars: &[char], from: usize, pattern: &[char]) -> Option<usize> {
    (from..chars.len()).find(|&p| chars[p..].starts_with(pattern))
}

/// Returns the end index of a `$tag$ ... $tag$` string starting at `start`, if one starts there.
fn dollar_quote_end(chars: &[char], start: usize) -> Option<usize> {
    let mut j = start + 1;
    while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
        j += 1;
    }
    if j >= chars.len() || chars[j] != '$' || chars[start + 1].is_ascii_digit() {
        return None;
    }
    let tag: Vec<char> = chars[start..=j].to_vec();
    Some(find_from(chars, j + 1, &tag).map_or(chars.len(), |p| p + tag.len()))
}

struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn bits(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn coin(&mut self) -> bool {
        self.bits() & 1 == 1
    }
}

/// Applies the mutations selected by `flags`: bit 0 whitespace, bit 1 case flips, bit 2 a tail.
fn mutate(sql: &str, seed: u64, flags: u8) -> String {
    let chars: Vec<char> = sql.chars().collect();
    let mask = code_mask(&chars);
    let mut rng = Rng::new(seed);
    let mut out = String::with_capacity(sql.len() + 16);
    for (i, &c) in chars.iter().enumerate() {
        if mask[i] && flags & 1 != 0 && c.is_whitespace() && rng.coin() {
            let replacements = ["/* g */", "\n-- g\n", "\t/**/\t"];
            out.push_str(replacements[(rng.bits() % 3) as usize]);
        } else if mask[i] && flags & 2 != 0 && c.is_ascii_alphabetic() && rng.coin() {
            out.push(if c.is_ascii_lowercase() {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            });
        } else {
            out.push(c);
        }
    }
    if flags & 4 != 0 {
        out.push_str(if rng.coin() { "\n;" } else { "\n-- x" });
    }
    out
}

const FRAGMENTS: &[&str] = &[
    "SELECT ",
    "INSERT ",
    "INTO ",
    "FROM ",
    "WITH ",
    "DELETE ",
    "EXPLAIN ",
    "ANALYZE ",
    "SHOW ",
    "FOR UPDATE ",
    "(",
    ")",
    ";",
    "'",
    "\"",
    "$$",
    "$a$",
    "$1",
    "--",
    "/*",
    "*/",
    "\n",
    " ",
    "\u{e9}",
    "\u{6f22}",
    "pg_sleep(1)",
    "nextval('s')",
    "::",
    ",",
    "*",
    "\\",
    "E'",
    "U&'",
    "x",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn check_never_panics(parts in proptest::collection::vec(proptest::sample::select(FRAGMENTS.to_vec()), 0..60)) {
        let sql: String = parts.concat().chars().take(300).collect();
        let _ = gate(&sql);
    }

    #[test]
    fn denied_blocks_stay_denied(
        idx in any::<proptest::sample::Index>(),
        seed in any::<u64>(),
        flags in 0u8..8,
    ) {
        let blocks = read_corpus("deny.sql");
        let block = &blocks[idx.index(blocks.len())];
        let expected = expected_code(block);
        let mutated = mutate(block, seed, flags);
        match gate(&mutated) {
            Err(rejection) => prop_assert_eq!(rejection.code, expected, "{}", mutated),
            Ok(accepted) => prop_assert!(false, "accepted as {:?}: {}", accepted, mutated),
        }
    }

    #[test]
    fn allowed_blocks_stay_allowed(
        idx in any::<proptest::sample::Index>(),
        seed in any::<u64>(),
        flags in 0u8..8,
    ) {
        let blocks = read_corpus("allow.sql");
        let block = &blocks[idx.index(blocks.len())];
        let mutated = mutate(block, seed, flags);
        match gate(&mutated) {
            Ok(_) => {}
            Err(rejection) => prop_assert!(false, "rejected {:?}: {}", rejection, mutated),
        }
    }
}

/// Every name the function deny list must refuse, each one of the corpus's denied names.
const NESTED_DENIED: [&str; 24] = [
    "pg_rotate_logfile",
    "pg_switch_wal",
    "pg_create_restore_point",
    "pg_promote",
    "pg_stat_reset",
    "pg_stat_reset_shared",
    "lo_put",
    "lo_from_bytea",
    "lowrite",
    "lo_export",
    "pg_export_snapshot",
    "table_to_xml",
    "schema_to_xml",
    "database_to_xml",
    "query_to_xmlschema",
    "cursor_to_xml",
    "pg_advisory_xact_lock",
    "pg_try_advisory_lock",
    "txid_current",
    "pg_replication_slot_advance",
    "pg_create_logical_replication_slot",
    "pg_drop_replication_slot",
    "dblink_exec",
    "dblink_connect",
];

/// One call of a denied function inside seven positions: subquery, CTE, LATERAL, FILTER, CASE, argument, ORDER BY.
fn nested_statements(call: &str) -> [String; 7] {
    [
        format!("SELECT * FROM (SELECT {call}) AS s"),
        format!("WITH c AS (SELECT {call}) SELECT * FROM c"),
        format!("SELECT * FROM generate_series(1, 1) AS g, LATERAL {call} AS l"),
        format!(
            "SELECT count(*) FILTER (WHERE {call} IS NOT NULL) OVER () FROM generate_series(1, 1) AS g"
        ),
        format!("SELECT CASE WHEN {call} IS NULL THEN 1 ELSE 2 END"),
        format!("SELECT length({call}::text)"),
        format!("SELECT 1 AS v ORDER BY {call}"),
    ]
}

#[test]
fn denied_names_are_rejected_when_nested() {
    for name in NESTED_DENIED {
        for call in [format!("{name}()"), format!("pg_catalog.{name}()")] {
            for sql in nested_statements(&call) {
                match gate(&sql) {
                    Err(rejection) => {
                        assert_eq!(rejection.code, "function_denied", "{sql}");
                        let prefix = format!("Function {name}() is not allowed: ");
                        assert!(
                            rejection.message.starts_with(&prefix),
                            "{sql}: {}",
                            rejection.message
                        );
                    }
                    Ok(accepted) => panic!("{sql} accepted as {accepted:?}"),
                }
            }
        }
    }
}

/// The dotted forms that name a function without a FuncCall node: `(NULL::text).x`, `(x).x`, `s.x`, `s.a.x`.
fn dotted_statements(name: &str) -> [String; 4] {
    [
        format!("SELECT (NULL::text).{name}"),
        format!("SELECT (x).{name} FROM (VALUES (1)) v(x)"),
        format!("SELECT s.{name} FROM (SELECT 1 AS a) s"),
        format!("SELECT s.a.{name} FROM (SELECT 1 AS a) s"),
    ]
}

/// A concrete name for each deny entry: the exact name, or the prefix plus a suffix for `prefix*` entries.
fn name_for_entry(pattern: &str) -> String {
    match pattern.strip_suffix('*') {
        Some(prefix) => format!("{prefix}x"),
        None => pattern.to_string(),
    }
}

#[test]
fn every_denied_name_is_rejected_after_a_dot() {
    for &(pattern, reason) in postgres_mcp::gate::denied_functions() {
        let name = name_for_entry(pattern);
        for sql in dotted_statements(&name) {
            let rejection = gate(&sql).expect_err(&sql);
            assert_eq!(rejection.code, "function_denied", "{sql}");
            assert_eq!(
                rejection.message,
                format!(
                    "\"{name}\" after a dot would call the function {name}(), which is not allowed: {reason}. If it is a column of yours, give it another name with AS in a subquery."
                ),
                "{sql}"
            );
        }
    }
}

#[test]
fn dotted_current_setting_is_rejected_with_the_computed_name_message() {
    for sql in [
        "SELECT ('ssl_key_file'::text).current_setting",
        "SELECT (x).current_setting FROM (VALUES ('ssl_key_file')) v(x)",
        "SELECT s.current_setting FROM (SELECT 1 AS a) s",
        "SELECT s.a.current_setting FROM (SELECT 1 AS a) s",
        "SELECT (NULL::text).Current_Setting",
    ] {
        let rejection = gate(sql).expect_err(sql);
        assert_eq!(rejection.code, "setting_denied", "{sql}");
        assert_eq!(
            rejection.message,
            "\"current_setting\" after a dot would call current_setting() with a computed name, which is not allowed. Use current_setting('name') with a literal name. If it is a column of yours, give it another name with AS in a subquery.",
            "{sql}"
        );
    }
}

#[test]
fn dotted_names_report_the_identifier_as_written() {
    let rejection = gate("SELECT (x).\"pg_terminate_backend\" FROM (VALUES (1)) v(x)")
        .expect_err("quoted dotted name");
    assert_eq!(rejection.code, "function_denied");
    assert_eq!(
        rejection.message,
        "\"pg_terminate_backend\" after a dot would call the function pg_terminate_backend(), which is not allowed: it controls the server or other sessions. If it is a column of yours, give it another name with AS in a subquery."
    );
}

#[test]
fn dotted_names_in_clauses_are_rejected() {
    for sql in [
        "SELECT * FROM t ORDER BY (t).pg_terminate_backend",
        "SELECT count(*) FROM t GROUP BY (t).pg_advisory_lock",
        "SELECT rank() OVER (PARTITION BY (t).pg_reload_conf) FROM t",
        "SELECT * FROM t ORDER BY t.pg_read_file",
        "SELECT * FROM t WHERE (x).nextval > 0",
        "SELECT ARRAY[(1).set_config]",
    ] {
        assert_eq!(code_of(sql), "function_denied", "{sql}");
    }
}

#[test]
fn schema_qualified_log_helpers_are_denied_with_exact_message() {
    let rejection =
        gate("SELECT pgmcp.read_log_file('postgresql.log', 0, 10)").expect_err("log helper");
    assert_eq!(rejection.code, "function_denied");
    assert_eq!(
        rejection.message,
        "Function read_log_file() is not allowed: the server log helper functions are reserved for the read_server_log tool."
    );
    let rejection = gate("SELECT * FROM PGMCP.list_log_files()").expect_err("log helper");
    assert_eq!(
        rejection.message,
        "Function list_log_files() is not allowed: the server log helper functions are reserved for the read_server_log tool."
    );
}

#[test]
fn dotted_and_schema_forms_of_ordinary_names_stay_accepted() {
    for sql in [
        "SELECT (name).upper FROM app.items",
        "SELECT s.to_json FROM (SELECT 1 AS a) s",
        "SELECT (r).field FROM (SELECT ROW(1, 2) AS r) s",
        "SELECT (v).x, t.col, s.t.col FROM (VALUES (1)) v(x), t, s.t",
        "SELECT (arr)[1], (arr)[1:2] FROM t",
        "SELECT (composite_col).sub.field FROM app.items",
        "SELECT t.* FROM t",
        "SELECT (r).* FROM (SELECT ROW(1, 2) AS r) s",
        "SELECT (x)._timescaledb_functions FROM (VALUES (1)) v(x)",
    ] {
        assert_eq!(
            gate(sql).map(|a| a.kind),
            Ok(StatementKind::Select),
            "{sql}"
        );
    }
}

#[test]
fn computed_names_in_dotted_form_cannot_bypass_the_function_gate() {
    for sql in [
        "SELECT (x).current_setting FROM (VALUES ('work_mem')) v(x)",
        "SELECT ('x'::text).set_config",
    ] {
        assert!(gate(sql).is_err(), "should be rejected: {sql}");
    }
}

#[test]
fn internal_schema_and_pgmcp_qualified_relations_use_exact_messages() {
    let rejection = gate("SELECT * FROM information_schema.user_mapping_options")
        .expect_err("user mapping options");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        "Relation user_mapping_options is not readable through this server. It can expose credentials."
    );
    let rejection = gate("SELECT * FROM pg_catalog.pg_statistic").expect_err("statistics");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        "Relation pg_statistic is not readable through this server. It can expose credentials."
    );
}

/// Dotted forms of every deny entry, for the mutation test below.
fn dotted_corpus() -> Vec<String> {
    postgres_mcp::gate::denied_functions()
        .iter()
        .flat_map(|&(pattern, _)| dotted_statements(&name_for_entry(pattern)))
        .collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn denied_dotted_forms_stay_denied(
        idx in any::<proptest::sample::Index>(),
        seed in any::<u64>(),
        flags in 0u8..8,
    ) {
        let forms = dotted_corpus();
        let block = &forms[idx.index(forms.len())];
        let mutated = mutate(block, seed, flags);
        match gate(&mutated) {
            Err(rejection) => prop_assert_eq!(rejection.code, "function_denied", "{}", mutated),
            Ok(accepted) => prop_assert!(false, "accepted as {:?}: {}", accepted, mutated),
        }
    }
}

/// The filtered catalog view that replaces a statistics-view reference; the brief's text, exactly.
fn filtered(view: &str, tail: &str) -> String {
    format!(
        "(SELECT * FROM pg_catalog.{view} WHERE schemaname OPERATOR(pg_catalog.<>) 'pg_catalog'::pg_catalog.name OR tablename OPERATOR(pg_catalog.<>) ALL ('{{pg_authid,pg_user_mapping,pg_subscription,pg_db_role_setting,pg_statistic,pg_statistic_ext_data,pg_foreign_server,pg_foreign_data_wrapper,pg_largeobject}}'::pg_catalog.name[]) OFFSET 0){tail}"
    )
}

fn rewritten(sql: &str) -> String {
    match gate(sql) {
        Ok(accepted) => accepted.sql,
        Err(rejection) => panic!("rejected {sql}: {}", rejection.message),
    }
}

#[test]
fn unqualified_reference_gets_the_view_name_as_alias() {
    let sql = "SELECT attname FROM pg_stats WHERE tablename = 'orders'";
    let expected = format!(
        "SELECT attname FROM {} WHERE tablename = 'orders'",
        filtered("pg_stats", " AS pg_stats")
    );
    assert_eq!(rewritten(sql), expected);
    assert!(gate(sql).unwrap().rewritten);
}

#[test]
fn qualified_and_quoted_references_are_rewritten_to_the_same_text() {
    let expected = |tail: &str| {
        format!(
            "SELECT attname FROM {} WHERE true",
            filtered("pg_stats", tail)
        )
    };
    assert_eq!(
        rewritten("SELECT attname FROM pg_catalog.pg_stats WHERE true"),
        expected(" AS pg_stats")
    );
    assert_eq!(
        rewritten("SELECT attname FROM \"pg_stats\" WHERE true"),
        expected(" AS pg_stats")
    );
    assert_eq!(
        rewritten("SELECT attname FROM pg_catalog.\"pg_stats\" WHERE true"),
        expected(" AS pg_stats")
    );
    assert_eq!(
        rewritten("SELECT attname FROM PG_STATS WHERE true"),
        expected(" AS pg_stats")
    );
}

#[test]
fn aliased_references_keep_the_users_alias_text() {
    let expected = |alias: &str| {
        format!(
            "SELECT s.attname FROM {} WHERE true",
            filtered("pg_stats", alias)
        )
    };
    assert_eq!(
        rewritten("SELECT s.attname FROM pg_stats s WHERE true"),
        expected(" s")
    );
    assert_eq!(
        rewritten("SELECT s.attname FROM pg_stats AS s WHERE true"),
        expected(" AS s")
    );
}

#[test]
fn joined_and_nested_references_are_rewritten() {
    let joined = rewritten("SELECT p.attname FROM (SELECT 1) AS q JOIN pg_stats AS p ON true");
    assert_eq!(
        joined,
        format!(
            "SELECT p.attname FROM (SELECT 1) AS q JOIN {} ON true",
            filtered("pg_stats", " AS p")
        )
    );
    let nested = rewritten("SELECT * FROM (SELECT * FROM pg_stats) AS q");
    assert_eq!(
        nested,
        format!(
            "SELECT * FROM (SELECT * FROM {}) AS q",
            filtered("pg_stats", " AS pg_stats")
        )
    );
}

#[test]
fn two_references_in_one_statement_are_both_rewritten() {
    let sql = "SELECT * FROM pg_stats a, pg_stats_ext b";
    let expected = format!(
        "SELECT * FROM {} a, {} b",
        filtered("pg_stats", ""),
        filtered("pg_stats_ext", "")
    );
    assert_eq!(rewritten(sql), expected);
}

#[test]
fn literals_and_comments_naming_the_view_are_untouched() {
    let sql = "SELECT 'FROM pg_stats', '\"pg_stats\"' /* pg_stats */ FROM pg_class -- pg_stats\nWHERE false";
    assert_eq!(rewritten(sql), sql);
    let mixed = "SELECT '--pg_stats' FROM pg_stats";
    assert_eq!(
        rewritten(mixed),
        format!(
            "SELECT '--pg_stats' FROM {}",
            filtered("pg_stats", " AS pg_stats")
        )
    );
}

#[test]
fn a_user_table_in_another_schema_named_like_the_view_is_untouched() {
    let sql = "SELECT * FROM app.pg_stats";
    assert_eq!(rewritten(sql), sql);
    assert!(!gate(sql).unwrap().rewritten);
}

#[test]
fn statements_without_statistics_views_are_byte_identical() {
    for sql in [
        "SELECT 1",
        "SELECT *\n  FROM   app.items  AS i\nWHERE i.id = 1",
        "WITH x AS (SELECT 1) SELECT * FROM x",
        "EXPLAIN (FORMAT JSON) SELECT * FROM pg_class",
        "SHOW search_path",
    ] {
        let accepted = gate(sql).unwrap();
        assert_eq!(accepted.sql, sql);
        assert!(!accepted.rewritten, "{sql}");
    }
}

#[test]
fn forms_that_cannot_be_spliced_are_refused_with_the_exact_text() {
    let message = |view: &str| {
        format!(
            "{view} can only be read as a plain table reference in FROM or JOIN, for example: SELECT attname, n_distinct FROM pg_stats WHERE tablename = 'orders'"
        )
    };
    for (sql, view) in [
        ("TABLE pg_stats", "pg_stats"),
        ("SELECT * FROM ONLY pg_stats", "pg_stats"),
        ("SELECT * FROM pg_stats *", "pg_stats"),
        ("SELECT * FROM pg_stats TABLESAMPLE SYSTEM (10)", "pg_stats"),
        (
            "WITH pg_stats AS (SELECT 1 AS x) SELECT * FROM pg_stats",
            "pg_stats",
        ),
        ("TABLE pg_stats_ext", "pg_stats_ext"),
    ] {
        match gate(sql) {
            Err(rejection) => {
                assert_eq!(rejection.code, "relation_denied", "{sql}");
                assert_eq!(rejection.message, message(view), "{sql}");
            }
            Ok(accepted) => panic!("accepted as {accepted:?}: {sql}"),
        }
    }
}

proptest! {
    /// Generated references: the rewritten text parses, and the view appears only inside the filter.
    #[test]
    fn rewritten_text_parses_and_names_the_view_only_in_the_filter(
        qualified in any::<bool>(),
        quoted in any::<bool>(),
        alias in 0_u8..3,
        copies in 1_usize..4,
    ) {
        let name = match (qualified, quoted) {
            (false, false) => "pg_stats".to_owned(),
            (false, true) => "\"pg_stats\"".to_owned(),
            (true, false) => "pg_catalog.pg_stats".to_owned(),
            (true, true) => "pg_catalog.\"pg_stats\"".to_owned(),
        };
        let froms: Vec<String> = (0..copies)
            .map(|i| match alias {
                0 => name.clone(),
                1 => format!("{name} x{i}"),
                _ => format!("{name} AS x{i}"),
            })
            .collect();
        let sql = format!("SELECT 1 FROM {}", froms.join(", "));
        let accepted = gate(&sql).expect("generated statement is accepted");
        prop_assert!(accepted.rewritten);
        prop_assert!(pg_query::parse(&accepted.sql, pg_query::ParserOptions::DEFAULT).is_ok(), "{}", accepted.sql);
        prop_assert_eq!(accepted.sql.matches("FROM pg_catalog.pg_stats WHERE").count(), copies, "{}", accepted.sql);
        prop_assert!(!accepted.sql.contains("FROM pg_stats "), "{}", accepted.sql);
    }
}

const TOAST_MESSAGE: &str =
    "TOAST tables are not readable through this server. Read the table they belong to.";

#[test]
fn toast_tables_are_refused_with_exact_message_in_every_spelling() {
    for sql in [
        "SELECT chunk_data FROM pg_toast.pg_toast_2619",
        "SELECT chunk_data FROM \"pg_toast\".\"pg_toast_2619\"",
        "SELECT chunk_data FROM \"PG_TOAST\".\"PG_TOAST_2619\"",
        "SELECT chunk_data FROM pg_toast_2619",
        "SELECT chunk_data FROM \"PG_TOAST_2619\"",
        "SELECT chunk_data FROM pg_toast.pg_toast_2619_index",
        "SELECT chunk_data FROM pg_toast.pg_toast_1260",
        "SELECT chunk_data FROM public.pg_toast_1260",
        "SELECT encode(chunk_data, 'base64') FROM pg_toast.pg_toast_2619",
        "SELECT convert_from(chunk_data, 'UTF8') FROM pg_toast.pg_toast_2619",
        "SELECT 1 FROM app.items i JOIN pg_toast.pg_toast_2619 t ON true",
        "SELECT 1 FROM pg_toast_temp_1.pg_toast_temp_1_x",
        "SELECT 1 FROM pg_toast_temp_1.anything",
        "SELECT 1 FROM pg_toast.anything_at_all",
    ] {
        let rejection = gate(sql).expect_err(sql);
        assert_eq!(rejection.code, "relation_denied", "{sql}");
        assert_eq!(rejection.message, TOAST_MESSAGE, "{sql}");
    }
}

#[test]
fn names_that_only_look_like_toast_tables_are_allowed() {
    for sql in [
        "SELECT 1 FROM app.pg_toast_items",
        "SELECT 1 FROM pg_toast_items",
        "SELECT 1 FROM pg_toast_2619x",
        "SELECT 1 FROM toast_2619",
        "SELECT 1 FROM pg_toast_index",
    ] {
        assert!(gate(sql).is_ok(), "{sql} should be accepted");
    }
}

#[test]
fn walinspect_functions_are_denied_with_the_wal_reason() {
    for name in [
        "pg_get_wal_block_info",
        "pg_get_wal_record_info",
        "pg_get_wal_records_info",
        "pg_get_wal_records_info_till_end_of_wal",
        "pg_get_wal_stats",
        "pg_get_wal_stats_till_end_of_wal",
    ] {
        let sql = format!("SELECT * FROM {name}('0/0', '0/1')");
        let rejection = gate(&sql).expect_err(&sql);
        assert_eq!(rejection.code, "function_denied", "{sql}");
        assert!(
            rejection
                .message
                .contains("it returns raw write-ahead log data"),
            "{sql}: {}",
            rejection.message
        );
    }
}

const VIEW_MESSAGE: &str = "pg_stats can only be read as a plain table reference in FROM or JOIN, for example: SELECT attname, n_distinct FROM pg_stats WHERE tablename = 'orders'";

#[test]
fn three_part_statistics_name_is_refused_with_the_plain_reference_message() {
    let rejection =
        gate("SELECT attname FROM appdb.pg_catalog.pg_stats").expect_err("three-part name");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(rejection.message, VIEW_MESSAGE);
}

#[test]
fn schema_qualified_column_of_a_statistics_view_is_refused_with_the_column_sentence() {
    let rejection =
        gate("SELECT pg_catalog.pg_stats.tablename FROM pg_stats").expect_err("qualified column");
    assert_eq!(rejection.code, "relation_denied");
    assert_eq!(
        rejection.message,
        format!("{VIEW_MESSAGE} Refer to its columns as pg_stats.column or through an alias.")
    );
}

#[test]
fn a_comment_between_from_and_the_name_is_skipped() {
    let block = "SELECT attname FROM /* note */ pg_stats WHERE tablename = 'orders'";
    assert_eq!(
        rewritten(block),
        format!(
            "SELECT attname FROM /* note */ {} WHERE tablename = 'orders'",
            filtered("pg_stats", " AS pg_stats")
        )
    );
    let line = "SELECT attname FROM -- note\n pg_stats WHERE tablename = 'orders'";
    assert!(
        rewritten(line).contains(&filtered("pg_stats", " AS pg_stats")),
        "{line}"
    );
}

#[test]
fn a_parenthesised_join_with_a_statistics_view_is_accepted_and_rewritten() {
    let sql = "SELECT s.attname, c.relname FROM (pg_stats s JOIN pg_class c ON c.relname = s.tablename) WHERE c.relname = 'items'";
    let accepted = rewritten(sql);
    assert!(accepted.contains(&filtered("pg_stats", "")), "{accepted}");
    assert!(accepted.contains(" s JOIN pg_class c"), "{accepted}");
}

#[test]
fn every_rewritten_statement_parses_again_with_one_filter_per_reference() {
    for (sql, references) in [
        ("SELECT attname FROM pg_stats", 1),
        (
            "SELECT * FROM pg_stats s, pg_stats_ext e WHERE s.tablename = e.statistics_name",
            2,
        ),
        (
            "SELECT attname FROM pg_catalog.pg_stats AS x WHERE x.tablename = 'orders'",
            1,
        ),
        (
            "SELECT attname FROM /* c */ pg_stats /* d */ WHERE tablename = 'orders'",
            1,
        ),
    ] {
        let out = rewritten(sql);
        assert!(
            pg_query::parse(&out, pg_query::ParserOptions::DEFAULT).is_ok(),
            "{out}"
        );
        assert_eq!(out.matches("OFFSET 0").count(), references, "{out}");
    }
}

#[test]
fn the_injected_filter_uses_the_pg_catalog_operators_and_types() {
    let out = rewritten("SELECT attname FROM pg_stats");
    assert!(out.contains("OPERATOR(pg_catalog.<>)"), "{out}");
    assert!(out.contains("::pg_catalog.name[]"), "{out}");
    assert!(!out.contains(" <> ALL"), "{out}");
}
