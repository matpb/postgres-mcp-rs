//! Documentation checks that need no database: the README recipe is the seeded recipe, and the docs name the
//! roles and the scrubber as the code does.

const README: &str = include_str!("../README.md");
const RECIPE_SEED: &str = include_str!("../docker/initdb/02_recipe_role.sql");

/// The first SQL block after the "Create a read-only role" heading, without its fences.
fn recipe_block() -> &'static str {
    let section = README
        .split("## Create a read-only role")
        .nth(1)
        .expect("README has the recipe section");
    let after_fence = section
        .split("```sql\n")
        .nth(1)
        .expect("recipe block opens");
    after_fence
        .split("\n```")
        .next()
        .expect("recipe block closes")
}

/// The statements of a block: the lines that end with a semicolon, in order.
fn statements(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim_end)
        .filter(|line| line.ends_with(';'))
        .map(str::to_owned)
        .collect()
}

#[test]
fn the_readme_recipe_is_the_seeded_recipe_after_the_test_substitutions() {
    let substituted = recipe_block()
        .replace("mcp_reader", "mcp_recipe")
        .replace("'change-me'", "'test-only-recipe'")
        .replace("app_owner", "postgres")
        .replace("IN SCHEMA public", "IN SCHEMA app")
        .replace(
            "ON ALL TABLES IN SCHEMA public",
            "ON ALL TABLES IN SCHEMA app",
        )
        .replace("USAGE ON SCHEMA public", "USAGE ON SCHEMA app");
    let expected = statements(&substituted);
    assert_eq!(expected.len(), 7, "{expected:#?}");
    assert_eq!(statements(RECIPE_SEED), expected);
}

#[test]
fn the_recipe_grants_monitoring_and_no_broad_role() {
    let block = recipe_block();
    assert!(block.contains("GRANT pg_monitor TO mcp_reader;"), "{block}");
    assert!(!block.contains("pg_read_all_data"), "{block}");
    assert!(!block.contains("pg_read_all_stats"), "{block}");
}

#[test]
fn the_docs_forbid_the_broad_profile_in_the_exact_words() {
    assert!(README.contains(
        "The server refuses to read those catalogs and their TOAST tables, removes their rows from the statistics views, and replaces text shaped like a stored password hash in every result. These are safeguards built into the server, whatever the role may do; a narrow role is still the better setup, because a role that was never granted the data has nothing to leak. If only monitoring is missing, `pg_monitor` is enough; it grants no table data, but it shows other sessions' statement text.\n"
    ));
    assert!(README.contains(
        "This is the recommended setup. It reads the tables it is granted and nothing else."
    ));
    assert!(README.contains("- **Password hash scrubber.** Every tool result, resource body, completion and error text, and every log field that can carry text from the database, is scanned before it leaves the server, and text shaped like a PostgreSQL password hash in its stored form (SCRAM-SHA-256 verifier or md5 hash) is replaced with [redacted password hash]. It is always on and cannot be configured off. Each successful tool result carries the number of markers it returns as `redactedHashes`; the audit line and a warning line carry the same count for tools, resources and completions. A quoted literal that follows the keyword PASSWORD after whitespace or a comment, as in CREATE ROLE or ALTER ROLE, is replaced with '***' in every string value and column name on a best-effort basis; that mask is not counted. Error texts and log lines get the hash replacement only."));
    assert!(README.contains(
        "`redactedHashes` is the number of `[redacted password hash]` markers in the result, as text and as the hex of their bytes, in column names, row keys and values."
    ));
    assert!(!README.contains("For local development only"));
}

#[test]
fn the_security_docs_carry_the_layer_texts_exactly() {
    let security = include_str!("../SECURITY.md");
    assert!(security.contains("- **Views and functions written by others.** The server refuses the credential catalogs by name and filters them out of pg_stats, pg_stats_ext and pg_stats_ext_exprs. A view or a SECURITY DEFINER function in your own schemas that reads those catalogs with its owner's rights is not known to the server; the role's privileges decide whether it can be used. pg_roles also shows per-role settings (rolconfig)."));
    assert!(security.contains("- **Transformed hashes.** The scrubber recognises password hashes in their stored form. SQL that transforms a value before returning it (reverse, substring, encode, a letter or digit directly before or after an md5 hash, an escaped form other than \\x hex, or a cut-short md5 hash read from pg_stat_activity through execute_query) is not recognised. For the credential catalogs, the gate refuses them and filters the statistics views; that is what stops such a query from reaching a hash in the first place. A hash copied into an ordinary table by someone with access is caught only in its stored form. The gate also refuses TOAST tables and the functions that return raw page or write-ahead log data. Statement text of other sessions, visible to a role with pg_monitor, can hold a password hash that someone typed in a CREATE ROLE or ALTER ROLE statement; it is redacted in its stored form only."));
    assert!(security.contains("- **TimescaleDB job configuration.** `list_jobs` returns each job's `config` as it is stored; only the hash scrubber and the PASSWORD literal mask run on its string values, so a secret under a key such as password is returned. Keep secrets out of job configuration."));
    assert!(security.contains("This holds for every role, superusers included."));
    assert!(security.contains("**19. Password hash scrubber.** Every tool result, resource body, completion and error text, and every log field that can carry text from the database, is scanned before it leaves the server, and text shaped like a PostgreSQL password hash in its stored form (SCRAM-SHA-256 verifier or md5 hash) is replaced with [redacted password hash]. It is always on and cannot be configured off. Each successful tool result carries the number of markers it returns as `redactedHashes`; the audit line and a warning line carry the same count for tools, resources and completions. A quoted literal that follows the keyword PASSWORD after whitespace or a comment, as in CREATE ROLE or ALTER ROLE, is replaced with '***' in every string value and column name on a best-effort basis; that mask is not counted. Error texts and log lines get the hash replacement only."));
    assert!(security.contains("The TOAST tables of all catalogs are refused by name, and so are the foreign server and foreign-data wrapper catalogs."));
    assert!(security.contains("The gate also refuses TOAST tables and the functions that return raw page or write-ahead log data. Statement text of other sessions, visible to a role with pg_monitor, can hold a password hash that someone typed in a CREATE ROLE or ALTER ROLE statement; it is redacted in its stored form only."));
    assert!(!security.contains("Statistics and role settings"));
}

#[test]
fn the_tool_description_carries_both_sentences() {
    let text = postgres_mcp::tools::text::EXECUTE_QUERY;
    assert!(text.contains("The statistics views pg_stats, pg_stats_ext and pg_stats_ext_exprs never return rows for the catalogs that hold credentials."));
    assert!(text.contains("Name them directly in FROM or JOIN; a correlated subquery over one scans the whole view once per outer row."));
    assert!(text.contains("Text shaped like a PostgreSQL password hash is replaced with [redacted password hash] in every result, and redactedHashes is the number of [redacted password hash] markers in the result."));
    assert!(text.contains(
        "A quoted literal after the keyword PASSWORD is replaced with '***' in every string value."
    ));
}
