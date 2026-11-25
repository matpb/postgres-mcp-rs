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
    assert!(!README.contains("For local development only"));
}

#[test]
fn the_security_docs_carry_the_layer_texts_exactly() {
    let security = include_str!("../SECURITY.md");
    assert!(security.contains("- **Views and functions written by others.** The server refuses the credential catalogs by name and filters them out of pg_stats, pg_stats_ext and pg_stats_ext_exprs. A view or a SECURITY DEFINER function in your own schemas that reads those catalogs with its owner's rights is not known to the server; the role's privileges decide whether it can be used. pg_roles also shows per-role settings (rolconfig)."));
    assert!(security.contains("- **Transformed hashes.** The scrubber recognises password hashes in their stored form. SQL that transforms a value before returning it (reverse, substring, encode) is not recognised; the gate, which refuses the credential catalogs and filters the statistics views, is what stops such a query from reaching a hash in the first place. A hash copied into an ordinary table by someone with access is caught only in its stored form."));
    assert!(security.contains("This holds for every role, superusers included."));
    assert!(security.contains("**19. Password hash scrubber.** Every tool result, resource body, completion and error text, and every log field that can carry text from the database, is scanned before it leaves the server, and text shaped like a PostgreSQL password hash in its stored form (SCRAM-SHA-256 verifier or md5 hash) is replaced with [redacted password hash]. A password literal after the word PASSWORD in statement text is masked the same way. It is always on and cannot be configured off. The audit line counts the replacements."));
    assert!(security.contains("The TOAST tables of all catalogs are refused by name, and so are the foreign server and foreign-data wrapper catalogs."));
    assert!(security.contains("The gate also refuses TOAST tables and the functions that return raw page or write-ahead log data. Statement text of other sessions, visible to a role with pg_monitor, can hold a password hash that someone typed in a CREATE ROLE or ALTER ROLE statement; it is redacted in its stored form only."));
    assert!(!security.contains("Statistics and role settings"));
}

#[test]
fn the_tool_description_carries_both_sentences() {
    let text = postgres_mcp::tools::text::EXECUTE_QUERY;
    assert!(text.contains("The statistics views pg_stats, pg_stats_ext and pg_stats_ext_exprs never return rows for the catalogs that hold credentials."));
    assert!(text.contains("Name them directly in FROM or JOIN; a correlated subquery over one scans the whole view once per outer row."));
    assert!(text.contains("Text shaped like a PostgreSQL password hash is replaced with [redacted password hash] in every result, and redactedHashes counts the replacements."));
}
