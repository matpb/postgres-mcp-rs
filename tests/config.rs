//! Environment-only configuration: defaults, database sources, validation messages and leak checks.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use postgres_mcp::config::{Config, ConfigError, LogFormat};
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::AuthPolicy;

const URL: &str = "postgres://app:pw-secret@db.example.com:5433/appdb";

fn load(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
    let map: HashMap<String, String> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    Config::from_lookup(&|name| map.get(name).cloned())
}

fn cfg(pairs: &[(&str, &str)]) -> Config {
    load(pairs).unwrap_or_else(|e| panic!("unexpected config error: {e}"))
}

fn load_err(pairs: &[(&str, &str)]) -> String {
    match load(pairs) {
        Ok(config) => panic!("expected a config error, got {config:?}"),
        Err(ConfigError(message)) => message,
    }
}

fn owned_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A temporary file under the system temp directory, removed on drop.
struct TempFile(PathBuf);

impl TempFile {
    fn new(contents: &str) -> TempFile {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let path =
            std::env::temp_dir().join(format!("pgmcp-config-test-{}-{n}", std::process::id()));
        std::fs::write(&path, contents).expect("write temp file");
        TempFile(path)
    }

    fn path(&self) -> String {
        self.0.to_str().expect("utf-8 temp path").to_owned()
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn defaults() {
    let config = cfg(&[("DATABASE_URL", "postgres://app:pw@db.example.com/appdb")]);
    assert_eq!(config.host.to_string(), "127.0.0.1");
    assert_eq!(config.port, 8432);
    assert_eq!(config.api_key, None);
    assert!(config.allowed_origins.is_empty());
    assert!(config.allowed_hosts.is_empty());
    assert_eq!(config.limits.max_rows, 1000);
    assert_eq!(config.limits.max_value_bytes, 4096);
    assert_eq!(config.limits.max_binary_preview_bytes, 256);
    assert_eq!(config.limits.max_response_bytes, 48_000);
    assert_eq!(config.limits.max_request_bytes, 1_048_576);
    assert_eq!(config.limits.max_sql_bytes, 102_400);
    assert_eq!(config.limits.max_concurrent_requests, 16);
    assert!(config.toolsets.schema && config.toolsets.monitor);
    assert!(config.toolsets.logs && config.toolsets.timescale);
    assert!(config.audit_log);
    assert_eq!(config.log_format, LogFormat::Text);
    assert_eq!(config.databases.len(), 1);
    let db = &config.databases[0];
    assert_eq!(db.name, "appdb");
    assert_eq!(db.connect.host, "db.example.com");
    assert_eq!(db.connect.port, 5432);
    assert_eq!(db.connect.ssl_mode, SslMode::Prefer);
    assert_eq!(db.connect.connect_timeout, Duration::from_secs(10));
    assert_eq!(db.max_connections, 4);
    assert_eq!(db.statement_timeout_ms, 30_000);
    assert_eq!(db.lock_timeout_ms, 5_000);
}

#[test]
fn url_parsing() {
    let config = cfg(&[(
        "DATABASE_URL",
        "postgres://app:p%40ss%2Fw@db.example.com:6543/reports?sslmode=verify-full&sslrootcert=/etc/ca.pem&application_name=tool&connect_timeout=7",
    )]);
    let db = &config.databases[0];
    assert_eq!(db.name, "reports");
    assert_eq!(db.connect.host, "db.example.com");
    assert_eq!(db.connect.port, 6543);
    assert_eq!(db.connect.database, "reports");
    assert_eq!(db.connect.user, "app");
    assert_eq!(db.connect.password.as_deref(), Some("p@ss/w"));
    assert_eq!(db.connect.ssl_mode, SslMode::VerifyFull);
    assert_eq!(db.connect.ssl_root_cert, Some(PathBuf::from("/etc/ca.pem")));
    assert_eq!(db.connect.connect_timeout, Duration::from_secs(7));
    assert_eq!(
        db.connect.startup_params[0],
        ("application_name".to_owned(), "tool".to_owned())
    );
}

#[test]
fn url_scheme_and_ipv6_host() {
    let config = cfg(&[("DATABASE_URL", "postgresql://app@[::1]:5544/appdb")]);
    let connect = &config.databases[0].connect;
    assert_eq!(connect.host, "::1");
    assert_eq!(connect.port, 5544);
    assert_eq!(connect.password, None);
}

#[test]
fn url_missing_user_or_database_is_error() {
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://db.example.com/appdb")]),
        "DATABASE_URL: the URL has no user"
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://app@db.example.com/")]),
        "DATABASE_URL: the URL has no database"
    );
}

#[test]
fn url_empty_host_is_error() {
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://app:pw@/appdb")]),
        "DATABASE_URL: not a valid postgres:// URL"
    );
}

#[test]
fn json_url_with_password_file_overrides_url_password() {
    let secret = TempFile::new("from-file\n");
    let json = format!(
        r#"[{{"name":"u","url":"postgres://app:from-url@h/x","password_file":"{}"}}]"#,
        secret.path()
    );
    let config = cfg(&[("PG_DATABASES", &json)]);
    assert_eq!(
        config.databases[0].connect.password.as_deref(),
        Some("from-file")
    );
}

#[test]
fn url_bad_percent_encoding_is_error() {
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://app:p%zz@db.example.com/appdb")]),
        "DATABASE_URL: invalid percent-encoding in the URL"
    );
}

#[test]
fn startup_params_exact() {
    let config = cfg(&[("DATABASE_URL", URL)]);
    assert_eq!(
        config.databases[0].connect.startup_params,
        owned_pairs(&[
            ("application_name", "postgres-mcp"),
            ("DateStyle", "ISO, MDY"),
            ("IntervalStyle", "iso_8601"),
            ("TimeZone", "UTC"),
            ("bytea_output", "hex"),
            ("extra_float_digits", "1"),
            ("standard_conforming_strings", "on"),
            ("default_transaction_read_only", "on"),
        ])
    );
}

#[test]
fn startup_params_application_name_precedence() {
    let with_env = cfg(&[
        (
            "DATABASE_URL",
            "postgres://app@h/appdb?application_name=from-url",
        ),
        ("PGAPPNAME", "from-env"),
    ]);
    assert_eq!(
        with_env.databases[0].connect.startup_params[0],
        ("application_name".to_owned(), "from-env".to_owned())
    );
    let with_url = cfg(&[(
        "DATABASE_URL",
        "postgres://app@h/appdb?application_name=from-url",
    )]);
    assert_eq!(
        with_url.databases[0].connect.startup_params[0],
        ("application_name".to_owned(), "from-url".to_owned())
    );
}

#[test]
fn pg_databases_json_two() {
    let secret = TempFile::new("pw-from-file\n");
    let json = format!(
        r#"[{{"name":"a","url":"postgres://u:pw-a@h1/da"}},{{"name":"b","host":"h2","port":5544,"database":"db2","user":"u2","password_file":"{}","sslmode":"require","max_connections":8,"statement_timeout_ms":5000,"lock_timeout_ms":900}}]"#,
        secret.path()
    );
    let config = cfg(&[("PG_DATABASES", &json)]);
    assert_eq!(config.databases.len(), 2);

    let a = config.database(Some("a")).expect("a is configured");
    assert_eq!(a.connect.host, "h1");
    assert_eq!(a.connect.port, 5432);
    assert_eq!(a.connect.database, "da");
    assert_eq!(a.connect.password.as_deref(), Some("pw-a"));
    assert_eq!(a.max_connections, 4);

    let b = config.database(Some("b")).expect("b is configured");
    assert_eq!(b.connect.host, "h2");
    assert_eq!(b.connect.port, 5544);
    assert_eq!(b.connect.database, "db2");
    assert_eq!(b.connect.user, "u2");
    assert_eq!(b.connect.password.as_deref(), Some("pw-from-file"));
    assert_eq!(b.connect.ssl_mode, SslMode::Require);
    assert_eq!(b.max_connections, 8);
    assert_eq!(b.statement_timeout_ms, 5000);
    assert_eq!(b.lock_timeout_ms, 900);
}

#[test]
fn pg_databases_file() {
    let file = TempFile::new(
        r#"[{"name":"filed","host":"fh","database":"fdb","user":"fu","password":"fpw"}]"#,
    );
    let config = cfg(&[("PG_DATABASES_FILE", &file.path())]);
    let db = &config.databases[0];
    assert_eq!(db.name, "filed");
    assert_eq!(db.connect.host, "fh");
    assert_eq!(db.connect.database, "fdb");
    assert_eq!(db.connect.user, "fu");
    assert_eq!(db.connect.password.as_deref(), Some("fpw"));
}

#[test]
fn pg_databases_file_missing_is_error() {
    let message = load_err(&[("PG_DATABASES_FILE", "/nonexistent/pgmcp/databases.json")]);
    assert!(
        message.starts_with("PG_DATABASES_FILE: cannot read /nonexistent/pgmcp/databases.json"),
        "{message}"
    );
}

#[test]
fn libpq_vars() {
    let config = cfg(&[
        ("PGHOST", "pghost.example.com"),
        ("PGPORT", "6000"),
        ("PGDATABASE", "pdb"),
        ("PGUSER", "pu"),
        ("PGPASSWORD", "ppw"),
        ("PGSSLMODE", "require"),
        ("PGSSLROOTCERT", "/etc/root.pem"),
        ("PG_NAME", "main"),
    ]);
    let db = &config.databases[0];
    assert_eq!(db.name, "main");
    assert_eq!(db.connect.host, "pghost.example.com");
    assert_eq!(db.connect.port, 6000);
    assert_eq!(db.connect.database, "pdb");
    assert_eq!(db.connect.user, "pu");
    assert_eq!(db.connect.password.as_deref(), Some("ppw"));
    assert_eq!(db.connect.ssl_mode, SslMode::Require);
    assert_eq!(
        db.connect.ssl_root_cert,
        Some(PathBuf::from("/etc/root.pem"))
    );
}

#[test]
fn libpq_defaults_and_name_from_database() {
    let config = cfg(&[("PGDATABASE", "pdb"), ("PGUSER", "pu")]);
    let db = &config.databases[0];
    assert_eq!(db.name, "pdb");
    assert_eq!(db.connect.host, "127.0.0.1");
    assert_eq!(db.connect.port, 5432);
    assert_eq!(db.connect.password, None);
    assert_eq!(db.connect.ssl_mode, SslMode::Prefer);
}

#[test]
fn libpq_requires_user_when_database_set() {
    assert_eq!(
        load_err(&[("PGDATABASE", "pdb")]),
        "PGUSER: required when PGDATABASE is set"
    );
}

#[test]
fn precedence() {
    let config = cfg(&[
        (
            "PG_DATABASES",
            r#"[{"name":"json","url":"postgres://u@h/x"}]"#,
        ),
        ("DATABASE_URL", URL),
        ("PGDATABASE", "pdb"),
        ("PGUSER", "pu"),
    ]);
    assert_eq!(config.databases.len(), 1);
    assert_eq!(config.databases[0].name, "json");

    let url_first = cfg(&[
        ("DATABASE_URL", URL),
        ("PGDATABASE", "pdb"),
        ("PGUSER", "pu"),
    ]);
    assert_eq!(url_first.databases[0].name, "appdb");
}

#[test]
fn no_database_error() {
    assert_eq!(
        load_err(&[("MCP_PORT", "9000")]),
        "no database configured: set PG_DATABASES, DATABASE_URL, or PGDATABASE with PGHOST and PGUSER"
    );
    assert_eq!(
        load_err(&[("PGHOST", "h"), ("PGUSER", "u")]),
        "no database configured: set PG_DATABASES, DATABASE_URL, or PGDATABASE with PGHOST and PGUSER"
    );
}

#[test]
fn duplicate_name_error() {
    let json = r#"[{"name":"a","url":"postgres://u@h/x"},{"name":"a","url":"postgres://u@h/y"}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[1] (\"a\"): duplicate database name \"a\""
    );
}

#[test]
fn bad_name_error() {
    let json = r#"[{"name":"my db","url":"postgres://u@h/x"}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0]: \"name\" must be 1 to 63 characters of A-Z, a-z, 0-9, _ or -"
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("PG_NAME", "my db")]),
        "PG_NAME: must be 1 to 63 characters of A-Z, a-z, 0-9, _ or -"
    );
    let long = "x".repeat(64);
    let json = format!(r#"[{{"name":"{long}","url":"postgres://u@h/x"}}]"#);
    assert_eq!(
        load_err(&[("PG_DATABASES", &json)]),
        "PG_DATABASES[0]: \"name\" must be 1 to 63 characters of A-Z, a-z, 0-9, _ or -"
    );
}

#[test]
fn unknown_json_field_error() {
    let json = r#"[{"name":"reports","url":"postgres://u@h/x","pasword":"oops"}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0] (\"reports\"): unknown field \"pasword\""
    );
}

#[test]
fn url_with_discrete_field_is_error() {
    let json = r#"[{"name":"x","url":"postgres://u@h/x","host":"other"}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0] (\"x\"): \"host\" cannot be combined with \"url\""
    );
}

#[test]
fn json_password_both_forms_is_error() {
    let json = r#"[{"name":"x","host":"h","database":"d","user":"u","password":"p","password_file":"/nonexistent"}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0] (\"x\"): \"password\" and \"password_file\" are both set"
    );
}

#[test]
fn json_non_string_password_is_not_echoed() {
    let json = r#"[{"name":"x","host":"h","database":"d","user":"u","password":1234567890123}]"#;
    let message = load_err(&[("PG_DATABASES", json)]);
    assert_eq!(
        message,
        "PG_DATABASES[0] (\"x\"): \"password\" must be a string"
    );
    assert!(!message.contains("1234567890123"), "{message}");
}

#[test]
fn json_shape_errors() {
    assert_eq!(
        load_err(&[("PG_DATABASES", "[]")]),
        "PG_DATABASES: at least one database is required"
    );
    assert_eq!(
        load_err(&[("PG_DATABASES", "{}")]),
        "PG_DATABASES: expected a JSON array of database objects"
    );
    assert_eq!(
        load_err(&[("PG_DATABASES", "[1]")]),
        "PG_DATABASES[0]: expected an object"
    );
    assert_eq!(
        load_err(&[("PG_DATABASES", r#"[{"url":"postgres://u@h/x"}]"#)]),
        "PG_DATABASES[0]: \"name\" is required"
    );
    assert_eq!(
        load_err(&[("PG_DATABASES", r#"[{"name":"x","host":"h","user":"u"}]"#)]),
        "PG_DATABASES[0] (\"x\"): \"database\" is required"
    );
    assert!(load_err(&[("PG_DATABASES", "not json")]).starts_with("PG_DATABASES: not valid JSON"));
}

#[test]
fn json_timeouts_are_range_checked() {
    let json = r#"[{"name":"x","url":"postgres://u@h/x","lock_timeout_ms":9}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0] (\"x\"): lock_timeout_ms: 9 is below the minimum 10"
    );
    let json = r#"[{"name":"x","url":"postgres://u@h/x","max_connections":65}]"#;
    assert_eq!(
        load_err(&[("PG_DATABASES", json)]),
        "PG_DATABASES[0] (\"x\"): max_connections: 65 is above the maximum 64"
    );
}

#[test]
fn many_json_databases() {
    let entries: Vec<String> = (0..1000)
        .map(|i| format!(r#"{{"name":"db{i}","url":"postgres://u@h/d{i}"}}"#))
        .collect();
    let json = format!("[{}]", entries.join(","));
    let config = cfg(&[("PG_DATABASES", &json)]);
    assert_eq!(config.databases.len(), 1000);
    assert_eq!(
        config
            .database(Some("db999"))
            .map(|d| d.connect.database.clone())
            .ok(),
        Some("d999".to_owned())
    );
}

#[test]
fn unknown_url_param_error() {
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://app@h/appdb?foo=1")]),
        "DATABASE_URL: unknown URL parameter \"foo\""
    );
}

#[test]
fn both_api_key_and_file_error() {
    let file = TempFile::new("0123456789abcdef0123");
    let message = load_err(&[
        ("DATABASE_URL", URL),
        ("API_KEY", "0123456789abcdef-key"),
        ("API_KEY_FILE", &file.path()),
    ]);
    assert_eq!(
        message,
        "API_KEY and API_KEY_FILE are both set; set only one"
    );
    assert!(!message.contains("0123456789abcdef"), "{message}");
}

#[test]
fn api_key_file_trimmed() {
    let file = TempFile::new("  0123456789abcdef-xyz \n");
    let config = cfg(&[("DATABASE_URL", URL), ("API_KEY_FILE", &file.path())]);
    assert_eq!(config.api_key.as_deref(), Some("0123456789abcdef-xyz"));
}

#[test]
fn short_api_key_error() {
    let key = "abcdefghijklmno";
    assert_eq!(key.len(), 15);
    let message = load_err(&[("DATABASE_URL", URL), ("API_KEY", key)]);
    assert_eq!(message, "API_KEY: must be at least 16 characters");
    assert!(!message.contains(key), "{message}");
}

#[test]
fn api_key_with_surrounding_whitespace_is_error() {
    let key = "0123456789abcdef-key";
    for padded in [format!(" {key}"), format!("{key} "), format!("{key}\t")] {
        let message = load_err(&[("DATABASE_URL", URL), ("API_KEY", &padded)]);
        assert_eq!(message, "API_KEY: must not start or end with whitespace");
        assert!(!message.contains(key), "{message}");
    }
}

#[test]
fn api_key_inner_whitespace_is_kept() {
    let key = "0123 4567 89abcdef";
    let config = cfg(&[("DATABASE_URL", URL), ("API_KEY", key)]);
    assert_eq!(config.api_key.as_deref(), Some(key));
}

#[test]
fn api_key_file_content_is_trimmed() {
    let file = TempFile::new(" 0123456789abcdef-key \n");
    let config = cfg(&[("DATABASE_URL", URL), ("API_KEY_FILE", &file.path())]);
    assert_eq!(config.api_key.as_deref(), Some("0123456789abcdef-key"));
}

#[test]
fn empty_api_key_is_none() {
    let config = cfg(&[("DATABASE_URL", URL), ("API_KEY", "")]);
    assert_eq!(config.api_key, None);
}

#[test]
fn api_key_file_empty_is_error() {
    let file = TempFile::new(" \n");
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("API_KEY_FILE", &file.path())]),
        "API_KEY_FILE: must be at least 16 characters"
    );
}

#[test]
fn limits_are_bounded_and_named() {
    let table: &[(&str, u64, u64)] = &[
        ("MAX_ROWS", 1, 100_000),
        ("MAX_VALUE_BYTES", 64, 1_048_576),
        ("MAX_BINARY_PREVIEW_BYTES", 16, 65_536),
        ("MAX_RESPONSE_BYTES", 1_024, 16_777_216),
        ("MAX_REQUEST_BYTES", 1_024, 16_777_216),
        ("MAX_SQL_BYTES", 256, 1_048_576),
        ("MAX_CONCURRENT_REQUESTS", 1, 1_024),
    ];
    for &(name, min, max) in table {
        let below = (min - 1).to_string();
        let above = (max + 1).to_string();
        let min_s = min.to_string();
        let max_s = max.to_string();
        assert_eq!(
            load_err(&[("DATABASE_URL", URL), (name, &below)]),
            format!("{name}: {below} is below the minimum {min}"),
            "{name} below"
        );
        assert_eq!(
            load_err(&[("DATABASE_URL", URL), (name, &above)]),
            format!("{name}: {above} is above the maximum {max}"),
            "{name} above"
        );
        assert!(
            load(&[("DATABASE_URL", URL), (name, &min_s)]).is_ok(),
            "{name} min"
        );
        assert!(
            load(&[("DATABASE_URL", URL), (name, &max_s)]).is_ok(),
            "{name} max"
        );
    }
    let config = cfg(&[("DATABASE_URL", URL), ("MAX_ROWS", "100000")]);
    assert_eq!(config.limits.max_rows, 100_000);
}

#[test]
fn limits_huge_number_is_above_maximum() {
    assert_eq!(
        load_err(&[
            ("DATABASE_URL", URL),
            ("MAX_ROWS", "99999999999999999999999")
        ]),
        "MAX_ROWS: 99999999999999999999999 is above the maximum 100000"
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("MAX_ROWS", "lots")]),
        "MAX_ROWS: \"lots\" is not a whole number"
    );
}

#[test]
fn timeout_defaults_come_from_environment() {
    let config = cfg(&[
        ("DATABASE_URL", URL),
        ("STATEMENT_TIMEOUT_MS", "250"),
        ("LOCK_TIMEOUT_MS", "20"),
    ]);
    assert_eq!(config.databases[0].statement_timeout_ms, 250);
    assert_eq!(config.databases[0].lock_timeout_ms, 20);
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("STATEMENT_TIMEOUT_MS", "50")]),
        "STATEMENT_TIMEOUT_MS: 50 is below the minimum 100"
    );
}

#[test]
fn bad_port() {
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("MCP_PORT", "abc")]),
        "MCP_PORT: \"abc\" is not a port number"
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("MCP_PORT", "0")]),
        "MCP_PORT: \"0\" is not a port number"
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("MCP_PORT", "70000")]),
        "MCP_PORT: \"70000\" is not a port number"
    );
    assert_eq!(
        cfg(&[("DATABASE_URL", URL), ("MCP_PORT", "9000")]).port,
        9000
    );
}

#[test]
fn bad_host() {
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("MCP_HOST", "localhost")]),
        "MCP_HOST: \"localhost\" is not an IP address; use 127.0.0.1 or ::1"
    );
    assert_eq!(
        cfg(&[("DATABASE_URL", URL), ("MCP_HOST", "0.0.0.0")])
            .host
            .to_string(),
        "0.0.0.0"
    );
    assert_eq!(
        cfg(&[("DATABASE_URL", URL), ("MCP_HOST", "::1")])
            .host
            .to_string(),
        "::1"
    );
}

#[test]
fn toolsets_parsing() {
    let config = cfg(&[("DATABASE_URL", URL), ("TOOLSETS", "schema,logs")]);
    assert!(config.toolsets.schema);
    assert!(!config.toolsets.monitor);
    assert!(config.toolsets.logs);
    assert!(!config.toolsets.timescale);

    let all = cfg(&[("DATABASE_URL", URL), ("TOOLSETS", "all")]);
    assert!(
        all.toolsets.schema && all.toolsets.monitor && all.toolsets.logs && all.toolsets.timescale
    );

    let core = cfg(&[("DATABASE_URL", URL), ("TOOLSETS", "core")]);
    assert!(
        !core.toolsets.schema
            && !core.toolsets.monitor
            && !core.toolsets.logs
            && !core.toolsets.timescale
    );

    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("TOOLSETS", "bogus")]),
        "TOOLSETS: unknown toolset \"bogus\" (expected schema, monitor, logs, timescale, core or all)"
    );
}

#[test]
fn allowed_origins_validation() {
    let config = cfg(&[
        ("DATABASE_URL", URL),
        (
            "ALLOWED_ORIGINS",
            "https://a.example.com,http://b.example.com:8080",
        ),
    ]);
    assert_eq!(
        config.allowed_origins,
        vec![
            "https://a.example.com".to_owned(),
            "http://b.example.com:8080".to_owned()
        ]
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("ALLOWED_ORIGINS", "a.example.com")]),
        "ALLOWED_ORIGINS: \"a.example.com\" is not an origin of the form scheme://host[:port]"
    );
    assert_eq!(
        load_err(&[
            ("DATABASE_URL", URL),
            ("ALLOWED_ORIGINS", "https://a.example.com/path")
        ]),
        "ALLOWED_ORIGINS: \"https://a.example.com/path\" is not an origin of the form scheme://host[:port]"
    );
}

#[test]
fn allowed_hosts_are_listed() {
    let config = cfg(&[
        ("DATABASE_URL", URL),
        ("ALLOWED_HOSTS", " mcp.example.com , ,other.example.com"),
    ]);
    assert_eq!(
        config.allowed_hosts,
        vec!["mcp.example.com".to_owned(), "other.example.com".to_owned()]
    );
}

#[test]
fn database_lookup() {
    let single = cfg(&[("DATABASE_URL", URL)]);
    assert_eq!(
        single.database(None).map(|d| d.name.clone()).ok(),
        Some("appdb".to_owned())
    );

    let two = cfg(&[(
        "PG_DATABASES",
        r#"[{"name":"a","url":"postgres://u@h/x"},{"name":"b","url":"postgres://u@h/y"}]"#,
    )]);
    assert_eq!(
        two.database(None).err().map(|e| e.0),
        Some("'database' is required: choose one of a, b".to_owned())
    );
    assert_eq!(
        two.database(Some("b"))
            .map(|d| d.connect.database.clone())
            .ok(),
        Some("y".to_owned())
    );
    assert_eq!(
        two.database(Some("zzz")).err().map(|e| e.0),
        Some("unknown database \"zzz\": configured databases are a, b".to_owned())
    );
}

#[test]
fn debug_never_leaks() {
    let config = cfg(&[
        (
            "DATABASE_URL",
            "postgres://app:pw-secret-123@db.example.com/appdb",
        ),
        ("API_KEY", "api-key-secret-0123456789"),
    ]);
    let text = format!("{config:?}");
    assert!(!text.contains("pw-secret-123"), "{text}");
    assert!(!text.contains("api-key-secret-0123456789"), "{text}");
    assert!(text.contains("set"), "{text}");
    let db = format!("{:?}", config.databases[0]);
    assert!(!db.contains("pw-secret-123"), "{db}");
    assert!(db.contains("db.example.com"), "{db}");
}

#[test]
fn error_never_leaks_url() {
    let message = load_err(&[(
        "DATABASE_URL",
        "postgres://app:hunter2-secret@db.example.com:notaport/appdb",
    )]);
    assert_eq!(message, "DATABASE_URL: not a valid postgres:// URL");
    let message = load_err(&[(
        "DATABASE_URL",
        "mysql://app:hunter2-secret@db.example.com/appdb",
    )]);
    assert_eq!(message, "DATABASE_URL: not a valid postgres:// URL");
    assert!(!message.contains("hunter2"), "{message}");
}

#[test]
fn sslmode_invalid_error() {
    assert_eq!(
        load_err(&[("DATABASE_URL", "postgres://app@h/appdb?sslmode=sometimes")]),
        "DATABASE_URL: sslmode: invalid ssl mode \"sometimes\"; expected disable, prefer, require, verify-ca or verify-full"
    );
    assert_eq!(
        load_err(&[
            ("PGDATABASE", "pdb"),
            ("PGUSER", "pu"),
            ("PGSSLMODE", "bogus")
        ]),
        "PGSSLMODE: invalid ssl mode \"bogus\"; expected disable, prefer, require, verify-ca or verify-full"
    );
}

#[test]
fn audit_log_and_log_format() {
    assert!(!cfg(&[("DATABASE_URL", URL), ("AUDIT_LOG", "off")]).audit_log);
    assert!(!cfg(&[("DATABASE_URL", URL), ("AUDIT_LOG", "0")]).audit_log);
    assert!(cfg(&[("DATABASE_URL", URL), ("AUDIT_LOG", "true")]).audit_log);
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("AUDIT_LOG", "maybe")]),
        "AUDIT_LOG: \"maybe\" is not on, off, true, false, 1 or 0"
    );
    assert_eq!(
        cfg(&[("DATABASE_URL", URL), ("LOG_FORMAT", "json")]).log_format,
        LogFormat::Json
    );
    assert_eq!(
        load_err(&[("DATABASE_URL", URL), ("LOG_FORMAT", "xml")]),
        "LOG_FORMAT: \"xml\" is not text or json"
    );
}

fn auth(scram: bool, md5: bool, password: bool, trust: bool) -> AuthPolicy {
    AuthPolicy {
        scram,
        md5,
        password,
        trust,
    }
}

#[test]
fn require_auth_default_is_scram_and_none() {
    let config = cfg(&[("DATABASE_URL", URL)]);
    assert_eq!(config.databases[0].auth, auth(true, false, false, true));
    assert_eq!(config.databases[0].auth, AuthPolicy::default());
}

#[test]
fn require_auth_from_libpq_environment() {
    let base = [("PGDATABASE", "pdb"), ("PGUSER", "pu")];
    let with = |value: &str| {
        let mut pairs = base.to_vec();
        pairs.push(("PGREQUIREAUTH", value));
        cfg(&pairs).databases[0].auth.clone()
    };
    assert_eq!(with("md5,password"), auth(false, true, true, false));
    assert_eq!(with("none"), auth(false, false, false, true));
    assert_eq!(with("scram-sha-256"), auth(true, false, false, false));
    assert_eq!(
        with("scram-sha-256,md5,password,none"),
        auth(true, true, true, true)
    );
    assert_eq!(with(""), AuthPolicy::default());
    assert_eq!(
        load_err(&[
            ("PGDATABASE", "pdb"),
            ("PGUSER", "pu"),
            ("PGREQUIREAUTH", "kerberos")
        ]),
        "PGREQUIREAUTH: unknown authentication method \"kerberos\"; expected scram-sha-256, md5, password or none"
    );
    assert_eq!(
        load_err(&[
            ("PGDATABASE", "pdb"),
            ("PGUSER", "pu"),
            ("PGREQUIREAUTH", " , ")
        ]),
        "PGREQUIREAUTH: no authentication method is listed"
    );
}

#[test]
fn require_auth_from_url_query() {
    let config = cfg(&[(
        "DATABASE_URL",
        "postgres://app:pw@db.example.com/appdb?require_auth=md5,password",
    )]);
    assert_eq!(config.databases[0].auth, auth(false, true, true, false));
    assert_eq!(
        load_err(&[(
            "DATABASE_URL",
            "postgres://app:pw@db.example.com/appdb?require_auth=md5,bogus"
        )]),
        "DATABASE_URL: require_auth: unknown authentication method \"bogus\"; expected scram-sha-256, md5, password or none"
    );
    assert_eq!(
        load_err(&[(
            "DATABASE_URL",
            "postgres://app:pw@db.example.com/appdb?require_auth="
        )]),
        "DATABASE_URL: require_auth: no authentication method is listed"
    );
}

#[test]
fn require_auth_from_json_entry() {
    let config = cfg(&[(
        "PG_DATABASES",
        r#"[{"name":"a","database":"db","user":"u","require_auth":"password"}]"#,
    )]);
    assert_eq!(config.databases[0].auth, auth(false, false, true, false));
    assert_eq!(
        load_err(&[(
            "PG_DATABASES",
            r#"[{"name":"a","database":"db","user":"u","require_auth":"none,kerberos"}]"#
        )]),
        "PG_DATABASES[0] (\"a\"): require_auth: unknown authentication method \"kerberos\"; expected scram-sha-256, md5, password or none"
    );
    assert_eq!(
        load_err(&[(
            "PG_DATABASES",
            r#"[{"name":"a","url":"postgres://u@h/db","require_auth":"md5"}]"#
        )]),
        "PG_DATABASES[0] (\"a\"): \"require_auth\" cannot be combined with \"url\""
    );
}

#[test]
fn verify_ca_needs_sslrootcert_in_each_source() {
    assert_eq!(
        load_err(&[
            ("PGDATABASE", "pdb"),
            ("PGUSER", "pu"),
            ("PGSSLMODE", "verify-ca")
        ]),
        "PGSSLMODE: sslmode=verify-ca needs sslrootcert"
    );
    assert_eq!(
        load_err(&[(
            "DATABASE_URL",
            "postgres://app:pw@db.example.com/appdb?sslmode=verify-ca"
        )]),
        "DATABASE_URL: sslmode=verify-ca needs sslrootcert"
    );
    assert_eq!(
        load_err(&[(
            "PG_DATABASES",
            r#"[{"name":"a","database":"db","user":"u","sslmode":"verify-ca"}]"#
        )]),
        "PG_DATABASES[0] (\"a\"): sslmode=verify-ca needs sslrootcert"
    );
    let ca = TempFile::new("not a certificate, only the path matters here");
    let root = ca.path();
    let config = cfg(&[
        ("PGDATABASE", "pdb"),
        ("PGUSER", "pu"),
        ("PGSSLMODE", "verify-ca"),
        ("PGSSLROOTCERT", root.as_str()),
    ]);
    assert_eq!(config.databases[0].connect.ssl_mode, SslMode::VerifyCa);
    let full = cfg(&[
        ("PGDATABASE", "pdb"),
        ("PGUSER", "pu"),
        ("PGSSLMODE", "verify-full"),
    ]);
    assert_eq!(full.databases[0].connect.ssl_mode, SslMode::VerifyFull);
}
