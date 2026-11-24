use std::path::Path;
use std::time::{Duration, Instant};

use bytes::Bytes;
use postgres_mcp::pg::tls::{SslMode, client_config};
use postgres_mcp::pg::wire::{
    ConnectConfig, Connection, FetchLimits, Field, Truncation, TxStatus, WireError,
    parse_server_version_num,
};

const BIG: FetchLimits = FetchLimits {
    max_rows: 100_000,
    max_bytes: 1 << 30,
    max_value_bytes: 1 << 20,
};

fn cfg(port: u16) -> ConnectConfig {
    ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: "appdb".into(),
        user: "mcp_ro".into(),
        password: Some("test-only-ro".into()),
        ssl_mode: SslMode::Prefer,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: vec![
            ("application_name".into(), "pgmcp-wire-test".into()),
            ("DateStyle".into(), "ISO".into()),
            ("IntervalStyle".into(), "iso_8601".into()),
            ("TimeZone".into(), "UTC".into()),
        ],
    }
}

async fn connect(port: u16) -> Connection {
    Connection::connect(&cfg(port))
        .await
        .expect("connect to test server")
}

fn text(value: &Option<Field>) -> Option<String> {
    value
        .as_ref()
        .map(|f| String::from_utf8(f.data.to_vec()).expect("utf8 value"))
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

#[tokio::test]
async fn connects_to_all_versions() {
    for (port, major) in [(15432u16, 18u32), (15433, 19), (15434, 15)] {
        let conn = connect(port).await;
        assert_eq!(conn.server_version_num() / 10000, major, "port {port}");
        assert_eq!(conn.parameter("TimeZone"), Some("UTC"), "port {port}");
        conn.close().await;
    }
}

#[tokio::test]
async fn wrong_password_is_error_without_leak() {
    let mut c = cfg(15432);
    c.password = Some("not-the-pass-xyz".into());
    let err = Connection::connect(&c)
        .await
        .err()
        .expect("wrong password must fail");
    assert!(
        matches!(err, WireError::Db(_) | WireError::Auth(_)),
        "unexpected error kind: {err:?}"
    );
    assert!(!err.to_string().contains("not-the-pass-xyz"));
}

#[tokio::test]
async fn ssl_require_fails_on_plain_server() {
    let mut c = cfg(15433);
    c.ssl_mode = SslMode::Require;
    match Connection::connect(&c).await {
        Err(WireError::Tls(_)) => {}
        Err(e) => panic!("expected Tls error, got {e:?}"),
        Ok(_) => panic!("expected Tls error, connected"),
    }
}

#[tokio::test]
async fn simple_query_multi_statement() {
    let mut conn = connect(15432).await;
    let r = conn
        .simple_query("BEGIN READ ONLY; SELECT 1")
        .await
        .expect("multi-statement");
    assert_eq!(r.status, TxStatus::InTransaction);
    assert_eq!(r.rows, vec![vec![s("1")]]);
    let r = conn.simple_query("ROLLBACK").await.expect("rollback");
    assert_eq!(r.status, TxStatus::Idle);
}

#[tokio::test]
async fn simple_query_error_keeps_connection() {
    let mut conn = connect(15432).await;
    match conn.simple_query("SELECT 1/0").await {
        Err(WireError::Db(e)) => assert_eq!(e.code, "22012"),
        other => panic!("expected Db error, got {other:?}"),
    }
    let r = conn.simple_query("SELECT 1").await.expect("still usable");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn query_text_results() {
    let mut conn = connect(15432).await;
    let r = conn
        .query(
            "SELECT id, name, qty, price, NULL::int AS n FROM app.items ORDER BY id LIMIT 2",
            &[],
            false,
            &BIG,
        )
        .await
        .expect("query");
    let names: Vec<&str> = r.columns.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(names, ["id", "name", "qty", "price", "n"]);
    let oids: Vec<u32> = r.columns.iter().map(|c| c.type_oid).collect();
    assert_eq!(oids, vec![23, 25, 20, 1700, 23]);
    assert_eq!(r.rows.len(), 2);
    let row = &r.rows[0];
    assert_eq!(text(&row[0]), s("1"));
    assert_eq!(text(&row[1]), s("item 1"));
    assert_eq!(text(&row[2]), s("1000000000000"));
    assert_eq!(text(&row[3]), s("1.50"));
    assert_eq!(row[4], None);
    assert_eq!(r.truncated, None);
    assert_eq!(r.command_tag.as_deref(), Some("SELECT 2"));
    assert_eq!(r.status, TxStatus::Idle);
}

#[tokio::test]
async fn query_empty_string_is_present_not_null() {
    let mut conn = connect(15432).await;
    let r = conn
        .query("SELECT ''::text, NULL::text", &[], false, &BIG)
        .await
        .expect("query");
    assert_eq!(text(&r.rows[0][0]), s(""));
    assert_eq!(r.rows[0][1], None);
}

#[tokio::test]
async fn query_zero_rows_has_tag() {
    let mut conn = connect(15432).await;
    let r = conn
        .query("SELECT 1 WHERE false", &[], false, &BIG)
        .await
        .expect("query");
    assert!(r.rows.is_empty());
    assert_eq!(r.command_tag.as_deref(), Some("SELECT 0"));
    assert_eq!(r.truncated, None);
}

#[tokio::test]
async fn row_limit_exact_is_not_truncated() {
    let mut conn = connect(15432).await;
    let limits = FetchLimits {
        max_rows: 10,
        max_bytes: 1 << 30,
        max_value_bytes: 1 << 20,
    };
    let r = conn
        .query(
            "SELECT g FROM generate_series(1, 10) g",
            &[],
            false,
            &limits,
        )
        .await
        .expect("query");
    assert_eq!(r.rows.len(), 10);
    assert_eq!(r.truncated, None);
    assert_eq!(r.command_tag.as_deref(), Some("SELECT 10"));
    assert_eq!(text(&r.rows[9][0]), s("10"));
}

#[tokio::test]
async fn query_with_params() {
    let mut conn = connect(15432).await;
    let r = conn
        .query("SELECT $1::int + 1", &[Some("41")], false, &BIG)
        .await
        .expect("query");
    assert_eq!(text(&r.rows[0][0]), s("42"));
}

#[tokio::test]
async fn user_sql_rejects_placeholders() {
    let mut conn = connect(15432).await;
    match conn.query("SELECT $1::int", &[], true, &BIG).await {
        Err(WireError::Refused(_)) => {}
        other => panic!("expected Refused, got {other:?}"),
    }
    let r = conn
        .query("SELECT 1", &[], true, &BIG)
        .await
        .expect("still usable");
    assert_eq!(text(&r.rows[0][0]), s("1"));
}

#[tokio::test]
async fn refuses_non_row_statements() {
    let mut conn = connect(15432).await;
    conn.simple_query("BEGIN READ ONLY").await.expect("begin");
    let statements = [
        "COMMIT",
        "ROLLBACK AND CHAIN",
        "PREPARE TRANSACTION 'x'",
        "SET work_mem = '1GB'",
        "LISTEN ch",
        "DO $$ begin end $$",
        "COPY app.items TO STDOUT",
        "SELECT 1 INTO TEMP zz",
        "DISCARD ALL",
    ];
    for sql in statements {
        match conn.query(sql, &[], false, &BIG).await {
            Err(WireError::Refused(m)) => assert_eq!(m, "statement does not return rows", "{sql}"),
            other => panic!("{sql}: expected Refused, got {other:?}"),
        }
    }
    let r = conn.simple_query("SELECT 1").await.expect("select");
    assert_eq!(r.status, TxStatus::InTransaction);
    conn.simple_query("ROLLBACK").await.expect("rollback");
}

#[tokio::test]
async fn rejects_multiple_statements() {
    let mut conn = connect(15432).await;
    match conn.query("SELECT 1; SELECT 2", &[], false, &BIG).await {
        Err(WireError::Db(e)) => assert_eq!(e.code, "42601"),
        other => panic!("expected Db 42601, got {other:?}"),
    }
}

#[tokio::test]
async fn rejects_nul_byte() {
    let mut conn = connect(15432).await;
    match conn.query("SELECT 1\0", &[], false, &BIG).await {
        Err(WireError::Refused(m)) => assert_eq!(m, "SQL contains a NUL byte"),
        other => panic!("expected Refused, got {other:?}"),
    }
    let r = conn
        .simple_query("SELECT 1")
        .await
        .expect("nothing was sent");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn row_limit_truncates_and_cancels() {
    let mut conn = connect(15432).await;
    conn.simple_query("BEGIN READ ONLY").await.expect("begin");
    let limits = FetchLimits {
        max_rows: 10,
        max_bytes: 1 << 30,
        max_value_bytes: 1 << 20,
    };
    let start = Instant::now();
    let r = conn
        .query(
            "SELECT g FROM generate_series(1, 50000000) g",
            &[],
            false,
            &limits,
        )
        .await
        .expect("truncated query");
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(r.rows.len(), 10);
    assert_eq!(text(&r.rows[0][0]), s("1"));
    assert_eq!(text(&r.rows[9][0]), s("10"));
    assert_eq!(r.truncated, Some(Truncation::Rows));
    assert_eq!(r.command_tag, None);
    conn.simple_query("ROLLBACK").await.expect("rollback");
    let r = conn.simple_query("SELECT 1").await.expect("usable again");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn byte_limit_truncates() {
    let mut conn = connect(15432).await;
    let limits = FetchLimits {
        max_rows: 1_000_000,
        max_bytes: 10_000,
        max_value_bytes: 1 << 20,
    };
    let r = conn
        .query(
            "SELECT repeat('x', 1000) FROM generate_series(1, 100000)",
            &[],
            false,
            &limits,
        )
        .await
        .expect("truncated query");
    assert_eq!(r.truncated, Some(Truncation::Bytes));
    assert!((1..=10).contains(&r.rows.len()), "rows: {}", r.rows.len());
    let r = conn.simple_query("SELECT 1").await.expect("usable again");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn oversized_value_is_prefixed() {
    let mut conn = connect(15432).await;
    let limits = FetchLimits {
        max_rows: 10,
        max_bytes: 1 << 30,
        max_value_bytes: 64,
    };
    let r = conn
        .query("SELECT repeat('y', 100000)", &[], false, &limits)
        .await
        .expect("query");
    let field = r.rows[0][0].as_ref().expect("value");
    assert_eq!(field.data.len(), 64);
    assert_eq!(field.full_len, 100000);
    assert_eq!(field.data, Bytes::from(vec![b'y'; 64]));
}

#[tokio::test]
async fn statement_timeout_is_db_error() {
    let mut conn = connect(15432).await;
    conn.simple_query("SET statement_timeout = 200")
        .await
        .expect("set");
    match conn.query("SELECT pg_sleep(5)", &[], false, &BIG).await {
        Err(WireError::Db(e)) => assert_eq!(e.code, "57014"),
        other => panic!("expected Db 57014, got {other:?}"),
    }
    conn.simple_query("SET statement_timeout = 0")
        .await
        .expect("reset");
    let r = conn.simple_query("SELECT 1").await.expect("usable");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn cancel_handle_stops_query() {
    let mut conn = connect(15432).await;
    let handle = conn.cancel_handle();
    let canceller = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.cancel().await
    });
    let start = Instant::now();
    match conn.query("SELECT pg_sleep(30)", &[], false, &BIG).await {
        Err(WireError::Db(e)) => assert_eq!(e.code, "57014"),
        other => panic!("expected Db 57014, got {other:?}"),
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "{:?}",
        start.elapsed()
    );
    canceller.await.expect("join").expect("cancel request");
    let r = conn.simple_query("SELECT 1").await.expect("usable");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}

#[tokio::test]
async fn notify_poisons_connection() {
    let mut conn = connect(15432).await;
    let first = tokio::time::timeout(
        Duration::from_secs(5),
        conn.simple_query("LISTEN x; NOTIFY x"),
    )
    .await
    .expect("must not hang");
    let _ = first;
    assert!(conn.is_poisoned());
    match conn.simple_query("SELECT 1").await {
        Err(WireError::Protocol(m)) => assert_eq!(m, "connection is poisoned"),
        other => panic!("expected poisoned error, got {other:?}"),
    }
}

#[tokio::test]
async fn reset_sequence_ends_idle() {
    let mut conn = connect(15432).await;
    conn.simple_query("BEGIN READ ONLY").await.expect("begin");
    conn.query("SELECT 1", &[], false, &BIG)
        .await
        .expect("query");
    conn.simple_query("ROLLBACK").await.expect("rollback");
    let r = conn.simple_query("DISCARD ALL").await.expect("discard");
    assert_eq!(r.status, TxStatus::Idle);
}

#[test]
fn server_version_parsing() {
    assert_eq!(parse_server_version_num("19.0"), 190000);
    assert_eq!(
        parse_server_version_num("18.7 (Ubuntu 18.7-1.pgdg22.04+5)"),
        180007
    );
    assert_eq!(parse_server_version_num("15.20"), 150020);
    assert_eq!(parse_server_version_num("20devel"), 200000);
}

#[test]
fn debug_redacts_password() {
    let c = cfg(15432);
    let shown = format!("{c:?}");
    assert!(!shown.contains("test-only-ro"), "{shown}");
    assert!(shown.contains("<redacted>"), "{shown}");
    let mut none = cfg(15432);
    none.password = None;
    let shown = format!("{none:?}");
    assert!(shown.contains("None"), "{shown}");
    assert!(!shown.contains("<redacted>"), "{shown}");
}

#[test]
fn ssl_mode_parses_names() {
    assert_eq!("disable".parse::<SslMode>(), Ok(SslMode::Disable));
    assert_eq!("prefer".parse::<SslMode>(), Ok(SslMode::Prefer));
    assert_eq!("require".parse::<SslMode>(), Ok(SslMode::Require));
    assert_eq!("verify-ca".parse::<SslMode>(), Ok(SslMode::VerifyCa));
    assert_eq!("verify-full".parse::<SslMode>(), Ok(SslMode::VerifyFull));
    assert_eq!(
        "bogus".parse::<SslMode>(),
        Err("invalid ssl mode \"bogus\"".to_string())
    );
}

#[test]
fn tls_client_config_builds_for_each_mode() {
    for mode in [
        SslMode::Prefer,
        SslMode::Require,
        SslMode::VerifyCa,
        SslMode::VerifyFull,
    ] {
        assert!(client_config(mode, None).is_ok(), "{mode:?}");
    }
}

#[test]
fn tls_root_cert_errors_are_exact() {
    let missing = Path::new("/nonexistent/pgmcp-root.pem");
    match client_config(SslMode::VerifyFull, Some(missing)) {
        Err(WireError::Tls(m)) => assert_eq!(
            m,
            "cannot open /nonexistent/pgmcp-root.pem: No such file or directory (os error 2)"
        ),
        other => panic!("expected Tls error, got {other:?}"),
    }
    let no_certs = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    match client_config(SslMode::VerifyCa, Some(&no_certs)) {
        Err(WireError::Tls(m)) => assert_eq!(
            m,
            format!("no certificates found in {}", no_certs.display())
        ),
        other => panic!("expected Tls error, got {other:?}"),
    }
}

#[tokio::test]
async fn oversized_row_is_skipped_not_buffered_on_real_server() {
    let mut conn = connect(15432).await;
    // Row cap for max_bytes 48000: 4 * 48000 + 1 MiB = 1240576 bytes.
    let limits = FetchLimits {
        max_rows: 1_000,
        max_bytes: 48_000,
        max_value_bytes: 4_096,
    };
    let r = conn
        .query("SELECT repeat('x', 300000000)", &[], false, &limits)
        .await
        .expect("truncated query");
    assert_eq!(r.truncated, Some(Truncation::Bytes));
    assert!(r.rows.len() <= 1, "rows: {}", r.rows.len());
    assert_eq!(r.command_tag, None);
    assert!(
        conn.peak_message_bytes() <= 1_240_576,
        "largest buffered message: {}",
        conn.peak_message_bytes()
    );
    assert!(!conn.is_poisoned());
    let r = conn.simple_query("SELECT 1").await.expect("usable again");
    assert_eq!(r.rows, vec![vec![s("1")]]);
}
