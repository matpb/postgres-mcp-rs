use std::sync::Arc;
use std::time::{Duration, Instant};

use postgres_mcp::encode::{TypeInfo, TypeKind};
use postgres_mcp::pg::pool::Pool;
use postgres_mcp::pg::session::{RunError, RunOutput, SessionSettings, run_readonly};
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{ConnectConfig, Connection, FetchLimits, Truncation};
use tokio::sync::OnceCell;
use tokio_util::sync::CancellationToken;

const HOST: &str = "127.0.0.1";
const VERSIONS: [(u16, u32); 3] = [(15432, 18), (15433, 19), (15434, 15)];

static SESS_TEST: OnceCell<()> = OnceCell::const_new();

fn startup_params() -> Vec<(String, String)> {
    [
        ("application_name", "pgmcp-session-test"),
        ("DateStyle", "ISO, MDY"),
        ("IntervalStyle", "iso_8601"),
        ("TimeZone", "UTC"),
        ("bytea_output", "hex"),
        ("extra_float_digits", "1"),
        ("standard_conforming_strings", "on"),
        ("default_transaction_read_only", "on"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

fn config(port: u16, password: &str) -> ConnectConfig {
    ConnectConfig {
        host: HOST.into(),
        port,
        database: "appdb".into(),
        user: "mcp_ro".into(),
        password: Some(password.into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: startup_params(),
    }
}

fn pool(port: u16, max: usize) -> Pool {
    Pool::new(config(port, "test-only-ro"), max)
}

fn tuned(statement_timeout_ms: u64, max_rows: usize, pool_wait: Duration) -> SessionSettings {
    SessionSettings {
        statement_timeout_ms,
        lock_timeout_ms: 500,
        fetch: FetchLimits {
            max_rows,
            max_bytes: 1 << 20,
            max_value_bytes: 4096,
        },
        pool_wait,
        search_path_catalog_only: false,
        unbound: false,
    }
}

fn settings() -> SessionSettings {
    tuned(2000, 1000, Duration::from_secs(5))
}

async fn run_with(
    pool: &Pool,
    sql: &str,
    settings: &SessionSettings,
) -> Result<RunOutput, RunError> {
    run_readonly(pool, sql, &[], true, settings, &CancellationToken::new()).await
}

async fn run(pool: &Pool, sql: &str) -> Result<RunOutput, RunError> {
    run_with(pool, sql, &settings()).await
}

fn texts(out: &RunOutput) -> Vec<Vec<Option<String>>> {
    out.result
        .rows
        .iter()
        .map(|row| {
            row.iter()
                .map(|cell| {
                    cell.as_ref()
                        .map(|f| String::from_utf8_lossy(&f.data).into_owned())
                })
                .collect()
        })
        .collect()
}

fn names(out: &RunOutput) -> Vec<String> {
    out.types.iter().map(|t| t.name.clone()).collect()
}

fn s(v: &str) -> Option<String> {
    Some(v.to_string())
}

async fn one(pool: &Pool, sql: &str) -> String {
    let out = run(pool, sql).await.expect("run");
    texts(&out)[0][0].clone().expect("non-null value")
}

fn superuser_config(port: u16) -> ConnectConfig {
    ConnectConfig {
        host: HOST.into(),
        port,
        database: "appdb".into(),
        user: "postgres".into(),
        password: Some("test-only-superuser".into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: Vec::new(),
    }
}

/// First value of the first row, from a superuser connection outside the pool.
async fn scalar(port: u16, sql: &str) -> String {
    let mut conn = Connection::connect(&superuser_config(port))
        .await
        .expect("superuser connect");
    let result = conn.simple_query(sql).await.expect("superuser query");
    result.rows[0][0].clone().expect("non-null value")
}

/// Polls a superuser count until it reads "0", for up to 2 seconds.
async fn eventually_zero(port: u16, sql: &str) {
    for _ in 0..20 {
        if scalar(port, sql).await == "0" {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(scalar(port, sql).await, "0", "{sql}");
}

const ACTIVE_SLEEP_10: &str = "SELECT count(*) FROM pg_stat_activity \
    WHERE application_name = 'pgmcp-session-test' AND query LIKE '%pg_sleep(10)%' AND state = 'active'";

fn sess_test_sql() -> String {
    let mut sql = String::from(
        "CREATE SCHEMA IF NOT EXISTS sess_test; \
         CREATE EXTENSION IF NOT EXISTS hstore; \
         CREATE EXTENSION IF NOT EXISTS citext;",
    );
    let mut add = |name: &str, create: &str| {
        sql.push_str(&format!(
            "DO $do$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type \
             WHERE typname = '{name}' AND typnamespace = 'sess_test'::regnamespace) \
             THEN {create}; END IF; END $do$; "
        ));
    };
    add("mood", "CREATE TYPE sess_test.mood AS ENUM ('sad', 'ok')");
    add("posint", "CREATE DOMAIN sess_test.posint AS int");
    add("pair", "CREATE TYPE sess_test.pair AS (a int, b text)");
    add(
        "typed",
        "CREATE TABLE sess_test.typed (mood sess_test.mood, dom sess_test.posint, \
         pr sess_test.pair, moods sess_test.mood[], r int4range, mr int4multirange, \
         iv int2vector, boxes box[], hs hstore, ct citext)",
    );
    add("dchain1", "CREATE DOMAIN sess_test.dchain1 AS int");
    for i in 2..=10 {
        add(
            &format!("dchain{i}"),
            &format!(
                "CREATE DOMAIN sess_test.dchain{i} AS sess_test.dchain{}",
                i - 1
            ),
        );
    }
    sql.push_str(
        "GRANT USAGE ON SCHEMA sess_test TO mcp_ro; GRANT SELECT ON sess_test.typed TO mcp_ro;",
    );
    sql
}

/// Creates the sess_test objects once per test process, as superuser.
async fn ensure_sess_test() {
    SESS_TEST
        .get_or_init(|| async {
            let mut conn = Connection::connect(&superuser_config(15432))
                .await
                .expect("superuser connect");
            conn.simple_query(&sess_test_sql())
                .await
                .expect("sess_test setup");
        })
        .await;
}

async fn oid_of(port: u16, typname: &str) -> u32 {
    scalar(
        port,
        &format!(
            "SELECT oid::text FROM pg_catalog.pg_type WHERE typname = '{typname}' \
             AND typnamespace = 'sess_test'::regnamespace"
        ),
    )
    .await
    .parse()
    .expect("oid")
}

fn info(oid: u32, name: &str, kind: TypeKind) -> TypeInfo {
    TypeInfo {
        oid,
        name: name.into(),
        kind,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn select_works_on_all_versions() {
    for (port, major) in VERSIONS {
        let pool = pool(port, 1);
        let out = run(
            &pool,
            "SELECT id, name, qty, price FROM app.items ORDER BY id LIMIT 3",
        )
        .await
        .expect("select");
        assert_eq!(out.server_version_num / 10_000, major, "port {port}");
        assert_eq!(
            texts(&out),
            vec![
                vec![s("1"), s("item 1"), s("1000000000000"), s("1.50")],
                vec![s("2"), s("item 2"), s("2000000000000"), s("3.00")],
                vec![s("3"), s("item 3"), s("3000000000000"), s("4.50")],
            ],
            "port {port}"
        );
        assert_eq!(
            names(&out),
            ["int4", "text", "int8", "numeric"],
            "port {port}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn connection_is_reused_and_clean() {
    let pool = pool(15432, 1);
    let mut pids = Vec::new();
    for _ in 0..3 {
        pids.push(one(&pool, "SELECT pg_backend_pid()").await);
    }
    assert!(pids.iter().all(|p| *p == pids[0]), "{pids:?}");
    assert_eq!(pool.idle_count(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn writes_are_refused_by_server() {
    let pool = pool(15432, 1);
    // nextval() needs UPDATE on the sequence, which mcp_ro lacks, so PostgreSQL reports 42501 before the read-only check.
    for (sql, code) in [
        (
            "INSERT INTO app.items VALUES (999999,'x',1,1) RETURNING id",
            "25006",
        ),
        (
            "UPDATE app.items SET name='x' WHERE id=1 RETURNING id",
            "25006",
        ),
        ("DELETE FROM app.items WHERE id=1 RETURNING id", "25006"),
        (
            "WITH d AS (DELETE FROM app.items RETURNING id) SELECT * FROM d",
            "25006",
        ),
        ("SELECT nextval('app.item_seq')", "42501"),
        ("SELECT lo_create(0)", "25006"),
    ] {
        match run(&pool, sql).await {
            Err(RunError::Db(e)) => assert_eq!(e.code, code, "{sql}"),
            other => panic!("{sql}: expected Db {code}, got {other:?}"),
        }
    }
    assert_eq!(
        scalar(15432, "SELECT count(*) FROM app.items").await,
        "5000"
    );
    assert_eq!(
        scalar(15432, "SELECT name FROM app.items WHERE id = 1").await,
        "item 1"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn non_row_statements_are_refused() {
    let pool = pool(15432, 1);
    for sql in [
        "COMMIT",
        "ROLLBACK AND CHAIN",
        "PREPARE TRANSACTION 'pgmcp_t1'",
        "SET statement_timeout = 0",
        "SET TRANSACTION READ WRITE",
        "LISTEN ch",
        "DO $$ begin end $$",
        "COPY app.items TO STDOUT",
        "SELECT 1 INTO TEMP zz",
        "CREATE TEMP TABLE zz(x int)",
        "DISCARD ALL",
        "LOCK TABLE app.items IN ACCESS SHARE MODE",
        "PREPARE p AS SELECT 1",
        "DECLARE c CURSOR WITH HOLD FOR SELECT 1",
        "BEGIN",
    ] {
        match run(&pool, sql).await {
            Err(RunError::Refused(m)) => {
                assert_eq!(m, "statement does not return rows", "{sql}")
            }
            other => panic!("{sql}: expected Refused, got {other:?}"),
        }
    }
    assert_eq!(
        scalar(15432, "SELECT count(*) FROM pg_prepared_xacts").await,
        "0"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn multiple_statements_fail() {
    let pool = pool(15432, 1);
    match run(&pool, "SELECT 1; SELECT 2").await {
        Err(RunError::Db(e)) => assert_eq!(e.code, "42601"),
        other => panic!("expected Db 42601, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn placeholders_refused_for_user_sql() {
    let pool = pool(15432, 1);
    match run(&pool, "SELECT $1::int").await {
        Err(RunError::Refused(m)) => assert_eq!(m, "parameter placeholders are not supported"),
        other => panic!("expected Refused, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn params_work_for_internal_sql() {
    let pool = pool(15432, 1);
    let out = run_readonly(
        &pool,
        "SELECT $1::text || 'x'",
        &[Some("a")],
        false,
        &settings(),
        &CancellationToken::new(),
    )
    .await
    .expect("params");
    assert_eq!(texts(&out), vec![vec![s("ax")]]);
}

#[tokio::test(flavor = "multi_thread")]
async fn read_write_cannot_be_enabled() {
    let pool = pool(15432, 1);
    let r = run(
        &pool,
        "SELECT set_config('transaction_read_only','off',true)",
    )
    .await;
    assert!(matches!(r, Err(RunError::Db(_))), "{r:?}");

    run(
        &pool,
        "SELECT set_config('default_transaction_read_only','off',false)",
    )
    .await
    .expect("set_config statement itself succeeds");
    match run(
        &pool,
        "INSERT INTO app.items VALUES (999998,'x',1,1) RETURNING id",
    )
    .await
    {
        Err(RunError::Db(e)) => assert_eq!(e.code, "25006"),
        other => panic!("expected Db 25006, got {other:?}"),
    }
    assert_eq!(
        scalar(15432, "SELECT count(*) FROM app.items").await,
        "5000"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn session_state_does_not_leak() {
    let pool = pool(15432, 1);
    let pid = one(&pool, "SELECT pg_backend_pid()").await;

    run(&pool, "SELECT pg_advisory_lock(424242)")
        .await
        .expect("advisory lock");
    assert_eq!(
        one(
            &pool,
            "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND pid = pg_backend_pid()"
        )
        .await,
        "0"
    );
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);

    run(&pool, "SELECT set_config('work_mem','123456kB',false)")
        .await
        .expect("work_mem");
    assert_ne!(
        one(&pool, "SELECT current_setting('work_mem')").await,
        "123456kB"
    );
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);

    run(&pool, "SELECT set_config('TimeZone','Asia/Tokyo',false)")
        .await
        .expect("TimeZone");
    assert!(one(&pool, "SELECT now()::text").await.ends_with("+00"));
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);

    run(&pool, "SELECT set_config('search_path','sess_test',false)")
        .await
        .expect("search_path");
    assert!(
        !one(&pool, "SELECT current_setting('search_path')")
            .await
            .starts_with("sess_test")
    );
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);

    run(&pool, "SELECT set_config('statement_timeout','0',false)")
        .await
        .expect("statement_timeout");
    match run_with(
        &pool,
        "SELECT pg_sleep(4)",
        &tuned(1000, 1000, Duration::from_secs(5)),
    )
    .await
    {
        Err(RunError::Timeout(1000)) => {}
        other => panic!("expected Timeout(1000), got {other:?}"),
    }
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);

    run(&pool, "SELECT pg_notify('ch','x')")
        .await
        .expect("notify");
    run(&pool, "SELECT set_config('application_name','evil',false)")
        .await
        .expect("application_name");
    assert_eq!(
        one(&pool, "SELECT current_setting('application_name')").await,
        "pgmcp-session-test"
    );
    assert_eq!(one(&pool, "SELECT pg_backend_pid()").await, pid);
}

#[tokio::test(flavor = "multi_thread")]
async fn statement_timeout_enforced_server_side() {
    let pool = pool(15432, 1);
    let started = Instant::now();
    match run_with(
        &pool,
        "SELECT pg_sleep(10)",
        &tuned(500, 1000, Duration::from_secs(5)),
    )
    .await
    {
        Err(RunError::Timeout(500)) => {}
        other => panic!("expected Timeout(500), got {other:?}"),
    }
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    eventually_zero(15432, ACTIVE_SLEEP_10).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn client_cancel_stops_server_query() {
    let pool = pool(15432, 1);
    let token = CancellationToken::new();
    let trigger = token.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    });
    let started = Instant::now();
    let r = run_readonly(
        &pool,
        "SELECT pg_sleep(20)",
        &[],
        true,
        &tuned(30_000, 1000, Duration::from_secs(5)),
        &token,
    )
    .await;
    assert!(matches!(r, Err(RunError::Cancelled)), "{r:?}");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "{:?}",
        started.elapsed()
    );
    eventually_zero(
        15432,
        "SELECT count(*) FROM pg_stat_activity WHERE application_name = 'pgmcp-session-test' \
         AND query LIKE '%pg_sleep(20)%' AND state = 'active'",
    )
    .await;
    assert_eq!(one(&pool, "SELECT 1").await, "1");
}

// PostgreSQL 18 needs about 3.4 s before the first row of this 50M-row series, so the brief's
// 2000 ms statement timeout fires first (see truncation_under_short_timeout_reports_timeout).
#[tokio::test(flavor = "multi_thread")]
async fn truncation_keeps_pool_usable() {
    let pool = pool(15432, 1);
    let out = run_with(
        &pool,
        "SELECT g FROM generate_series(1, 50000000) g",
        &tuned(10_000, 50, Duration::from_secs(5)),
    )
    .await
    .expect("truncated select");
    assert_eq!(out.result.rows.len(), 50);
    assert_eq!(out.result.truncated, Some(Truncation::Rows));
    assert_eq!(names(&out), ["int4"]);
    assert_eq!(one(&pool, "SELECT 1").await, "1");
}

#[tokio::test(flavor = "multi_thread")]
async fn truncation_under_short_timeout_is_timeout_or_truncated() {
    let pool = pool(15432, 1);
    match run_with(
        &pool,
        "SELECT g FROM generate_series(1, 50000000) g",
        &tuned(2000, 50, Duration::from_secs(5)),
    )
    .await
    {
        Err(RunError::Timeout(2000)) => {}
        Ok(out) => assert_eq!(out.result.truncated, Some(Truncation::Rows)),
        other => panic!("expected Timeout(2000) or a truncated result, got {other:?}"),
    }
    assert_eq!(one(&pool, "SELECT 1").await, "1");
}

#[tokio::test(flavor = "multi_thread")]
async fn runaway_recursive_cte_is_bounded() {
    let pool = pool(15432, 1);
    let started = Instant::now();
    let out = run_with(
        &pool,
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM r) SELECT n FROM r",
        &tuned(2000, 100, Duration::from_secs(5)),
    )
    .await
    .expect("bounded recursive query");
    assert_eq!(out.result.truncated, Some(Truncation::Rows));
    assert_eq!(out.result.rows.len(), 100);
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn types_resolved_for_non_builtin() {
    ensure_sess_test().await;
    let pool = pool(15432, 1);
    let out = run(&pool, "SELECT * FROM sess_test.typed")
        .await
        .expect("select typed");
    let cols: Vec<u32> = out.result.columns.iter().map(|c| c.type_oid).collect();
    assert_eq!(cols[1], 23, "domain column reports its base type");
    let mood = info(cols[0], "sess_test.mood", TypeKind::Text);
    let int4 = info(23, "int4", TypeKind::Int);
    let expected = vec![
        mood.clone(),
        int4.clone(),
        info(cols[2], "sess_test.pair", TypeKind::Text),
        info(
            cols[3],
            "sess_test.mood[]",
            TypeKind::Array {
                elem: Box::new(mood),
                delim: ',',
            },
        ),
        info(
            3904,
            "int4range",
            TypeKind::Range {
                sub: Box::new(int4.clone()),
            },
        ),
        info(
            4451,
            "int4multirange",
            TypeKind::Multirange {
                sub: Box::new(int4),
            },
        ),
        info(22, "int2vector", TypeKind::Text),
        info(
            1020,
            "_box",
            TypeKind::Array {
                elem: Box::new(info(603, "box", TypeKind::Text)),
                delim: ';',
            },
        ),
        info(cols[8], "hstore", TypeKind::Text),
        info(cols[9], "citext", TypeKind::Text),
    ];
    assert_eq!(out.types, expected);
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_chains_are_depth_limited() {
    ensure_sess_test().await;
    let pool = pool(15432, 1);
    let short = oid_of(15432, "dchain3").await;
    let long = oid_of(15432, "dchain10").await;
    let mut lease = pool
        .checkout(Duration::from_secs(5))
        .await
        .expect("checkout");
    let types = pool
        .type_cache()
        .resolve(lease.conn(), &[short, long])
        .await
        .expect("resolve");
    lease.release(true);
    assert_eq!(
        types,
        vec![
            info(short, "sess_test.dchain3", TypeKind::Int),
            info(long, "sess_test.dchain10", TypeKind::Text),
        ]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn builtin_types_need_no_lookup() {
    let pool = pool(15432, 1);
    let mut lease = pool
        .checkout(Duration::from_secs(5))
        .await
        .expect("checkout");
    let types = pool
        .type_cache()
        .resolve(lease.conn(), &[23, 25, 1020])
        .await
        .expect("resolve");
    lease.release(true);
    assert_eq!(pool.type_cache().lookups(), 0);
    assert_eq!(
        types.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["int4", "text", "_box"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn type_cache_is_reused() {
    ensure_sess_test().await;
    let source = pool(15432, 1);
    let out = run(&source, "SELECT * FROM sess_test.typed")
        .await
        .expect("select typed");
    let moods_oid = out.result.columns[3].type_oid;

    let pool = pool(15432, 1);
    let mut lease = pool
        .checkout(Duration::from_secs(5))
        .await
        .expect("checkout");
    let first = pool
        .type_cache()
        .resolve(lease.conn(), &[moods_oid])
        .await
        .expect("first resolve");
    let after_first = pool.type_cache().lookups();
    assert!(after_first > 0, "first resolve must query pg_type");
    let second = pool
        .type_cache()
        .resolve(lease.conn(), &[moods_oid])
        .await
        .expect("second resolve");
    lease.release(true);
    assert_eq!(second, first);
    assert_eq!(pool.type_cache().lookups(), after_first);
}

#[tokio::test(flavor = "multi_thread")]
async fn standard_conforming_strings_pinned() {
    for (port, _) in VERSIONS {
        let pool = pool(port, 1);
        assert_eq!(
            one(
                &pool,
                "SELECT current_setting('standard_conforming_strings')"
            )
            .await,
            "on",
            "port {port}"
        );
        let out = run(&pool, r"SELECT '\' || 'a'").await.expect("backslash");
        assert_eq!(texts(&out), vec![vec![s(r"\a")]], "port {port}");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn busy_pool_reports_unavailable() {
    let pool = Arc::new(pool(15432, 1));
    let holder = {
        let pool = pool.clone();
        tokio::spawn(async move { run(&pool, "SELECT pg_sleep(1)").await })
    };
    tokio::time::sleep(Duration::from_millis(500)).await;
    let r = run_with(
        &pool,
        "SELECT 1",
        &tuned(2000, 1000, Duration::from_millis(200)),
    )
    .await;
    match r {
        Err(RunError::Unavailable(m)) => assert_eq!(m, "all connections are busy, retry shortly"),
        other => panic!("expected Unavailable, got {other:?}"),
    }
    holder.await.expect("join").expect("holder run");
}

#[tokio::test(flavor = "multi_thread")]
async fn closed_pool_reports_unavailable() {
    let pool = pool(15432, 1);
    pool.close().await;
    match run(&pool, "SELECT 1").await {
        Err(RunError::Unavailable(m)) => assert_eq!(m, "the pool is closed"),
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bad_password_is_unavailable_without_leak() {
    let pool = Pool::new(config(15432, "not-the-password-xyz"), 1);
    match run(&pool, "SELECT 1").await {
        Err(RunError::Unavailable(m)) => {
            assert!(!m.contains("not-the-password-xyz"), "{m}");
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_host_is_unavailable() {
    let pool = Pool::new(config(15999, "test-only-ro"), 1);
    match run(&pool, "SELECT 1").await {
        Err(RunError::Unavailable(_)) => {}
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stale_idle_connection_is_replaced() {
    let pool = pool(15432, 1);
    let old = one(&pool, "SELECT pg_backend_pid()").await;
    scalar(15432, &format!("SELECT pg_terminate_backend({old})")).await;
    eventually_zero(
        15432,
        &format!("SELECT count(*) FROM pg_stat_activity WHERE pid = {old}"),
    )
    .await;
    let new = one(&pool, "SELECT pg_backend_pid()").await;
    assert_ne!(new, old);
    assert_eq!(one(&pool, "SELECT 1").await, "1");
}
