//! Wire client against scripted fake servers: auth policy, SCRAM completion, SSL answers,
//! timeouts, oversized headers, copy refusal, mid-session parameters and async messages.

use std::time::{Duration, Instant};

use bytes::Bytes;
use postgres_mcp::pg::pool::{Pool, PoolError};
use postgres_mcp::pg::session::{RunError, SessionSettings, run_readonly};
use postgres_mcp::pg::tls::SslMode;
use postgres_mcp::pg::wire::{
    AuthPolicy, ConnectConfig, Connection, DbError, FetchLimits, QueryResult, Truncation, TxStatus,
    WireError,
};
use postgres_mcp::tools::ToolError;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

mod common;
use common::{app, call_tool, config_with, db_entry, result_of};

const PASSWORD: &str = "fake-server-pw-9f2";
const TIMEOUT: Duration = Duration::from_secs(10);

/// One action of the scripted server.
enum Step {
    /// Reads one startup-style frontend message (length prefix only).
    ReadUntagged,
    /// Reads one tagged frontend message.
    ReadTagged,
    Write(Vec<u8>),
    /// Writes bytes computed from everything the client sent so far.
    Reply(fn(&[u8]) -> Vec<u8>),
    /// Records what the client sends for this long.
    Drain(Duration),
    /// Holds the socket without answering.
    Sleep(Duration),
}

/// Runs the script on a fresh listener; the task yields every byte the client sent.
async fn spawn_server(steps: Vec<Step>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        tokio::time::timeout(TIMEOUT, serve(listener, steps))
            .await
            .unwrap_or_default()
    });
    (port, task)
}

/// Runs the script on the first connection, then keeps accepting and closing so that a
/// CancelRequest on a second connection reaches a listening socket.
async fn serve(listener: TcpListener, steps: Vec<Step>) -> Vec<u8> {
    let mut recorded = Vec::new();
    let Ok((mut sock, _)) = listener.accept().await else {
        return recorded;
    };
    run_steps(&mut sock, steps, &mut recorded).await;
    drop(sock);
    tokio::spawn(async move {
        while let Ok((extra, _)) = listener.accept().await {
            drop(extra);
        }
    });
    recorded
}

async fn run_steps(sock: &mut TcpStream, steps: Vec<Step>, recorded: &mut Vec<u8>) {
    for step in steps {
        let carry_on = match step {
            Step::ReadUntagged => read_frame(sock, recorded, false).await,
            Step::ReadTagged => read_frame(sock, recorded, true).await,
            Step::Write(bytes) => sock.write_all(&bytes).await.is_ok(),
            Step::Reply(build) => {
                let bytes = build(recorded);
                sock.write_all(&bytes).await.is_ok()
            }
            Step::Drain(for_how_long) => drain(sock, recorded, for_how_long).await,
            Step::Sleep(how_long) => {
                tokio::time::sleep(how_long).await;
                true
            }
        };
        if !carry_on {
            break;
        }
    }
}

async fn read_frame(sock: &mut TcpStream, rec: &mut Vec<u8>, tagged: bool) -> bool {
    let head = if tagged { 5 } else { 4 };
    let mut hdr = [0u8; 5];
    if sock.read_exact(&mut hdr[..head]).await.is_err() {
        return false;
    }
    let at = usize::from(tagged);
    let len = u32::from_be_bytes([hdr[at], hdr[at + 1], hdr[at + 2], hdr[at + 3]]) as usize;
    rec.extend_from_slice(&hdr[..head]);
    let start = rec.len();
    rec.resize(start + len.saturating_sub(4), 0);
    sock.read_exact(&mut rec[start..]).await.is_ok()
}

async fn drain(sock: &mut TcpStream, rec: &mut Vec<u8>, for_how_long: Duration) -> bool {
    let end = Instant::now() + for_how_long;
    let mut buf = [0u8; 4096];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return true;
        }
        match tokio::time::timeout(left, sock.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => rec.extend_from_slice(&buf[..n]),
            Ok(_) => return false,
            Err(_) => return true,
        }
    }
}

/// Tagged frames of a recording as (tag, body), after `untagged` leading length-only frames.
fn tagged(raw: &[u8], untagged: usize) -> Vec<(u8, Vec<u8>)> {
    let mut pos = 0usize;
    for _ in 0..untagged {
        pos += u32_at(raw, pos).max(4);
    }
    let mut frames = Vec::new();
    while pos + 5 <= raw.len() {
        let total = (1 + u32_at(raw, pos + 1)).max(5);
        let end = (pos + total).min(raw.len());
        frames.push((raw[pos], raw[pos + 5..end].to_vec()));
        pos = end;
    }
    frames
}

/// The big-endian u32 at `pos`, or 0 when fewer than four bytes are left.
fn u32_at(raw: &[u8], pos: usize) -> usize {
    match raw.get(pos..pos + 4) {
        Some(b) => u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as usize,
        None => 0,
    }
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn cstr(s: &str) -> Vec<u8> {
    let mut v = s.as_bytes().to_vec();
    v.push(0);
    v
}

fn frame(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&((body.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn fields(pairs: &[(u8, &str)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in pairs {
        out.push(*kind);
        out.extend_from_slice(&cstr(value));
    }
    out.push(0);
    out
}

fn auth(code: u32, extra: &[u8]) -> Vec<u8> {
    frame(b'R', &cat(&[&code.to_be_bytes(), extra]))
}

fn auth_ok() -> Vec<u8> {
    auth(0, &[])
}

fn auth_cleartext() -> Vec<u8> {
    auth(3, &[])
}

fn auth_md5(salt: [u8; 4]) -> Vec<u8> {
    auth(5, &salt)
}

fn auth_sasl(mechanisms: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    for m in mechanisms {
        body.extend_from_slice(&cstr(m));
    }
    body.push(0);
    auth(10, &body)
}

fn auth_sasl_continue(data: &[u8]) -> Vec<u8> {
    auth(11, data)
}

fn auth_sasl_final(data: &[u8]) -> Vec<u8> {
    auth(12, data)
}

fn parameter_status(name: &str, value: &str) -> Vec<u8> {
    frame(b'S', &cat(&[&cstr(name), &cstr(value)]))
}

fn backend_key_data() -> Vec<u8> {
    frame(
        b'K',
        &cat(&[&1234i32.to_be_bytes(), &5678i32.to_be_bytes()]),
    )
}

fn ready(status: u8) -> Vec<u8> {
    frame(b'Z', &[status])
}

fn error_response(code: &str, message: &str) -> Vec<u8> {
    frame(
        b'E',
        &fields(&[(b'S', "FATAL"), (b'C', code), (b'M', message)]),
    )
}

fn notice_response(message: &str) -> Vec<u8> {
    frame(
        b'N',
        &fields(&[(b'S', "NOTICE"), (b'C', "00000"), (b'M', message)]),
    )
}

fn notification_response(channel: &str, payload: &str) -> Vec<u8> {
    frame(
        b'A',
        &cat(&[&7i32.to_be_bytes(), &cstr(channel), &cstr(payload)]),
    )
}

fn parse_complete() -> Vec<u8> {
    frame(b'1', &[])
}

fn bind_complete() -> Vec<u8> {
    frame(b'2', &[])
}

fn parameter_description(oids: &[u32]) -> Vec<u8> {
    let mut body = (oids.len() as u16).to_be_bytes().to_vec();
    for oid in oids {
        body.extend_from_slice(&oid.to_be_bytes());
    }
    frame(b't', &body)
}

fn row_description(columns: &[(&str, u32)]) -> Vec<u8> {
    let mut body = (columns.len() as u16).to_be_bytes().to_vec();
    for (name, oid) in columns {
        body.extend_from_slice(&cstr(name));
        body.extend_from_slice(&cat(&[
            &0u32.to_be_bytes(),
            &0u16.to_be_bytes(),
            &oid.to_be_bytes(),
            &(-1i16).to_be_bytes(),
            &(-1i32).to_be_bytes(),
            &0u16.to_be_bytes(),
        ]));
    }
    frame(b'T', &body)
}

fn data_row(values: &[&[u8]]) -> Vec<u8> {
    let mut body = (values.len() as u16).to_be_bytes().to_vec();
    for value in values {
        body.extend_from_slice(&(value.len() as i32).to_be_bytes());
        body.extend_from_slice(value);
    }
    frame(b'D', &body)
}

fn command_complete(tag: &str) -> Vec<u8> {
    frame(b'C', &cstr(tag))
}

/// Body of CopyOutResponse, CopyInResponse and CopyBothResponse: text format, no columns.
fn copy_body() -> Vec<u8> {
    vec![0, 0, 0]
}

/// Startup, trust authentication, key data and ReadyForQuery.
fn startup_ok() -> Vec<Step> {
    vec![
        Step::ReadUntagged,
        Step::Write(auth_ok()),
        Step::Write(backend_key_data()),
        Step::Write(ready(b'I')),
    ]
}

/// Parse, Describe and Sync answered for a one-column int4 statement.
fn describe_one_int4() -> Vec<Step> {
    vec![
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(parse_complete()),
        Step::Write(parameter_description(&[])),
        Step::Write(row_description(&[("x", 23)])),
        Step::Write(ready(b'I')),
    ]
}

fn cfg(port: u16) -> ConnectConfig {
    ConnectConfig {
        host: "127.0.0.1".into(),
        port,
        database: "appdb".into(),
        user: "app".into(),
        password: Some(PASSWORD.into()),
        ssl_mode: SslMode::Disable,
        ssl_root_cert: None,
        connect_timeout: Duration::from_secs(5),
        startup_params: Vec::new(),
    }
}

fn pol(scram: bool, md5: bool, password: bool, trust: bool) -> AuthPolicy {
    AuthPolicy {
        scram,
        md5,
        password,
        trust,
    }
}

fn limits(max_bytes: usize) -> FetchLimits {
    FetchLimits {
        max_rows: 1_000,
        max_bytes,
        max_value_bytes: 1 << 20,
    }
}

/// The error of a failed connect or query; panics with `what` when the call succeeded.
trait ExpectErr {
    fn expect_err_with(self, what: &str) -> WireError;
}

impl<T> ExpectErr for Result<T, WireError> {
    fn expect_err_with(self, what: &str) -> WireError {
        match self {
            Ok(_) => panic!("{what}"),
            Err(e) => e,
        }
    }
}

/// Compares errors by their Debug text, since WireError has no PartialEq.
#[track_caller]
fn assert_same(actual: &WireError, expected: WireError) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// The nonce the client picked in its SASL initial response (last tagged frame).
fn client_nonce(rec: &[u8]) -> Vec<u8> {
    let frames = tagged(rec, 1);
    let body = frames.last().map(|(_, b)| b.clone()).unwrap_or_default();
    let at = body
        .windows(2)
        .position(|w| w == b"r=")
        .unwrap_or(body.len());
    body[(at + 2).min(body.len())..].to_vec()
}

fn scram_server_first(rec: &[u8]) -> Vec<u8> {
    let mut data = b"r=".to_vec();
    data.extend_from_slice(&client_nonce(rec));
    data.extend_from_slice(b"SERVERNONCE,s=c2FsdHNhbHQ=,i=4096");
    auth_sasl_continue(&data)
}

fn scram_wrong_signature(_rec: &[u8]) -> Vec<u8> {
    let mut data = b"v=".to_vec();
    data.extend_from_slice("A".repeat(43).as_bytes());
    data.push(b'=');
    auth_sasl_final(&data)
}

#[tokio::test]
async fn cleartext_over_plain_tcp_is_refused_and_password_never_sent() {
    let (port, task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_cleartext()),
        Step::ReadTagged,
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("cleartext must be refused");
    assert_eq!(
        err.to_string(),
        "authentication failed: server asked for a cleartext password on an unencrypted connection"
    );
    let recorded = task.await.expect("server task");
    assert!(!contains(&recorded, PASSWORD.as_bytes()), "password sent");
    assert!(tagged(&recorded, 1).is_empty(), "client sent a message");
}

#[tokio::test]
async fn cleartext_refused_when_policy_omits_password() {
    let (port, task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_cleartext()),
        Step::ReadTagged,
    ])
    .await;
    let policy = pol(true, true, false, true);
    let err = Connection::connect_with(&cfg(port), &policy)
        .await
        .expect_err_with("cleartext must be refused");
    assert!(matches!(err, WireError::Auth(_)), "{err:?}");
    let recorded = task.await.expect("server task");
    assert!(!contains(&recorded, PASSWORD.as_bytes()), "password sent");
}

#[tokio::test]
async fn md5_challenge_refused_by_default_without_response() {
    let (port, task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_md5([1, 2, 3, 4])),
        Step::ReadTagged,
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("md5 must be refused by default");
    assert_eq!(
        err.to_string(),
        "authentication failed: the server asked for MD5 authentication, which is not allowed here (require_auth)"
    );
    let recorded = task.await.expect("server task");
    assert!(tagged(&recorded, 1).is_empty(), "client answered md5");
    assert!(!contains(&recorded, PASSWORD.as_bytes()), "password sent");
}

#[tokio::test]
async fn md5_challenge_answered_when_policy_allows_it() {
    // Expected: "md5" + md5(md5(password || user) || salt), computed with Python's hashlib.
    let expected = "md52021dcc237c9fcc2d7eb7484af91ea4d";
    let mut steps = vec![Step::ReadUntagged, Step::Write(auth_md5([1, 2, 3, 4]))];
    steps.push(Step::ReadTagged);
    steps.extend([
        Step::Write(auth_ok()),
        Step::Write(backend_key_data()),
        Step::Write(ready(b'I')),
    ]);
    let (port, task) = spawn_server(steps).await;
    let policy = pol(true, true, false, true);
    let conn = Connection::connect_with(&cfg(port), &policy).await;
    assert!(conn.is_ok(), "md5 with policy must connect");
    drop(conn);
    let recorded = task.await.expect("server task");
    let sent = tagged(&recorded, 1);
    assert_eq!(sent.len(), 1, "one password message");
    assert_eq!(sent[0].0, b'p');
    let mut want = expected.as_bytes().to_vec();
    want.push(0);
    assert_eq!(sent[0].1, want);
}

#[tokio::test]
async fn scram_without_final_then_ok_is_refused() {
    let (port, task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl(&["SCRAM-SHA-256"])),
        Step::ReadTagged,
        Step::Write(auth_ok()),
        Step::Write(ready(b'I')),
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("ok without proof must fail");
    assert_eq!(
        err.to_string(),
        "authentication failed: the server ended SCRAM authentication without proving its identity"
    );
    let recorded = task.await.expect("server task");
    assert!(!contains(&recorded, PASSWORD.as_bytes()), "password sent");
}

#[tokio::test]
async fn scram_wrong_server_signature_fails() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl(&["SCRAM-SHA-256"])),
        Step::ReadTagged,
        Step::Reply(scram_server_first),
        Step::ReadTagged,
        Step::Reply(scram_wrong_signature),
        Step::Write(auth_ok()),
        Step::Write(ready(b'I')),
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("wrong signature must fail");
    assert_same(&err, WireError::Auth("SCRAM verification error".into()));
}

#[tokio::test]
async fn scram_offer_without_scram_sha_256_is_refused() {
    for offered in [vec!["SCRAM-SHA-256-PLUS"], vec!["OAUTHBEARER", "PLAIN"]] {
        let (port, task) = spawn_server(vec![
            Step::ReadUntagged,
            Step::Write(auth_sasl(&offered)),
            Step::ReadTagged,
        ])
        .await;
        let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
            .await
            .expect_err_with("unsupported mechanisms must fail");
        assert_same(
            &err,
            WireError::Auth(
                "server offered no supported SASL mechanism (SCRAM-SHA-256 required)".into(),
            ),
        );
        let recorded = task.await.expect("server task");
        assert!(tagged(&recorded, 1).is_empty(), "{offered:?}: client sent");
    }
}

#[tokio::test]
async fn scram_refused_when_policy_forbids_it() {
    let (port, task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl(&["SCRAM-SHA-256"])),
        Step::ReadTagged,
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &pol(false, false, false, true))
        .await
        .expect_err_with("SCRAM must be refused");
    assert_same(
        &err,
        WireError::Auth(
            "the server asked for SCRAM-SHA-256 authentication, which is not allowed here (require_auth)"
                .into(),
        ),
    );
    let recorded = task.await.expect("server task");
    assert!(tagged(&recorded, 1).is_empty(), "client sent a message");
}

#[tokio::test]
async fn sasl_continue_or_final_without_start_is_refused() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl_continue(b"r=x")),
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("continue without start must fail");
    assert_same(
        &err,
        WireError::Protocol("SASL continue without SASL start".into()),
    );
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl_final(b"v=AAAA")),
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("final without start must fail");
    assert_same(
        &err,
        WireError::Protocol("SASL final without SASL start".into()),
    );
}

#[tokio::test]
async fn second_sasl_start_is_refused() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_sasl(&["SCRAM-SHA-256"])),
        Step::ReadTagged,
        Step::Write(auth_sasl(&["SCRAM-SHA-256"])),
    ])
    .await;
    let err = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect_err_with("second start must fail");
    assert_same(
        &err,
        WireError::Protocol("SASL start received twice".into()),
    );
}

#[tokio::test]
async fn trust_is_accepted_by_default() {
    let mut steps = vec![Step::ReadUntagged];
    steps.extend([
        Step::Write(auth_ok()),
        Step::Write(backend_key_data()),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let _conn = Connection::connect_with(&cfg(port), &AuthPolicy::default())
        .await
        .expect("trust by default");
}

#[tokio::test]
async fn trust_is_refused_when_policy_allows_scram_only() {
    let (port, _task) = spawn_server(startup_ok()).await;
    let scram_only = pol(true, false, false, false);
    let err = Connection::connect_with(&cfg(port), &scram_only)
        .await
        .expect_err_with("trust must be refused");
    assert_same(
        &err,
        WireError::Auth(
            "the server asked for trust authentication, which is not allowed here (require_auth)"
                .into(),
        ),
    );
}

#[tokio::test]
async fn ssl_require_refused_by_plain_server_answer_n() {
    let (port, _task) = spawn_server(vec![Step::ReadUntagged, Step::Write(b"N".to_vec())]).await;
    let mut c = cfg(port);
    c.ssl_mode = SslMode::Require;
    let err = Connection::connect(&c).await.expect_err_with("must fail");
    assert_same(&err, WireError::Tls("server does not support TLS".into()));
}

#[tokio::test]
async fn ssl_answer_s_with_plaintext_in_same_packet_is_refused() {
    let mut answer = b"S".to_vec();
    answer.extend_from_slice(&ready(b'I'));
    let (port, _task) = spawn_server(vec![Step::ReadUntagged, Step::Write(answer)]).await;
    let mut c = cfg(port);
    c.ssl_mode = SslMode::Require;
    let err = Connection::connect(&c).await.expect_err_with("must fail");
    assert_same(
        &err,
        WireError::Tls("unexpected data after the SSL response".into()),
    );
}

#[tokio::test]
async fn ssl_garbage_answer_is_refused() {
    let (port, _task) = spawn_server(vec![Step::ReadUntagged, Step::Write(b"X".to_vec())]).await;
    let mut c = cfg(port);
    c.ssl_mode = SslMode::Prefer;
    let err = Connection::connect(&c).await.expect_err_with("must fail");
    assert_same(
        &err,
        WireError::Protocol("unexpected answer to SSLRequest 'X'".into()),
    );
}

#[tokio::test]
async fn silent_server_hits_connect_timeout() {
    let (port, _task) = spawn_server(vec![Step::Sleep(Duration::from_secs(8))]).await;
    let mut c = cfg(port);
    c.connect_timeout = Duration::from_secs(1);
    let start = Instant::now();
    let err = Connection::connect(&c)
        .await
        .expect_err_with("must time out");
    assert_same(&err, WireError::Timeout);
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn oversized_header_on_non_datarow_is_protocol_error() {
    let mut steps = startup_ok();
    steps.push(Step::ReadTagged);
    steps.push(Step::Write(vec![b'E', 0x7f, 0xff, 0xff, 0xff]));
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .simple_query("SELECT 1")
        .await
        .expect_err_with("must fail");
    assert_same(
        &err,
        WireError::Protocol("message 'E' of 2147483647 bytes is too large".into()),
    );
    assert!(conn.is_poisoned());
}

#[tokio::test]
async fn copy_responses_after_execute_poison_and_send_no_copy_data() {
    for reply in [copy_out(), copy_in(), copy_both()] {
        let mut steps = startup_ok();
        steps.extend(describe_one_int4());
        steps.extend([
            Step::ReadTagged,
            Step::ReadTagged,
            Step::ReadTagged,
            Step::Write(bind_complete()),
            Step::Write(reply),
            Step::Drain(Duration::from_millis(300)),
        ]);
        let (port, task) = spawn_server(steps).await;
        let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
        let err = conn
            .query("SELECT 1", &[], false, &limits(1 << 20))
            .await
            .expect_err_with("copy must be refused");
        assert!(matches!(err, WireError::Protocol(_)), "{err:?}");
        assert!(conn.is_poisoned());
        let recorded = task.await.expect("server task");
        let tags: Vec<u8> = tagged(&recorded, 1).iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, b"PDSBES".to_vec(), "client sent after copy response");
    }
}

fn copy_out() -> Vec<u8> {
    frame(b'H', &copy_body())
}

fn copy_in() -> Vec<u8> {
    frame(b'G', &copy_body())
}

fn copy_both() -> Vec<u8> {
    frame(b'W', &copy_body())
}

#[tokio::test]
async fn startup_error_28p01_is_db_error_without_password() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(error_response(
            "28P01",
            "password authentication failed for user \"app\"",
        )),
    ])
    .await;
    let err = Connection::connect(&cfg(port))
        .await
        .expect_err_with("must fail");
    match &err {
        WireError::Db(e) => assert_eq!(
            e,
            &DbError {
                severity: "FATAL".into(),
                code: "28P01".into(),
                message: "password authentication failed for user \"app\"".into(),
                detail: None,
                hint: None,
                position: None,
            }
        ),
        other => panic!("expected Db error, got {other:?}"),
    }
    assert!(!err.to_string().contains(PASSWORD));
}

#[tokio::test]
async fn standard_conforming_strings_off_mid_session_poisons() {
    let mut steps = startup_ok();
    steps.extend([
        Step::ReadTagged,
        Step::Write(parameter_status("standard_conforming_strings", "off")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .simple_query("SELECT 1")
        .await
        .expect_err_with("must fail");
    assert_same(
        &err,
        WireError::Protocol("server changed standard_conforming_strings to \"off\"".into()),
    );
    assert!(conn.is_poisoned());
}

#[tokio::test]
async fn client_encoding_not_utf8_mid_session_poisons() {
    let mut steps = startup_ok();
    steps.extend([
        Step::ReadTagged,
        Step::Write(parameter_status("client_encoding", "LATIN1")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .simple_query("SELECT 1")
        .await
        .expect_err_with("must fail");
    assert_same(
        &err,
        WireError::Protocol("server changed client_encoding to \"LATIN1\"".into()),
    );
    assert!(conn.is_poisoned());
}

#[tokio::test]
async fn notice_and_notification_between_rows_are_skipped() {
    let mut steps = startup_ok();
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(bind_complete()),
        Step::Write(data_row(&[b"1"])),
        Step::Write(notice_response("a notice")),
        Step::Write(notification_response("chan", "payload")),
        Step::Write(data_row(&[b"2"])),
        Step::Write(command_complete("SELECT 2")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let r = conn
        .query("SELECT 1", &[], false, &limits(1 << 20))
        .await
        .expect("query");
    let values: Vec<Vec<u8>> = r
        .rows
        .iter()
        .map(|row| row[0].as_ref().map(|f| f.data.to_vec()).unwrap_or_default())
        .collect();
    assert_eq!(values, vec![b"1".to_vec(), b"2".to_vec()]);
    assert_eq!(r.truncated, None);
    assert_eq!(r.command_tag.as_deref(), Some("SELECT 2"));
    assert_eq!(r.status, TxStatus::Idle);
    assert!(!conn.is_poisoned());
}

#[tokio::test]
async fn oversized_data_row_keeps_its_prefix_and_stops_at_the_budget() {
    // A 3 MiB value with 1 MiB kept per value and a zero byte budget: the first row is kept and truncated.
    let big = vec![b'x'; 3 << 20];
    let mut steps = startup_ok();
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(bind_complete()),
        Step::Write(data_row(&[big.as_slice()])),
        Step::Write(command_complete("SELECT 1")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let r = conn
        .query("SELECT 1", &[], false, &limits(0))
        .await
        .expect("truncated query");
    assert_eq!(r.rows.len(), 1);
    let field = r.rows[0][0].as_ref().expect("value");
    assert_eq!(field.data.len(), 1 << 20);
    assert_eq!(field.full_len, 3 << 20);
    assert_eq!(r.truncated, Some(Truncation::Bytes));
    assert_eq!(r.command_tag, None);
    assert_eq!(r.status, TxStatus::Idle);
    assert!(
        conn.peak_message_bytes() <= 1 << 20,
        "{}",
        conn.peak_message_bytes()
    );
    assert!(!conn.is_poisoned());
}

/// Runs the script on the first connection only. The listener closes once that connection is accepted,
/// so a CancelRequest on a second connection is refused.
async fn spawn_server_refusing_cancel(steps: Vec<Step>) -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let task = tokio::spawn(async move {
        let mut recorded = Vec::new();
        let accepted = tokio::time::timeout(TIMEOUT, listener.accept()).await;
        drop(listener);
        if let Ok(Ok((mut sock, _))) = accepted {
            tokio::time::timeout(TIMEOUT, run_steps(&mut sock, steps, &mut recorded))
                .await
                .ok();
        }
        recorded
    });
    (port, task)
}

#[tokio::test]
async fn refused_cancel_after_the_row_cap_still_returns_the_capped_rows() {
    let mut steps = startup_ok();
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(bind_complete()),
        Step::Write(data_row(&[b"1"])),
        Step::Write(data_row(&[b"2"])),
        Step::Write(data_row(&[b"3"])),
        Step::Write(command_complete("SELECT 3")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server_refusing_cancel(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let capped = FetchLimits {
        max_rows: 2,
        max_bytes: 1 << 20,
        max_value_bytes: 1 << 20,
    };
    let r = conn
        .query("SELECT 1", &[], false, &capped)
        .await
        .expect("capped query succeeds when the cancel is refused");
    let values: Vec<Vec<u8>> = r
        .rows
        .iter()
        .map(|row| row[0].as_ref().map(|f| f.data.to_vec()).unwrap_or_default())
        .collect();
    assert_eq!(values, vec![b"1".to_vec(), b"2".to_vec()]);
    assert_eq!(r.truncated, Some(Truncation::Rows));
    assert_eq!(r.command_tag, None);
    assert_eq!(r.status, TxStatus::Idle);
    assert!(!conn.is_poisoned());
}

#[tokio::test]
async fn refused_cancel_and_a_dropped_drain_fail_and_poison() {
    let mut steps = startup_ok();
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(bind_complete()),
        Step::Write(data_row(&[b"1"])),
        Step::Write(data_row(&[b"2"])),
        Step::Write(data_row(&[b"3"])),
    ]);
    let (port, _task) = spawn_server_refusing_cancel(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let capped = FetchLimits {
        max_rows: 2,
        max_bytes: 1 << 20,
        max_value_bytes: 1 << 20,
    };
    let err = conn
        .query("SELECT 1", &[], false, &capped)
        .await
        .expect_err_with("the drain hits EOF before ReadyForQuery");
    assert!(matches!(err, WireError::Io(_)), "{err:?}");
    assert!(conn.is_poisoned());
}

/// A statement cancelled by the server after the limit, with a message in French: a timeout, not a cancel.
#[tokio::test]
async fn localized_57014_after_the_statement_limit_is_a_timeout() {
    let mut steps = startup_ok();
    // The session check: BEGIN READ ONLY, three SET LOCAL lines, then the check row.
    let check_values: [&[u8]; 8] = [
        b"on",
        b"ISO, MDY",
        b"iso_8601",
        b"UTC",
        b"hex",
        b"on",
        b"UTF8",
        b"true",
    ];
    steps.extend([
        Step::ReadTagged,
        Step::Write(command_complete("BEGIN")),
        Step::Write(command_complete("SET")),
        Step::Write(command_complete("SET")),
        Step::Write(command_complete("SET")),
        Step::Write(row_description(&[
            ("a", 25),
            ("b", 25),
            ("c", 25),
            ("d", 25),
            ("e", 25),
            ("f", 25),
            ("g", 25),
            ("h", 25),
        ])),
        Step::Write(data_row(&check_values)),
        Step::Write(command_complete("SELECT 1")),
        Step::Write(ready(b'T')),
    ]);
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Sleep(Duration::from_millis(300)),
        Step::Write(bind_complete()),
        Step::Write(error_response(
            "57014",
            "annulation de la requête à cause du délai écoulé pour l'exécution de l'instruction",
        )),
        Step::Write(ready(b'E')),
        Step::ReadTagged,
        Step::Write(command_complete("ROLLBACK")),
        Step::Write(ready(b'I')),
        Step::ReadTagged,
        Step::Write(command_complete("DISCARD ALL")),
        Step::Write(ready(b'I')),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let pool = Pool::new(cfg(port), 1);
    let settings = SessionSettings {
        statement_timeout_ms: 200,
        lock_timeout_ms: 1_000,
        fetch: limits(1 << 20),
        pool_wait: TIMEOUT,
        search_path_catalog_only: false,
    };
    let err = run_readonly(
        &pool,
        "SELECT 1",
        &[],
        false,
        &settings,
        &CancellationToken::new(),
    )
    .await
    .expect_err("the server cancelled the statement");
    assert!(matches!(err, RunError::Timeout(200)), "{err:?}");
    assert!(matches!(
        ToolError::from_run(err, "appdb", 0),
        ToolError::Timeout(200)
    ));
}

#[tokio::test]
async fn data_row_field_longer_than_the_message_is_protocol_error_and_poisons() {
    // One field declares 100 bytes, but the message holds 10 after its length word.
    let mut body = 1u16.to_be_bytes().to_vec();
    body.extend_from_slice(&100i32.to_be_bytes());
    body.extend_from_slice(b"0123456789");
    let mut steps = startup_ok();
    steps.extend(describe_one_int4());
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(bind_complete()),
        Step::Write(frame(b'D', &body)),
    ]);
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .query("SELECT 1", &[], false, &limits(1 << 20))
        .await
        .expect_err("bad row");
    assert_same(
        &err,
        WireError::Protocol("data row field is longer than the message".into()),
    );
    assert!(conn.is_poisoned());
}

/// Startup with an MD5 challenge, then the password is accepted: AuthenticationOk and ReadyForQuery.
fn md5_accepted_steps() -> Vec<Step> {
    vec![
        Step::ReadUntagged,
        Step::Write(auth_md5([1, 2, 3, 4])),
        Step::ReadTagged,
        Step::Write(auth_ok()),
        Step::Write(backend_key_data()),
        Step::Write(ready(b'I')),
    ]
}

/// The MD5 password is accepted, the session check is answered with an error: the auth step is over.
fn md5_accepted_then_session_refused() -> Vec<Step> {
    let mut steps = md5_accepted_steps();
    steps.extend([
        Step::ReadTagged,
        Step::Write(error_response(
            "0A000",
            "fake server reached the session check",
        )),
        Step::Write(ready(b'I')),
    ]);
    steps
}

#[tokio::test]
async fn pool_with_md5_policy_answers_md5_challenge() {
    // Same expected hash as md5_challenge_answered_when_policy_allows_it (salt 1,2,3,4).
    let (port, task) = spawn_server(md5_accepted_steps()).await;
    let pool = Pool::with_auth(cfg(port), 1, pol(true, true, false, true));
    let lease = pool
        .checkout(TIMEOUT)
        .await
        .expect("pool with md5 policy must connect");
    drop(lease);
    let recorded = task.await.expect("server task");
    let sent = tagged(&recorded, 1);
    assert_eq!(sent.len(), 1, "one password message");
    assert_eq!(sent[0].0, b'p');
    let mut want = b"md52021dcc237c9fcc2d7eb7484af91ea4d".to_vec();
    want.push(0);
    assert_eq!(sent[0].1, want);
}

#[tokio::test]
async fn default_pool_refuses_md5_challenge() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_md5([1, 2, 3, 4])),
    ])
    .await;
    let pool = Pool::new(cfg(port), 1);
    match pool.checkout(TIMEOUT).await {
        Err(PoolError::Connect(text)) => assert_eq!(text, "authentication failed"),
        Err(other) => panic!("expected a connect refusal, got {other:?}"),
        Ok(_) => panic!("the default pool answered an MD5 challenge"),
    }
}

/// A PG_DATABASES entry on the fake server, with `require_auth` set when given.
fn fake_entry(port: u16, require_auth: Option<&str>) -> serde_json::Value {
    let mut entry = db_entry("fake", port);
    if let Some(methods) = require_auth {
        entry["require_auth"] = json!(methods);
    }
    entry
}

#[tokio::test]
async fn list_databases_with_require_auth_md5_reaches_the_session_check() {
    let (port, _task) = spawn_server(md5_accepted_then_session_refused()).await;
    let app = app(config_with(&[fake_entry(port, Some("md5"))], &[]));
    let response = call_tool(&app, "list_databases", json!({})).await;
    let database = &result_of(&response)["structuredContent"]["databases"][0];
    assert_eq!(database["reachable"], json!(false), "{database}");
    assert_eq!(
        database["error"],
        json!("PostgreSQL error 0A000: fake server reached the session check"),
        "{database}"
    );
}

#[tokio::test]
async fn list_databases_without_require_auth_refuses_md5() {
    let (port, _task) = spawn_server(vec![
        Step::ReadUntagged,
        Step::Write(auth_md5([1, 2, 3, 4])),
    ])
    .await;
    let app = app(config_with(&[fake_entry(port, None)], &[]));
    let response = call_tool(&app, "list_databases", json!({})).await;
    let database = &result_of(&response)["structuredContent"]["databases"][0];
    assert_eq!(database["reachable"], json!(false), "{database}");
    assert_eq!(
        database["error"],
        json!("Database \"fake\" is unavailable: authentication failed"),
        "{database}"
    );
}

/// The tagged frontend messages the client sent, after its untagged startup message.
fn client_tags(recorded: &[u8]) -> Vec<u8> {
    let mut tags = Vec::new();
    let mut at = u32::from_be_bytes([recorded[0], recorded[1], recorded[2], recorded[3]]) as usize;
    while at + 5 <= recorded.len() {
        tags.push(recorded[at]);
        let len = u32::from_be_bytes([
            recorded[at + 1],
            recorded[at + 2],
            recorded[at + 3],
            recorded[at + 4],
        ]) as usize;
        at += 1 + len;
    }
    tags
}

/// Preflight answered as one statement that returns rows: ParseComplete, RowDescription, ReadyForQuery 'T'.
fn explain_preflight_ok() -> Vec<Step> {
    vec![
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(parse_complete()),
        Step::Write(parameter_description(&[])),
        Step::Write(row_description(&[("QUERY PLAN", 25)])),
        Step::Write(ready(b'T')),
    ]
}

#[tokio::test]
async fn explain_preflight_error_sends_no_query_message() {
    let mut steps = startup_ok();
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(error_response(
            "42601",
            "cannot insert multiple commands into a prepared statement",
        )),
        Step::Write(ready(b'E')),
    ]);
    let (port, task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .explain_unbound("EXPLAIN SELECT 1; CREATE TABLE t()", 1 << 20)
        .await
        .expect_err("preflight refused");
    assert!(
        matches!(err, WireError::Db(ref db) if db.code == "42601"),
        "{err:?}"
    );
    assert!(!conn.is_poisoned());
    let recorded = task.await.expect("server task");
    assert_eq!(client_tags(&recorded), vec![b'P', b'D', b'S']);
    assert!(!client_tags(&recorded).contains(&b'Q'));
}

#[tokio::test]
async fn explain_preflight_without_row_description_sends_no_query_message() {
    let mut steps = startup_ok();
    steps.extend([
        Step::ReadTagged,
        Step::ReadTagged,
        Step::ReadTagged,
        Step::Write(parse_complete()),
        Step::Write(parameter_description(&[])),
        Step::Write(frame(b'n', &[])),
        Step::Write(ready(b'T')),
    ]);
    let (port, task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .explain_unbound("CREATE TABLE t()", 1 << 20)
        .await
        .expect_err("no rows");
    assert_same(
        &err,
        WireError::Protocol("unexpected response to the explain preflight".into()),
    );
    assert!(conn.is_poisoned());
    let recorded = task.await.expect("server task");
    assert!(!client_tags(&recorded).contains(&b'Q'));
}

#[tokio::test]
async fn explain_returns_the_plan_rows_after_a_clean_preflight() {
    let mut steps = startup_ok();
    steps.extend(explain_preflight_ok());
    steps.extend([
        Step::ReadTagged,
        Step::Write(row_description(&[("QUERY PLAN", 25)])),
        Step::Write(data_row(&[b"Result  (cost=0.00..0.01 rows=1 width=4)"])),
        Step::Write(command_complete("EXPLAIN")),
        Step::Write(ready(b'T')),
    ]);
    let (port, task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let r = conn
        .explain_unbound("EXPLAIN SELECT 1", 1 << 20)
        .await
        .expect("plan");
    assert_eq!(r.rows.len(), 1);
    let field = r.rows[0][0].as_ref().expect("line");
    assert_eq!(
        field.data,
        Bytes::from_static(b"Result  (cost=0.00..0.01 rows=1 width=4)")
    );
    assert_eq!(r.command_tag.as_deref(), Some("EXPLAIN"));
    assert_eq!(r.status, TxStatus::InTransaction);
    assert!(!conn.is_poisoned());
    let recorded = task.await.expect("server task");
    assert_eq!(client_tags(&recorded), vec![b'P', b'D', b'S', b'Q']);
}

/// Preflight passes, then the simple query is answered with `answer`.
async fn explain_with_answer(answer: Vec<Vec<u8>>) -> (Result<QueryResult, WireError>, bool) {
    let mut steps = startup_ok();
    steps.extend(explain_preflight_ok());
    steps.push(Step::ReadTagged);
    steps.extend(answer.into_iter().map(Step::Write));
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let result = conn.explain_unbound("EXPLAIN SELECT 1", 1 << 20).await;
    let poisoned = conn.is_poisoned();
    (result, poisoned)
}

#[tokio::test]
async fn explain_two_command_completes_is_protocol_error_and_poisons() {
    let answer = vec![
        row_description(&[("QUERY PLAN", 25)]),
        data_row(&[b"one"]),
        command_complete("EXPLAIN"),
        command_complete("EXPLAIN"),
        ready(b'T'),
    ];
    let (result, poisoned) = explain_with_answer(answer).await;
    assert_same(
        &result.expect_err("two tags"),
        WireError::Protocol("unexpected response to the explain query".into()),
    );
    assert!(poisoned);
}

#[tokio::test]
async fn explain_ready_idle_after_the_plan_is_protocol_error_and_poisons() {
    let answer = vec![
        row_description(&[("QUERY PLAN", 25)]),
        command_complete("EXPLAIN"),
        ready(b'I'),
    ];
    let (result, poisoned) = explain_with_answer(answer).await;
    assert_same(
        &result.expect_err("idle"),
        WireError::Protocol("unexpected response to the explain query".into()),
    );
    assert!(poisoned);
}

#[tokio::test]
async fn explain_other_command_tag_is_protocol_error_and_poisons() {
    let answer = vec![
        row_description(&[("QUERY PLAN", 25)]),
        command_complete("SELECT 1"),
        ready(b'T'),
    ];
    let (result, poisoned) = explain_with_answer(answer).await;
    assert_same(
        &result.expect_err("tag"),
        WireError::Protocol("unexpected response to the explain query".into()),
    );
    assert!(poisoned);
}

#[tokio::test]
async fn explain_empty_query_response_is_protocol_error_and_poisons() {
    let answer = vec![
        row_description(&[("QUERY PLAN", 25)]),
        frame(b'I', &[]),
        command_complete("EXPLAIN"),
        ready(b'T'),
    ];
    let (result, poisoned) = explain_with_answer(answer).await;
    assert_same(
        &result.expect_err("empty"),
        WireError::Protocol("unexpected response to the explain query".into()),
    );
    assert!(poisoned);
}

#[tokio::test]
async fn explain_plan_over_the_byte_cap_is_refused_and_poisons() {
    let big = vec![b'p'; 2048];
    let answer = vec![
        row_description(&[("QUERY PLAN", 25)]),
        data_row(&[&big]),
        data_row(&[&big]),
        command_complete("EXPLAIN"),
        ready(b'T'),
    ];
    let mut steps = startup_ok();
    steps.extend(explain_preflight_ok());
    steps.push(Step::ReadTagged);
    steps.extend(answer.into_iter().map(Step::Write));
    let (port, _task) = spawn_server(steps).await;
    let mut conn = Connection::connect(&cfg(port)).await.expect("connect");
    let err = conn
        .explain_unbound("EXPLAIN SELECT 1", 3000)
        .await
        .expect_err("too large");
    assert_same(&err, WireError::Refused("plan too large".into()));
    assert!(conn.is_poisoned());
}
