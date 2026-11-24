//! Integration tests for the stdio transport and the command line, run against the built binary.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::{DB_NAME, DB_PASSWORD, DB_USER, PORT_19, PROTOCOL_2025};
use serde_json::{Value, json};
use sha2::Digest;

const BIN: &str = env!("CARGO_BIN_EXE_postgres-mcp");

fn database_url(port: u16) -> String {
    format!("postgres://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{port}/{DB_NAME}?sslmode=disable")
}

/// A binary invocation with the inherited environment cleared, so only what a test sets is visible.
fn command(args: &[&str]) -> Command {
    let mut cmd = Command::new(BIN);
    cmd.args(args).env_clear();
    if let Ok(path) = std::env::var("PATH") {
        cmd.env("PATH", path);
    }
    cmd
}

fn wait_with_timeout(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().expect("child can be polled") {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// A port from the 20000..40000 range, varied by attempt and time.
fn pick_port(attempt: u64) -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let spread = u64::try_from(nanos % 20_000).unwrap_or_default();
    20_000 + u16::try_from(spread.wrapping_add(attempt * 7919) % 20_000).unwrap_or_default()
}

#[test]
fn stdio_serves_json_rpc_and_exits_on_eof() {
    let mut child = command(&["stdio"])
        .env("DATABASE_URL", database_url(PORT_19))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");

    let (sender, receiver) = mpsc::channel::<String>();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 42 AS answer"}}}),
    ];
    for message in &messages {
        writeln!(stdin, "{message}").expect("request is written");
    }
    stdin.flush().expect("request is flushed");

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut answer: Option<Value> = None;
    let mut seen_ids = Vec::new();
    while answer.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = receiver
            .recv_timeout(remaining)
            .expect("a response line arrives within 10 s");
        let value: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("stdout line is not JSON: {line}: {e}"));
        seen_ids.push(value["id"].clone());
        if value["id"] == 3 {
            answer = Some(value);
        }
    }
    assert!(
        seen_ids.contains(&json!(1)) && seen_ids.contains(&json!(2)),
        "{seen_ids:?}"
    );
    let answer = answer.expect("answer was captured");
    let result = &answer["result"];
    assert_eq!(result["isError"], false, "{answer}");
    assert_eq!(result["structuredContent"]["rows"], json!([{"answer": 42}]));

    drop(stdin);
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    let status = status.expect("process exits within 5 s of stdin closing");
    assert!(status.success(), "{status:?}");
    reader.join().expect("stdout reader finishes");
    // Logs may go to stderr; stdout was already checked line by line above.
    stderr_reader.join().expect("stderr reader finishes");
}

#[test]
fn version_flag_prints_version() {
    let output = command(&["--version"]).output().expect("binary runs");
    assert!(output.status.success(), "{:?}", output.status);
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "postgres-mcp 0.1.0\n"
    );
}

#[test]
fn unknown_command_exits_2_with_usage() {
    let output = command(&["bogus"]).output().expect("binary runs");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage"));
}

#[test]
fn http_without_database_is_configuration_error() {
    let output = command(&["http"]).output().expect("binary runs");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration error"), "{stderr}");
}

#[test]
fn healthcheck_fails_on_closed_port() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
    let port = listener.local_addr().expect("local address").port();
    drop(listener);
    let status = command(&["healthcheck"])
        .env("MCP_PORT", port.to_string())
        .status()
        .expect("binary runs");
    assert_eq!(status.code(), Some(1));
}

#[test]
fn healthcheck_passes_against_running_http_server() {
    for attempt in 0..10 {
        let port = pick_port(attempt);
        let mut server = command(&["http"])
            .env("DATABASE_URL", database_url(PORT_19))
            .env("MCP_PORT", port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("server starts");
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut healthy = false;
        let mut exited = false;
        while Instant::now() < deadline {
            if server.try_wait().expect("child can be polled").is_some() {
                exited = true;
                break;
            }
            let probe = command(&["healthcheck"])
                .env("MCP_PORT", port.to_string())
                .status()
                .expect("healthcheck runs");
            if probe.success() {
                healthy = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        // Kill (a no-op when it already exited) and reap the server on every path.
        let _ = server.kill();
        let _ = server.wait();
        if healthy {
            return;
        }
        // An early exit means the port was taken, so the next attempt uses another one.
        assert!(exited, "server on port {port} never answered /health");
    }
    panic!("no free port answered within 10 attempts");
}

#[test]
fn audit_line_per_tool_call_without_sql_text() {
    let sql = "SELECT 42 AS audited";
    let mut child = command(&["stdio"])
        .env("DATABASE_URL", database_url(PORT_19))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": sql}}}),
    ];
    for message in &messages {
        writeln!(stdin, "{message}").expect("request is written");
    }
    drop(stdin);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_string(&mut stderr)
        .expect("stderr is readable");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{stderr}");

    let line = stderr
        .lines()
        .find(|l| l.contains("tool call") && l.contains("audit"))
        .unwrap_or_else(|| panic!("no audit line in {stderr}"));
    assert!(line.contains("tool=\"execute_query\""), "{line}");
    assert!(line.contains("ok=true"), "{line}");
    assert!(line.contains("database=\"appdb\""), "{line}");
    let digest: String = sha2::Sha256::digest(sql.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect();
    assert!(line.contains(&format!("sql_sha256=\"{digest}\"")), "{line}");
    assert!(!stderr.contains("audited"), "SQL text was logged: {stderr}");
}

#[test]
fn log_format_json_writes_only_json_lines_to_stderr() {
    let mut child = command(&["stdio"])
        .env("DATABASE_URL", database_url(PORT_19))
        .env("LOG_FORMAT", "json")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 1 AS fine"}}}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 1/0 AS broken"}}}),
    ];
    for message in &messages {
        writeln!(stdin, "{message}").expect("request is written");
    }
    drop(stdin);
    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("stderr is piped")
        .read_to_string(&mut stderr)
        .expect("stderr is readable");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{stderr}");

    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(!lines.is_empty(), "no log lines were written");
    for line in &lines {
        let parsed: Value = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("stderr line is not JSON: {line}: {e}"));
        assert!(parsed.is_object(), "{line}");
    }
    assert!(lines.iter().any(|l| l.contains("tool call")), "{stderr}");
}

/// Starts `http` on `port` and forwards each stderr line over a channel.
fn spawn_http(port: u16, extra: &[(&str, &str)]) -> (Child, mpsc::Receiver<String>) {
    let mut cmd = command(&["http"]);
    cmd.env("DATABASE_URL", database_url(PORT_19))
        .env("MCP_PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in extra {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("server starts");
    let stderr = child.stderr.take().expect("stderr is piped");
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        for line in BufReader::new(stderr).lines().map_while(Result::ok) {
            if sender.send(line).is_err() {
                break;
            }
        }
    });
    (child, receiver)
}

/// Collects stderr lines until one contains `needle` or `limit` passes; returns everything collected.
fn lines_until(receiver: &mpsc::Receiver<String>, needle: &str, limit: Duration) -> Vec<String> {
    let deadline = Instant::now() + limit;
    let mut seen = Vec::new();
    while let Ok(line) = receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        let hit = line.contains(needle);
        seen.push(line);
        if hit {
            break;
        }
    }
    seen
}

#[test]
fn non_loopback_bind_without_api_key_warns() {
    let port = pick_port(0);
    let (mut child, receiver) = spawn_http(port, &[("MCP_HOST", "0.0.0.0")]);
    let seen = lines_until(
        &receiver,
        "listening on a non-loopback address without an API key",
        Duration::from_secs(5),
    );
    let _ = child.kill();
    let _ = child.wait();
    assert!(
        seen.iter()
            .any(|l| l.contains("listening on a non-loopback address without an API key")),
        "{seen:?}"
    );
}

#[test]
fn non_loopback_bind_with_api_key_does_not_warn() {
    let port = pick_port(1);
    let key = ("API_KEY", "test-only-api-key-0123456789");
    let (mut child, receiver) = spawn_http(port, &[("MCP_HOST", "0.0.0.0"), key]);
    let mut seen = lines_until(&receiver, "serving MCP", Duration::from_secs(10));
    // The warning, when it exists, follows the startup line at once; the pause lets it arrive.
    thread::sleep(Duration::from_millis(500));
    seen.extend(receiver.try_iter());
    let _ = child.kill();
    let _ = child.wait();
    assert!(seen.iter().any(|l| l.contains("serving MCP")), "{seen:?}");
    assert!(!seen.iter().any(|l| l.contains("non-loopback")), "{seen:?}");
}

#[cfg(unix)]
#[test]
fn sigterm_stops_http_with_exit_status_zero() {
    let port = pick_port(2);
    let (mut child, receiver) = spawn_http(port, &[]);
    let seen = lines_until(&receiver, "serving MCP", Duration::from_secs(10));
    assert!(seen.iter().any(|l| l.contains("serving MCP")), "{seen:?}");
    // The listener is up once /health answers; only then is the shutdown handler surely armed.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let probe = command(&["healthcheck"])
            .env("MCP_PORT", port.to_string())
            .status()
            .expect("healthcheck runs");
        if probe.success() {
            break;
        }
        thread::sleep(Duration::from_millis(100));
    }
    let sent = std::process::Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .expect("kill runs");
    assert!(sent.success(), "kill -TERM failed: {sent:?}");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    let status = status.expect("server exits within 5 s of SIGTERM");
    assert_eq!(status.code(), Some(0), "{status:?}");
}

/// The tool names `tools/list` returns from a stdio server whose TOOLSETS is `toolsets`.
fn listed_tool_names(toolsets: &str) -> Vec<String> {
    let mut child = command(&["stdio"])
        .env("DATABASE_URL", database_url(PORT_19))
        .env("TOOLSETS", toolsets)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
    ];
    for message in &messages {
        writeln!(stdin, "{message}").expect("request is written");
    }
    drop(stdin);
    let mut text = String::new();
    stdout
        .read_to_string(&mut text)
        .expect("stdout is readable");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{text}");
    let answer = text
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["id"] == 2)
        .unwrap_or_else(|| panic!("no tools/list answer in {text}"));
    answer["result"]["tools"]
        .as_array()
        .expect("tools is an array")
        .iter()
        .filter_map(|tool| tool["name"].as_str().map(str::to_owned))
        .collect()
}

#[test]
fn each_disabled_toolset_is_absent_and_the_others_are_listed() {
    const CORE: [&str; 4] = [
        "list_databases",
        "execute_query",
        "explain_query",
        "server_info",
    ];
    let groups: [(&str, &[&str]); 4] = [
        (
            "schema",
            &[
                "list_schemas",
                "list_objects",
                "describe_table",
                "describe_function",
                "search_schema",
                "get_privileges",
            ],
        ),
        (
            "monitor",
            &[
                "list_activity",
                "query_stats",
                "database_stats",
                "table_stats",
                "replication_status",
            ],
        ),
        ("logs", &["read_server_log"]),
        (
            "timescale",
            &[
                "list_hypertables",
                "describe_hypertable",
                "list_continuous_aggregates",
                "list_jobs",
            ],
        ),
    ];
    for (disabled, tools) in groups {
        let enabled: Vec<&str> = groups
            .iter()
            .map(|(name, _)| *name)
            .filter(|name| *name != disabled)
            .collect();
        let names = listed_tool_names(&enabled.join(","));
        for tool in tools {
            assert!(
                !names.iter().any(|n| n == tool),
                "{disabled} is disabled but {tool} is listed: {names:?}"
            );
        }
        for tool in CORE {
            assert!(
                names.iter().any(|n| n == tool),
                "core {tool} missing: {names:?}"
            );
        }
        for (name, group) in groups.iter().filter(|(name, _)| *name != disabled) {
            for tool in group.iter() {
                assert!(
                    names.iter().any(|n| n == tool),
                    "{name} is enabled but {tool} is missing: {names:?}"
                );
            }
        }
    }
}
