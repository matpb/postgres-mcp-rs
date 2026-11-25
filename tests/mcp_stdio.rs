//! Integration tests for the stdio transport and the command line, run against the built binary.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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

/// A loopback port that was free a moment ago: bound to port 0, read, and released.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a free loopback port");
    listener.local_addr().expect("local address").port()
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
        "postgres-mcp 0.1.5\n"
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

/// Exit status of `healthcheck` on `port` with MCP_HOST set to `host`.
fn healthcheck_on(host: &str, port: u16) -> ExitStatus {
    command(&["healthcheck"])
        .env("MCP_HOST", host)
        .env("MCP_PORT", port.to_string())
        .status()
        .expect("healthcheck runs")
}

#[test]
fn healthcheck_probes_the_mcp_host_address() {
    if std::net::TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipping: this machine has no IPv6 loopback address");
        return;
    }
    for _ in 0..5 {
        let port = free_port();
        let mut server = command(&["http"])
            .env("DATABASE_URL", database_url(PORT_19))
            .env("MCP_HOST", "::1")
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
            if healthcheck_on("::1", port).success() {
                healthy = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let _ = server.kill();
        let _ = server.wait();
        if healthy {
            return;
        }
        assert!(exited, "server on [::1]:{port} never answered /health");
    }
    panic!("no free port answered within 5 attempts");
}

/// Runs `http` with DATABASE_URL carrying the given sslrootcert and returns its exit code and stderr.
/// A server that starts instead of failing is killed and reported.
fn startup_with_root_cert(root_cert: &str) -> (Option<i32>, String) {
    let url = format!(
        "postgres://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{PORT_19}/{DB_NAME}?sslmode=verify-full&sslrootcert={root_cert}"
    );
    startup_with_url(&url)
}

/// Runs `http` with the given DATABASE_URL and returns its exit code and stderr.
/// A server that starts instead of failing is killed and reported.
fn startup_with_url(url: &str) -> (Option<i32>, String) {
    let mut child = command(&["http"])
        .env("DATABASE_URL", url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let Some(status) = wait_with_timeout(&mut child, Duration::from_secs(10)) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("the server started instead of failing its configuration check");
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)
            .expect("stderr is readable");
    }
    (status.code(), stderr.trim_end().to_owned())
}

#[test]
fn nonexistent_sslrootcert_fails_startup_with_exit_2() {
    let (code, stderr) = startup_with_root_cert("/nonexistent/pgmcp-ca.pem");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(
        stderr,
        "configuration error: appdb: cannot read sslrootcert: No such file or directory (os error 2)"
    );
}

#[test]
fn sslrootcert_without_certificates_fails_startup_with_exit_2() {
    let path = std::env::temp_dir().join(format!("pgmcp-no-certs-{}.pem", std::process::id()));
    std::fs::write(&path, "not a certificate\n").expect("write the test file");
    let (code, stderr) = startup_with_root_cert(&path.to_string_lossy());
    std::fs::remove_file(&path).expect("remove the test file");
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(
        stderr,
        "configuration error: appdb: sslrootcert holds no certificate"
    );
}

#[test]
fn sslrootcert_with_sslmode_require_fails_startup_with_exit_2() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let url = format!(
        "postgres://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{PORT_19}/{DB_NAME}?sslmode=require&sslrootcert={root}"
    );
    let (code, stderr) = startup_with_url(&url);
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(
        stderr,
        "configuration error: DATABASE_URL: sslrootcert is set but sslmode=require does not verify the server; use sslmode=verify-ca or sslmode=verify-full"
    );
}

#[test]
fn sslrootcert_with_sslmode_disable_fails_startup_with_exit_2() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");
    let url = format!(
        "postgres://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{PORT_19}/{DB_NAME}?sslmode=disable&sslrootcert={root}"
    );
    let (code, stderr) = startup_with_url(&url);
    assert_eq!(code, Some(2), "{stderr}");
    assert_eq!(
        stderr,
        "configuration error: DATABASE_URL: sslrootcert is set but sslmode=disable does not use TLS; use sslmode=verify-ca or sslmode=verify-full"
    );
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
    for _ in 0..5 {
        let port = free_port();
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
fn stdio_resources_list_and_read_round_trip() {
    let mut child = command(&["stdio"])
        .env("DATABASE_URL", database_url(PORT_19))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let mut stderr = child.stderr.take().expect("stderr is piped");
    let stderr_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = stderr.read_to_string(&mut text);
        text
    });

    let messages = [
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        json!({"jsonrpc": "2.0", "id": 2, "method": "resources/list"}),
        json!({"jsonrpc": "2.0", "id": 3, "method": "resources/read", "params": {"uri": "postgres://appdb"}}),
    ];
    for message in &messages {
        writeln!(stdin, "{message}").expect("request is written");
    }
    stdin.flush().expect("request is flushed");
    drop(stdin);

    let mut output = String::new();
    stdout
        .read_to_string(&mut output)
        .expect("stdout is readable");
    let stderr = stderr_reader.join().expect("stderr reader finishes");
    let status = wait_with_timeout(&mut child, Duration::from_secs(5));
    assert!(status.is_some_and(|s| s.success()), "{stderr}");

    let replies: Vec<Value> = output
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("stdout line is not JSON: {line}: {e}"))
        })
        .collect();
    let reply = |id: u64| {
        replies
            .iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("no reply {id} in {output}"))
            .clone()
    };
    let listed = &reply(2)["result"]["resources"];
    assert_eq!(listed[0]["uri"], "postgres://appdb", "{output}");
    assert_eq!(listed[0]["mimeType"], "application/json", "{output}");

    let read = reply(3);
    let text = read["result"]["contents"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text in {read}"));
    let summary: Value = serde_json::from_str(text).expect("summary is JSON");
    assert_eq!(
        summary["serverVersionNum"].as_u64().map(|n| n / 10_000),
        Some(19)
    );

    let audit_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("audit") && l.contains("tool=\"resource:database\""))
        .collect();
    assert_eq!(audit_lines.len(), 1, "{stderr}");
    assert!(audit_lines[0].contains("ok=true"), "{}", audit_lines[0]);
    assert!(
        audit_lines[0].contains("database=\"appdb\""),
        "{}",
        audit_lines[0]
    );
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
/// Starts the HTTP server on a free port. A child that exits at once, such as on a bind race, is retried on another port.
fn spawn_http_free_port(extra: &[(&str, &str)]) -> (Child, mpsc::Receiver<String>, u16) {
    for _ in 0..5 {
        let port = free_port();
        let (mut child, receiver) = spawn_http(port, extra);
        thread::sleep(Duration::from_millis(500));
        if child.try_wait().expect("child can be polled").is_none() {
            return (child, receiver, port);
        }
    }
    panic!("the HTTP server exited on five different ports");
}

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
    let (mut child, receiver, _port) = spawn_http_free_port(&[("MCP_HOST", "0.0.0.0")]);
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
    let key = ("API_KEY", "test-only-api-key-0123456789");
    let (mut child, receiver, _port) = spawn_http_free_port(&[("MCP_HOST", "0.0.0.0"), key]);
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
    let (mut child, receiver, port) = spawn_http_free_port(&[]);
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

fn init_messages() -> Vec<Value> {
    vec![
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": PROTOCOL_2025, "capabilities": {}, "clientInfo": {"name": "test-client", "version": "0.0.0"}}}),
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    ]
}

/// Runs `stdio` with JSON logs and the given variables, sends the messages, and returns stderr.
fn stdio_stderr(env: &[(&str, &str)], messages: &[Value]) -> String {
    let mut cmd = command(&["stdio"]);
    cmd.env("LOG_FORMAT", "json")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    for (key, value) in env {
        cmd.env(key, value);
    }
    let mut child = cmd.spawn().expect("binary starts");
    let mut stdin = child.stdin.take().expect("stdin is piped");
    for message in messages {
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
    let status = wait_with_timeout(&mut child, Duration::from_secs(10));
    assert!(status.is_some_and(|s| s.success()), "{stderr}");
    stderr
}

/// Each stderr line parsed as a JSON object; every line must be one.
fn json_lines(stderr: &str) -> Vec<Value> {
    stderr
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("not JSON: {l}: {e}")))
        .collect()
}

#[test]
fn connection_failure_log_names_the_connection_not_the_user_or_password() {
    let databases = json!([{
        "name": "bad_conn",
        "host": "127.0.0.1",
        "port": PORT_19,
        "database": DB_NAME,
        "user": DB_USER,
        "password": "not-the-password-zz",
        "sslmode": "disable",
        "max_connections": 1,
    }]);
    let mut messages = init_messages();
    messages.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"database": "bad_conn", "sql": "SELECT 1"}}}));
    let stderr = stdio_stderr(&[("PG_DATABASES", &databases.to_string())], &messages);
    let failure = json_lines(&stderr)
        .into_iter()
        .find(|l| l["fields"]["message"] == "connection failed")
        .unwrap_or_else(|| panic!("no connection failure line in {stderr}"));
    assert_eq!(failure["fields"]["connection"], "bad_conn", "{failure}");
    assert_eq!(failure["fields"]["host"], "127.0.0.1", "{failure}");
    assert_eq!(failure["fields"]["port"], PORT_19, "{failure}");
    assert_eq!(
        failure["fields"]["reason"], "authentication failed",
        "{failure}"
    );
    for secret in [DB_USER, DB_PASSWORD, "not-the-password-zz"] {
        assert!(!stderr.contains(secret), "{secret} was logged: {stderr}");
    }
}

#[test]
fn connection_failure_log_carries_the_postgresql_message_with_sqlstate() {
    let databases = json!([{
        "name": "bad_conn",
        "host": "127.0.0.1",
        "port": PORT_19,
        "database": DB_NAME,
        "user": DB_USER,
        "password": "not-the-password-zz",
        "sslmode": "disable",
        "max_connections": 1,
    }]);
    let mut messages = init_messages();
    messages.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"database": "bad_conn", "sql": "SELECT 1"}}}));
    let stderr = stdio_stderr(&[("PG_DATABASES", &databases.to_string())], &messages);
    let failure = json_lines(&stderr)
        .into_iter()
        .find(|l| l["fields"]["message"] == "connection failed")
        .unwrap_or_else(|| panic!("no connection failure line in {stderr}"));
    assert_eq!(
        failure["fields"]["error"],
        "password authentication failed for user \"<user>\" (SQLSTATE 28P01)",
        "{failure}"
    );
    assert!(!stderr.contains("not-the-password-zz"), "{stderr}");
}

const SUPERUSER_WARNING: &str = "database \"appdb\": the role is a superuser; the read-only transaction is then the only barrier against the functions it may call. Use a least-privilege role.";

const DEBUG_WARNING: &str = "debug logging is on: requests and responses, including SQL text and rows, are written to the log";

/// The init handshake and one query on the default database.
fn query_messages() -> Vec<Value> {
    let mut messages = init_messages();
    messages.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 1 AS one"}}}));
    messages
}

fn has_warning(stderr: &str, text: &str) -> bool {
    json_lines(stderr)
        .iter()
        .any(|l| l["level"] == "WARN" && l["fields"]["message"] == text)
}

#[test]
fn superuser_role_logs_one_warning_on_its_first_connection() {
    let url = format!(
        "postgres://postgres:test-only-superuser@127.0.0.1:{PORT_19}/{DB_NAME}?sslmode=disable"
    );
    let stderr = stdio_stderr(&[("DATABASE_URL", &url)], &query_messages());
    let count = json_lines(&stderr)
        .iter()
        .filter(|l| l["fields"]["message"] == SUPERUSER_WARNING)
        .count();
    assert_eq!(count, 1, "{stderr}");
}

#[test]
fn least_privilege_role_logs_no_superuser_warning() {
    let url = database_url(PORT_19);
    let stderr = stdio_stderr(&[("DATABASE_URL", &url)], &query_messages());
    assert!(!stderr.contains("the role is a superuser"), "{stderr}");
}

#[test]
fn debug_log_level_warns_that_requests_and_rows_are_logged() {
    let url = database_url(PORT_19);
    let stderr = stdio_stderr(
        &[("DATABASE_URL", &url), ("LOG_LEVEL", "debug")],
        &init_messages(),
    );
    assert!(has_warning(&stderr, DEBUG_WARNING), "{stderr}");
    let stderr = stdio_stderr(
        &[("DATABASE_URL", &url), ("RUST_LOG", "info,rmcp=trace")],
        &init_messages(),
    );
    assert!(has_warning(&stderr, DEBUG_WARNING), "{stderr}");
}

#[test]
fn info_level_and_rmcp_held_at_warn_log_no_debug_warning() {
    let url = database_url(PORT_19);
    for env in [
        vec![("DATABASE_URL", url.as_str()), ("LOG_LEVEL", "info")],
        vec![
            ("DATABASE_URL", url.as_str()),
            ("LOG_LEVEL", "debug"),
            ("RUST_LOG", "debug,rmcp=warn"),
        ],
    ] {
        let stderr = stdio_stderr(&env, &init_messages());
        assert!(!has_warning(&stderr, DEBUG_WARNING), "{env:?}: {stderr}");
    }
}

#[test]
fn default_log_filter_hides_rmcp_info_and_keeps_the_audit_line() {
    let mut messages = init_messages();
    messages.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 1 AS quiet"}}}));
    let url = database_url(PORT_19);
    let stderr = stdio_stderr(&[("DATABASE_URL", &url)], &messages);
    let lines = json_lines(&stderr);
    let loud_rmcp: Vec<&Value> = lines
        .iter()
        .filter(|l| {
            l["target"].as_str().unwrap_or_default().starts_with("rmcp") && l["level"] == "INFO"
        })
        .collect();
    assert!(loud_rmcp.is_empty(), "rmcp info lines: {loud_rmcp:?}");
    assert!(
        lines.iter().any(|l| l["target"] == "audit"),
        "no audit line in {stderr}"
    );
}

#[test]
fn completion_writes_one_audit_line_with_tool_completion() {
    let mut messages = init_messages();
    messages.push(
        json!({"jsonrpc": "2.0", "id": 2, "method": "completion/complete", "params": {
            "ref": {"type": "ref/resource", "uri": "postgres://{database}/{schema}"},
            "argument": {"name": "schema", "value": ""},
            "context": {"arguments": {"database": "appdb"}},
        }}),
    );
    let url = database_url(PORT_19);
    let stderr = stdio_stderr(&[("DATABASE_URL", &url)], &messages);
    let completions: Vec<Value> = json_lines(&stderr)
        .into_iter()
        .filter(|l| l["target"] == "audit" && l["fields"]["tool"] == "completion")
        .collect();
    assert_eq!(completions.len(), 1, "{stderr}");
}

/// One raw HTTP/1.1 POST to `/mcp` on the loopback port; returns the status code.
fn raw_post(port: u16, target: &str, headers: &[(&str, &str)]) -> u16 {
    use std::net::TcpStream;
    let body = "{}";
    let mut request = format!(
        "POST {target} HTTP/1.1\r\nHost: localhost:{port}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream
        .write_all(request.as_bytes())
        .expect("request is written");
    let mut reply = String::new();
    stream.read_to_string(&mut reply).expect("reply is read");
    reply
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .expect("status line")
}

#[test]
fn http_guard_rejections_log_reason_and_path_but_no_key_or_origin() {
    let key = "fixture-key-0123456789abcdef";
    let (mut child, receiver, port) =
        spawn_http_free_port(&[("API_KEY", key), ("LOG_FORMAT", "json")]);
    assert_eq!(raw_post(port, "/mcp?secret=q1", &[]), 401);
    assert_eq!(
        raw_post(port, "/mcp", &[("X-API-Key", "wrong-key-value-zzzz")]),
        401
    );
    assert_eq!(
        raw_post(
            port,
            "/mcp",
            &[
                ("X-API-Key", key),
                ("Origin", "https://evil.example.org/?k=1")
            ]
        ),
        403
    );
    let seen = lines_until(&receiver, "origin not allowed", Duration::from_secs(5));
    child.kill().expect("server stops");
    let _ = child.wait();
    let stderr = seen.join("\n");
    let lines = json_lines(&stderr);
    for reason in ["missing key", "wrong key", "origin not allowed"] {
        assert!(
            lines
                .iter()
                .any(|l| l["fields"]["reason"] == reason && l["fields"]["path"] == "/mcp"),
            "no {reason} line in {stderr}"
        );
    }
    for secret in [
        key,
        "wrong-key-value-zzzz",
        "evil.example.org",
        "secret=q1",
        "k=1",
    ] {
        assert!(!stderr.contains(secret), "{secret} was logged: {stderr}");
    }
}

#[test]
fn rust_log_wins_over_log_level_and_is_used_verbatim() {
    let mut messages = init_messages();
    messages.push(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "execute_query", "arguments": {"sql": "SELECT 1 AS verbatim"}}}));
    let url = database_url(PORT_19);
    let stderr = stdio_stderr(
        &[
            ("DATABASE_URL", &url),
            ("RUST_LOG", "info"),
            ("LOG_LEVEL", "error"),
        ],
        &messages,
    );
    let lines = json_lines(&stderr);
    assert!(
        lines.iter().any(
            |l| l["target"].as_str().unwrap_or_default().starts_with("rmcp")
                && l["level"] == "INFO"
        ),
        "RUST_LOG=info should show rmcp info lines: {stderr}"
    );
}
