//! Command line, shared state, HTTP router, stdio serving and the local health check.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderName, HeaderValue, Method};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::get;
use rmcp::transport::streamable_http_server::session::never::NeverSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, ConfigError, DatabaseConfig, LogFormat};
use crate::http_guard::{ApiKey, GuardState};
use crate::pg::pool::Pool;
use crate::tools::{PgMcp, ToolError};

const USAGE: &str = "Usage: postgres-mcp [http|stdio|healthcheck|--help|-h|--version|-V]

Commands:
  http         serve MCP over Streamable HTTP (default)
  stdio        serve MCP over stdin and stdout
  healthcheck  exit 0 when the local HTTP server answers /health

Configuration is read from environment variables, see README.";

const HEALTH_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_MCP_PORT: u16 = 8432;

/// Shared by every request: the configuration and one lazy pool per database.
pub struct AppState {
    pub config: Arc<Config>,
    pools: HashMap<String, Arc<Pool>>,
}

impl AppState {
    pub fn new(config: Config) -> AppState {
        let pools = config
            .databases
            .iter()
            .map(|db| {
                (
                    db.name.clone(),
                    Arc::new(Pool::new(db.connect.clone(), db.max_connections)),
                )
            })
            .collect();
        AppState {
            config: Arc::new(config),
            pools,
        }
    }

    /// The database entry and its pool; `None` selects the only configured database.
    pub fn pool(&self, database: Option<&str>) -> Result<(&DatabaseConfig, Arc<Pool>), ToolError> {
        let db = self
            .config
            .database(database)
            .map_err(|e: ConfigError| ToolError::Config(e.0))?;
        let pool = self
            .pools
            .get(&db.name)
            .cloned()
            .ok_or_else(|| ToolError::Internal(format!("no pool for database {}", db.name)))?;
        Ok((db, pool))
    }

    /// The configured name the database argument selects, or None when it selects nothing.
    pub fn resolve_name(&self, database: Option<&str>) -> Option<String> {
        self.config
            .database(database)
            .ok()
            .map(|db| db.name.clone())
    }

    /// Closes every pool; later checkouts fail.
    pub async fn close(&self) {
        for pool in self.pools.values() {
            pool.close().await;
        }
    }
}

/// Entry point of the binary: parses the command line and runs the chosen mode.
pub async fn run() -> ExitCode {
    let args: Vec<String> = std::env::args_os()
        .skip(1)
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    match args.as_slice() {
        [] => serve_http().await,
        [command] => match command.as_str() {
            "http" => serve_http().await,
            "stdio" => serve_stdio().await,
            "healthcheck" => healthcheck(),
            "--help" | "-h" => {
                println!("{USAGE}");
                ExitCode::SUCCESS
            }
            "--version" | "-V" => {
                println!("postgres-mcp {}", env!("CARGO_PKG_VERSION"));
                ExitCode::SUCCESS
            }
            _ => usage_error(),
        },
        _ => usage_error(),
    }
}

fn usage_error() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

fn config_error(message: &str) -> ExitCode {
    eprintln!("configuration error: {message}");
    ExitCode::from(2)
}

/// Installs the stderr subscriber. The filter comes from RUST_LOG, else LOG_LEVEL, else info.
fn init_logging(format: LogFormat) -> Result<(), String> {
    let filter = match env_value("RUST_LOG")? {
        Some(value) => EnvFilter::try_new(&value).map_err(|e| format!("RUST_LOG: {e}"))?,
        None => match env_value("LOG_LEVEL")? {
            Some(value) => EnvFilter::try_new(&value).map_err(|e| format!("LOG_LEVEL: {e}"))?,
            None => EnvFilter::new("info"),
        },
    };
    // Colour only when stderr is a terminal, so piped logs stay plain text.
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()));
    let installed = match format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
    installed.map_err(|e| format!("cannot start logging: {e}"))
}

/// A variable's value; unset and empty both count as unset.
fn env_value(name: &str) -> Result<Option<String>, String> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name}: value is not valid UTF-8")),
    }
}

/// Reads the configuration and starts logging; a failure is reported and returned as the exit code.
fn start(config: Result<Config, ConfigError>) -> Result<Config, ExitCode> {
    let config = config.map_err(|e| config_error(&e.0))?;
    init_logging(config.log_format).map_err(|e| config_error(&e))?;
    Ok(config)
}

async fn serve_http() -> ExitCode {
    let config = match start(Config::from_env()) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let host = config.host;
    let port = config.port;
    let api_key_set = config.api_key.is_some();
    let names = database_names(&config);
    let state = Arc::new(AppState::new(config));
    let addr = SocketAddr::new(host, port);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!(address = %addr, error = %error, "cannot bind the HTTP address");
            state.close().await;
            return ExitCode::FAILURE;
        }
    };
    tracing::info!(
        address = %addr,
        databases = %names,
        api_key = api_key_set,
        "serving MCP over Streamable HTTP"
    );
    if !host.is_loopback() && !api_key_set {
        tracing::warn!(address = %addr, "listening on a non-loopback address without an API key");
    }

    let served = axum::serve(listener, build_router(state.clone()))
        .with_graceful_shutdown(shutdown_signal())
        .await;
    state.close().await;
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "HTTP server failed");
            ExitCode::FAILURE
        }
    }
}

async fn serve_stdio() -> ExitCode {
    let config = match start(Config::from_env()) {
        Ok(config) => config,
        Err(code) => return code,
    };
    let state = Arc::new(AppState::new(config));
    let transport = rmcp::transport::io::stdio();
    let running = match rmcp::serve_server(PgMcp::new(state.clone()), transport).await {
        Ok(running) => running,
        Err(error) => {
            tracing::error!(error = %error, "cannot start the stdio session");
            state.close().await;
            return ExitCode::FAILURE;
        }
    };
    let outcome = running.waiting().await;
    state.close().await;
    match outcome {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "stdio session ended abnormally");
            ExitCode::FAILURE
        }
    }
}

fn database_names(config: &Config) -> String {
    config
        .databases
        .iter()
        .map(|d| d.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Resolves when SIGINT or SIGTERM arrives. A failed signal registration is logged and never fires.
async fn shutdown_signal() {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(error = %error, "cannot listen for SIGINT");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut stream) => {
                stream.recv().await;
            }
            Err(error) => {
                tracing::error!(error = %error, "cannot listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = interrupt => {}
        () = terminate => {}
    }
    tracing::info!("shutdown signal received");
}

/// The HTTP router: `/health` open, `/mcp` behind the guard, every other path 404.
pub fn build_router(state: Arc<AppState>) -> Router {
    let config = state.config.clone();
    let limits = &config.limits;

    let mut allowed_hosts = vec![
        "localhost".to_owned(),
        "127.0.0.1".to_owned(),
        "::1".to_owned(),
    ];
    allowed_hosts.extend(config.allowed_hosts.iter().cloned());
    let mcp_config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(false)
        .with_json_response(true)
        .with_allowed_hosts(allowed_hosts)
        .with_max_request_body_bytes(limits.max_request_bytes);
    let factory_state = state.clone();
    let service = StreamableHttpService::new(
        move || Ok(PgMcp::new(factory_state.clone())),
        Arc::new(NeverSessionManager::default()),
        mcp_config,
    );
    let guard = GuardState {
        api_key: config.api_key.as_deref().map(ApiKey::new),
        allowed_origins: Arc::new(config.allowed_origins.clone()),
    };
    let mcp = Router::new()
        .route_service("/mcp", service)
        .layer(ConcurrencyLimitLayer::new(limits.max_concurrent_requests))
        .layer(from_fn_with_state(guard, crate::http_guard::guard));

    let mut router = Router::new()
        .route("/health", get(health))
        .merge(mcp)
        .layer(RequestBodyLimitLayer::new(limits.max_request_bytes));
    if !config.allowed_origins.is_empty() {
        router = router.layer(cors_layer(&config.allowed_origins));
    }
    router.layer(TraceLayer::new_for_http())
}

async fn health() -> impl IntoResponse {
    ([(CONTENT_TYPE, "text/plain; charset=utf-8")], "ok")
}

/// CORS for exactly the configured origins, normalised the way the guard compares them.
fn cors_layer(origins: &[String]) -> CorsLayer {
    // The config already rejected anything that is not an origin, so every entry serialises.
    let values: Vec<HeaderValue> = origins
        .iter()
        .filter_map(|origin| url::Url::parse(origin).ok())
        .filter_map(|url| HeaderValue::from_str(&url.origin().ascii_serialization()).ok())
        .collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(values))
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            ACCEPT,
            AUTHORIZATION,
            CONTENT_TYPE,
            HeaderName::from_static("x-api-key"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("mcp-method"),
            HeaderName::from_static("mcp-name"),
            HeaderName::from_static("mcp-session-id"),
        ])
}

/// Probes `/health` on 127.0.0.1 and exits 0 only for a 200 status line.
fn healthcheck() -> ExitCode {
    let port = match env_value("MCP_PORT") {
        Ok(None) => DEFAULT_MCP_PORT,
        Ok(Some(raw)) => match raw.parse::<u16>() {
            Ok(port) if port > 0 => port,
            _ => return config_error(&format!("MCP_PORT: \"{raw}\" is not a port number")),
        },
        Err(message) => return config_error(&message),
    };
    if probe_health(port) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn probe_health(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, HEALTH_TIMEOUT) else {
        return false;
    };
    if stream.set_read_timeout(Some(HEALTH_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(HEALTH_TIMEOUT)).is_err()
    {
        return false;
    }
    let request = b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).is_err() {
        return false;
    }
    let mut received = Vec::new();
    let mut chunk = [0_u8; 512];
    // Stops at the end of the status line, at EOF, or on a read error or timeout (which fails the probe).
    while !received.windows(2).any(|pair| pair == b"\r\n") {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => received.extend_from_slice(&chunk[..n]),
            Err(_) => return false,
        }
    }
    let text = String::from_utf8_lossy(&received);
    text.lines()
        .next()
        .is_some_and(|status| status.contains(" 200 "))
}
