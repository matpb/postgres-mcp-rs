//! Environment-only configuration: server, API key, limits, toolsets, logging and database connections.

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value};
use url::Url;

use crate::http_guard::parse_origin;
use std::sync::Arc;

use rustls::ClientConfig;

use crate::pg::tls::{self, PemSource, SslMode, TlsSources};
use crate::pg::wire::{AuthPolicy, ConnectConfig};

const DEFAULT_PORT: u16 = 8432;
const MIN_API_KEY_CHARS: usize = 16;
const DEFAULT_PG_HOST: &str = "127.0.0.1";
const DEFAULT_PG_PORT: u16 = 5432;
const DEFAULT_APP_NAME: &str = "postgres-mcp";
const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 10;
const MAX_CONNECT_TIMEOUT_SECS: u64 = 3_600;
const DEFAULT_MAX_CONNECTIONS: usize = 4;
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 30_000;
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 5_000;
const MAX_NAME_LEN: usize = 63;
const NAME_RULE: &str = "1 to 63 characters of A-Z, a-z, 0-9, _ or -";

const DATABASE_FIELDS: &[&str] = &[
    "name",
    "url",
    "host",
    "port",
    "database",
    "user",
    "password",
    "password_file",
    "sslmode",
    "sslrootcert",
    "sslrootcert_pem",
    "sslcert",
    "sslcert_pem",
    "sslkey",
    "sslkey_pem",
    "require_auth",
    "max_connections",
    "statement_timeout_ms",
    "lock_timeout_ms",
];
/// Fields that describe the connection itself, so they cannot accompany `url`. Inline PEM fields may.
const URL_EXCLUSIVE_FIELDS: &[&str] = &[
    "host",
    "port",
    "database",
    "user",
    "password",
    "sslmode",
    "sslrootcert",
    "sslcert",
    "sslkey",
    "require_auth",
];

/// Every variable this module reads; `from_env` copies them out of the process environment.
const ENV_VARS: &[&str] = &[
    "MCP_HOST",
    "MCP_PORT",
    "API_KEY",
    "API_KEY_FILE",
    "ALLOWED_ORIGINS",
    "ALLOWED_HOSTS",
    "PG_DATABASES",
    "PG_DATABASES_FILE",
    "DATABASE_URL",
    "PG_NAME",
    "PGHOST",
    "PGPORT",
    "PGDATABASE",
    "PGUSER",
    "PGPASSWORD",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGSSLCERT",
    "PGSSLKEY",
    "PGSSLROOTCERT_PEM",
    "PGSSLCERT_PEM",
    "PGSSLKEY_PEM",
    "PGREQUIREAUTH",
    "PGAPPNAME",
    "MAX_ROWS",
    "MAX_VALUE_BYTES",
    "MAX_BINARY_PREVIEW_BYTES",
    "MAX_RESPONSE_BYTES",
    "MAX_REQUEST_BYTES",
    "MAX_SQL_BYTES",
    "MAX_CONCURRENT_REQUESTS",
    "STATEMENT_TIMEOUT_MS",
    "LOCK_TIMEOUT_MS",
    "TOOLSETS",
    "AUDIT_LOG",
    "LOG_FORMAT",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_rows: usize,
    pub max_value_bytes: usize,
    pub max_binary_preview_bytes: usize,
    pub max_response_bytes: usize,
    pub max_request_bytes: usize,
    pub max_sql_bytes: usize,
    pub max_concurrent_requests: usize,
}

#[derive(Clone)]
pub struct DatabaseConfig {
    pub name: String,
    pub connect: ConnectConfig,
    /// Authentication methods the server may use, from `require_auth`.
    pub auth: AuthPolicy,
    pub max_connections: usize,
    pub statement_timeout_ms: u64,
    pub lock_timeout_ms: u64,
    /// TLS configuration built by `Config::prepare_tls`; None until then or when sslmode is disable.
    pub tls: Option<Arc<ClientConfig>>,
    /// The root and client certificate settings that `prepare_tls` reads; inline PEM stays redacted in Debug.
    pub tls_sources: TlsSources,
}

impl fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("name", &self.name)
            .field("host", &self.connect.host)
            .field("port", &self.connect.port)
            .field("database", &self.connect.database)
            .field("user", &self.connect.user)
            .field("ssl_mode", &self.connect.ssl_mode)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Toolsets {
    pub schema: bool,
    pub monitor: bool,
    pub logs: bool,
    pub timescale: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Text,
    Json,
}

#[derive(Clone)]
pub struct Config {
    pub host: IpAddr,
    pub port: u16,
    pub api_key: Option<String>,
    pub allowed_origins: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub databases: Vec<DatabaseConfig>,
    pub limits: Limits,
    pub toolsets: Toolsets,
    pub audit_log: bool,
    pub log_format: LogFormat,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let api_key = if self.api_key.is_some() {
            "set"
        } else {
            "unset"
        };
        f.debug_struct("Config")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("api_key", &api_key)
            .field("allowed_origins", &self.allowed_origins)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("databases", &self.databases)
            .field("limits", &self.limits)
            .field("toolsets", &self.toolsets)
            .field("audit_log", &self.audit_log)
            .field("log_format", &self.log_format)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// Defaults for the timeouts that a database entry may override.
struct Defaults {
    statement_timeout_ms: u64,
    lock_timeout_ms: u64,
}

/// One database's connection settings before the startup parameters are added.
struct Target {
    host: String,
    port: u16,
    database: String,
    user: String,
    password: Option<String>,
    ssl_mode: SslMode,
    tls: TlsSources,
    auth: AuthPolicy,
    /// `application_name` from a URL query, used when PGAPPNAME is unset.
    application_name: Option<String>,
    connect_timeout: Option<Duration>,
}

impl Config {
    /// Reads the process environment and validates it; see `from_lookup`.
    pub fn from_env() -> Result<Config, ConfigError> {
        let mut vars = HashMap::new();
        for name in ENV_VARS {
            match std::env::var(name) {
                Ok(value) => {
                    vars.insert(*name, value);
                }
                Err(std::env::VarError::NotPresent) => {}
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(ConfigError(format!("{name}: value is not valid UTF-8")));
                }
            }
        }
        let mut config = Config::from_lookup(&|name| vars.get(name).cloned())?;
        config.prepare_tls()?;
        Ok(config)
    }

    /// Builds each database's TLS configuration once, so the root file is read at startup, not per connection.
    /// A failure names the database and the cause, never the file contents.
    pub fn prepare_tls(&mut self) -> Result<(), ConfigError> {
        for db in &mut self.databases {
            if db.connect.ssl_mode == SslMode::Disable {
                continue;
            }
            let config = tls::startup_client_config(db.connect.ssl_mode, &db.tls_sources)
                .map_err(|reason| ConfigError(format!("{}: {reason}", db.name)))?;
            db.tls = Some(config);
        }
        Ok(())
    }

    /// Same logic with an injectable variable lookup, for tests. An empty value counts as unset.
    pub fn from_lookup(get: &dyn Fn(&str) -> Option<String>) -> Result<Config, ConfigError> {
        let host = match var(get, "MCP_HOST") {
            Some(raw) => raw.parse::<IpAddr>().map_err(|_| {
                ConfigError(format!(
                    "MCP_HOST: \"{raw}\" is not an IP address; use 127.0.0.1 or ::1"
                ))
            })?,
            None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        };
        let port = match var(get, "MCP_PORT") {
            Some(raw) => parse_port("MCP_PORT", &raw)?,
            None => DEFAULT_PORT,
        };
        let defaults = Defaults {
            statement_timeout_ms: bounded(
                get,
                "STATEMENT_TIMEOUT_MS",
                100,
                3_600_000,
                DEFAULT_STATEMENT_TIMEOUT_MS,
            )?,
            lock_timeout_ms: bounded(get, "LOCK_TIMEOUT_MS", 10, 600_000, DEFAULT_LOCK_TIMEOUT_MS)?,
        };
        Ok(Config {
            host,
            port,
            api_key: api_key(get)?,
            allowed_origins: allowed_origins(var(get, "ALLOWED_ORIGINS"))?,
            allowed_hosts: list(var(get, "ALLOWED_HOSTS")),
            databases: databases(get, &defaults)?,
            limits: limits(get)?,
            toolsets: toolsets(var(get, "TOOLSETS"))?,
            audit_log: audit_log(var(get, "AUDIT_LOG"))?,
            log_format: log_format(var(get, "LOG_FORMAT"))?,
        })
    }

    /// Returns the named database, or the only one when `name` is None.
    pub fn database(&self, name: Option<&str>) -> Result<&DatabaseConfig, ConfigError> {
        match name {
            None => match self.databases.as_slice() {
                [only] => Ok(only),
                _ => Err(ConfigError(format!(
                    "'database' is required: choose one of {}",
                    self.database_names()
                ))),
            },
            Some(wanted) => self
                .databases
                .iter()
                .find(|d| d.name == wanted)
                .ok_or_else(|| {
                    ConfigError(format!(
                        "unknown database \"{wanted}\": configured databases are {}",
                        self.database_names()
                    ))
                }),
        }
    }

    fn database_names(&self) -> String {
        self.databases
            .iter()
            .map(|d| d.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// The variable's value, where an empty value counts as unset.
fn var(get: &dyn Fn(&str) -> Option<String>, name: &str) -> Option<String> {
    get(name).filter(|v| !v.is_empty())
}

/// Reads a numeric variable with bounds, or returns `default` when it is unset.
fn bounded(
    get: &dyn Fn(&str) -> Option<String>,
    name: &str,
    min: u64,
    max: u64,
    default: u64,
) -> Result<u64, ConfigError> {
    match var(get, name) {
        Some(raw) => whole(name, &raw, min, max),
        None => Ok(default),
    }
}

fn whole(name: &str, raw: &str, min: u64, max: u64) -> Result<u64, ConfigError> {
    match raw.parse::<u64>() {
        Ok(value) => check_range(name, value, min, max),
        Err(_) if !raw.is_empty() && raw.bytes().all(|b| b.is_ascii_digit()) => Err(ConfigError(
            format!("{name}: {raw} is above the maximum {max}"),
        )),
        Err(_) => Err(ConfigError(format!(
            "{name}: \"{raw}\" is not a whole number"
        ))),
    }
}

fn check_range(name: &str, value: u64, min: u64, max: u64) -> Result<u64, ConfigError> {
    if value < min {
        Err(ConfigError(format!(
            "{name}: {value} is below the minimum {min}"
        )))
    } else if value > max {
        Err(ConfigError(format!(
            "{name}: {value} is above the maximum {max}"
        )))
    } else {
        Ok(value)
    }
}

fn parse_port(name: &str, raw: &str) -> Result<u16, ConfigError> {
    match raw.parse::<u16>() {
        Ok(port) if port > 0 => Ok(port),
        _ => Err(ConfigError(format!(
            "{name}: \"{raw}\" is not a port number"
        ))),
    }
}

/// The TLS settings of one database as written; a file and an inline value of one item stay apart.
#[derive(Default)]
struct TlsInputs {
    root_file: Option<PathBuf>,
    root_pem: Option<String>,
    cert_file: Option<PathBuf>,
    cert_pem: Option<String>,
    key_file: Option<PathBuf>,
    key_pem: Option<String>,
}

/// The setting names that TLS rule errors are reported under.
struct TlsNames<'a> {
    sslmode: &'a str,
    root: &'a str,
    cert: &'a str,
    key: &'a str,
}

/// Applies the TLS rules of one database and returns its sources.
fn resolve_tls(
    names: &TlsNames,
    mode: SslMode,
    inputs: TlsInputs,
) -> Result<TlsSources, ConfigError> {
    let cert_set = inputs.cert_file.is_some() || inputs.cert_pem.is_some();
    let key_set = inputs.key_file.is_some() || inputs.key_pem.is_some();
    if cert_set != key_set {
        let name = if cert_set { names.cert } else { names.key };
        return Err(ConfigError(format!(
            "{name}: sslcert and sslkey must be set together"
        )));
    }
    if inputs.root_file.is_some() && inputs.root_pem.is_some() {
        return Err(ConfigError(format!(
            "{}: sslrootcert and sslrootcert_pem cannot both be set",
            names.root
        )));
    }
    if inputs.cert_file.is_some() && inputs.cert_pem.is_some() {
        return Err(ConfigError(format!(
            "{}: sslcert and sslcert_pem cannot both be set",
            names.cert
        )));
    }
    if inputs.key_file.is_some() && inputs.key_pem.is_some() {
        return Err(ConfigError(format!(
            "{}: sslkey and sslkey_pem cannot both be set",
            names.key
        )));
    }
    if cert_set && mode == SslMode::Disable {
        return Err(ConfigError(format!(
            "{}: sslcert needs TLS: sslmode must not be disable",
            names.sslmode
        )));
    }
    let has_root = inputs.root_file.is_some() || inputs.root_pem.is_some();
    // verify-ca checks the chain only, so it needs a root certificate to check against.
    if mode == SslMode::VerifyCa && !has_root {
        return Err(ConfigError(format!(
            "{}: sslmode=verify-ca needs sslrootcert",
            names.sslmode
        )));
    }
    Ok(TlsSources {
        root: pick(inputs.root_file, inputs.root_pem),
        client_cert: pick(inputs.cert_file, inputs.cert_pem),
        client_key: pick(inputs.key_file, inputs.key_pem),
    })
}

/// The one source of an item; both forms set is rejected earlier.
fn pick(file: Option<PathBuf>, pem: Option<String>) -> Option<PemSource> {
    match (file, pem) {
        (Some(path), _) => Some(PemSource::File(path)),
        (None, Some(text)) => Some(PemSource::Inline(text)),
        (None, None) => None,
    }
}

/// Inline PEM variables; a literal backslash-n becomes a newline, since env values cannot hold one.
fn env_pem(get: &dyn Fn(&str) -> Option<String>) -> TlsInputs {
    TlsInputs {
        root_pem: var(get, "PGSSLROOTCERT_PEM").map(unescape_newlines),
        cert_pem: var(get, "PGSSLCERT_PEM").map(unescape_newlines),
        key_pem: var(get, "PGSSLKEY_PEM").map(unescape_newlines),
        ..TlsInputs::default()
    }
}

fn unescape_newlines(raw: String) -> String {
    raw.replace("\\n", "\n")
}

/// Parses a `require_auth` comma list; each item names one method the server may use.
fn parse_require_auth(name: &str, raw: &str) -> Result<AuthPolicy, ConfigError> {
    let mut policy = AuthPolicy {
        scram: false,
        md5: false,
        password: false,
        trust: false,
    };
    let mut listed = false;
    for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        listed = true;
        match item {
            "scram-sha-256" => policy.scram = true,
            "md5" => policy.md5 = true,
            "password" => policy.password = true,
            "none" => policy.trust = true,
            other => {
                return Err(ConfigError(format!(
                    "{name}: unknown authentication method \"{other}\"; expected scram-sha-256, md5, password or none"
                )));
            }
        }
    }
    if !listed {
        return Err(ConfigError(format!(
            "{name}: no authentication method is listed"
        )));
    }
    Ok(policy)
}

fn parse_ssl_mode(name: &str, raw: &str) -> Result<SslMode, ConfigError> {
    raw.parse::<SslMode>().map_err(|_| {
        ConfigError(format!(
            "{name}: invalid ssl mode \"{raw}\"; expected disable, prefer, require, verify-ca or verify-full"
        ))
    })
}

fn read_file(name: &str, path: &str) -> Result<String, ConfigError> {
    std::fs::read_to_string(path)
        .map_err(|e| ConfigError(format!("{name}: cannot read {path}: {e}")))
}

/// Reads a password file, dropping only the trailing line break; an empty file means no password.
fn read_password_file(name: &str, path: &str) -> Result<Option<String>, ConfigError> {
    let text = read_file(name, path)?;
    let password = text.trim_end_matches(['\r', '\n']);
    Ok((!password.is_empty()).then(|| password.to_owned()))
}

fn api_key(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<String>, ConfigError> {
    let (source, key) = match (var(get, "API_KEY"), var(get, "API_KEY_FILE")) {
        (Some(_), Some(_)) => {
            return Err(ConfigError(
                "API_KEY and API_KEY_FILE are both set; set only one".into(),
            ));
        }
        (Some(key), None) => ("API_KEY", key),
        (None, Some(path)) => (
            "API_KEY_FILE",
            read_file("API_KEY_FILE", &path)?.trim().to_owned(),
        ),
        (None, None) => return Ok(None),
    };
    if key != key.trim() {
        return Err(ConfigError(format!(
            "{source}: must not start or end with whitespace"
        )));
    }
    if key.chars().count() < MIN_API_KEY_CHARS {
        return Err(ConfigError(format!(
            "{source}: must be at least {MIN_API_KEY_CHARS} characters"
        )));
    }
    Ok(Some(key))
}

/// Splits a comma list, trimming entries and dropping empty ones.
fn list(raw: Option<String>) -> Vec<String> {
    raw.map(|r| {
        r.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

fn allowed_origins(raw: Option<String>) -> Result<Vec<String>, ConfigError> {
    let origins = list(raw);
    if let Some(bad) = origins.iter().find(|o| parse_origin(o).is_none()) {
        return Err(ConfigError(format!(
            "ALLOWED_ORIGINS: \"{bad}\" is not an origin of the form scheme://host[:port]"
        )));
    }
    Ok(origins)
}

fn toolsets(raw: Option<String>) -> Result<Toolsets, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Toolsets {
            schema: true,
            monitor: true,
            logs: true,
            timescale: true,
        });
    };
    let mut toolsets = Toolsets {
        schema: false,
        monitor: false,
        logs: false,
        timescale: false,
    };
    let mut listed = false;
    for name in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        listed = true;
        match name {
            "schema" => toolsets.schema = true,
            "monitor" => toolsets.monitor = true,
            "logs" => toolsets.logs = true,
            "timescale" => toolsets.timescale = true,
            "core" => {}
            "all" => {
                toolsets.schema = true;
                toolsets.monitor = true;
                toolsets.logs = true;
                toolsets.timescale = true;
            }
            other => {
                return Err(ConfigError(format!(
                    "TOOLSETS: unknown toolset \"{other}\" (expected schema, monitor, logs, timescale, core or all)"
                )));
            }
        }
    }
    if !listed {
        return Err(ConfigError("TOOLSETS: no toolset is listed".into()));
    }
    Ok(toolsets)
}

fn audit_log(raw: Option<String>) -> Result<bool, ConfigError> {
    match raw.as_deref() {
        None | Some("on" | "true" | "1") => Ok(true),
        Some("off" | "false" | "0") => Ok(false),
        Some(other) => Err(ConfigError(format!(
            "AUDIT_LOG: \"{other}\" is not on, off, true, false, 1 or 0"
        ))),
    }
}

fn log_format(raw: Option<String>) -> Result<LogFormat, ConfigError> {
    match raw.as_deref() {
        None | Some("text") => Ok(LogFormat::Text),
        Some("json") => Ok(LogFormat::Json),
        Some(other) => Err(ConfigError(format!(
            "LOG_FORMAT: \"{other}\" is not text or json"
        ))),
    }
}

fn limits(get: &dyn Fn(&str) -> Option<String>) -> Result<Limits, ConfigError> {
    Ok(Limits {
        max_rows: bounded(get, "MAX_ROWS", 1, 100_000, 1_000)? as usize,
        max_value_bytes: bounded(get, "MAX_VALUE_BYTES", 64, 1_048_576, 4_096)? as usize,
        max_binary_preview_bytes: bounded(get, "MAX_BINARY_PREVIEW_BYTES", 16, 65_536, 256)?
            as usize,
        max_response_bytes: bounded(get, "MAX_RESPONSE_BYTES", 1_024, 16_777_216, 48_000)? as usize,
        max_request_bytes: bounded(get, "MAX_REQUEST_BYTES", 1_024, 16_777_216, 1_048_576)?
            as usize,
        max_sql_bytes: bounded(get, "MAX_SQL_BYTES", 256, 1_048_576, 102_400)? as usize,
        max_concurrent_requests: bounded(get, "MAX_CONCURRENT_REQUESTS", 1, 1_024, 16)? as usize,
    })
}

fn databases(
    get: &dyn Fn(&str) -> Option<String>,
    defaults: &Defaults,
) -> Result<Vec<DatabaseConfig>, ConfigError> {
    let app_name = var(get, "PGAPPNAME");
    let app_name = app_name.as_deref();
    match (var(get, "PG_DATABASES_FILE"), var(get, "PG_DATABASES")) {
        (Some(_), Some(_)) => Err(ConfigError(
            "PG_DATABASES_FILE and PG_DATABASES are both set; set only one".into(),
        )),
        (Some(path), None) => {
            let text = read_file("PG_DATABASES_FILE", &path)?;
            json_databases("PG_DATABASES_FILE", &text, defaults, app_name)
        }
        (None, Some(json)) => json_databases("PG_DATABASES", &json, defaults, app_name),
        (None, None) => {
            if let Some(url) = var(get, "DATABASE_URL") {
                let target = url_target("DATABASE_URL", &url, env_pem(get))?;
                let name = resolve_name(get, &target.database, "DATABASE_URL")?;
                Ok(vec![env_database(name, target, defaults, app_name)])
            } else if let Some(database) = var(get, "PGDATABASE") {
                Ok(vec![libpq_database(get, database, defaults, app_name)?])
            } else {
                Err(ConfigError(
                    "no database configured: set PG_DATABASES, DATABASE_URL, or PGDATABASE with PGHOST and PGUSER".into(),
                ))
            }
        }
    }
}

fn libpq_database(
    get: &dyn Fn(&str) -> Option<String>,
    database: String,
    defaults: &Defaults,
    app_name: Option<&str>,
) -> Result<DatabaseConfig, ConfigError> {
    let name = resolve_name(get, &database, "PGDATABASE")?;
    let user = var(get, "PGUSER")
        .ok_or_else(|| ConfigError("PGUSER: required when PGDATABASE is set".into()))?;
    let ssl_mode = match var(get, "PGSSLMODE") {
        Some(raw) => parse_ssl_mode("PGSSLMODE", &raw)?,
        None => SslMode::Prefer,
    };
    let inputs = TlsInputs {
        root_file: var(get, "PGSSLROOTCERT").map(PathBuf::from),
        cert_file: var(get, "PGSSLCERT").map(PathBuf::from),
        key_file: var(get, "PGSSLKEY").map(PathBuf::from),
        ..env_pem(get)
    };
    let names = TlsNames {
        sslmode: "PGSSLMODE",
        root: "PGSSLROOTCERT",
        cert: "PGSSLCERT",
        key: "PGSSLKEY",
    };
    let tls = resolve_tls(&names, ssl_mode, inputs)?;
    let auth = match var(get, "PGREQUIREAUTH") {
        Some(raw) => parse_require_auth("PGREQUIREAUTH", &raw)?,
        None => AuthPolicy::default(),
    };
    let target = Target {
        host: var(get, "PGHOST").unwrap_or_else(|| DEFAULT_PG_HOST.to_owned()),
        port: match var(get, "PGPORT") {
            Some(raw) => parse_port("PGPORT", &raw)?,
            None => DEFAULT_PG_PORT,
        },
        database,
        user,
        password: var(get, "PGPASSWORD"),
        ssl_mode,
        tls,
        auth,
        application_name: None,
        connect_timeout: None,
    };
    Ok(env_database(name, target, defaults, app_name))
}

/// The connection name: PG_NAME when set, else the database name, which must itself be a valid name.
fn resolve_name(
    get: &dyn Fn(&str) -> Option<String>,
    database: &str,
    database_source: &str,
) -> Result<String, ConfigError> {
    match var(get, "PG_NAME") {
        Some(name) if valid_name(&name) => Ok(name),
        Some(_) => Err(ConfigError(format!("PG_NAME: must be {NAME_RULE}"))),
        None if valid_name(database) => Ok(database.to_owned()),
        None => Err(ConfigError(format!(
            "{database_source}: the database name cannot be used as a connection name; set PG_NAME"
        ))),
    }
}

fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A database from the environment forms, which take the default timeouts and pool size.
fn env_database(
    name: String,
    target: Target,
    defaults: &Defaults,
    app_name: Option<&str>,
) -> DatabaseConfig {
    let auth = target.auth.clone();
    let tls_sources = target.tls.clone();
    DatabaseConfig {
        name,
        connect: connect_config(target, app_name),
        auth,
        max_connections: DEFAULT_MAX_CONNECTIONS,
        statement_timeout_ms: defaults.statement_timeout_ms,
        lock_timeout_ms: defaults.lock_timeout_ms,
        tls: None,
        tls_sources,
    }
}

fn connect_config(target: Target, app_name: Option<&str>) -> ConnectConfig {
    // A root file is also passed to the wire client, which reads it only without a prepared configuration.
    let ssl_root_cert = match &target.tls.root {
        Some(PemSource::File(path)) => Some(path.clone()),
        _ => None,
    };
    let application_name = app_name
        .map(str::to_owned)
        .or(target.application_name)
        .unwrap_or_else(|| DEFAULT_APP_NAME.to_owned());
    let mut startup_params = vec![("application_name".to_owned(), application_name)];
    let fixed = [
        ("DateStyle", "ISO, MDY"),
        ("IntervalStyle", "iso_8601"),
        ("TimeZone", "UTC"),
        ("bytea_output", "hex"),
        ("extra_float_digits", "1"),
        ("standard_conforming_strings", "on"),
        ("default_transaction_read_only", "on"),
    ];
    startup_params.extend(
        fixed
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
    );
    ConnectConfig {
        host: target.host,
        port: target.port,
        database: target.database,
        user: target.user,
        password: target.password,
        ssl_mode: target.ssl_mode,
        ssl_root_cert,
        connect_timeout: target
            .connect_timeout
            .unwrap_or(Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS)),
        startup_params,
    }
}

/// Parses a `postgres://` or `postgresql://` URL, with the inline PEM settings the caller holds. Errors never echo the URL.
fn url_target(label: &str, raw: &str, pem: TlsInputs) -> Result<Target, ConfigError> {
    let invalid = || ConfigError(format!("{label}: not a valid postgres:// URL"));
    let url = Url::parse(raw).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "postgres" | "postgresql") {
        return Err(invalid());
    }
    if url.username().is_empty() {
        return Err(ConfigError(format!("{label}: the URL has no user")));
    }
    let user = percent_decode(label, url.username())?;
    let password = url
        .password()
        .map(|p| percent_decode(label, p))
        .transpose()?
        .filter(|p| !p.is_empty());
    let database = percent_decode(label, url.path().strip_prefix('/').unwrap_or_default())?;
    if database.is_empty() {
        return Err(ConfigError(format!("{label}: the URL has no database")));
    }
    let host = match url.host_str() {
        Some(host) if !host.is_empty() => host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host)
            .to_owned(),
        _ => DEFAULT_PG_HOST.to_owned(),
    };

    let mut sslmode = None;
    let mut sslrootcert = None;
    let mut sslcert = None;
    let mut sslkey = None;
    let mut require_auth = None;
    let mut application_name = None;
    let mut connect_timeout = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "sslmode" => sslmode = Some(value.into_owned()),
            "sslrootcert" => sslrootcert = Some(PathBuf::from(value.as_ref())),
            "sslcert" => sslcert = Some(PathBuf::from(value.as_ref())),
            "sslkey" => sslkey = Some(PathBuf::from(value.as_ref())),
            "require_auth" => require_auth = Some(value.into_owned()),
            "application_name" => application_name = Some(value.into_owned()),
            "connect_timeout" => connect_timeout = Some(value.into_owned()),
            other => {
                return Err(ConfigError(format!(
                    "{label}: unknown URL parameter \"{other}\""
                )));
            }
        }
    }
    let ssl_mode = match sslmode {
        Some(raw) => parse_ssl_mode(&format!("{label}: sslmode"), &raw)?,
        None => SslMode::Prefer,
    };
    let inputs = TlsInputs {
        root_file: sslrootcert,
        cert_file: sslcert,
        key_file: sslkey,
        ..pem
    };
    let names = TlsNames {
        sslmode: label,
        root: label,
        cert: label,
        key: label,
    };
    let tls = resolve_tls(&names, ssl_mode, inputs)?;
    let auth = match require_auth {
        Some(raw) => parse_require_auth(&format!("{label}: require_auth"), &raw)?,
        None => AuthPolicy::default(),
    };
    let connect_timeout = connect_timeout
        .map(|raw| {
            whole(
                &format!("{label}: connect_timeout"),
                &raw,
                1,
                MAX_CONNECT_TIMEOUT_SECS,
            )
            .map(Duration::from_secs)
        })
        .transpose()?;
    Ok(Target {
        host,
        port: url.port().unwrap_or(DEFAULT_PG_PORT),
        database,
        user,
        password,
        ssl_mode,
        tls,
        auth,
        application_name,
        connect_timeout,
    })
}

/// Decodes `%XX` escapes; a malformed escape is an error that does not echo the input.
fn percent_decode(label: &str, raw: &str) -> Result<String, ConfigError> {
    let mut out = Vec::with_capacity(raw.len());
    let mut bytes = raw.bytes();
    while let Some(byte) = bytes.next() {
        if byte != b'%' {
            out.push(byte);
            continue;
        }
        match (
            bytes.next().and_then(hex_value),
            bytes.next().and_then(hex_value),
        ) {
            (Some(high), Some(low)) => out.push(high * 16 + low),
            _ => {
                return Err(ConfigError(format!(
                    "{label}: invalid percent-encoding in the URL"
                )));
            }
        }
    }
    String::from_utf8(out).map_err(|_| ConfigError(format!("{label}: URL is not valid UTF-8")))
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Parses the JSON array in PG_DATABASES or PG_DATABASES_FILE.
fn json_databases(
    source: &str,
    text: &str,
    defaults: &Defaults,
    app_name: Option<&str>,
) -> Result<Vec<DatabaseConfig>, ConfigError> {
    let value: Value = serde_json::from_str(text)
        .map_err(|e| ConfigError(format!("{source}: not valid JSON: {e}")))?;
    let Value::Array(entries) = value else {
        return Err(ConfigError(format!(
            "{source}: expected a JSON array of database objects"
        )));
    };
    if entries.is_empty() {
        return Err(ConfigError(format!(
            "{source}: at least one database is required"
        )));
    }
    let mut databases: Vec<DatabaseConfig> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let database = json_database(&format!("{source}[{index}]"), entry, defaults, app_name)?;
        if databases.iter().any(|d| d.name == database.name) {
            return Err(ConfigError(format!(
                "{source}[{index}] (\"{}\"): duplicate database name \"{}\"",
                database.name, database.name
            )));
        }
        databases.push(database);
    }
    Ok(databases)
}

fn json_database(
    base: &str,
    entry: &Value,
    defaults: &Defaults,
    app_name: Option<&str>,
) -> Result<DatabaseConfig, ConfigError> {
    let Value::Object(map) = entry else {
        return Err(ConfigError(format!("{base}: expected an object")));
    };
    let name = json_string(map, "name", base)?
        .ok_or_else(|| ConfigError(format!("{base}: \"name\" is required")))?;
    if !valid_name(&name) {
        return Err(ConfigError(format!("{base}: \"name\" must be {NAME_RULE}")));
    }
    let label = format!("{base} (\"{name}\")");
    if let Some(key) = map
        .keys()
        .find(|key| !DATABASE_FIELDS.contains(&key.as_str()))
    {
        return Err(ConfigError(format!("{label}: unknown field \"{key}\"")));
    }
    let statement_timeout_ms = json_bounded(map, "statement_timeout_ms", &label, 100, 3_600_000)?
        .unwrap_or(defaults.statement_timeout_ms);
    let lock_timeout_ms = json_bounded(map, "lock_timeout_ms", &label, 10, 600_000)?
        .unwrap_or(defaults.lock_timeout_ms);
    let max_connections = json_bounded(map, "max_connections", &label, 1, 64)?
        .map_or(DEFAULT_MAX_CONNECTIONS, |n| n as usize);
    let target = match json_string(map, "url", &label)? {
        Some(url) => {
            if let Some(key) = URL_EXCLUSIVE_FIELDS
                .iter()
                .find(|key| map.contains_key(**key))
            {
                return Err(ConfigError(format!(
                    "{label}: \"{key}\" cannot be combined with \"url\""
                )));
            }
            let mut target = url_target(&label, &url, json_pem(map, &label)?)?;
            if let Some(path) = json_string(map, "password_file", &label)? {
                target.password = read_password_file(&format!("{label}: password_file"), &path)?;
            }
            target
        }
        None => json_discrete_target(map, &label)?,
    };
    let auth = target.auth.clone();
    let tls_sources = target.tls.clone();
    Ok(DatabaseConfig {
        name,
        connect: connect_config(target, app_name),
        auth,
        max_connections,
        statement_timeout_ms,
        lock_timeout_ms,
        tls: None,
        tls_sources,
    })
}

/// The inline PEM fields of a JSON entry; they may accompany `url` as well as the discrete fields.
fn json_pem(map: &Map<String, Value>, label: &str) -> Result<TlsInputs, ConfigError> {
    Ok(TlsInputs {
        root_pem: json_string(map, "sslrootcert_pem", label)?,
        cert_pem: json_string(map, "sslcert_pem", label)?,
        key_pem: json_string(map, "sslkey_pem", label)?,
        ..TlsInputs::default()
    })
}

/// The discrete-field form of a JSON entry; passwords are never echoed in errors.
fn json_discrete_target(map: &Map<String, Value>, label: &str) -> Result<Target, ConfigError> {
    let database = json_string(map, "database", label)?
        .ok_or_else(|| ConfigError(format!("{label}: \"database\" is required")))?;
    let user = json_string(map, "user", label)?
        .ok_or_else(|| ConfigError(format!("{label}: \"user\" is required")))?;
    let password = match (
        json_string(map, "password", label)?,
        json_string(map, "password_file", label)?,
    ) {
        (Some(_), Some(_)) => {
            return Err(ConfigError(format!(
                "{label}: \"password\" and \"password_file\" are both set"
            )));
        }
        (Some(password), None) => Some(password),
        (None, Some(path)) => read_password_file(&format!("{label}: password_file"), &path)?,
        (None, None) => None,
    };
    let port = match json_bounded(map, "port", label, 1, 65_535)? {
        Some(port) => port as u16,
        None => DEFAULT_PG_PORT,
    };
    let ssl_mode = match json_string(map, "sslmode", label)? {
        Some(raw) => parse_ssl_mode(&format!("{label}: sslmode"), &raw)?,
        None => SslMode::Prefer,
    };
    let inputs = TlsInputs {
        root_file: json_string(map, "sslrootcert", label)?.map(PathBuf::from),
        cert_file: json_string(map, "sslcert", label)?.map(PathBuf::from),
        key_file: json_string(map, "sslkey", label)?.map(PathBuf::from),
        ..json_pem(map, label)?
    };
    let names = TlsNames {
        sslmode: label,
        root: label,
        cert: label,
        key: label,
    };
    let tls = resolve_tls(&names, ssl_mode, inputs)?;
    let auth = match json_string(map, "require_auth", label)? {
        Some(raw) => parse_require_auth(&format!("{label}: require_auth"), &raw)?,
        None => AuthPolicy::default(),
    };
    Ok(Target {
        host: json_string(map, "host", label)?.unwrap_or_else(|| DEFAULT_PG_HOST.to_owned()),
        port,
        database,
        user,
        password,
        ssl_mode,
        tls,
        auth,
        application_name: None,
        connect_timeout: None,
    })
}

/// A string field; an empty string counts as absent, and any non-string is an error.
fn json_string(
    map: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<Option<String>, ConfigError> {
    match map.get(key) {
        None => Ok(None),
        Some(Value::String(text)) if !text.is_empty() => Ok(Some(text.clone())),
        Some(Value::String(_)) => Ok(None),
        Some(_) => Err(ConfigError(format!("{label}: \"{key}\" must be a string"))),
    }
}

/// A whole-number field with bounds, named `label: key` in errors.
fn json_bounded(
    map: &Map<String, Value>,
    key: &str,
    label: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, ConfigError> {
    let Some(value) = map.get(key) else {
        return Ok(None);
    };
    let name = format!("{label}: {key}");
    let number = value
        .as_u64()
        .ok_or_else(|| ConfigError(format!("{name} must be a whole number")))?;
    check_range(&name, number, min, max).map(Some)
}
