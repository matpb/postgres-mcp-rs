//! MCP tool layer: error texts, the shared query runner, the tool catalog and the rmcp server handler.

pub mod core;
pub mod envelope;
pub mod logs;
pub mod monitor;
pub mod schema;
// text.rs holds every client-facing string; rustfmt leaves its layout alone.
#[rustfmt::skip]
pub mod text;
pub mod timescale;

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, Implementation,
    ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData as McpError, RoleServer, ServerHandler};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::audit;
use crate::config::{DatabaseConfig, Toolsets};
use crate::gate::{self, Accepted, GateOptions, StatementKind};
use crate::pg::pool::Pool;
use crate::pg::session::{RunError, RunOutput, SessionSettings, run_readonly};
use crate::pg::wire::{DbError, FetchLimits};
use crate::server::AppState;
use envelope::QueryEnvelope;

/// How long a call waits for a free pooled connection.
const POOL_WAIT: Duration = Duration::from_secs(10);
/// Row cap for internal queries, which the server never returns in full to a client.
const INTERNAL_MAX_ROWS: usize = 5_000;

/// Tool groups; a tool is listed and callable only when its group is enabled in the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Toolset {
    Core,
    Schema,
    Monitor,
    Logs,
    Timescale,
}

impl Toolset {
    pub fn enabled(self, toolsets: &Toolsets) -> bool {
        match self {
            Toolset::Core => true,
            Toolset::Schema => toolsets.schema,
            Toolset::Monitor => toolsets.monitor,
            Toolset::Logs => toolsets.logs,
            Toolset::Timescale => toolsets.timescale,
        }
    }
}

/// Why a tool call failed. `message` is the exact text the client receives.
#[derive(Debug)]
pub enum ToolError {
    /// Configuration or database lookup failure, shown verbatim.
    Config(String),
    /// Gate or server refusal, shown as its full text.
    Rejected(String),
    /// PostgreSQL error; its position is already relative to the submitted SQL.
    Db(Box<DbError>),
    Timeout(u64),
    Cancelled,
    Unavailable {
        database: String,
        message: String,
    },
    Internal(String),
}

impl ToolError {
    pub fn message(&self) -> String {
        match self {
            ToolError::Config(text) | ToolError::Rejected(text) => text.clone(),
            ToolError::Db(e) => db_message(e),
            ToolError::Timeout(ms) => format!(
                "The query exceeded the {ms} ms time limit and was cancelled on the server. Narrow it with WHERE, LIMIT or an aggregate."
            ),
            ToolError::Cancelled => "The request was cancelled.".to_owned(),
            ToolError::Unavailable { database, message } => {
                format!("Database \"{database}\" is unavailable: {message}")
            }
            ToolError::Internal(message) => format!("Internal error: {message}"),
        }
    }

    pub fn sqlstate(&self) -> Option<&str> {
        match self {
            ToolError::Db(e) => Some(e.code.as_str()),
            _ => None,
        }
    }

    /// Maps a session error; `offset` is the length of any SQL prefix added before the submitted text.
    pub fn from_run(error: RunError, database: &str, offset: u32) -> ToolError {
        match error {
            RunError::Refused(message) => ToolError::Rejected(refusal_text(&message)),
            RunError::Db(mut e) => {
                e.position = e
                    .position
                    .and_then(|p| p.checked_sub(offset))
                    .filter(|p| *p > 0);
                ToolError::Db(Box::new(e))
            }
            RunError::Timeout(ms) => ToolError::Timeout(ms),
            RunError::Cancelled => ToolError::Cancelled,
            RunError::Unavailable(message) => ToolError::Unavailable {
                database: database.to_owned(),
                message,
            },
            RunError::Internal(message) => ToolError::Internal(message),
        }
    }
}

fn db_message(e: &DbError) -> String {
    let mut text = format!("PostgreSQL error {}: {}", e.code, e.message);
    if let Some(detail) = &e.detail {
        text.push_str(" Detail: ");
        text.push_str(detail);
    }
    if let Some(hint) = &e.hint {
        text.push_str(" Hint: ");
        text.push_str(hint);
    }
    if let Some(position) = e.position {
        text.push_str(&format!(" Position: {position}"));
    }
    text
}

fn refusal_text(message: &str) -> String {
    if message == "statement does not return rows" {
        "Query rejected: only statements that return rows can run here.".to_owned()
    } else {
        format!("Query rejected: {message}.")
    }
}

/// One SQL execution: the text, its bind values, whether it is user SQL and its fetch limits.
pub struct Statement<'a> {
    pub sql: &'a str,
    pub params: &'a [Option<&'a str>],
    pub user_sql: bool,
    pub fetch: FetchLimits,
    /// Characters the runner prepended to the submitted SQL, subtracted from error positions.
    pub offset: u32,
}

/// Runs SQL for the tools: user SQL through the gate, internal SQL without it.
pub struct Runner<'a> {
    state: &'a AppState,
}

impl<'a> Runner<'a> {
    pub fn new(state: &'a AppState) -> Runner<'a> {
        Runner { state }
    }

    /// Gates the SQL, runs it read-only and encodes the rows.
    pub async fn user_query(
        &self,
        database: Option<&str>,
        sql: &str,
        ct: &CancellationToken,
    ) -> Result<QueryEnvelope, ToolError> {
        let limits = &self.state.config.limits;
        let (db, pool) = self.state.pool(database)?;
        let options = GateOptions {
            allow_placeholders: false,
            max_sql_bytes: limits.max_sql_bytes,
        };
        let accepted = gate::check(sql, &options)
            .map_err(|r| ToolError::Rejected(format!("Query rejected: {}", r.message)))?;
        let statement = Statement {
            sql,
            params: &[],
            user_sql: true,
            fetch: user_fetch(limits.max_rows, self.state),
            offset: 0,
        };
        let output = run(db, &pool, statement, ct).await?;
        Ok(envelope::build(
            &db.name,
            output,
            limits,
            hides_secret_rows(&accepted),
        ))
    }

    /// Runs internal SQL (no gate) and encodes the rows.
    pub async fn internal_query(
        &self,
        database: Option<&str>,
        sql: &str,
        params: &[Option<&str>],
        ct: &CancellationToken,
    ) -> Result<QueryEnvelope, ToolError> {
        let statement = Statement {
            sql,
            params,
            user_sql: false,
            fetch: user_fetch(INTERNAL_MAX_ROWS, self.state),
            offset: 0,
        };
        let (name, output) = self.internal_raw(database, statement, ct).await?;
        Ok(envelope::build(
            &name,
            output,
            &self.state.config.limits,
            false,
        ))
    }

    /// Runs internal SQL and returns the database name with the raw output.
    pub async fn internal_raw(
        &self,
        database: Option<&str>,
        statement: Statement<'_>,
        ct: &CancellationToken,
    ) -> Result<(String, RunOutput), ToolError> {
        let (db, pool) = self.state.pool(database)?;
        let output = run(db, &pool, statement, ct).await?;
        Ok((db.name.clone(), output))
    }
}

fn user_fetch(max_rows: usize, state: &AppState) -> FetchLimits {
    FetchLimits {
        max_rows,
        max_bytes: state.config.limits.max_response_bytes,
        max_value_bytes: state.config.limits.max_value_bytes,
    }
}

async fn run(
    db: &DatabaseConfig,
    pool: &Pool,
    statement: Statement<'_>,
    ct: &CancellationToken,
) -> Result<RunOutput, ToolError> {
    let settings = SessionSettings {
        statement_timeout_ms: db.statement_timeout_ms,
        lock_timeout_ms: db.lock_timeout_ms,
        fetch: statement.fetch,
        pool_wait: POOL_WAIT,
    };
    run_readonly(
        pool,
        statement.sql,
        statement.params,
        statement.user_sql,
        &settings,
        ct,
    )
    .await
    .map_err(|e| ToolError::from_run(e, &db.name, statement.offset))
}

/// `SHOW ALL` is the only statement whose rows are filtered.
fn hides_secret_rows(accepted: &Accepted) -> bool {
    matches!(&accepted.kind, StatementKind::Show { name } if name == "all")
}

/// One tool call's outcome, with what the audit line needs.
pub struct Call {
    pub result: Result<Value, ToolError>,
    pub database: Option<String>,
    pub rows: Option<usize>,
    /// The SQL text, used only to compute the audit digest.
    pub sql: Option<String>,
}

/// Serializes a successful result.
pub fn value_of<T: Serialize>(value: &T) -> Result<Value, ToolError> {
    serde_json::to_value(value).map_err(|e| ToolError::Internal(e.to_string()))
}

/// The server handler: lists the enabled tools and dispatches calls.
#[derive(Clone)]
pub struct PgMcp {
    state: Arc<AppState>,
    tools: Arc<Vec<Tool>>,
}

impl PgMcp {
    pub fn new(state: Arc<AppState>) -> PgMcp {
        let tools = core::catalog()
            .into_iter()
            .chain(schema::catalog())
            .chain(monitor::catalog())
            .chain(logs::catalog())
            .chain(timescale::catalog())
            .filter(|(set, _)| set.enabled(&state.config.toolsets))
            .map(|(_, tool)| tool)
            .collect();
        PgMcp {
            state,
            tools: Arc::new(tools),
        }
    }
}

pub fn parse_args<T: DeserializeOwned>(args: Value) -> Result<T, McpError> {
    serde_json::from_value(args)
        .map_err(|e| McpError::invalid_params(format!("invalid arguments: {e}"), None))
}

/// The client-facing success shape: structured content and the same JSON as one text block.
fn success(value: Value) -> CallToolResult {
    let text = value.to_string();
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(value);
    result
}

impl ServerHandler for PgMcp {
    fn get_info(&self) -> ServerConfig {
        let names: Vec<String> = self
            .state
            .config
            .databases
            .iter()
            .map(|d| d.name.clone())
            .collect();
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(
                "postgres-mcp",
                env!("CARGO_PKG_VERSION"),
            ))
            .with_instructions(text::server_instructions(&names))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(self.tools.as_ref().clone()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        let name = request.name.to_string();
        if !self.tools.iter().any(|t| t.name.as_ref() == name) {
            return Err(McpError::invalid_params(
                format!("unknown tool: {name}"),
                None,
            ));
        }
        let args = Value::Object(request.arguments.unwrap_or_default());
        let ct = context.ct;
        let state = &self.state;
        let started = Instant::now();
        let call = match name.as_str() {
            "list_databases" => core::list_databases(state.clone(), &ct).await,
            "execute_query" => core::execute_query(state, parse_args(args)?, &ct).await,
            "explain_query" => core::explain_query(state, parse_args(args)?, &ct).await,
            "server_info" => core::server_info(state, parse_args(args)?, &ct).await,
            _ => {
                let routed = match schema::dispatch(state, &name, args.clone(), &ct).await {
                    Some(call) => Some(call),
                    None => match monitor::dispatch(state, &name, args.clone(), &ct).await {
                        Some(call) => Some(call),
                        None => match logs::dispatch(state, &name, args.clone(), &ct).await {
                            Some(call) => Some(call),
                            None => timescale::dispatch(state, &name, args, &ct).await,
                        },
                    },
                };
                match routed {
                    Some(call) => call?,
                    None => {
                        return Err(McpError::invalid_params(
                            format!("unknown tool: {name}"),
                            None,
                        ));
                    }
                }
            }
        };
        audit::record(
            state.config.audit_log,
            &audit::Record {
                tool: &name,
                database: call.database.as_deref(),
                ok: call.result.is_ok(),
                duration: started.elapsed(),
                rows: call.rows,
                sqlstate: call.result.as_ref().err().and_then(ToolError::sqlstate),
                sql: call.sql.as_deref(),
            },
        );
        let result = match call.result {
            Ok(value) => success(value),
            Err(error) => CallToolResult::error(vec![ContentBlock::text(error.message())]),
        };
        Ok(CallToolResponse::from(result))
    }
}
