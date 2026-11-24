//! Read-only MCP server for PostgreSQL and TimescaleDB.

pub mod config;
pub mod encode;
pub mod gate;
pub mod http_guard;
pub mod pg;
pub mod typeinfo;

pub async fn run() -> std::process::ExitCode {
    std::process::ExitCode::SUCCESS
}
