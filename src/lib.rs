//! Read-only MCP server for PostgreSQL and TimescaleDB.

pub mod audit;
pub mod config;
pub mod encode;
pub mod gate;
pub mod http_guard;
pub mod pg;
pub mod resources;
pub mod server;
pub mod tools;
pub mod typeinfo;

pub use server::{AppState, build_router, run};
