use rmcp::ErrorData as McpError;
use rmcp::model::Tool;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use super::{Call, Toolset};
use crate::server::AppState;

/// Server log tools with their toolset tag.
pub fn catalog() -> Vec<(Toolset, Tool)> {
    Vec::new()
}

/// Runs the named tool, or returns None when the name is not one of this module's tools.
pub async fn dispatch(
    _state: &AppState,
    _name: &str,
    _args: Value,
    _ct: &CancellationToken,
) -> Option<Result<Call, McpError>> {
    None
}
