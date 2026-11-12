// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::borrow::Cow;
use std::sync::Arc;

use super::{PgmonetaHandler, hints};
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ClearRequest {
    pub username: String,
}

/// Tool for clearing data or statistics.
pub struct ClearTool;

impl ToolBase for ClearTool {
    type Parameter = ClearRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "clear".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Clear or Reset Prometheus data or statistics. \
            Requires a username of a pgmoneta admin to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ClearTool {
    async fn invoke(_service: &PgmonetaHandler, request: ClearRequest) -> Result<String, McpError> {
        let result = PgmonetaClient::request_clear_data(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to clear data: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use rmcp::handler::server::router::tool::ToolBase;
    use serde_json::{Map, Value};

    #[test]
    fn test_clear_data_tool_metadata() {
        assert_eq!(ClearTool::name(), "clear");
        let desc = ClearTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("Clear"));
    }

    #[test]
    fn test_handler_has_clear_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"clear"),
            "clear tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_clear() {
        let response = r#"{"Outcome": {"Status": true, "Command": 10}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "clear prometheus");
    }
}
