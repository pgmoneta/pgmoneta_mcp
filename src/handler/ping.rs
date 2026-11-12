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
pub struct PingRequest {
    pub username: String,
}

/// Tool for pinging a server to check if pgmoneta is alive.
pub struct PingTool;

impl ToolBase for PingTool {
    type Parameter = PingRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "ping".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Ping pgmoneta to check if pgmoneta is alive.".into())
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = PingRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for PingTool {
    async fn invoke(_service: &PgmonetaHandler, request: PingRequest) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_ping(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to ping server: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::Command;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_ping_tool_metadata() {
        assert_eq!(PingTool::name(), "ping");
        let desc = PingTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("alive"));
    }

    #[test]
    fn test_parse_ping_success_response() {
        let response = r#"{"Outcome": {"Command": 9, "Status": "OK"}}"#;
        let result = PgmonetaHandler::_parse_and_check_result(response);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("Outcome"));
        let outcome = map.get("Outcome").unwrap();
        assert_eq!(outcome["Command"], Command::PING);
        assert_eq!(outcome["Status"], "OK");
    }

    #[test]
    fn test_translate_ping_command() {
        let result = Command::translate_command_enum(9);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "ping");
    }

    #[test]
    fn test_generate_ping_result() {
        let response = r#"{"Outcome": {"Command": 9, "Status": "OK"}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_handler_has_ping_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"ping"),
            "ping tool should be registered, found: {:?}",
            tool_names
        );
    }
}
