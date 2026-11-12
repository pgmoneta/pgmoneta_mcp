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
pub struct ModeRequest {
    pub username: String,
    pub server: String,
    pub action: String,
}

/// Tool for switching a server between online and offline mode.
pub struct SetModeTool;

impl ToolBase for SetModeTool {
    type Parameter = ModeRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "set_mode".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::additive().idempotent(true))
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Switch a pgmoneta server between online and offline mode. \
            The action must be either \"online\" or \"offline\". \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta"
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = ModeRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for SetModeTool {
    async fn invoke(_service: &PgmonetaHandler, request: ModeRequest) -> Result<String, McpError> {
        let result: String =
            PgmonetaClient::request_mode(&request.username, &request.server, &request.action)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to switch server mode: {:?}", e), None)
                })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constant::{Command, ManagementError};
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_set_mode_tool_metadata() {
        assert_eq!(SetModeTool::name(), "set_mode");
        let desc = SetModeTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("online"));
    }

    #[test]
    fn test_parse_mode_success_response() {
        let response = r#"{"Outcome": {"Command": 24, "Status": "OK"}, "Server": "primary", "Mode": "online"}"#;
        let result = PgmonetaHandler::_parse_and_check_result(response);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("Outcome"));
        assert!(map.contains_key("Server"));
    }

    #[test]
    fn test_parse_mode_error_response() {
        let response = r#"{"Outcome": {"Command": 24, "Error": 2800}}"#;
        let result = PgmonetaHandler::_parse_and_check_result(response);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert!(map.contains_key("Outcome"));
    }

    #[test]
    fn test_parse_mode_missing_outcome() {
        let response = r#"{"Server": "primary", "Mode": "online"}"#;
        let result = PgmonetaHandler::_parse_and_check_result(response);
        assert!(result.is_err());
    }

    #[test]
    fn test_translate_mode_error_noserver() {
        let error_msg = ManagementError::translate_error_enum(2800);
        assert_eq!(error_msg, "Mode: no server");
    }

    #[test]
    fn test_translate_mode_error_unknown_action() {
        let error_msg = ManagementError::translate_error_enum(2805);
        assert_eq!(error_msg, "Mode: unknown action");
    }

    #[test]
    fn test_translate_mode_command() {
        let result = Command::translate_command_enum(24);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "mode");
    }

    #[test]
    fn test_generate_mode_result() {
        let response = r#"{"Outcome": {"Command": 24, "Status": "OK"}, "Server": "primary", "Mode": "online"}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
    }
}
