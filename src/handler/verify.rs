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
pub struct VerifyRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
    #[serde(default)]
    pub directory: Option<String>,
}

/// Tool for verifying the integrity of a specific backup.
pub struct VerifyBackupTool;

impl ToolBase for VerifyBackupTool {
    type Parameter = VerifyRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "verify".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::additive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Verify the integrity of a backup using given backup ID and server name. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            Optionally provide a target directory; /tmp is used by default. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta"
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = VerifyRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for VerifyBackupTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: VerifyRequest,
    ) -> Result<String, McpError> {
        let directory = request.directory.as_deref().unwrap_or("/tmp");
        let result: String = PgmonetaClient::request_verify(
            &request.username,
            &request.server,
            &request.backup_id,
            directory,
        )
        .await
        .map_err(|e| McpError::internal_error(format!("Failed to verify backup: {:?}", e), None))?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use rmcp::handler::server::router::tool::ToolBase;
    use serde_json::{Map, Value, json};

    #[test]
    fn test_verify_backup_tool_metadata() {
        assert_eq!(VerifyBackupTool::name(), "verify");
        let desc = VerifyBackupTool::description();
        assert!(desc.is_some());
        let desc = desc.unwrap();
        assert!(desc.contains("Verify"));
        assert!(desc.contains("/tmp"));
    }

    #[test]
    fn test_handler_has_verify_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"verify"),
            "verify tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_verify_request_directory_defaults_to_none_on_deserialize() {
        let request: VerifyRequest = serde_json::from_value(json!({
            "username": "alice",
            "server": "main",
            "backup_id": "latest"
        }))
        .unwrap();

        assert_eq!(request.username, "alice");
        assert_eq!(request.server, "main");
        assert_eq!(request.backup_id, "latest");
        assert_eq!(request.directory, None);
    }

    #[test]
    fn test_verify_request_deserializes_explicit_directory() {
        let request: VerifyRequest = serde_json::from_value(json!({
            "username": "alice",
            "server": "main",
            "backup_id": "latest",
            "directory": "/var/tmp/verify"
        }))
        .unwrap();

        assert_eq!(request.directory.as_deref(), Some("/var/tmp/verify"));
    }

    #[test]
    fn test_generate_call_tool_result_string_verify() {
        let response = r#"{"Outcome": {"Status": true, "Command": 19}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "verify");
    }

    #[test]
    fn test_verify_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 19, "Error": 805}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Verify: network error");
    }
}
