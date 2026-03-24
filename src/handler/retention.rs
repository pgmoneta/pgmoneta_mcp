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

use super::PgmonetaHandler;
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct RetainRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ExpungeRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
}

/// Tool for marking a backup as retained so it is not removed by retention policy.
pub struct RetainBackupTool;

impl ToolBase for RetainBackupTool {
    type Parameter = RetainRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "retain_backup".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Retain a backup so it will not be removed by the retention policy. \
            Requires a server name and backup ID. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = RetainRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for RetainBackupTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: RetainRequest,
    ) -> Result<String, McpError> {
        let result: String =
            PgmonetaClient::request_retain(&request.username, &request.server, &request.backup_id)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to retain backup: {:?}", e), None)
                })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for removing the retain flag from a backup so it can be removed by retention policy.
pub struct ExpungeBackupTool;

impl ToolBase for ExpungeBackupTool {
    type Parameter = ExpungeRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "expunge_backup".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Expunge a backup so it can be removed by the retention policy. \
            Requires a server name and backup ID. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ExpungeBackupTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ExpungeRequest,
    ) -> Result<String, McpError> {
        let result: String =
            PgmonetaClient::request_expunge(&request.username, &request.server, &request.backup_id)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to expunge backup: {:?}", e), None)
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
    fn test_retain_backup_tool_metadata() {
        assert_eq!(RetainBackupTool::name(), "retain_backup");
        assert!(RetainBackupTool::description().is_some());
        assert!(RetainBackupTool::description().unwrap().contains("Retain"));
    }

    #[test]
    fn test_expunge_backup_tool_metadata() {
        assert_eq!(ExpungeBackupTool::name(), "expunge_backup");
        assert!(ExpungeBackupTool::description().is_some());
        assert!(
            ExpungeBackupTool::description()
                .unwrap()
                .contains("Expunge")
        );
    }

    #[test]
    fn test_handler_has_retain_expunge_tools() {
        let handler = PgmonetaHandler::new();
        let tools = handler.tool_router.list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"retain_backup"),
            "retain_backup tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"expunge_backup"),
            "expunge_backup tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_retain() {
        let response = r#"{"Outcome": {"Status": true, "Command": 12}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "retain");
    }

    #[test]
    fn test_generate_call_tool_result_string_expunge() {
        let response = r#"{"Outcome": {"Status": true, "Command": 13}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "expunge");
    }

    #[test]
    fn test_retain_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 12, "Error": 1200}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Retention: no backup available");
    }

    #[test]
    fn test_expunge_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 13, "Error": 1300}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Expunge: no backup available");
    }
}
