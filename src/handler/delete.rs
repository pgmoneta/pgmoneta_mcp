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
pub struct DeleteRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
    pub force: Option<bool>,
    /// Return immediately with a job identifier and run the deletion in the background.
    #[serde(rename = "async")]
    #[schemars(rename = "async")]
    pub asynchronous: Option<bool>,
}

/// Tool for deleting a backup.
pub struct DeleteTool;

impl ToolBase for DeleteTool {
    type Parameter = DeleteRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "delete".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Delete a backup from the pgmoneta server. \
            Requires the server name, backup identifier, and an optional force flag. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            Set async to true to return immediately with a job identifier and run the deletion in the background. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = DeleteRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for DeleteTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: DeleteRequest,
    ) -> Result<String, McpError> {
        let force = request.force.unwrap_or(false);
        let result: String = PgmonetaClient::request_delete(
            &request.username,
            &request.server,
            &request.backup_id,
            force,
            request.asynchronous.unwrap_or(false),
        )
        .await
        .map_err(|e| McpError::internal_error(format!("Failed to delete backup: {:?}", e), None))?;
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
    fn test_delete_tool_metadata() {
        assert_eq!(DeleteTool::name(), "delete");
        assert!(DeleteTool::description().is_some());
        assert!(DeleteTool::description().unwrap().contains("Delete"));
    }

    #[test]
    fn test_handler_has_delete_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"delete"),
            "delete tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_delete() {
        let response = r#"{"Outcome": {"Status": true, "Command": 5}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "delete");
    }

    #[test]
    fn test_delete_response_with_error_setup_failed() {
        let response = r#"{"Outcome": {"Status": false, "Command": 5, "Error": 500}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Delete backup: setup failed");
    }

    #[test]
    fn test_delete_response_with_error_no_backup_found() {
        let response = r#"{"Outcome": {"Status": false, "Command": 5, "Error": 505}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Delete backup: backup not found");
    }
}
