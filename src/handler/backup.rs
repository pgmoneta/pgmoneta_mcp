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
pub struct BackupRequest {
    pub username: String,
    pub server: String,
    pub backup_id: Option<String>,
}

/// Tool for creating a full or incremental backup of a server.
pub struct BackupServerTool;

impl ToolBase for BackupServerTool {
    type Parameter = BackupRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "backup".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Create a backup of a server. \
            Requires a server name. \
            If the backup identifier is not provided, a full backup will be created. \
            If the backup identifier is provided, an incremental backup will be created. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for BackupServerTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: BackupRequest,
    ) -> Result<String, McpError> {
        let result = if let Some(backup_id) = &request.backup_id {
            PgmonetaClient::request_backup(&request.username, &request.server, Some(backup_id))
                .await
                .map_err(|e| {
                    McpError::internal_error(
                        format!("Failed to create incremental backup: {:?}", e),
                        None,
                    )
                })?
        } else {
            PgmonetaClient::request_backup(&request.username, &request.server, None)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to create full backup: {:?}", e), None)
                })?
        };
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
    fn test_backup_server_tool_metadata() {
        assert_eq!(BackupServerTool::name(), "backup");
        let desc = BackupServerTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("backup"));
    }

    #[test]
    fn test_handler_has_backup_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"backup"),
            "backup tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_backup() {
        let response = r#"{"Outcome": {"Status": true, "Command": 1}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "backup");
    }

    #[test]
    fn test_backup_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 1, "Error": 111}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Backup: server not found");
    }
}
