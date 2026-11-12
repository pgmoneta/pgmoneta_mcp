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
pub struct AnnotateRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
    pub action: String,
    pub key: String,
    pub comment: Option<String>,
}

/// Tool for adding or updating backup annotations.
pub struct AnnotateBackupTool;

impl ToolBase for AnnotateBackupTool {
    type Parameter = AnnotateRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "annotate_backup".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Annotate a backup using an action and key. \
            Supported actions are add, remove and update. \
            The add and update actions require a comment. \
            The remove action does not require a comment. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for AnnotateBackupTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: AnnotateRequest,
    ) -> Result<String, McpError> {
        let action = normalize_action(&request.action)?;

        let comment = match action.as_str() {
            "add" | "update" => {
                let value = request.comment.as_deref().unwrap_or("").trim();
                if value.is_empty() {
                    return Err(McpError::invalid_params(
                        format!("The '{}' action requires a non-empty comment", action),
                        None,
                    ));
                }
                Some(value)
            }
            "remove" => None,
            _ => None,
        };

        let result: String = PgmonetaClient::request_annotate(
            &request.username,
            &request.server,
            &request.backup_id,
            &action,
            &request.key,
            comment,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to annotate backup: {:?}", e), None)
        })?;

        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

fn normalize_action(action: &str) -> Result<String, McpError> {
    let normalized = action.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "add" | "update" | "remove" => Ok(normalized),
        _ => Err(McpError::invalid_params(
            format!(
                "Unsupported annotate action '{}'. Supported actions: add, remove, update",
                action
            ),
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use rmcp::handler::server::router::tool::ToolBase;
    use serde_json::{Map, Value};

    #[test]
    fn test_annotate_backup_tool_metadata() {
        assert_eq!(AnnotateBackupTool::name(), "annotate_backup");
        assert!(AnnotateBackupTool::description().is_some());
        assert!(
            AnnotateBackupTool::description()
                .unwrap()
                .to_ascii_lowercase()
                .contains("annotate")
        );
    }

    #[test]
    fn test_handler_has_annotate_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"annotate_backup"),
            "annotate_backup tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_normalize_action() {
        assert_eq!(normalize_action(" add ").unwrap(), "add");
        assert_eq!(normalize_action("UPDATE").unwrap(), "update");
        assert_eq!(normalize_action("Remove").unwrap(), "remove");
        assert!(normalize_action("replace").is_err());
    }

    #[test]
    fn test_generate_call_tool_result_string_annotate() {
        let response = r#"{"Outcome": {"Status": true, "Command": 20}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "annotate");
    }

    #[test]
    fn test_annotate_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 20, "Error": 2506}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Annotate: unknown action");
    }
}
