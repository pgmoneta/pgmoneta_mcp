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
pub struct EncryptRequest {
    pub username: String,
    pub file_path: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct DecryptRequest {
    pub username: String,
    pub file_path: String,
}

/// Tool for encrypting a file on the pgmoneta server.
pub struct EncryptFileTool;

impl ToolBase for EncryptFileTool {
    type Parameter = EncryptRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "encrypt".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Encrypt a file on the pgmoneta server. \
            Requires the full file path on the server. \
            The file is encrypted using the algorithm configured in pgmoneta.conf. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = EncryptRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for EncryptFileTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: EncryptRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_encrypt(&request.username, &request.file_path)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to encrypt file: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for decrypting a file on the pgmoneta server.
pub struct DecryptFileTool;

impl ToolBase for DecryptFileTool {
    type Parameter = DecryptRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "decrypt".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Decrypt a file on the pgmoneta server. \
            Requires the full file path on the server. \
            The file is decrypted using the algorithm configured in pgmoneta.conf. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for DecryptFileTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: DecryptRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_decrypt(&request.username, &request.file_path)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to decrypt file: {:?}", e), None)
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
    fn test_encrypt_file_tool_metadata() {
        assert_eq!(EncryptFileTool::name(), "encrypt");
        assert!(EncryptFileTool::description().is_some());
        assert!(EncryptFileTool::description().unwrap().contains("Encrypt"));
    }

    #[test]
    fn test_decrypt_file_tool_metadata() {
        assert_eq!(DecryptFileTool::name(), "decrypt");
        assert!(DecryptFileTool::description().is_some());
        assert!(DecryptFileTool::description().unwrap().contains("Decrypt"));
    }

    #[test]
    fn test_handler_has_encrypt_decrypt_tools() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"encrypt"),
            "encrypt tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"decrypt"),
            "decrypt tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_encrypt() {
        let response = r#"{"Outcome": {"Status": true, "Command": 15}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "encrypt");
    }

    #[test]
    fn test_generate_call_tool_result_string_decrypt() {
        let response = r#"{"Outcome": {"Status": true, "Command": 14}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "decrypt");
    }

    #[test]
    fn test_encrypt_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 15, "Error": 1500}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Encrypt: file not found");
    }

    #[test]
    fn test_decrypt_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 14, "Error": 1400}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Decrypt: file not found");
    }
}
