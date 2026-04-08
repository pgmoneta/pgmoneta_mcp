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
pub struct CompressRequest {
    pub username: String,
    pub file_path: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct DecompressRequest {
    pub username: String,
    pub file_path: String,
}

/// Tool for compressing a file on the pgmoneta server.
pub struct CompressFileTool;

impl ToolBase for CompressFileTool {
    type Parameter = CompressRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "compress_file".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Compress a file on the pgmoneta server. \
            Requires the full file path on the server. \
            The file is compressed using the algorithm configured in pgmoneta.conf. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = CompressRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for CompressFileTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: CompressRequest,
    ) -> Result<String, McpError> {
        let result: String =
            PgmonetaClient::request_compress(&request.username, &request.file_path)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to compress file: {:?}", e), None)
                })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for decompressing a file on the pgmoneta server.
pub struct DecompressFileTool;

impl ToolBase for DecompressFileTool {
    type Parameter = DecompressRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "decompress_file".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Decompress a file on the pgmoneta server. \
            Requires the full file path on the server. \
            The file is decompressed using the algorithm configured in pgmoneta.conf. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for DecompressFileTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: DecompressRequest,
    ) -> Result<String, McpError> {
        let result: String =
            PgmonetaClient::request_decompress(&request.username, &request.file_path)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to decompress file: {:?}", e), None)
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
    fn test_compress_file_tool_metadata() {
        assert_eq!(CompressFileTool::name(), "compress_file");
        assert!(CompressFileTool::description().is_some());
        assert!(
            CompressFileTool::description()
                .unwrap()
                .contains("Compress")
        );
    }

    #[test]
    fn test_decompress_file_tool_metadata() {
        assert_eq!(DecompressFileTool::name(), "decompress_file");
        assert!(DecompressFileTool::description().is_some());
        assert!(
            DecompressFileTool::description()
                .unwrap()
                .contains("Decompress")
        );
    }

    #[test]
    fn test_handler_has_compress_decompress_tools() {
        let handler = PgmonetaHandler::new();
        let tools = handler.tool_router.list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"compress_file"),
            "compress_file tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"decompress_file"),
            "decompress_file tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_compress() {
        let response = r#"{"Outcome": {"Status": true, "Command": 17}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "compress");
    }

    #[test]
    fn test_generate_call_tool_result_string_decompress() {
        let response = r#"{"Outcome": {"Status": true, "Command": 16}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "decompress");
    }

    #[test]
    fn test_compress_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 17, "Error": 2101}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Compress: unknown format");
    }

    #[test]
    fn test_decompress_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 16, "Error": 2001}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Decompress: unknown format");
    }
}
