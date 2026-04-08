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

pub mod compression;
pub mod conf;
pub mod hello;
pub mod info;
pub mod mode;
pub mod retention;
pub mod shutdown;

use super::constant::*;
use super::constant::{Command, Compression, Encryption};
use crate::utils::Utility;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::router::tool::ToolRouter,
    model::*, service::RequestContext, tool_handler,
};
use serde_json::Map;
use serde_json::Value;

/// The core handler for incoming Model Context Protocol (MCP) requests.
///
/// This struct routes MCP tool calls from the client (like an AI model)
/// to the appropriate internal functions that communicate with pgmoneta.
#[derive(Clone)]
pub struct PgmonetaHandler {
    tool_router: ToolRouter<PgmonetaHandler>,
}

impl PgmonetaHandler {
    /// Creates a new instance of the `PgmonetaHandler` with an initialized tool router.
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// Builds the tool router by registering each tool via the trait-based API.
    pub fn tool_router() -> ToolRouter<Self> {
        ToolRouter::new()
            .with_sync_tool::<hello::SayHelloTool>()
            .with_async_tool::<info::GetBackupInfoTool>()
            .with_async_tool::<info::ListBackupsTool>()
            .with_async_tool::<retention::RetainBackupTool>()
            .with_async_tool::<retention::ExpungeBackupTool>()
            .with_async_tool::<shutdown::ShutdownTool>()
            .with_async_tool::<conf::ConfReloadTool>()
            .with_async_tool::<conf::ConfLsTool>()
            .with_async_tool::<conf::ConfGetTool>()
            .with_async_tool::<conf::ConfSetTool>()
            .with_async_tool::<mode::SetModeTool>()
            .with_async_tool::<compression::CompressFileTool>()
            .with_async_tool::<compression::DecompressFileTool>()
    }
}

impl PgmonetaHandler {
    /// Parses the raw string response from pgmoneta into a JSON map.
    ///
    /// Ensures the response contains the required `Outcome` category key.
    pub(crate) fn _parse_and_check_result(result: &str) -> Result<Map<String, Value>, McpError> {
        let response: Map<String, Value> = serde_json::from_str(result).map_err(|e| {
            McpError::parse_error(format!("Failed to parse result {result}: {:?}", e), None)
        })?;
        if !response.contains_key(MANAGEMENT_CATEGORY_OUTCOME) {
            return Err(McpError::internal_error(
                format!("Fail to find outcome inside response {:?}", response),
                None,
            ));
        }
        Ok(response)
    }

    /// Recursively translates numeric/raw fields in the pgmoneta response into human-readable formats.
    ///
    /// This includes:
    /// * Formatting byte counts into human-readable file sizes (e.g., KB, MB).
    /// * Converting LSNs (Log Sequence Numbers) into hex strings.
    /// * Translating numeric enum codes (Compression, Encryption, Error) into descriptive strings.
    pub(crate) fn _translate_result<'a, M>(map: M) -> anyhow::Result<Map<String, Value>>
    where
        M: IntoIterator<Item = (&'a String, &'a Value)>,
    {
        // fields to be translated
        // file size, hex string, compression, encryption, command method, object(recursive), error
        let file_size_fields = vec![
            "BackupSize",
            "RestoreSize",
            "BiggestFileSize",
            "Delta",
            "TotalSpace",
            "FreeSpace",
            "UsedSpace",
            "WorkspaceFreeSpace",
            "HotStandbySize",
        ];
        let hex_string_fields = [
            "CheckpointHiLSN",
            "CheckpointLoLSN",
            "StartHiLSN",
            "StartLoLSN",
            "EndHiLSN",
            "EndLoLSN",
        ];
        let object_arr_fields = ["Backups"];
        let compression_field = "Compression";
        let encryption_field = "Encryption";
        let command_field = "Command";
        let error_field = "Error";

        let mut trans_res: Map<String, Value> = Map::new();
        for (key, value) in map {
            if file_size_fields.contains(&key.as_str()) {
                let size = value.as_u64().unwrap();
                let size_str = Utility::format_file_size(size);
                trans_res.insert(key.clone(), Value::from(size_str));
            } else if hex_string_fields.contains(&key.as_str()) {
                let num = value.as_u64().unwrap();
                let hex_str = format!("0x{:X}", num);
                trans_res.insert(key.clone(), Value::from(hex_str));
            } else if key == compression_field {
                let compression = value.as_u64().unwrap();
                let compression_str = Compression::translate_compression_enum(compression as u8)?;
                trans_res.insert(key.clone(), Value::from(compression_str));
            } else if key == encryption_field {
                let encryption = value.as_u64().unwrap();
                let encryption_str = Encryption::translate_encryption_enum(encryption as u8)?;
                trans_res.insert(key.clone(), Value::from(encryption_str));
            } else if key == command_field {
                let command = value.as_u64().unwrap();
                let command_str = Command::translate_command_enum(command as u32)?;
                trans_res.insert(key.clone(), Value::from(command_str));
            } else if key == error_field {
                let error = value.as_u64().unwrap();
                let error_msg = ManagementError::translate_error_enum(error as u32);
                trans_res.insert(key.clone(), Value::from(error_msg));
            } else if object_arr_fields.contains(&key.as_str()) {
                let mut trans_arr: Vec<Value> = Vec::new();
                if value.as_array().is_none() {
                    trans_res.insert(key.clone(), Value::from(trans_arr));
                    return Ok(trans_res);
                }
                let arr = value.as_array().unwrap();
                for item in arr {
                    if let Value::Object(object) = item {
                        let trans_obj = Self::_translate_result(object)?;
                        trans_arr.push(Value::Object(trans_obj));
                    } else {
                        trans_arr.push(item.clone())
                    }
                }
                trans_res.insert(key.clone(), Value::from(trans_arr));
                return Ok(trans_res);
            } else if value.is_object() {
                let object = value.as_object().unwrap();
                let trans_obj = Self::_translate_result(object)?;
                trans_res.insert(key.clone(), Value::Object(trans_obj));
            } else {
                trans_res.insert(key.clone(), value.clone());
            }
        }
        Ok(trans_res)
    }

    /// Parses, translates, and serializes the pgmoneta response into a JSON string
    /// suitable for returning as tool output.
    pub(crate) fn generate_call_tool_result_string(result: &str) -> Result<String, McpError> {
        let res = Self::_parse_and_check_result(result)?;
        let trans_res = Self::_translate_result(&res).map_err(|e| {
            McpError::internal_error(
                format!("Failed to translate some of the result fields: {:?}", e),
                None,
            )
        })?;
        serde_json::to_string(&trans_res).map_err(|e| {
            McpError::internal_error(format!("Failed to serialize result: {:?}", e), None)
        })
    }
}

impl Default for PgmonetaHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[tool_handler]
impl ServerHandler for PgmonetaHandler {
    /// Provides the MCP initialization capabilities and metadata for this server.
    fn get_info(&self) -> ServerInfo {
        let pkg_name = env!("CARGO_PKG_NAME");
        let pkg_version = env!("CARGO_PKG_VERSION");

        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new(pkg_name, pkg_version))
            .with_instructions("This server provides capabilities to interact with pgmoneta, a backup/restore tool for PostgreSQL.")
    }

    /// Handles the initial connection setup and handshake from an MCP client.
    async fn initialize(
        &self,
        _request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, McpError> {
        if let Some(http_request_part) = context.extensions.get::<axum::http::request::Parts>() {
            let initialize_headers = &http_request_part.headers;
            let initialize_uri = &http_request_part.uri;
            tracing::info!(?initialize_headers, %initialize_uri, "initialize from http server");
        }
        Ok(self.get_info())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_parse_and_check_result_valid() {
        let input = r#"{"Outcome": "success", "Server": "test"}"#;
        let result = PgmonetaHandler::_parse_and_check_result(input);
        assert!(result.is_ok());
        let map = result.unwrap();
        assert_eq!(map.get("Outcome").unwrap(), "success");
        assert_eq!(map.get("Server").unwrap(), "test");
    }

    #[test]
    fn test_parse_and_check_result_missing_outcome() {
        let input = r#"{"Server": "test"}"#;
        let result = PgmonetaHandler::_parse_and_check_result(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_and_check_result_invalid_json() {
        let input = "not valid json";
        let result = PgmonetaHandler::_parse_and_check_result(input);
        assert!(result.is_err());
    }

    #[test]
    fn test_translate_result_file_size() {
        let mut map = Map::new();
        map.insert("BackupSize".to_string(), json!(1048576));
        map.insert("Server".to_string(), json!("test"));

        let result = PgmonetaHandler::_translate_result(&map);
        assert!(result.is_ok());
        let translated = result.unwrap();
        assert_eq!(translated.get("BackupSize").unwrap(), "1.00 MB");
        assert_eq!(translated.get("Server").unwrap(), "test");
    }

    #[test]
    fn test_generate_call_tool_result_string_valid() {
        let input = r#"{"Outcome": "success", "BackupSize": 2048}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);
        assert!(result.is_ok());
        let output = result.unwrap();
        // The output should be a JSON string with translated fields
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed.get("Outcome").unwrap(), "success");
        assert_eq!(parsed.get("BackupSize").unwrap(), "2.00 KB");
    }
}
