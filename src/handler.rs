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

pub mod annotate;
pub mod archive;
pub mod backup;
pub mod clear;
pub mod compression;
pub mod conf;
pub mod delete;
pub mod encryption;
pub mod info;
pub mod job;
pub mod metrics;
pub mod mode;
pub mod ping;
pub mod restore;
pub mod retention;
pub mod shutdown;
pub mod status;
pub mod verify;

use super::constant::*;
use super::constant::{Command, Compression, Encryption};
use crate::utils::Utility;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, handler::server::router::tool::ToolRouter,
    model::*, service::RequestContext, tool_handler,
};
use serde_json::Map;
use serde_json::Value;

/// MCP annotations for the tools, so a client can tell the tools that only
/// read from pgmoneta apart from the ones that change or remove something.
pub mod hints {
    use rmcp::model::ToolAnnotations;

    /// The tool only reads from pgmoneta.
    pub fn read_only() -> ToolAnnotations {
        ToolAnnotations::new().read_only(true)
    }

    /// The tool changes something, but does not remove or overwrite data.
    pub fn additive() -> ToolAnnotations {
        ToolAnnotations::new().read_only(false).destructive(false)
    }

    /// The tool can remove or overwrite data, or stop the server.
    pub fn destructive() -> ToolAnnotations {
        ToolAnnotations::new().read_only(false).destructive(true)
    }
}

/// The core handler for incoming Model Context Protocol (MCP) requests.
///
/// This struct routes MCP tool calls from the client (like an AI model)
/// to the appropriate internal functions that communicate with pgmoneta.
#[derive(Clone)]
pub struct PgmonetaHandler;

impl PgmonetaHandler {
    /// Creates a new instance of the `PgmonetaHandler` with an initialized tool router.
    pub fn new() -> Self {
        Self
    }

    /// Builds the tool router by registering each tool via the trait-based API.
    pub fn tool_router() -> ToolRouter<Self> {
        ToolRouter::new()
            .with_async_tool::<annotate::AnnotateBackupTool>()
            .with_async_tool::<archive::ArchiveTool>()
            .with_async_tool::<backup::BackupServerTool>()
            .with_async_tool::<clear::ClearTool>()
            .with_async_tool::<info::GetBackupInfoTool>()
            .with_async_tool::<info::ListBackupsTool>()
            .with_async_tool::<job::JobTool>()
            .with_async_tool::<job::JobStatusTool>()
            .with_async_tool::<job::JobListAllTool>()
            .with_async_tool::<job::JobListServerTool>()
            .with_async_tool::<job::JobListStatusTool>()
            .with_async_tool::<job::JobRemoveTool>()
            .with_async_tool::<metrics::GetMetricsTool>()
            .with_async_tool::<metrics::MetricTool>()
            .with_async_tool::<retention::RetainBackupTool>()
            .with_async_tool::<restore::RestoreTool>()
            .with_async_tool::<retention::ExpungeBackupTool>()
            .with_async_tool::<shutdown::ShutdownTool>()
            .with_async_tool::<conf::ConfReloadTool>()
            .with_async_tool::<conf::ConfLsTool>()
            .with_async_tool::<conf::ConfGetTool>()
            .with_async_tool::<conf::ConfSetTool>()
            .with_async_tool::<mode::SetModeTool>()
            .with_async_tool::<ping::PingTool>()
            .with_async_tool::<compression::CompressFileTool>()
            .with_async_tool::<compression::DecompressFileTool>()
            .with_async_tool::<encryption::EncryptFileTool>()
            .with_async_tool::<encryption::DecryptFileTool>()
            .with_async_tool::<verify::VerifyBackupTool>()
            .with_async_tool::<delete::DeleteTool>()
            .with_async_tool::<status::StatusTool>()
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
            if value.is_null() {
                trans_res.insert(key.clone(), Value::from(""));
            } else if file_size_fields.contains(&key.as_str()) {
                if let Some(size) = value.as_u64() {
                    let size_str = Utility::format_file_size(size);
                    trans_res.insert(key.clone(), Value::from(size_str));
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if hex_string_fields.contains(&key.as_str()) {
                if let Some(num) = value.as_u64() {
                    let hex_str = format!("0x{:X}", num);
                    trans_res.insert(key.clone(), Value::from(hex_str));
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if key == compression_field {
                if let Some(compression) = value.as_u64() {
                    match Compression::translate_compression_enum(compression as u8) {
                        Ok(compression_str) => {
                            trans_res.insert(key.clone(), Value::from(compression_str));
                        }
                        Err(_) => {
                            trans_res.insert(key.clone(), Value::from("zstd"));
                        }
                    }
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if key == encryption_field {
                if let Some(encryption) = value.as_u64() {
                    match Encryption::translate_encryption_enum(encryption as u8) {
                        Ok(encryption_str) => {
                            trans_res.insert(key.clone(), Value::from(encryption_str));
                        }
                        Err(_) => {
                            trans_res.insert(key.clone(), value.clone());
                        }
                    }
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if key == command_field {
                if let Some(command) = value.as_u64() {
                    match Command::translate_command_enum(command as u32) {
                        Ok(command_str) => {
                            trans_res.insert(key.clone(), Value::from(command_str));
                        }
                        Err(_) => {
                            trans_res.insert(key.clone(), value.clone());
                        }
                    }
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if key == error_field {
                if let Some(error) = value.as_u64() {
                    let error_msg = ManagementError::translate_error_enum(error as u32);
                    trans_res.insert(key.clone(), Value::from(error_msg));
                } else {
                    trans_res.insert(key.clone(), value.clone());
                }
            } else if object_arr_fields.contains(&key.as_str()) {
                let mut trans_arr: Vec<Value> = Vec::new();
                if let Some(arr) = value.as_array() {
                    for item in arr {
                        if let Value::Object(object) = item {
                            let trans_obj = Self::_translate_result(object)?;
                            trans_arr.push(Value::Object(trans_obj));
                        } else {
                            trans_arr.push(item.clone())
                        }
                    }
                }
                trans_res.insert(key.clone(), Value::from(trans_arr));
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
    pub fn generate_call_tool_result_string(result: &str) -> Result<String, McpError> {
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
    fn get_info(&self) -> ServerConfig {
        let pkg_name = env!("CARGO_PKG_NAME");
        let pkg_version = env!("CARGO_PKG_VERSION");

        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
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
            tracing::debug!(?initialize_headers, %initialize_uri, "initialize from http server");
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

    #[test]
    fn test_generate_call_tool_result_string_preserves_null_command() {
        let input = r#"{"Outcome":"success","Response":{"Command":null}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);

        assert!(result.is_ok());
        let parsed: Map<String, Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["Response"]["Command"], json!(""));
    }

    #[test]
    fn test_translate_result_preserves_null_backups_and_following_fields() {
        let input = r#"{"Outcome":"success","Backups":null,"Elapsed":12}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);

        assert!(result.is_ok());
        let parsed: Map<String, Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["Backups"], json!(""));
        assert_eq!(parsed["Elapsed"], json!(12));
    }

    #[test]
    fn test_translate_result_defaults_unknown_compression_enum_to_zstd() {
        let input = r#"{"Outcome":"success","Compression":18}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);

        assert!(result.is_ok());
        let parsed: Map<String, Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["Compression"], json!("zstd"));
    }

    #[test]
    fn test_translate_result_preserves_unknown_command_enum() {
        let input = r#"{"Outcome":"success","Response":{"Command":999}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);

        assert!(result.is_ok());
        let parsed: Map<String, Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["Response"]["Command"], json!(999));
    }

    #[test]
    fn test_translate_result_normalizes_backup_entries() {
        let input = r#"{
            "Outcome":"success",
            "Response":{
                "Backups":[
                    {
                        "Comments":null,
                        "IncrementalParent":null,
                        "Compression":18
                    }
                ]
            }
        }"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(input);

        assert!(result.is_ok());
        let parsed: Map<String, Value> = serde_json::from_str(&result.unwrap()).unwrap();
        assert_eq!(parsed["Response"]["Backups"][0]["Comments"], json!(""));
        assert_eq!(
            parsed["Response"]["Backups"][0]["IncrementalParent"],
            json!("")
        );
        assert_eq!(
            parsed["Response"]["Backups"][0]["Compression"],
            json!("zstd")
        );
    }

    #[test]
    fn test_every_tool_says_whether_it_is_read_only() {
        let tools = PgmonetaHandler::tool_router().list_all();
        assert!(!tools.is_empty());

        for tool in &tools {
            let annotations = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("tool '{}' has no annotations", tool.name));
            let read_only = annotations
                .read_only_hint
                .unwrap_or_else(|| panic!("tool '{}' has no readOnlyHint", tool.name));
            if !read_only {
                assert!(
                    annotations.destructive_hint.is_some(),
                    "tool '{}' changes things but has no destructiveHint",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn test_tool_hints_match_what_the_tools_do() {
        let router = PgmonetaHandler::tool_router();
        let annotations = |name: &str| {
            router
                .get(name)
                .and_then(|tool| tool.annotations.clone())
                .unwrap_or_else(|| panic!("tool '{name}' is missing or has no annotations"))
        };

        for name in [
            "get_info",
            "list_backups",
            "status",
            "ping",
            "conf_ls",
            "conf_get",
            "get_metrics",
            "metric",
            "job",
            "job_status",
            "job_list_all",
            "job_list_server",
            "job_list_status",
        ] {
            assert_eq!(annotations(name).read_only_hint, Some(true), "{name}");
        }

        for name in [
            "delete",
            "expunge",
            "restore",
            "shutdown",
            "clear",
            "conf_set",
            "job_remove",
        ] {
            let hints = annotations(name);
            assert_eq!(hints.read_only_hint, Some(false), "{name}");
            assert!(hints.is_destructive(), "{name}");
        }

        for name in ["backup", "archive", "retain", "set_mode", "conf_reload"] {
            let hints = annotations(name);
            assert_eq!(hints.read_only_hint, Some(false), "{name}");
            assert!(!hints.is_destructive(), "{name}");
        }
    }
}
