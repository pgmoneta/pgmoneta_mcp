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
use crate::constant::Sort;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct InfoRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ListBackupsRequest {
    pub username: String,
    pub server: String,
    pub sort: Option<String>,
}

/// Tool for fetching detailed information about a specific backup.
pub struct GetBackupInfoTool;

impl ToolBase for GetBackupInfoTool {
    type Parameter = InfoRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "get_backup_info".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Get information of a backup using given backup ID and server name. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta"
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = InfoRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for GetBackupInfoTool {
    async fn invoke(_service: &PgmonetaHandler, request: InfoRequest) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_backup_info(
            &request.username,
            &request.server,
            &request.backup_id,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(
                format!("Failed to retrieve backup information: {:?}", e),
                None,
            )
        })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for listing available backups on a specified server.
pub struct ListBackupsTool;

impl ToolBase for ListBackupsTool {
    type Parameter = ListBackupsRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "list_backups".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "List backups of a server. \
            Specify asc or desc to determine the sorting order. \
            The backups are sorted in ascending order if not specified."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = ListBackupsRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ListBackupsTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ListBackupsRequest,
    ) -> Result<String, McpError> {
        let sort = request.sort.unwrap_or(Sort::ASC.to_string());
        let result: String =
            PgmonetaClient::request_list_backups(&request.username, &request.server, &sort)
                .await
                .map_err(|e| {
                    McpError::internal_error(format!("Failed to list backups: {:?}", e), None)
                })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_get_backup_info_tool_metadata() {
        assert_eq!(GetBackupInfoTool::name(), "get_backup_info");
        let desc = GetBackupInfoTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("backup"));
    }

    #[test]
    fn test_list_backups_tool_metadata() {
        assert_eq!(ListBackupsTool::name(), "list_backups");
        let desc = ListBackupsTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("backups"));
    }
}
