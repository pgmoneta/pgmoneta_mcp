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

use super::PgmonetaClient;
use super::PgmonetaHandler;
use rmcp::ErrorData as McpError;
use rmcp::model::{CallToolResult, Content};
use rmcp::schemars;

#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct InfoRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
}

impl PgmonetaHandler {
    pub(super) async fn _get_backup_info(
        &self,
        request: InfoRequest,
    ) -> Result<CallToolResult, McpError> {
        let result = PgmonetaClient::request_backup_info(
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
        let result = Self::_parse_and_check_result(&result)?;
        let trans_res = Self::_translate_result(&result).map_err(|e| {
            McpError::internal_error(
                format!("Failed to translate some of the result fields: {:?}", e),
                None,
            )
        })?;
        let trans_res_str = serde_json::to_string(&trans_res).map_err(|e| {
            McpError::internal_error(format!("Failed to serialize result: {:?}", e), None)
        })?;
        Ok(CallToolResult::success(vec![Content::text(trans_res_str)]))
    }
}
