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
pub struct ShutdownRequest {
    pub username: String,
}

/// Tool for shutting down the pgmoneta server.
pub struct ShutdownTool;

impl ToolBase for ShutdownTool {
    type Parameter = ShutdownRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "shutdown".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Shutdown the pgmoneta server. \
            The username has to be one of the pgmoneta admins to be able to perform this action. \
            Note: After pgmoneta is shut down, subsequent backup-related tool calls will fail until pgmoneta is restarted."
                .into(),
        )
    }

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ShutdownTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ShutdownRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_shutdown(&request.username)
            .await
            .map_err(|e| {
                let error_msg = format!("{:?}", e);
                if error_msg.contains("Connection refused")
                    || error_msg.contains("connect")
                    || error_msg.contains("os error 111")
                {
                    McpError::internal_error(
                        format!(
                            "Failed to connect to pgmoneta server: {}. \
                             Hint: The pgmoneta server may not be running.",
                            error_msg
                        ),
                        None,
                    )
                } else {
                    McpError::internal_error(format!("Failed to shutdown pgmoneta: {:?}", e), None)
                }
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_shutdown_tool_metadata() {
        assert_eq!(ShutdownTool::name(), "shutdown");
        let desc = ShutdownTool::description();
        assert!(desc.is_some());
        let desc_str = desc.unwrap().to_lowercase();
        assert!(desc_str.contains("shutdown"));
        assert!(desc_str.contains("pgmoneta"));
    }
}
