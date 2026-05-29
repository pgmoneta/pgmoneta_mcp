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

#[derive(Debug, Default, serde::Serialize, serde::Deserialize, schemars::JsonSchema)]
pub struct WalInfoRequest {
    pub username: String,
    pub server: String,
    /// Output mode: "user" (human-readable timeline, default) or "developer" (raw JSON).
    pub mode: Option<String>,
    /// Filter records by time of day. Accepts natural formats such as "4:02pm","16:02", "13:24:57". Records within `window_minutes` of this time are returned.
    pub time: Option<String>,
    /// Minutes either side of `time` to include (default: 5).
    pub window_minutes: Option<u32>,
}

/// Tool for retrieving WAL information for a given server.
pub struct WalInfoTool;

impl ToolBase for WalInfoTool {
    type Parameter = WalInfoRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "walinfo".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Get Write-Ahead Log (WAL) information for a PostgreSQL server managed by pgmoneta.\n\
            \n\
            Output modes (via the `mode` field):\n\
            • \"user\" (default)  human-readable transaction timeline grouped by XID\n\
            • \"developer\"       raw JSON records from pgmoneta-walinfo\n\
            \n\
            Time filtering (via the `time` field):\n\
            • Accepts natural formats: \"4:02pm\", \"4pm\", \"16:02\", \"13:24:57\"\n\
            • Use `window_minutes` (default 5) to widen the time window\n\
            • Example: time=\"4:02pm\" window_minutes=10 shows ±10 min around 16:02\n\
            \n\
            The `username` must be one of the pgmoneta admins."
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

impl AsyncTool<PgmonetaHandler> for WalInfoTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: WalInfoRequest,
    ) -> Result<String, McpError> {
        let is_developer = request
            .mode
            .as_deref()
            .map(|m| m.eq_ignore_ascii_case("developer"))
            .unwrap_or(false);

        let result: String = PgmonetaClient::request_walinfo(
            &request.username,
            &request.server,
            request.mode,
            request.time,
            request.window_minutes,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to retrieve WAL information: {:?}", e), None)
        })?;

        if is_developer {
            PgmonetaHandler::generate_call_tool_result_string(&result)
        } else {
            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_walinfo_tool_metadata() {
        assert_eq!(WalInfoTool::name(), "walinfo");
        let desc = WalInfoTool::description();
        assert!(desc.is_some());
        let desc = desc.unwrap();
        assert!(desc.contains("WAL"));
        assert!(desc.contains("pgmoneta admins"));
        assert!(desc.contains("user"));
        assert!(desc.contains("developer"));
    }

    #[test]
    fn test_handler_has_walinfo_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"walinfo"),
            "walinfo tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_walinfo_request_deserializes_minimal() {
        let request: WalInfoRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "server": "primary"
        }))
        .expect("Failed to deserialize WalInfoRequest");
        assert_eq!(request.username, "alice");
        assert_eq!(request.server, "primary");
        assert!(request.mode.is_none());
        assert!(request.time.is_none());
        assert!(request.window_minutes.is_none());
    }

    #[test]
    fn test_walinfo_request_deserializes_full() {
        let request: WalInfoRequest = serde_json::from_value(serde_json::json!({
            "username": "alice",
            "server": "primary",
            "mode": "developer",
            "time": "4:02pm",
            "window_minutes": 10
        }))
        .expect("Failed to deserialize WalInfoRequest");
        assert_eq!(request.mode.as_deref(), Some("developer"));
        assert_eq!(request.time.as_deref(), Some("4:02pm"));
        assert_eq!(request.window_minutes, Some(10));
    }

    #[test]
    fn test_walinfo_tool_output_schema_is_none() {
        assert!(WalInfoTool::output_schema().is_none());
    }
}
