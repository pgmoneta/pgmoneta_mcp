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
pub struct StatusRequest {
    pub username: String,
}

/// Tool for retrieving the overall status of the pgmoneta server.
pub struct GetStatusTool;

impl ToolBase for GetStatusTool {
    type Parameter = StatusRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "status".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Get the status of the pgmoneta server. \
            Returns general information such as server version, number of servers, \
            total space, free space and used space."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for GetStatusTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: StatusRequest,
    ) -> Result<String, McpError> {
        let result = PgmonetaClient::request_status(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to retrieve status: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for retrieving detailed per-server status from pgmoneta.
pub struct GetStatusDetailsTool;

impl ToolBase for GetStatusDetailsTool {
    type Parameter = StatusRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "status_details".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Get detailed status of the pgmoneta server. \
            Returns per-server information including backup sizes, WAL, \
            retention policy, hot standby size and workers."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for GetStatusDetailsTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: StatusRequest,
    ) -> Result<String, McpError> {
        let result = PgmonetaClient::request_status_details(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(
                    format!("Failed to retrieve status details: {:?}", e),
                    None,
                )
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
    fn test_get_status_tool_metadata() {
        assert_eq!(GetStatusTool::name(), "status");
        let desc = GetStatusTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("status"));
    }

    #[test]
    fn test_get_status_details_tool_metadata() {
        assert_eq!(GetStatusDetailsTool::name(), "status_details");
        let desc = GetStatusDetailsTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("detailed"));
    }

    #[test]
    fn test_handler_has_status_tools() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"status"),
            "status tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"status_details"),
            "status_details tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_status() {
        let response = r#"{"Outcome": {"Status": true, "Command": 7}, "TotalSpace": 1073741824, "FreeSpace": 536870912, "UsedSpace": 536870912}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);

        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "status");
        assert_eq!(parsed["TotalSpace"], "1.00 GB");
        assert_eq!(parsed["FreeSpace"], "512.00 MB");
        assert_eq!(parsed["UsedSpace"], "512.00 MB");
    }

    #[test]
    fn test_generate_call_tool_result_string_status_details() {
        let response = r#"{"Outcome": {"Status": true, "Command": 8}, "HotStandbySize": 2147483648, "WorkspaceFreeSpace": 10737418240}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);

        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "status details");
        assert_eq!(parsed["HotStandbySize"], "2.00 GB");
        assert_eq!(parsed["WorkspaceFreeSpace"], "10.00 GB");
    }

    #[test]
    fn test_status_details_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 8, "Error": 1100}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);

        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Status details: no fork");
    }
}
