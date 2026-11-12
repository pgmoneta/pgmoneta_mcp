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
pub struct ConfReloadRequest {
    pub username: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ConfLsRequest {
    pub username: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ConfGetRequest {
    pub username: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct ConfSetRequest {
    pub username: String,
    pub config_key: String,
    pub config_value: String,
}

/// Tool for reloading the pgmoneta configuration.
pub struct ConfReloadTool;

impl ToolBase for ConfReloadTool {
    type Parameter = ConfReloadRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "conf_reload".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::additive().idempotent(true))
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Reload the pgmoneta server configuration. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = ConfReloadRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ConfReloadTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ConfReloadRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_conf_reload(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to reload configuration: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for listing the pgmoneta configuration.
pub struct ConfLsTool;

impl ToolBase for ConfLsTool {
    type Parameter = ConfLsRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "conf_ls".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "List the pgmoneta server configuration. \
            Returns the current configuration of the pgmoneta server. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ConfLsTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ConfLsRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_conf_ls(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to list configuration: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for getting the pgmoneta configuration.
pub struct ConfGetTool;

impl ToolBase for ConfGetTool {
    type Parameter = ConfGetRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "conf_get".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Get the pgmoneta server configuration. \
            Returns the full configuration details of the pgmoneta server. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ConfGetTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ConfGetRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_conf_get(&request.username)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to get configuration: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

/// Tool for setting a pgmoneta configuration value.
pub struct ConfSetTool;

impl ToolBase for ConfSetTool {
    type Parameter = ConfSetRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "conf_set".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive().idempotent(true))
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Set a configuration value on the pgmoneta server. \
            Requires a configuration key and value. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for ConfSetTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: ConfSetRequest,
    ) -> Result<String, McpError> {
        let result: String = PgmonetaClient::request_conf_set(
            &request.username,
            &request.config_key,
            &request.config_value,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to set configuration: {:?}", e), None)
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
    fn test_conf_reload_tool_metadata() {
        assert_eq!(ConfReloadTool::name(), "conf_reload");
        assert!(ConfReloadTool::description().is_some());
        assert!(ConfReloadTool::description().unwrap().contains("Reload"));
    }

    #[test]
    fn test_conf_ls_tool_metadata() {
        assert_eq!(ConfLsTool::name(), "conf_ls");
        assert!(ConfLsTool::description().is_some());
        assert!(ConfLsTool::description().unwrap().contains("List"));
    }

    #[test]
    fn test_conf_get_tool_metadata() {
        assert_eq!(ConfGetTool::name(), "conf_get");
        assert!(ConfGetTool::description().is_some());
        assert!(ConfGetTool::description().unwrap().contains("Get"));
    }

    #[test]
    fn test_conf_set_tool_metadata() {
        assert_eq!(ConfSetTool::name(), "conf_set");
        assert!(ConfSetTool::description().is_some());
        assert!(ConfSetTool::description().unwrap().contains("Set"));
    }

    #[test]
    fn test_handler_has_conf_tools() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"conf_reload"),
            "conf_reload tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"conf_ls"),
            "conf_ls tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"conf_get"),
            "conf_get tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"conf_set"),
            "conf_set tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_generate_call_tool_result_string_conf_reload() {
        let response = r#"{"Outcome": {"Status": true, "Command": 11}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "conf reload");
    }

    #[test]
    fn test_generate_call_tool_result_string_conf_ls() {
        let response = r#"{"Outcome": {"Status": true, "Command": 21}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "conf ls");
    }

    #[test]
    fn test_generate_call_tool_result_string_conf_get() {
        let response = r#"{"Outcome": {"Status": true, "Command": 22}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "conf get");
    }

    #[test]
    fn test_generate_call_tool_result_string_conf_set() {
        let response = r#"{"Outcome": {"Status": true, "Command": 23}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Command"], "conf set");
    }

    #[test]
    fn test_conf_set_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 23, "Error": 2704}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Config set: unknown configuration key");
    }

    #[test]
    fn test_conf_get_response_with_error() {
        let response = r#"{"Outcome": {"Status": false, "Command": 22, "Error": 2600}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let output = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&output).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome["Error"], "Config get: no fork");
    }
}
