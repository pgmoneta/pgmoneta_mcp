// Copyright (C) 2025 The pgmoneta community
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

mod info;

use super::constant::*;
use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler,
    handler::server::{
        router::{tool::ToolRouter},
        wrapper::Parameters,
    },
    model::*,
    service::RequestContext,
    tool, tool_handler, tool_router,
};
use std::collections::HashMap;
use serde_json::Value;
use super::client::PgmonetaClient;

#[derive(Clone)]
pub struct PgmonetaHandler {
    tool_router: ToolRouter<PgmonetaHandler>,
}

#[tool_router]
impl PgmonetaHandler {
    pub fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Say hello to the client")]
    fn say_hello(&self) -> Result<CallToolResult, McpError> {
        Ok(CallToolResult::success(vec![Content::text("Hello from pgmoneta MCP server!")]))
    }

    #[tool(description = "Get information of a backup using given backup ID and server name. \
    \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier.\
    The username has to be one of the pgmoneta admins to be able to access pgmoneta")]
    async fn get_backup_info(&self, Parameters(args): Parameters<info::InfoRequest>) -> Result<CallToolResult, McpError> {
        self._get_backup_info(args).await
    }
}

impl PgmonetaHandler {
    fn _check_result(result: &str) -> Result<(), McpError> {
        let response: HashMap<String, Value> = serde_json::from_str(result).map_err(|e| {
            McpError::parse_error(format!("Failed to parse result {result}: {:?}", e), None)
        })?;
        if !response.contains_key(MANAGEMENT_CATEGORY_OUTCOME) {
            return Err(McpError::internal_error(format!("Fail to find outcome inside response {:?}", response), None));
        }
        if let Value::Object(outcome) = response.get(MANAGEMENT_CATEGORY_OUTCOME).unwrap() {
            if !outcome.contains_key(MANAGEMENT_ARGUMENT_STATUS) {
                return Err(McpError::internal_error(format!("Fail to find status inside outcome {:?}", outcome), None));
            }
            if let &Value::Bool(status) = outcome.get(MANAGEMENT_ARGUMENT_STATUS).unwrap() {
                if !status {
                    return Err(McpError::invalid_request(format!("Getting false status inside outcome {:?}", outcome), None));
                }
                Ok(())
            } else {
                Err(McpError::internal_error(format!("Incorrect status type inside outcome {:?}, expect bool", outcome), None))
            }
        } else {
            Err(McpError::internal_error(format!("Incorrect outcome type inside response {:?}, expect json object", response), None))
        }
    }
}
#[tool_handler]
impl ServerHandler for PgmonetaHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides capabilities to interact with pgmoneta, a backup/restore tool for PostgreSQL.".to_string()),
        }
    }

    async fn initialize(
        &self,
        _request: InitializeRequestParam,
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
