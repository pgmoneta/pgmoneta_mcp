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

use super::PgmonetaHandler;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{SyncTool, ToolBase};
use rmcp::model::JsonObject;
use std::sync::Arc;

/// Simple ping tool to verify the MCP server is responsive.
pub struct SayHelloTool;

impl ToolBase for SayHelloTool {
    type Parameter = ();
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "say_hello".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some("Say hello to the client".into())
    }

    // input_schema is overridden to return None because this tool takes no parameters.
    fn input_schema() -> Option<Arc<JsonObject>> {
        None
    }

    // output_schema is overridden to return None because our Output type is String,
    // and the MCP spec requires output schema root type to be 'object'.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl SyncTool<PgmonetaHandler> for SayHelloTool {
    fn invoke(_service: &PgmonetaHandler, _param: ()) -> Result<String, McpError> {
        Ok("Hello from pgmoneta MCP server!".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::{SyncTool, ToolBase};

    #[test]
    fn test_say_hello_tool() {
        let handler = PgmonetaHandler::new();
        let result = SayHelloTool::invoke(&handler, ());
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            "Hello from pgmoneta MCP server!".to_string()
        );
    }

    #[test]
    fn test_say_hello_tool_metadata() {
        assert_eq!(SayHelloTool::name(), "say_hello");
        assert!(SayHelloTool::description().is_some());
        assert_eq!(
            SayHelloTool::description().unwrap(),
            "Say hello to the client"
        );
    }
}
