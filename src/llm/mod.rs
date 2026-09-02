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

pub mod openai;

pub use openai::OpenAiClient;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::HashMap;

/// Represents a single message in the conversation history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// The role of the message sender (`system`, `user`, `assistant`, or `tool`).
    pub role: String,
    /// The text content of the message.
    pub content: String,
    /// Tool calls requested by the assistant (present when role is `assistant`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// The name of the tool that produced this result (present when role is `tool`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,
}

/// A tool call requested by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    /// The function invocation details.
    pub function: ToolCallFunction,
}

/// The function name and arguments within a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCallFunction {
    /// Name of the tool/function to call.
    pub name: String,
    /// Arguments as a JSON object (key-value pairs).
    pub arguments: HashMap<String, Value>,
}

/// A tool definition in the format expected by LLM APIs (OpenAI function-calling schema).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Always `"function"`.
    #[serde(rename = "type")]
    pub tool_type: String,
    /// The function schema.
    pub function: FunctionDefinition,
}

/// The schema of a function/tool that the LLM can invoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDefinition {
    /// The name of the function.
    pub name: String,
    /// A description of what the function does.
    pub description: String,
    /// JSON Schema describing the function parameters.
    pub parameters: Value,
}

/// The response from an LLM after processing a prompt.
#[derive(Debug, Clone)]
pub enum LlmResponse {
    /// The LLM responded with plain text (no tool calls).
    Text(String),
    /// The LLM wants to invoke one or more tools.
    ToolCalls(Vec<ToolCall>),
}

/// Trait defining the interface for an LLM client.
///
/// Implementations of this trait communicate through the OpenAI API.
#[allow(async_fn_in_trait)]
pub trait LlmClient {
    /// Sends a conversation with available tool definitions to the LLM and returns its response.
    ///
    /// # Arguments
    /// * `messages` - The conversation history.
    /// * `tools` - Available tool definitions the LLM may choose to invoke.
    ///
    /// # Returns
    /// An [`LlmResponse`] containing either text or tool call requests.
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> anyhow::Result<LlmResponse>;
}

/// Converts MCP tool objects (from `rmcp`) into the LLM function-calling schema format.
///
/// This bridges MCP tool discovery output to the OpenAI function-calling schema.
///
/// # Arguments
/// * `tools` - A slice of `rmcp::model::Tool` objects discovered from an MCP server.
///
/// # Returns
/// A vector of [`ToolDefinition`] objects ready to be sent to an LLM.
pub fn mcp_tools_to_llm_schema(tools: &[rmcp::model::Tool]) -> Vec<ToolDefinition> {
    tools
        .iter()
        .map(|tool| ToolDefinition {
            tool_type: "function".to_string(),
            function: FunctionDefinition {
                name: tool.name.to_string(),
                description: sanitize_tool_description(
                    &tool
                        .description
                        .as_ref()
                        .map(|d| d.to_string())
                        .unwrap_or_default(),
                ),
                parameters: sanitize_tool_parameters(
                    serde_json::to_value(&*tool.input_schema)
                        .unwrap_or(Value::Object(serde_json::Map::new())),
                ),
            },
        })
        .collect()
}

fn sanitize_tool_description(description: &str) -> String {
    description
        .replace(
            " The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
            "",
        )
        .replace(
            " The username has to be one of the pgmoneta admins to be able to perform this action.",
            "",
        )
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_tool_parameters(parameters: Value) -> Value {
    let Value::Object(mut schema) = parameters else {
        return parameters;
    };

    if let Some(Value::Object(properties)) = schema.get_mut("properties") {
        properties.remove("username");
    }

    if let Some(Value::Array(required)) = schema.get_mut("required") {
        required.retain(|value| value.as_str() != Some("username"));
    }

    schema
        .entry("properties".to_string())
        .or_insert_with(|| Value::Object(Map::new()));

    Value::Object(schema)
}

impl ChatMessage {
    /// Creates a system message.
    pub fn system(content: &str) -> Self {
        Self {
            role: "system".to_string(),
            content: content.to_string(),
            tool_calls: None,
            tool_name: None,
        }
    }

    /// Creates a user message.
    pub fn user(content: &str) -> Self {
        Self {
            role: "user".to_string(),
            content: content.to_string(),
            tool_calls: None,
            tool_name: None,
        }
    }

    /// Creates an assistant message with tool calls.
    pub fn assistant_tool_calls(tool_calls: Vec<ToolCall>) -> Self {
        Self {
            role: "assistant".to_string(),
            content: String::new(),
            tool_calls: Some(tool_calls),
            tool_name: None,
        }
    }

    /// Creates an assistant message with text content.
    pub fn assistant(content: &str) -> Self {
        Self {
            role: "assistant".to_string(),
            content: content.to_string(),
            tool_calls: None,
            tool_name: None,
        }
    }

    /// Creates a tool result message.
    pub fn tool_result(tool_name: &str, content: &str) -> Self {
        Self {
            role: "tool".to_string(),
            content: content.to_string(),
            tool_calls: None,
            tool_name: Some(tool_name.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::PgmonetaHandler;
    use serde_json::json;

    #[test]
    fn test_sanitize_tool_description_removes_username_boilerplate() {
        assert_eq!(
            sanitize_tool_description(
                "List backups of a server. The username has to be one of the pgmoneta admins to be able to access pgmoneta."
            ),
            "List backups of a server."
        );
        assert_eq!(
            sanitize_tool_description(
                "Shutdown the pgmoneta server. The username has to be one of the pgmoneta admins to be able to perform this action. Note: After pgmoneta is shut down, subsequent backup-related tool calls will fail until pgmoneta is restarted."
            ),
            "Shutdown the pgmoneta server. Note: After pgmoneta is shut down, subsequent backup-related tool calls will fail until pgmoneta is restarted."
        );
    }

    #[test]
    fn test_sanitize_tool_parameters_removes_username() {
        let schema = json!({
            "type": "object",
            "properties": {
                "server": { "type": "string" },
                "username": { "type": "string" }
            },
            "required": ["server", "username"]
        });

        assert_eq!(
            sanitize_tool_parameters(schema),
            json!({
                "type": "object",
                "properties": {
                    "server": { "type": "string" }
                },
                "required": ["server"]
            })
        );
    }

    #[test]
    fn test_mcp_tools_to_llm_schema_hides_injected_username() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let schemas = mcp_tools_to_llm_schema(&tools);
        let list_backups = schemas
            .iter()
            .find(|tool| tool.function.name == "list_backups")
            .expect("list_backups tool should exist");

        assert!(!list_backups.function.description.contains("username"));
        assert_eq!(
            list_backups.function.parameters["properties"].get("username"),
            None
        );
        assert_eq!(
            list_backups.function.parameters["required"],
            json!(["server"])
        );
    }
}
