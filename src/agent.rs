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

use crate::llm::{ChatMessage, LlmClient, LlmResponse, ToolDefinition};
use anyhow::anyhow;
use rmcp::RoleClient;
use rmcp::model::CallToolRequestParams;
use rmcp::service::Peer;

/// Default system prompt for the pgmoneta backup management assistant.
pub const SYSTEM_PROMPT: &str = "\
You are a PostgreSQL backup management assistant powered by pgmoneta. \
Use the available tools to answer questions about backups, server status, \
and management operations. Always use tools when the user asks about backup \
information rather than making up data. \
When presenting results, format them in Markdown as clear, human-readable text. \
Use bold for the most recent or most important item (e.g. the latest backup). \
Present lists as bullet points. \
Do not show raw JSON to the user; instead explain what happened in plain language. \
Never use emojis, icons, or unicode symbols. Use plain text headings and labels only.";

/// Orchestrates the interaction loop between a user, a local LLM, and an MCP tool server.
///
/// The agent manages conversation history, sends prompts to the LLM along with
/// available tool definitions, executes any tool calls the LLM requests via the
/// MCP client, feeds results back, and returns the final text response.
pub struct Agent<'a, L: LlmClient> {
    /// The LLM client (e.g., Ollama).
    llm: &'a L,
    /// The MCP client peer for invoking tools.
    mcp_peer: &'a Peer<RoleClient>,
    /// Tool definitions in the format the LLM expects.
    tools: Vec<ToolDefinition>,
    /// Conversation history.
    history: Vec<ChatMessage>,
    /// Maximum number of tool-calling rounds before forcing a text response.
    max_tool_rounds: usize,
}

impl<'a, L: LlmClient> Agent<'a, L> {
    /// Creates a new agent.
    ///
    /// # Arguments
    /// * `llm` - The LLM client to use for inference.
    /// * `mcp_peer` - The MCP client peer for tool invocation.
    /// * `tools` - Available tool definitions (converted from MCP tools).
    /// * `system_prompt` - The system prompt to initialize the conversation with.
    /// * `max_tool_rounds` - Maximum tool-calling iterations per user prompt.
    pub fn new(
        llm: &'a L,
        mcp_peer: &'a Peer<RoleClient>,
        tools: Vec<ToolDefinition>,
        system_prompt: &str,
        max_tool_rounds: usize,
    ) -> Self {
        let history = vec![ChatMessage::system(system_prompt)];
        Self {
            llm,
            mcp_peer,
            tools,
            history,
            max_tool_rounds,
        }
    }

    /// Processes a user prompt through the LLM and MCP tool loop.
    ///
    /// The flow is:
    /// 1. Append user message to conversation history
    /// 2. Send history + tool schemas to the LLM
    /// 3. If the LLM responds with tool calls:
    ///    a. Execute each tool call via the MCP client
    ///    b. Append the assistant's tool call message and tool results to history
    ///    c. Re-send to the LLM (repeat up to `max_tool_rounds`)
    /// 4. If the LLM responds with text, return it
    ///
    /// # Arguments
    /// * `user_input` - The user's question or command.
    ///
    /// # Returns
    /// The LLM's final text response, or an error.
    pub async fn prompt(&mut self, user_input: &str) -> anyhow::Result<String> {
        self.history.push(ChatMessage::user(user_input));

        for round in 0..self.max_tool_rounds {
            let response = self.llm.chat(&self.history, &self.tools).await?;

            match response {
                LlmResponse::Text(text) => {
                    self.history.push(ChatMessage::assistant(&text));
                    return Ok(text);
                }
                LlmResponse::ToolCalls(tool_calls) => {
                    tracing::info!(
                        round = round + 1,
                        count = tool_calls.len(),
                        "LLM requested tool calls"
                    );

                    // Append the assistant's tool call message to history
                    self.history
                        .push(ChatMessage::assistant_tool_calls(tool_calls.clone()));

                    // Execute each tool call and append results
                    for tool_call in &tool_calls {
                        let tool_name = &tool_call.function.name;
                        let tool_args = &tool_call.function.arguments;

                        tracing::debug!(
                            tool = %tool_name,
                            args = ?tool_args,
                            "Executing tool call"
                        );

                        let result = self.execute_tool_call(tool_name, tool_args).await;

                        match result {
                            Ok(content) => {
                                self.history
                                    .push(ChatMessage::tool_result(tool_name, &content));
                            }
                            Err(e) => {
                                let error_msg =
                                    format!("Error calling tool '{}': {}", tool_name, e);
                                tracing::warn!(%error_msg);
                                self.history
                                    .push(ChatMessage::tool_result(tool_name, &error_msg));
                            }
                        }
                    }
                }
            }
        }

        Err(anyhow!(
            "Exceeded maximum tool-calling rounds ({}). The LLM may be stuck in a tool-calling loop.",
            self.max_tool_rounds
        ))
    }

    /// Clears the conversation history, preserving only the system prompt.
    pub fn clear_history(&mut self) {
        let system_msg = self.history.first().cloned();
        self.history.clear();
        if let Some(msg) = system_msg {
            self.history.push(msg);
        }
    }

    /// Returns a reference to the current conversation history.
    pub fn history(&self) -> &[ChatMessage] {
        &self.history
    }

    /// Executes a single tool call via the MCP client peer.
    ///
    /// # Arguments
    /// * `tool_name` - The name of the tool to invoke.
    /// * `arguments` - The arguments to pass to the tool.
    ///
    /// # Returns
    /// The text content of the tool's response.
    async fn execute_tool_call(
        &self,
        tool_name: &str,
        arguments: &std::collections::HashMap<String, serde_json::Value>,
    ) -> anyhow::Result<String> {
        let arguments: serde_json::Map<String, serde_json::Value> =
            arguments.clone().into_iter().collect();

        let request = CallToolRequestParams::new(tool_name.to_string()).with_arguments(arguments);

        let result = self
            .mcp_peer
            .call_tool(request)
            .await
            .map_err(|e| anyhow!("MCP tool call failed: {:?}", e))?;

        // Check if the tool call returned an error
        if result.is_error == Some(true) {
            let error_text: String = result
                .content
                .iter()
                .filter_map(|c| c.as_text().map(|t| t.text.to_string()))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(anyhow!("Tool returned error: {}", error_text));
        }

        // Extract text content from the result
        let text: String = result
            .content
            .iter()
            .filter_map(|c| c.as_text().map(|t| t.text.to_string()))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(text)
    }
}
