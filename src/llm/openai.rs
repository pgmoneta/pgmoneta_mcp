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

use super::{ChatMessage, LlmClient, LlmResponse, ToolCall, ToolCallFunction, ToolDefinition};
use anyhow::anyhow;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Client for communicating with an OpenAI-compatible inference server (e.g. `llama-server`, `vLLM`).
///
/// Uses the standard OpenAI-compatible `/v1/chat/completions` endpoint for tool/function calling.
/// The model loaded into the server must have tool-calling templates aligned with the OpenAI
/// function calling specification.
pub struct OpenAiClient {
    http_client: Client,
    provider_name: String,
    endpoint: String,
    model: String,
}

/// Request body for OpenAI's `/v1/chat/completions` endpoint.
#[derive(Debug, Serialize)]
struct OpenAiChatRequest<'a> {
    model: &'a str,
    messages: &'a [ChatMessage],
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    tools: Option<&'a [ToolDefinition]>,
}

/// Response from OpenAI's `/v1/chat/completions` endpoint.
#[derive(Debug, Deserialize)]
struct OpenAiChatResponse {
    choices: Vec<OpenAiChoice>,
}

/// A choice within the OpenAI chat response.
#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    message: OpenAiMessage,
}

/// A message within an OpenAI choice.
#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    #[allow(dead_code)]
    role: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Option<Vec<OpenAiToolCall>>,
}

/// A tool call in the OpenAI response format.
#[derive(Debug, Deserialize)]
struct OpenAiToolCall {
    #[allow(dead_code)]
    id: String,
    #[allow(dead_code)]
    #[serde(rename = "type")]
    tool_type: String,
    function: OpenAiToolCallFunction,
}

/// Function details within an OpenAI tool call.
///
/// Note: The OpenAI specification returns `arguments` as a stringified JSON object
/// (a plain string), not as a nested JSON value. It must be parsed separately.
#[derive(Debug, Deserialize)]
struct OpenAiToolCallFunction {
    name: String,
    arguments: String,
}

/// Model information returned by the `/v1/models` endpoint.
#[derive(Debug, Deserialize)]
struct OpenAiModelsResponse {
    data: Vec<OpenAiModelData>,
}

/// Individual model details from the models endpoint.
#[derive(Debug, Deserialize)]
pub struct OpenAiModelData {
    pub id: String,
}

/// Parses a stringified JSON `arguments` string from an OpenAI tool call into a key-value map.
///
/// Returns an empty map if `arguments` is empty or whitespace-only.
fn parse_tool_arguments(arguments: &str) -> anyhow::Result<HashMap<String, serde_json::Value>> {
    let trimmed = arguments.trim();
    if trimmed.is_empty() {
        return Ok(HashMap::new());
    }
    serde_json::from_str(trimmed)
        .map_err(|e| anyhow!("Failed to parse JSON arguments from tool call: {}", e))
}

impl OpenAiClient {
    /// Creates a new `OpenAiClient`.
    ///
    /// # Arguments
    /// * `provider_name` - The logical name of the backend (e.g. `llama.cpp`, `vllm`).
    /// * `endpoint` - The base URL of the inference server (e.g., `http://localhost:8080`).
    /// * `model` - The model ID or name to include in chat requests.
    pub fn new(provider_name: &str, endpoint: &str, model: &str) -> Self {
        Self {
            http_client: Client::new(),
            provider_name: provider_name.to_string(),
            endpoint: endpoint.trim_end_matches('/').to_string(),
            model: model.to_string(),
        }
    }

    /// Checks whether the inference server is running and reachable.
    ///
    /// # Returns
    /// `Ok(())` if the server responds to a basic `/health` or `/v1/models` endpoint, or an error.
    pub async fn health_check(&self) -> anyhow::Result<()> {
        let health_url = format!("{}/health", self.endpoint);
        let resp = self.http_client.get(&health_url).send().await;

        match resp {
            Ok(r) if r.status().is_success() => Ok(()),
            _ => {
                // Try /v1/models as a fallback (RamaLama/vLLM)
                let models_url = format!("{}/v1/models", self.endpoint);
                let resp = self
                    .http_client
                    .get(&models_url)
                    .send()
                    .await
                    .map_err(|e| {
                        anyhow!(
                            "Cannot reach {} at {}: {}",
                            self.provider_name,
                            self.endpoint,
                            e
                        )
                    })?;

                if !resp.status().is_success() {
                    return Err(anyhow!(
                        "{} health check failed (tried /health and /v1/models)",
                        self.provider_name,
                    ));
                }
                Ok(())
            }
        }
    }

    /// Lists the models available on the server using the `/v1/models` endpoint.
    ///
    /// # Returns
    /// A vector of model IDs.
    pub async fn list_models(&self) -> anyhow::Result<Vec<String>> {
        let url = format!("{}/v1/models", self.endpoint);
        let resp = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to list models from {}: {}", self.provider_name, e))?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Failed to list models from {}, status: {}",
                self.provider_name,
                resp.status()
            ));
        }

        let models_resp: OpenAiModelsResponse = resp.json().await?;
        Ok(models_resp.data.into_iter().map(|m| m.id).collect())
    }

    /// Returns the model name this client is configured to use.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Returns the endpoint URL this client connects to.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}

impl LlmClient for OpenAiClient {
    /// Sends a chat request to the inference server using the OpenAI `/v1/chat/completions` API.
    ///
    /// Returns either a text response or a list of tool calls the model wants to invoke.
    async fn chat(
        &self,
        messages: &[ChatMessage],
        tools: &[ToolDefinition],
    ) -> anyhow::Result<LlmResponse> {
        let url = format!("{}/v1/chat/completions", self.endpoint);

        let request = OpenAiChatRequest {
            model: &self.model,
            messages,
            stream: false,
            tools: if tools.is_empty() { None } else { Some(tools) },
        };

        tracing::debug!(
            provider = %self.provider_name,
            model = %self.model,
            messages = messages.len(),
            tools = tools.len(),
            "Sending chat request to OpenAI-compatible provider"
        );

        let resp = self
            .http_client
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                anyhow!(
                    "Failed to send chat request to {}: {}",
                    self.provider_name,
                    e
                )
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "{} chat completion failed (status {}): {}",
                self.provider_name,
                status,
                body
            ));
        }

        let chat_resp: OpenAiChatResponse = resp.json().await.map_err(|e| {
            anyhow!(
                "Failed to parse {} chat response: {}",
                self.provider_name,
                e
            )
        })?;

        let message = chat_resp
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("{} returned empty choices list", self.provider_name))?
            .message;

        match message.tool_calls {
            Some(calls) if !calls.is_empty() => {
                let mapped_calls = calls
                    .into_iter()
                    .map(|tc| {
                        let arguments = parse_tool_arguments(&tc.function.arguments)?;
                        Ok(ToolCall {
                            function: ToolCallFunction {
                                name: tc.function.name,
                                arguments,
                            },
                        })
                    })
                    .collect::<anyhow::Result<Vec<_>>>()?;
                Ok(LlmResponse::ToolCalls(mapped_calls))
            }
            _ => Ok(LlmResponse::Text(message.content.unwrap_or_default())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies that a plain text response from an OpenAI-compatible server is parsed correctly.
    #[test]
    fn test_parse_text_response() {
        let json = r#"
        {
          "choices": [
            {
              "message": {
                "role": "assistant",
                "content": "I can help you list your pgmoneta backups.",
                "tool_calls": null
              }
            }
          ]
        }"#;

        let resp: OpenAiChatResponse = serde_json::from_str(json).expect("should parse");
        let msg = resp.choices.into_iter().next().unwrap().message;

        assert!(msg.tool_calls.is_none() || msg.tool_calls.unwrap().is_empty());
        assert_eq!(
            msg.content.unwrap(),
            "I can help you list your pgmoneta backups."
        );
    }

    /// Verifies that a tool call response is parsed and arguments are deserialized correctly.
    /// In the OpenAI schema, `arguments` is a *stringified* JSON object.
    #[test]
    fn test_parse_tool_call_response() {
        let json = r#"
        {
          "choices": [
            {
              "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                  {
                    "id": "call_abc123",
                    "type": "function",
                    "function": {
                      "name": "list_backups",
                      "arguments": "{\"server\": \"primary\"}"
                    }
                  }
                ]
              }
            }
          ]
        }"#;

        let resp: OpenAiChatResponse = serde_json::from_str(json).expect("should parse");
        let msg = resp.choices.into_iter().next().unwrap().message;
        let calls = msg.tool_calls.unwrap();

        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "list_backups");

        let args = parse_tool_arguments(&calls[0].function.arguments).unwrap();
        assert_eq!(args["server"], serde_json::json!("primary"));
    }

    /// Verifies that an empty arguments string is handled gracefully.
    #[test]
    fn test_parse_tool_call_empty_arguments() {
        let args = parse_tool_arguments("").unwrap();
        assert!(args.is_empty(), "empty arguments should produce empty map");

        let args = parse_tool_arguments("   ").unwrap();
        assert!(
            args.is_empty(),
            "whitespace arguments should produce empty map"
        );
    }

    /// Verifies the OpenAiClient is constructed correctly and trims trailing slashes.
    #[test]
    fn test_client_construction() {
        let client = OpenAiClient::new("vllm", "http://localhost:8080/", "my-model");
        assert_eq!(client.endpoint(), "http://localhost:8080");
        assert_eq!(client.model(), "my-model");
    }
}
