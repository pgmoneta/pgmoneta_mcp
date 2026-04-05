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

pub mod interactive;

use anyhow::{Result, anyhow, bail};
use clap::{Args, Parser, Subcommand};
use interactive::run_interactive_router;
use pgmoneta_mcp::mcp_client::McpClient;
use pgmoneta_mcp::utils::SafeFileReader;
use rmcp::model::{CallToolResult, Tool};
use serde::Serialize;
use std::collections::HashMap;
use treelog::{Tree, config::RenderConfig, renderer::write_tree_with_config};

#[derive(Debug, Parser)]
#[command(
    name = "pgmoneta-mcp-inspector",
    about = "Model Context Protocol (MCP) inspector for pgmoneta, a backup/restore tool for PostgreSQL",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<McpCli>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum McpCli {
    /// Inspector operations (connect to MCP server)
    Inspector {
        /// Path to pgmoneta MCP inspector configuration file
        #[arg(
            short = 'c',
            long,
            default_value = "/etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf"
        )]
        conf: String,

        #[command(subcommand)]
        action: InspectorCommands,
    },

    /// Launch the interactive wizard
    Interactive,
}

#[derive(Subcommand, Debug, Clone)]
pub enum InspectorCommands {
    /// Manage and execute tools provided by the MCP Server
    Tool {
        #[command(subcommand)]
        action: ToolCommands,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum ToolCommands {
    /// List all available tools on the MCP server
    List {
        #[command(flatten)]
        print_opts: PrintArgs,
    },

    /// Call a specific tool on the MCP server
    Call {
        #[command(flatten)]
        call_args: CallArgs,

        #[command(flatten)]
        print_opts: PrintArgs,
    },
}

#[derive(Args, Debug, Clone)]
pub struct CallArgs {
    /// Name of the tool to call
    pub name: String,

    /// Optional path to a JSON file containing the arguments
    #[arg(short = 'f', long = "file")]
    pub file: Option<String>,

    /// JSON arguments for the tool (Strict JSON format)
    #[arg(default_value = "{}")]
    pub args: String,
}

#[derive(Args, Debug, Clone)]
pub struct PrintArgs {
    /// Output format for responses
    #[arg(short = 'o', long, value_enum, default_value_t = OutputFormat::Tree)]
    pub output: OutputFormat,
}

#[derive(Debug, Clone, clap::ValueEnum, PartialEq)]
pub enum OutputFormat {
    /// Print response as an ASCII tree
    Tree,
    /// Print response as raw JSON
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    let cmd = args.command.unwrap_or(McpCli::Interactive);

    match cmd {
        McpCli::Interactive => {
            run_interactive_router().await?;
        }
        McpCli::Inspector { conf, action } => {
            let app = AppInspector::connect(&conf).await?;

            match action {
                InspectorCommands::Tool {
                    action: tool_action,
                } => match tool_action {
                    ToolCommands::List { print_opts } => {
                        app.run_list_tools(&print_opts.output).await?;
                    }
                    ToolCommands::Call {
                        call_args,
                        print_opts,
                    } => {
                        app.run_call_tool(&call_args, &print_opts.output).await?;
                    }
                },
            }

            app.cleanup().await?;
        }
    }

    Ok(())
}

pub struct AppInspector {
    client: McpClient,
}
impl AppInspector {
    pub async fn connect(conf_path: &str) -> Result<Self> {
        let config = pgmoneta_mcp::configuration::load_inspector_configuration(conf_path)?;
        let client = McpClient::connect(&config.url, config.timeout).await?;
        Ok(Self { client })
    }

    pub async fn cleanup(self) -> Result<()> {
        self.client.cleanup().await?;
        Ok(())
    }

    pub fn server_info(&self) -> Option<(&str, &str, &str)> {
        self.client.server_info()
    }

    pub async fn list_tools(&self) -> Result<Vec<Tool>> {
        self.client.list_tools().await
    }

    pub async fn call_tool(
        &self,
        name: String,
        args: HashMap<String, serde_json::Value>,
    ) -> Result<CallToolResult> {
        self.client.call_tool(name, args).await
    }

    pub async fn run_list_tools(&self, format: &OutputFormat) -> Result<()> {
        let tools = self.list_tools().await?;
        let output = Self::format_response(&tools, format)?;
        println!("{}", output);
        Ok(())
    }

    pub async fn run_call_tool(&self, args: &CallArgs, format: &OutputFormat) -> Result<()> {
        let map_args = Self::parse_call_args(args)?;
        self.run_call_tool_raw(args.name.clone(), map_args, format)
            .await
    }

    pub async fn run_call_tool_raw(
        &self,
        name: String,
        args: HashMap<String, serde_json::Value>,
        format: &OutputFormat,
    ) -> Result<()> {
        let result = self.call_tool(name, args).await?;
        let output = Self::format_response(&result, format)?;
        println!("{}", output);
        Ok(())
    }

    fn format_response<T: Serialize>(data: &T, format: &OutputFormat) -> Result<String> {
        println!();
        let value =
            serde_json::to_value(data).map_err(|e| anyhow!("Error serializing data: {:?}", e))?;
        let value = Self::deep_decode(value);

        match format {
            OutputFormat::Json => serde_json::to_string_pretty(&value)
                .map_err(|e| anyhow!("Error serializing pretty json: {:?}", e)),
            OutputFormat::Tree => match serde_json::to_string(&value) {
                Ok(compact_json) => match Tree::from_arbitrary_json(&compact_json) {
                    Ok(tree) => {
                        let mut output = String::new();
                        let config = RenderConfig::default();
                        if write_tree_with_config(&mut output, &tree, &config).is_ok() {
                            Ok(output)
                        } else {
                            bail!("Failed to format tree output via treelog")
                        }
                    }
                    Err(e) => bail!("Error parsing arbitrary JSON into tree: {:?}", e),
                },
                Err(e) => bail!("Error compacting data for tree: {:?}", e),
            },
        }
    }

    fn parse_call_args(call_args: &CallArgs) -> Result<HashMap<String, serde_json::Value>> {
        if let Some(file_path) = &call_args.file {
            let content = SafeFileReader::new()
                .max_size(10 * 1024 * 1024)
                .read(file_path)?;
            serde_json::from_str(&content)
                .map_err(|e| anyhow!("Invalid JSON in file '{}': {}", file_path, e))
        } else {
            let args_trimmed = call_args.args.trim();
            if args_trimmed.is_empty() || args_trimmed == "{}" {
                Ok(HashMap::new())
            } else if args_trimmed.starts_with('{') {
                serde_json::from_str(args_trimmed)
                    .map_err(|e| anyhow!("Invalid JSON arguments provided: {}", e))
            } else {
                bail!("Invalid format. Use strict JSON '{{\"key\": \"val\"}}' or -f <PATH>");
            }
        }
    }

    fn deep_decode(v: serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::String(mut s) => {
                if let Ok(inner) = serde_json::from_str::<serde_json::Value>(&s) {
                    Self::deep_decode(inner)
                } else {
                    if s.len() > 100
                        && let Some((idx, _)) = s.char_indices().nth(100)
                    {
                        s.truncate(idx);
                        s.push_str("...");
                    }
                    serde_json::Value::String(s)
                }
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.into_iter().map(Self::deep_decode).collect())
            }
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.into_iter()
                    .map(|(k, v)| (k, Self::deep_decode(v)))
                    .collect(),
            ),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_call_args(name: &str, args: &str, file: Option<&str>) -> CallArgs {
        CallArgs {
            name: name.to_string(),
            args: args.to_string(),
            file: file.map(|f| f.to_string()),
        }
    }

    #[test]
    fn test_parse_empty_or_whitespace() {
        // Test empty braces
        let call_args = make_call_args("tool", "{}", None);
        let result = AppInspector::parse_call_args(&call_args).unwrap();
        assert!(result.is_empty());

        // Test empty string
        let call_args = make_call_args("tool", "", None);
        let result = AppInspector::parse_call_args(&call_args).unwrap();
        assert!(result.is_empty());

        // Test whitespace only
        let call_args = make_call_args("tool", "   ", None);
        let result = AppInspector::parse_call_args(&call_args).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_valid_json() {
        // Test single key
        let call_args = make_call_args("tool", r#"{"server":"s1"}"#, None);
        let result = AppInspector::parse_call_args(&call_args).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result.get("server").unwrap(), "s1");

        // Test multiple keys
        let call_args = make_call_args("tool", r#"{"server":"s1","backup":"b1"}"#, None);
        let result = AppInspector::parse_call_args(&call_args).unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result.get("server").unwrap(), "s1");
        assert_eq!(result.get("backup").unwrap(), "b1");
    }

    #[test]
    fn test_parse_invalid_json() {
        // Test not json
        let call_args = make_call_args("tool", "not json", None);
        let result = AppInspector::parse_call_args(&call_args);
        assert!(result.is_err());

        // Test missing brace
        let call_args = make_call_args("tool", r#"{"key": "val""#, None);
        let result = AppInspector::parse_call_args(&call_args);
        assert!(result.is_err());

        // Test invalid inside JSON
        let call_args = make_call_args("tool", r#"{"key: unquoted_value}"#, None);
        let result = AppInspector::parse_call_args(&call_args);
        assert!(result.is_err());
    }

    #[test]
    fn test_format_response_formats() {
        let data = json!({"name": "test_tool", "status": "ok"});

        // Test JSON format
        let result_json = AppInspector::format_response(&data, &OutputFormat::Json);
        assert!(result_json.is_ok());

        // Test Tree format
        let result_tree = AppInspector::format_response(&data, &OutputFormat::Tree);
        assert!(result_tree.is_ok());
    }

    #[test]
    fn test_format_response_data_types() {
        // Nested JSON
        let nested_data = json!({
            "tool": {
                "name": "get_backup_info",
                "params": {
                    "server": "primary",
                    "backup": "latest"
                }
            },
            "status": "success"
        });
        assert!(AppInspector::format_response(&nested_data, &OutputFormat::Json).is_ok());
        assert!(AppInspector::format_response(&nested_data, &OutputFormat::Tree).is_ok());

        // Empty array
        let empty_data: Vec<String> = vec![];
        assert!(AppInspector::format_response(&empty_data, &OutputFormat::Json).is_ok());
        assert!(AppInspector::format_response(&empty_data, &OutputFormat::Tree).is_ok());

        // Large payload
        let large_data = json!({
            "field1": "value1",
            "field2": "value2",
            "field3": "value3",
            "field4": 12345,
            "field5": true,
            "field6": null,
            "field7": [1, 2, 3],
            "field8": {"nested": "object"}
        });
        assert!(AppInspector::format_response(&large_data, &OutputFormat::Json).is_ok());
        assert!(AppInspector::format_response(&large_data, &OutputFormat::Tree).is_ok());
    }

    #[test]
    fn test_deep_decode_scenarios() {
        // 1. Embedded JSON extracting
        let val_embedded = json!("{\"status\": \"ok\", \"count\": 5}");
        let decoded1 = AppInspector::deep_decode(val_embedded);
        assert_eq!(decoded1, json!({"status": "ok", "count": 5}));

        // 2. Double-encoded recursive unpacking
        let inner = json!({"status": "ok"}).to_string();
        let val_double = json!(inner);
        let decoded2 = AppInspector::deep_decode(val_double);
        assert_eq!(decoded2, json!({"status": "ok"}));

        // 3. Deeply nested Array/Object decoding
        let nested = json!(["normal_string", "{\"nested_key\": \"nested_val\"}"]);
        let decoded3 = AppInspector::deep_decode(nested);
        assert_eq!(
            decoded3,
            json!(["normal_string", {"nested_key": "nested_val"}])
        );

        // 4. Invalid JSON fallback (it remains a string)
        let invalid_json = json!("{\"broken_key\": \"val\"");
        let decoded_invalid = AppInspector::deep_decode(invalid_json.clone());
        assert_eq!(decoded_invalid, invalid_json);
    }
}
