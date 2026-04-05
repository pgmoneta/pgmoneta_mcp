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

use crate::{AppInspector, OutputFormat};
use anyhow::{Result, anyhow, bail};
use inquire::{Select, Text};
use pgmoneta_mcp::utils::SafeFileReader;
use std::collections::HashMap;

pub trait InteractiveWizard {
    #[allow(async_fn_in_trait)]
    async fn run(&self) -> Result<()>;
}

/// Gracefully handles Inquire cancellations such as Esc or Ctrl+C
macro_rules! prompt_or_cancel {
    ($prompt_result:expr, $err_msg:expr) => {
        match $prompt_result {
            Ok(val) => val,
            Err(inquire::InquireError::OperationCanceled)
            | Err(inquire::InquireError::OperationInterrupted) => return Ok(None),
            Err(e) => anyhow::bail!("{}: {}", $err_msg, e),
        }
    };
}

/// The main entry point for the interactive router.
/// Displays a greeting and allows the user to select and launch the desired wizard module.
pub async fn run_interactive_router() -> Result<()> {
    let inspector_version = env!("CARGO_PKG_VERSION");
    println!();
    println!(
        "Welcome to pgmoneta MCP Inspector Interactive Shell! v{}",
        inspector_version
    );
    println!();

    let options = vec!["Inspector", "Exit"];

    loop {
        let choice = Select::new("Select a module:", options.clone()).prompt();

        match choice {
            Ok("Inspector") => {
                let wizard = InspectorWizard;
                if let Err(e) = wizard.run().await {
                    eprintln!("Error executing command: {}", e);
                }
            }
            Ok("Exit")
            | Err(inquire::InquireError::OperationCanceled)
            | Err(inquire::InquireError::OperationInterrupted) => break,
            Ok(_) => {}
            Err(e) => anyhow::bail!("An error occurred: {}", e),
        }
    }
    Ok(())
}

pub struct InspectorWizard;
impl InteractiveWizard for InspectorWizard {
    async fn run(&self) -> Result<()> {
        let default_conf = "/etc/pgmoneta-mcp/pgmoneta-mcp-inspector.conf";
        let prompt_text = format!(
            "Enter configuration file path [default: {}] =",
            default_conf
        );

        let conf_input = match Text::new(&prompt_text).prompt() {
            Ok(val) => val,
            Err(inquire::InquireError::OperationCanceled)
            | Err(inquire::InquireError::OperationInterrupted) => return Ok(()),
            Err(e) => anyhow::bail!("Configuration path input failed: {}", e),
        };

        let conf_path = if conf_input.trim().is_empty() {
            default_conf.to_string()
        } else {
            conf_input.trim().to_string()
        };

        let app_inspector = AppInspector::connect(&conf_path).await?; // One single connection

        if let Some((server_name, server_version, url)) = app_inspector.server_info() {
            println!();
            println!("  Connected to: {}", url);
            println!("  Server: {} v{}", server_name, server_version);
            println!();
        }

        let options = vec!["Tools", "Exit"];
        loop {
            let choice = Select::new("What would you like to manage?", options.clone()).prompt();

            match choice {
                Ok("Tools") => {
                    if let Err(e) = PageTool::handle_tools(&app_inspector).await {
                        eprintln!("Error: {}", e);
                    }
                }
                Ok("Exit")
                | Err(inquire::InquireError::OperationCanceled)
                | Err(inquire::InquireError::OperationInterrupted) => break,
                Ok(_) => continue,
                Err(e) => bail!("An error occurred: {}", e),
            }
        }
        app_inspector.cleanup().await?;
        Ok(())
    }
}

pub struct PageTool;
impl PageTool {
    pub async fn handle_tools(inspector: &AppInspector) -> Result<()> {
        let options = vec!["List Tools", "Call Tool"];
        let choice = match Select::new("What would you like to do with tools?", options).prompt() {
            Ok(c) => c,
            Err(inquire::InquireError::OperationCanceled)
            | Err(inquire::InquireError::OperationInterrupted) => return Ok(()),
            Err(e) => bail!("Selection failed: {}", e),
        };

        match choice {
            "List Tools" => {
                inspector.run_list_tools(&OutputFormat::Tree).await?;
            }
            "Call Tool" => {
                let tools = inspector.list_tools().await?;

                if tools.is_empty() {
                    bail!("Notice: No tools are currently available on the server.");
                }

                let tool_names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();

                let name = match Select::new("Select a tool to call:", tool_names).prompt() {
                    Ok(n) => n,
                    Err(inquire::InquireError::OperationCanceled)
                    | Err(inquire::InquireError::OperationInterrupted) => return Ok(()),
                    Err(e) => bail!("Tool selection failed: {}", e),
                };

                let tool = tools
                    .iter()
                    .find(|t| t.name == name)
                    .ok_or_else(|| anyhow!("Tool '{}' not found", name))?;

                if let Some(args) = Self::build_calltool_args(&tool.input_schema)? {
                    inspector
                        .run_call_tool_raw(name, args, &OutputFormat::Tree)
                        .await?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    /// Extracts the type, description, and formats a user prompt for a given schema property.
    fn extract_property_info(
        prop_name: &str,
        prop_schema: &serde_json::Value,
    ) -> (String, String, String) {
        let prop_type = prop_schema
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("unknown type");
        let desc = prop_schema
            .get("description")
            .and_then(|d| d.as_str())
            .unwrap_or("unknown description");

        let short_desc = desc.chars().take(30).collect::<String>();
        let prompt = format!("{} [{}] [{}] =", prop_name, prop_type, short_desc);

        (prop_type.to_string(), desc.to_string(), prompt)
    }

    /// Interactively builds arguments for a tool call by prompting the user based on its JSON schema.
    /// Supports `@`-prefixed file paths to load values from local files.
    fn build_calltool_args(
        schema: &serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<HashMap<String, serde_json::Value>>> {
        let mut args = HashMap::new();
        let props = schema
            .get("properties")
            .and_then(|v| v.as_object())
            .ok_or_else(|| anyhow!("Tool schema missing properties"))?;

        for (prop_name, prop_schema) in props {
            let (_, _, prompt) = Self::extract_property_info(prop_name, prop_schema);

            let v = prompt_or_cancel!(Text::new(&prompt).prompt(), "Input failed");

            if !v.trim().is_empty() {
                let content = if let Some(path) = v.trim().strip_prefix('@') {
                    SafeFileReader::new()
                        .max_size(10 * 1024 * 1024)
                        .read(path)?
                } else {
                    v
                };

                let parsed =
                    serde_json::from_str(&content).map_err(|e| anyhow!("Invalid JSON: {}", e))?;
                args.insert(prop_name.clone(), parsed);
            }
        }
        Ok(Some(args))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_extract_property_info_scenarios() {
        // Test with type and description
        let schema_full = json!({"type": "string", "description": "The server name"});
        let (ptype, desc, prompt) = PageTool::extract_property_info("server", &schema_full);
        assert_eq!(ptype, "string");
        assert_eq!(desc, "The server name");
        assert!(prompt.contains("server"));
        assert!(prompt.contains("[string]"));
        assert!(prompt.contains("[The server name]"));

        // Test missing type
        let schema_no_type = json!({"description": "Some description"});
        let (ptype, _, _) = PageTool::extract_property_info("field", &schema_no_type);
        assert_eq!(ptype, "unknown type");

        // Test missing description
        let schema_no_desc = json!({"type": "integer"});
        let (_, desc, _) = PageTool::extract_property_info("field", &schema_no_desc);
        assert_eq!(desc, "unknown description");

        // Test long description truncated
        let long_desc =
            "This is a very long description that should be truncated to thirty characters";
        let schema_long = json!({"type": "string", "description": long_desc});
        let (_, _, prompt) = PageTool::extract_property_info("field", &schema_long);
        let short: String = long_desc.chars().take(30).collect();
        assert!(prompt.contains(&short));
        assert!(!prompt.contains(long_desc));
    }

    #[test]
    fn test_build_calltool_args_scenarios() {
        // Test missing properties
        let schema_missing: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();
        let result_missing = PageTool::build_calltool_args(&schema_missing);
        assert!(result_missing.is_err());
        assert!(format!("{:?}", result_missing.unwrap_err()).contains("missing properties"));

        // Test empty properties
        let mut schema_empty = serde_json::Map::new();
        schema_empty.insert("properties".to_string(), json!({}));
        let result_empty = PageTool::build_calltool_args(&schema_empty);
        assert!(result_empty.is_ok());
        let args = result_empty.unwrap().unwrap();
        assert!(args.is_empty());
    }
}
