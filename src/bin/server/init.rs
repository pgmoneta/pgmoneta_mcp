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

use anyhow::Result;
use pgmoneta_mcp::{
    config_input::{
        prompt_bool, prompt_default, prompt_number, prompt_required, prompt_with_options,
        prompt_with_options_required,
    },
    configuration::{
        default_llm_max_tool_rounds, default_log_level, default_log_line_prefix, default_log_mode,
        default_log_path, default_log_rotation_age, default_log_type, default_metrics_port,
        default_port, write_config_file,
    },
};
use std::fmt::Display;

const LOG_TYPE_OPTIONS: &[&str] = &["console", "file", "syslog"];

const LOG_LEVEL: &[&str] = &["trace", "debug", "info", "warn", "error"];

const LOG_MODE: &[&str] = &["append", "create"];

pub fn run_init() -> Result<()> {
    println!("pgmoneta_mcp server configuration");
    println!("=================================");

    let server_port = prompt_number("port", default_port())?;
    let log_type = prompt_with_options("log_type", &default_log_type(), LOG_TYPE_OPTIONS)?;
    let log_level = prompt_with_options("log_level", &default_log_level(), LOG_LEVEL)?;
    let log_path = prompt_default("log_path", &default_log_path())?;
    let log_line_prefix = prompt_default("log_line_prefix", &default_log_line_prefix())?;
    let log_mode = prompt_with_options("log_mode", &default_log_mode(), LOG_MODE)?;
    let log_rotation_age = prompt_number("log_rotation_age", default_log_rotation_age())?;

    let host = prompt_required("host:")?;
    let port = prompt_required("port:")?;
    let metrics = prompt_number("metrics", default_metrics_port())?;

    let llm = prompt_bool("configure llm section", false)?;
    let mut provider = String::new();
    let mut endpoint = String::new();
    let mut model = String::new();
    let mut max_tool_calls = 0;
    if llm {
        provider = prompt_with_options_required("provider: ", &["openai"])?;
        endpoint = prompt_required("endpoint: ")?;
        model = prompt_required("model: ")?;
        max_tool_calls = prompt_number("max tool calls", default_llm_max_tool_rounds())?;
    }

    let mut mcp_section = vec![];

    if server_port != default_port() {
        mcp_section.push(format_key_value("port", server_port));
    }

    if log_type != default_log_type() {
        mcp_section.push(format_key_value("log_type", log_type));
    }

    if log_level != default_log_level() {
        mcp_section.push(format_key_value("log_level", log_level));
    }

    if log_path != default_log_path() {
        mcp_section.push(format_key_value("log_path", log_path));
    }

    if log_line_prefix != default_log_line_prefix() {
        mcp_section.push(format_key_value("log_line_prefix", log_line_prefix));
    }

    if log_mode != default_log_mode() {
        mcp_section.push(format_key_value("log_mode", log_mode));
    }

    if log_rotation_age != default_log_rotation_age() {
        mcp_section.push(format_key_value("log_rotation_age", log_rotation_age));
    }

    let mut pgmoneta_section = vec![
        format_key_value("host", host),
        format_key_value("port", port),
    ];

    if metrics != default_metrics_port() {
        pgmoneta_section.push(format_key_value("metrics", metrics));
    }

    let mut llm_section = vec![];

    if llm {
        llm_section.push(format_key_value("provider", provider));
        llm_section.push(format_key_value("endpoint", endpoint));
        llm_section.push(format_key_value("model", model));

        if max_tool_calls != default_llm_max_tool_rounds() {
            llm_section.push(format_key_value("max_tool_calls", max_tool_calls));
        }
    }

    let mut content = format!(
        "[pgmoneta_mcp]\n{}\n[pgmoneta]\n{}\n\n",
        mcp_section.join("\n"),
        pgmoneta_section.join("\n")
    );

    if llm {
        content.push_str(&format!("[llm]\n{}", llm_section.join("\n")));
    }

    println!("\n\nContent will be written \n{}", content);

    if !prompt_bool("Write this configuration?", true)? {
        println!("Aborted. No changes written.");
        return Ok(());
    }

    match write_config_file(&content, "pgmoneta-mcp.conf") {
        Ok(msg_result) => println!("{msg_result}"),
        Err(err) => println!("failed to write result, Err: {}", err),
    }

    Ok(())
}

fn format_key_value<T: Display>(key: &str, value: T) -> String {
    format!("{key}={value}")
}
