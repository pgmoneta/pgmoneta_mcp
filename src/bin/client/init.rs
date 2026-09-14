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

use pgmoneta_mcp::config_input::{
    prompt_bool, prompt_number, prompt_required, prompt_with_options, prompt_with_options_required,
};

use pgmoneta_mcp::configuration::{
    default_llm_max_tool_rounds, default_timeout, write_config_file,
};

struct Profile {
    name: String,
    provider: String,
    endpoint: String,
    model: String,
    max_tool_rounds: usize,
}

pub fn run_init() -> Result<()> {
    println!("pgmoneta_mcp client configuration");
    println!("=================================");

    let url = prompt_required("url: ")?;
    let timeout = prompt_number("timeout", default_timeout())?;

    println!("\nLLM profiles");
    println!("------------");

    let mut profiles = Vec::new();

    loop {
        println!();

        let name = prompt_required("Profile name: ")?;

        let provider = prompt_with_options("provider", "openai", &["openai"])?;

        let endpoint = prompt_required("endpoint: ")?;

        let model = prompt_required("model: ")?;

        let max_tool_rounds = prompt_number("max tool rounds", default_llm_max_tool_rounds())?;

        profiles.push(Profile {
            name,
            provider,
            endpoint,
            model,
            max_tool_rounds,
        });

        if !prompt_bool("Add another profile?", false)? {
            break;
        }
    }

    let default_profile = if profiles.len() == 1 {
        profiles[0].name.clone()
    } else {
        let names: Vec<&str> = profiles
            .iter()
            .map(|profile| profile.name.as_str())
            .collect();

        prompt_with_options_required("Default profile: ", &names)?
    };

    let mut content = format!(
        "[pgmoneta_mcp_client]\nurl={}\ntimeout={}\nmodel={}\n",
        url, timeout, default_profile,
    );

    for profile in &profiles {
        content.push_str(&format!(
            "\n[{}]\nprovider={}\nendpoint={}\nmodel={}\nmax_tool_rounds={}\n",
            profile.name,
            profile.provider,
            profile.endpoint,
            profile.model,
            profile.max_tool_rounds,
        ));
    }

    println!("\nContent will be written:\n\n{}", content);

    if !prompt_bool("Write this configuration?", true)? {
        println!("Aborted. No changes written.");
        return Ok(());
    }

    match write_config_file(&content, "pgmoneta-mcp-client.conf") {
        Ok(msg_result) => println!("{msg_result}"),
        Err(err) => println!("failed to write result, Err: {}", err),
    }

    Ok(())
}
