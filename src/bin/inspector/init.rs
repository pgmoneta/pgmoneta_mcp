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

use pgmoneta_mcp::config_input::{prompt_bool, prompt_number, prompt_required};

use pgmoneta_mcp::configuration::{default_timeout, write_config_file};

pub fn run_init() -> Result<()> {
    println!("pgmoneta_mcp inspector configuration");
    println!("====================================");

    let url = prompt_required("url: ")?;
    let timeout = prompt_number("timeout", default_timeout())?;

    let content = format!(
        "[inspector]\n\
         url={}\n\
         timeout={}\n",
        url, timeout,
    );

    println!("\nContent will be written:\n\n{}", content);

    if !prompt_bool("Write this configuration?", true)? {
        println!("Aborted. No changes written.");
        return Ok(());
    }

    match write_config_file(&content, "pgmoneta-mcp-inspector.conf") {
        Ok(msg_result) => println!("{msg_result}"),
        Err(err) => println!("Failed to write configuration: {err}"),
    }

    Ok(())
}
