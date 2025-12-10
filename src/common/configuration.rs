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

use anyhow::anyhow;
use std::collections::HashMap;
use config::Config;
use serde::Deserialize;
use once_cell::sync::OnceCell;

pub static CONFIG: OnceCell<Configuration> = OnceCell::new();


#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub pgmoneta: Pgmoneta,
    #[serde(default = "default_port")]
    pub port: i32,
    pub admins: HashMap<String, String> //username -> password
}

#[derive(Clone, Debug, Deserialize)]
pub struct Pgmoneta {
    pub host: String,
    pub port: i32,
    pub version: String,
}

pub fn load_configuration(config_path: &str, user_path: &str) -> anyhow::Result<Configuration> {
    let conf = Config::builder()
        .add_source(config::File::with_name(config_path))
        .add_source(config::File::with_name(user_path))
        .build()?;
    conf.try_deserialize::<Configuration>().map_err(|e| {
        anyhow!("Error deserializing configuration at path {}, user {}: {:?}", config_path, user_path, e)
    })
}

fn default_port() -> i32 {
    8000
}
