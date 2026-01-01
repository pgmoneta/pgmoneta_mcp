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

use anyhow::anyhow;
use config::{Config, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub static CONFIG: OnceCell<Configuration> = OnceCell::new();
pub type UserConf = HashMap<String, HashMap<String, String>>;

#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    pub pgmoneta_mcp: PgmonetaMcpConfiguration,
    pub pgmoneta: PgmonetaConfiguration,
    pub admins: HashMap<String, String>, //username -> password
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PgmonetaConfiguration {
    pub host: String,
    pub port: i32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PgmonetaMcpConfiguration {
    #[serde(default = "default_port")]
    pub port: i32,
}

pub fn load_configuration(config_path: &str, user_path: &str) -> anyhow::Result<Configuration> {
    let conf = Config::builder()
        .add_source(config::File::with_name(config_path).format(FileFormat::Ini))
        .add_source(config::File::with_name(user_path).format(FileFormat::Ini))
        .build()?;
    conf.try_deserialize::<Configuration>().map_err(|e| {
        anyhow!(
            "Error parsing configuration at path {}, user {}: {:?}",
            config_path,
            user_path,
            e
        )
    })
}

pub fn load_user_configuration(user_path: &str) -> anyhow::Result<UserConf> {
    let conf = Config::builder()
        .add_source(config::File::with_name(user_path).format(FileFormat::Ini))
        .build()?;
    conf.try_deserialize::<UserConf>().map_err(|e| {
        anyhow!(
            "Error parsing user configuration at path {}: {:?}",
            user_path,
            e
        )
    })
}

fn default_port() -> i32 {
    8000
}
