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

use super::constant::{LogLevel, LogType};
use anyhow::anyhow;
use config::{Config, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Global, thread-safe instance of the application configuration.
///
/// This is initialized once at startup using [`load_configuration`] and accessed
/// globally throughout the application lifecycle.
pub static CONFIG: OnceCell<Configuration> = OnceCell::new();

/// Type alias representing the parsed user configuration.
///
/// Maps a section name (e.g., username) to a dictionary of properties (e.g., password).
pub type UserConf = HashMap<String, HashMap<String, String>>;

/// The root configuration structure containing all application settings.
///
/// The configuration of `pgmoneta` is split into sections. This structure
/// aggregates the `[pgmoneta_mcp]` and `[pgmoneta]` sections from the
/// configuration file, along with the parsed admin users.
#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    /// The overall properties of the MCP server.
    pub pgmoneta_mcp: PgmonetaMcpConfiguration,
    /// Settings to configure the connection with the remote `pgmoneta` server.
    pub pgmoneta: PgmonetaConfiguration,
    /// Parsed admin users mapping (username -> password).
    pub admins: HashMap<String, String>,
}

/// Configuration properties for connecting to the remote `pgmoneta` instance.
///
/// This corresponds to the `[pgmoneta]` section in the configuration file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PgmonetaConfiguration {
    /// The address of the pgmoneta instance (Required).
    pub host: String,
    /// The port of the pgmoneta instance (Required).
    pub port: i32,
}

/// Configuration properties for the MCP server itself.
///
/// This corresponds to the `[pgmoneta_mcp]` section in the configuration file,
/// where you configure the overall properties of the MCP server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PgmonetaMcpConfiguration {
    /// The port the MCP server starts on. Default: 8000.
    #[serde(default = "default_port")]
    pub port: i32,
<<<<<<< HEAD
=======
    /// API key to username mapping for authenticating MCP requests.
    #[serde(default = "default_api_keys")]
    pub api_keys: HashMap<String, String>, // api_key -> username
>>>>>>> 9679ae3 (Security: Fix Authentication Bypass, XSS hardening, and API key handling)
    /// The log file location. Default: `pgmoneta_mcp.log`.
    #[serde(default = "default_log_path")]
    pub log_path: String,
    /// The logging level (`trace`, `debug`, `info`, `warn`, `error`). Default: `info`.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// The logging type (`console`, `file`, `syslog`). Default: `console`.
    #[serde(default = "default_log_type")]
    pub log_type: String,
    /// The timestamp format prefix for log messages. Default: `%Y-%m-%d %H:%M:%S`.
    #[serde(default = "default_log_line_prefix")]
    pub log_line_prefix: String,
    /// Append to or create the log file (`append`, `create`). Default: `append`.
    #[serde(default = "default_log_mode")]
    pub log_mode: String,
    /// The time after which log file rotation is triggered (when `log_type = file` and `log_mode = append`).
    ///
    /// Supported values:
    /// * `0`: Never rotate
    /// * `m`, `M`: Minutely rotation
    /// * `h`, `H`: Hourly rotation
    /// * `d`, `D`: Daily rotation
    /// * `w`, `W`: Weekly rotation
    ///
    /// Default: `0`.
    #[serde(default = "default_log_rotation_age")]
    pub log_rotation_age: String,
<<<<<<< HEAD
=======
>>>>>>> 25c2ddd (Security: Fix Authentication Bypass, XSS hardening, and API key handling)
>>>>>>> 9679ae3 (Security: Fix Authentication Bypass, XSS hardening, and API key handling)
}

/// Loads the main configuration and user configuration from the specified file paths.
///
/// The files are parsed as INI format and deserialized into the [`Configuration`] struct.
///
/// # Arguments
///
/// * `config_path` - The file path to the main configuration (e.g., `pgmoneta-mcp.conf`).
/// * `user_path` - The file path to the user/admin configuration.
///
/// # Returns
///
/// Returns a populated [`Configuration`] object, or an error if the files cannot
/// be read or parsed correctly.
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

/// Loads only the user configuration from the specified file path.
///
/// # Arguments
///
/// * `user_path` - The file path to the user configuration file.
///
/// # Returns
///
/// Returns a parsed [`UserConf`] map, or an error if the file cannot be read or parsed.
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

// Private default value functions for Serde deserialization.
// Note: Internal helper functions generally do not require public API documentation.

fn default_port() -> i32 {
    8000
}

fn default_log_path() -> String {
    "pgmoneta_mcp.log".to_string()
}

fn default_log_level() -> String {
    LogLevel::INFO.to_string()
}

fn default_log_type() -> String {
    LogType::CONSOLE.to_string()
}

fn default_log_line_prefix() -> String {
    "%Y-%m-%d %H:%M:%S".to_string()
}

fn default_log_mode() -> String {
    "append".to_string()
}

<<<<<<< HEAD
=======
fn default_api_keys() -> HashMap<String, String> {
    HashMap::new()
}

>>>>>>> 9679ae3 (Security: Fix Authentication Bypass, XSS hardening, and API key handling)
fn default_log_rotation_age() -> String {
    "0".to_string()
}
