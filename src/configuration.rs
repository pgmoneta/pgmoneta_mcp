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

use super::constant::{Compression, Encryption, LogLevel, LogType};
use anyhow::{Context, Result, anyhow, bail};
use config::{Config, FileFormat};
use once_cell::sync::OnceCell;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Global, thread-safe instance of the application configuration.
///
/// This is initialized once at startup using [`load_configuration`] and accessed
/// globally throughout the application lifecycle.
pub static CONFIG: OnceCell<Configuration> = OnceCell::new();

/// Type alias representing the parsed user configuration.
///
/// Maps a section name to a dictionary of properties (e.g., username to encrypted password).
pub type UserConf = HashMap<String, HashMap<String, String>>;

pub const USER_SECTION: &str = "pgmoneta-mcp-users";
pub const USER_SECTION_HYPHEN: &str = USER_SECTION;
pub const DEFAULT_USER_SECTION: &str = USER_SECTION;

pub fn is_valid_user_section(section: &str) -> bool {
    section == USER_SECTION
}

pub fn validate_user_configuration(conf: &UserConf) -> anyhow::Result<()> {
    for section in conf.keys() {
        if !is_valid_user_section(section) {
            bail!(
                "Invalid section header '[{}]' in users configuration. Expected '[{}]'",
                section,
                USER_SECTION
            );
        }
    }

    Ok(())
}

pub fn get_user_section_name(conf: &UserConf) -> Option<&str> {
    if conf.contains_key(USER_SECTION) {
        Some(USER_SECTION)
    } else {
        None
    }
}

pub fn get_users(conf: &UserConf) -> Option<&HashMap<String, String>> {
    conf.get(USER_SECTION)
}

pub fn get_users_mut(conf: &mut UserConf) -> Option<&mut HashMap<String, String>> {
    conf.get_mut(USER_SECTION)
}

/// The root configuration structure containing all application settings.
///
/// The configuration of `pgmoneta` is split into sections. This structure
/// aggregates the `[pgmoneta_mcp]` and `[pgmoneta]` sections from the
/// configuration file, along with the parsed admin users.
#[derive(Clone, Debug, Deserialize)]
pub struct Configuration {
    /// The overall properties of the MCP server.
    #[serde(alias = "pgmoneta-mcp")]
    pub pgmoneta_mcp: PgmonetaMcpConfiguration,
    /// Settings to configure the connection with the remote `pgmoneta` server.
    pub pgmoneta: PgmonetaConfiguration,
    /// Parsed admin users mapping (username -> password).
    #[serde(default)]
    pub admins: HashMap<String, String>,
    /// Optional configuration for the local LLM integration.
    pub llm: Option<LlmConfiguration>,
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
    /// The port of the pgmoneta Prometheus metrics endpoint. Default: 5001.
    #[serde(default = "default_metrics_port")]
    pub metrics: i32,
    /// Compression algorithm for MCP <-> pgmoneta communication.
    /// Supported: "none", "gzip", "zstd", "lz4", "bzip2".
    /// Default: "zstd".
    #[serde(default = "default_compression")]
    pub compression: String,
    /// Encryption algorithm for MCP <-> pgmoneta communication.
    /// Supported: "none", "aes_256_gcm", "aes_192_gcm", "aes_128_gcm".
    /// Default: "aes_256_gcm".
    #[serde(default = "default_encryption")]
    pub encryption: String,
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
}

/// Configuration properties for the local LLM integration.
///
/// This corresponds to the optional `[llm]` section in the configuration file,
/// where you configure the connection to a local LLM inference server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LlmConfiguration {
    /// The endpoint URL for the LLM server. Required when `[llm]` is present.
    pub endpoint: String,
    /// The model name to use for inference. Required when `[llm]` is present.
    #[serde(default)]
    pub model: String,
    /// Maximum number of tool-calling rounds per user prompt. Default: `10`.
    #[serde(default = "default_llm_max_tool_rounds")]
    pub max_tool_rounds: usize,
}

/// Configuration properties for the inspector.
///
/// This corresponds to the `[inspector]` section in the inspector configuration file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InspectorConfiguration {
    /// The URL of the MCP server.
    pub url: String,
    /// Connection timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
}

/// Configuration properties for the interactive MCP client.
///
/// This corresponds to the `[pgmoneta_mcp_client]` section in the client configuration file.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientConfiguration {
    /// The MCP server endpoint.
    pub url: String,
    /// Connection timeout in seconds. Default: 30.
    #[serde(default = "default_timeout")]
    pub timeout: u64,
    /// Default named LLM profile for natural-language requests.
    #[serde(default)]
    pub model: String,
    /// Ask before running a tool that is not read-only in user mode. Default: off.
    #[serde(default)]
    pub confirm: bool,
}

/// Root configuration for the interactive MCP client.
///
/// This includes the required `[pgmoneta_mcp_client]` section and any number of
/// named LLM profile sections that follow the shared LLM configuration format.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientAppConfiguration {
    /// Configuration for the interactive MCP client.
    pub client: ClientConfiguration,
    /// Named LLM profiles keyed by section name in the client configuration file.
    pub llms: HashMap<String, LlmConfiguration>,
}

#[derive(Deserialize)]
struct InspectorConfRoot {
    pub inspector: InspectorConfiguration,
}

#[derive(Deserialize)]
struct ClientConfRoot {
    #[serde(rename = "pgmoneta_mcp_client")]
    pub client: ClientConfiguration,
    #[serde(flatten)]
    pub llms: HashMap<String, HashMap<String, String>>,
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
        .build()?;
    let mut conf = conf.try_deserialize::<Configuration>().map_err(|e| {
        anyhow!(
            "Error parsing configuration at path {}: {:?}",
            config_path,
            e
        )
    })?;

    let user_conf = load_user_configuration(user_path)?;
    if let Some(users) = get_users(&user_conf) {
        conf.admins = users.clone();
    } else {
        bail!(
            "Missing user configuration section in '{}'. Expected '[{}]'",
            user_path,
            USER_SECTION
        );
    }

    normalize_configuration(conf)
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
    let user_conf = conf.try_deserialize::<UserConf>().map_err(|e| {
        anyhow!(
            "Error parsing user configuration at path {}: {:?}",
            user_path,
            e
        )
    })?;
    validate_user_configuration(&user_conf)?;
    Ok(user_conf)
}

/// Loads only the inspector configuration from the specified file path.
///
/// # Arguments
///
/// * `inspector_path` - The file path to the inspector configuration file.
///
/// # Returns
///
/// Returns a parsed [`InspectorConfiguration`] object, or an error if the file cannot be read or parsed.
pub fn load_inspector_configuration(
    inspector_path: &str,
) -> anyhow::Result<InspectorConfiguration> {
    let conf = Config::builder()
        .add_source(config::File::with_name(inspector_path).format(FileFormat::Ini))
        .build()?;
    let root = conf.try_deserialize::<InspectorConfRoot>().map_err(|e| {
        anyhow!(
            "Error parsing inspector configuration at path {}: {:?}",
            inspector_path,
            e
        )
    })?;
    Ok(root.inspector)
}

/// Loads only the interactive client configuration from the specified file path.
///
/// # Arguments
///
/// * `client_path` - The file path to the client configuration file.
///
/// # Returns
///
/// Returns a parsed [`ClientAppConfiguration`] object, or an error if the file cannot be read or parsed.
pub fn load_client_configuration(client_path: &str) -> anyhow::Result<ClientAppConfiguration> {
    let conf = Config::builder()
        .add_source(config::File::with_name(client_path).format(FileFormat::Ini))
        .build()?;
    let root = conf.try_deserialize::<ClientConfRoot>().map_err(|e| {
        anyhow!(
            "Error parsing client configuration at path {}: {:?}",
            client_path,
            e
        )
    })?;
    normalize_client_configuration(ClientAppConfiguration {
        client: root.client,
        llms: parse_client_llm_profiles(root.llms)?,
    })
}

pub fn default_port() -> i32 {
    8000
}

pub fn default_log_path() -> String {
    "pgmoneta_mcp.log".to_string()
}

pub fn default_log_level() -> String {
    LogLevel::INFO.to_string()
}

pub fn default_log_type() -> String {
    LogType::CONSOLE.to_string()
}

pub fn default_log_line_prefix() -> String {
    "%Y-%m-%d %H:%M:%S".to_string()
}

pub fn default_log_mode() -> String {
    "append".to_string()
}

pub fn default_log_rotation_age() -> String {
    "0".to_string()
}

pub fn default_llm_max_tool_rounds() -> usize {
    10
}

fn normalize_configuration(mut conf: Configuration) -> anyhow::Result<Configuration> {
    // Fail at startup on a typo instead of on the first request.
    Compression::from_config_name(&conf.pgmoneta.compression)
        .map_err(|e| anyhow!("Invalid [pgmoneta] compression: {e}"))?;
    Encryption::from_config_name(&conf.pgmoneta.encryption)
        .map_err(|e| anyhow!("Invalid [pgmoneta] encryption: {e}"))?;

    if let Some(llm) = conf.llm.as_mut() {
        normalize_llm_configuration(llm)?;
    }

    Ok(conf)
}

fn normalize_client_configuration(
    mut conf: ClientAppConfiguration,
) -> anyhow::Result<ClientAppConfiguration> {
    conf.client.model = conf.client.model.trim().to_string();

    for llm in conf.llms.values_mut() {
        normalize_llm_configuration(llm)?;
    }

    if conf.llms.is_empty() {
        conf.client.model.clear();
        return Ok(conf);
    }

    if conf.client.model.is_empty() {
        if conf.llms.len() == 1 {
            conf.client.model = conf
                .llms
                .keys()
                .next()
                .cloned()
                .ok_or_else(|| anyhow!("Missing LLM model definition"))?;
        } else {
            return Err(anyhow!(
                "Client configuration must define [pgmoneta_mcp_client].model when multiple LLM profiles are configured"
            ));
        }
    }

    if !conf.llms.contains_key(&conf.client.model) {
        return Err(anyhow!(
            "Client model '{}' is not defined in the client configuration",
            conf.client.model
        ));
    }

    Ok(conf)
}

fn normalize_llm_configuration(llm: &mut LlmConfiguration) -> anyhow::Result<()> {
    llm.endpoint = llm.endpoint.trim().to_string();
    llm.model = llm.model.trim().to_string();

    if llm.endpoint.is_empty() {
        return Err(anyhow!("LLM endpoint must not be empty"));
    }

    if llm.model.is_empty() {
        return Err(anyhow!("LLM model must not be empty"));
    }

    Ok(())
}

fn parse_client_llm_profiles(
    sections: HashMap<String, HashMap<String, String>>,
) -> anyhow::Result<HashMap<String, LlmConfiguration>> {
    sections
        .into_iter()
        .map(|(name, values)| {
            let endpoint = values.get("endpoint").cloned().unwrap_or_default();
            let model = values.get("model").cloned().unwrap_or_default();
            let max_tool_rounds = match values.get("max_tool_rounds") {
                Some(value) => value.trim().parse::<usize>().map_err(|e| {
                    anyhow!(
                        "Invalid max_tool_rounds '{}' for client LLM profile '{}': {}",
                        value,
                        name,
                        e
                    )
                })?,
                None => default_llm_max_tool_rounds(),
            };

            Ok((
                name,
                LlmConfiguration {
                    endpoint,
                    model,
                    max_tool_rounds,
                },
            ))
        })
        .collect()
}

pub fn default_compression() -> String {
    "zstd".to_string()
}

pub fn default_encryption() -> String {
    "aes_256_gcm".to_string()
}

pub fn default_metrics_port() -> i32 {
    5001
}

pub fn default_timeout() -> u64 {
    30
}

pub fn write_config_file(content: &str, file_name: &str, dir: PathBuf) -> Result<String> {
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("failed to create directory {}", dir.display()))?;

    let path = dir.join(file_name);

    std::fs::write(&path, content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(format!("\nWrote {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_load_client_configuration_with_llm_section() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\ntimeout = 15\n\n[llm]\nendpoint = http://localhost:8100/v1\nmodel = ggml-org/gemma-4-E4B-it-GGUF\nmax_tool_rounds = 7\n"
        )
        .unwrap();

        let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

        assert_eq!(conf.client.url, "http://localhost:8000/mcp");
        assert_eq!(conf.client.timeout, 15);
        assert_eq!(conf.client.model, "llm");

        let llm = conf.llms.get("llm").unwrap();
        assert_eq!(llm.endpoint, "http://localhost:8100/v1");
        assert_eq!(llm.model, "ggml-org/gemma-4-E4B-it-GGUF");
        assert_eq!(llm.max_tool_rounds, 7);
    }

    #[test]
    fn test_load_client_configuration_without_llm_section() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\n"
        )
        .unwrap();

        let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

        assert_eq!(conf.client.url, "http://localhost:8000/mcp");
        assert_eq!(conf.client.timeout, 30);
        assert!(conf.client.model.is_empty());
        assert!(!conf.client.confirm);
        assert!(conf.llms.is_empty());
    }

    #[test]
    fn test_load_client_configuration_confirm() {
        for (value, expected) in [
            ("on", true),
            ("true", true),
            ("off", false),
            ("false", false),
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            writeln!(
                file,
                "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\nconfirm = {value}\n"
            )
            .unwrap();

            let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

            assert_eq!(conf.client.confirm, expected, "confirm = {value}");
        }
    }

    #[test]
    fn test_load_client_configuration_with_named_llm_profiles() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\nmodel = gemma\n\n[gemma]\nendpoint = http://localhost:8100/v1\nmodel = ggml-org/gemma-4-E4B-it-GGUF\n\n[coder]\nendpoint = http://localhost:8200/v1\nmodel = unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF\n"
        )
        .unwrap();

        let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

        assert_eq!(conf.client.model, "gemma");
        assert_eq!(conf.llms.len(), 2);
        assert_eq!(
            conf.llms.get("gemma").unwrap().endpoint,
            "http://localhost:8100/v1"
        );
        assert_eq!(
            conf.llms.get("coder").unwrap().endpoint,
            "http://localhost:8200/v1"
        );
    }

    #[test]
    fn test_load_client_configuration_requires_default_model_for_multiple_profiles() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\n\n[gemma]\nendpoint = http://localhost:8100/v1\nmodel = ggml-org/gemma-4-E4B-it-GGUF\n\n[coder]\nendpoint = http://localhost:8200/v1\nmodel = unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF\n"
        )
        .unwrap();

        let err = load_client_configuration(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("must define [pgmoneta_mcp_client].model")
        );
    }

    #[test]
    fn test_load_configuration_defaults_metrics_port() {
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        let mut user_file = tempfile::NamedTempFile::new().unwrap();

        writeln!(
            config_file,
            "[pgmoneta_mcp]\nport = 8000\n\n[pgmoneta]\nhost = localhost\nport = 5000\n"
        )
        .unwrap();
        writeln!(
            user_file,
            "[pgmoneta-mcp-users]\nadmin = encrypted-password\n"
        )
        .unwrap();

        let conf = load_configuration(
            config_file.path().to_str().unwrap(),
            user_file.path().to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(conf.pgmoneta.metrics, 5001);
        assert_eq!(
            conf.admins.get("admin").map(String::as_str),
            Some("encrypted-password")
        );
    }

    #[test]
    fn test_load_configuration_with_explicit_metrics_port() {
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        let mut user_file = tempfile::NamedTempFile::new().unwrap();

        writeln!(
            config_file,
            "[pgmoneta_mcp]\nport = 8000\n\n[pgmoneta]\nhost = localhost\nport = 5000\nmetrics = 7001\n"
        )
        .unwrap();
        writeln!(
            user_file,
            "[pgmoneta-mcp-users]\nadmin = encrypted-password\n"
        )
        .unwrap();

        let conf = load_configuration(
            config_file.path().to_str().unwrap(),
            user_file.path().to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(conf.pgmoneta.metrics, 7001);
    }

    #[test]
    fn test_load_user_configuration_accepts_valid_header() {
        let mut hyphen_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(hyphen_file, "[pgmoneta-mcp-users]\nu1 = p1\n").unwrap();
        let hyphen_conf = load_user_configuration(hyphen_file.path().to_str().unwrap()).unwrap();
        assert_eq!(
            get_users(&hyphen_conf)
                .unwrap()
                .get("u1")
                .map(String::as_str),
            Some("p1")
        );
    }

    #[test]
    fn test_load_user_configuration_rejects_underscore_header() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "[pgmoneta_mcp_users]\nadmin = pass\n").unwrap();

        let err = load_user_configuration(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid section header '[pgmoneta_mcp_users]'")
        );
    }

    #[test]
    fn test_load_user_configuration_rejects_admins_header() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "[admins]\nadmin = pass\n").unwrap();

        let err = load_user_configuration(file.path().to_str().unwrap()).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid section header '[admins]'")
        );
    }

    #[test]
    fn test_load_user_configuration_rejects_arbitrary_header() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(file, "[users]\nadmin = pass\n").unwrap();

        let err = load_user_configuration(file.path().to_str().unwrap()).unwrap_err();
        assert!(err.to_string().contains("Invalid section header '[users]'"));
    }

    fn load_main_configuration(pgmoneta_section: &str) -> anyhow::Result<Configuration> {
        let mut conf_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            conf_file,
            "[pgmoneta_mcp]

[pgmoneta]
host = localhost
port = 5002
{pgmoneta_section}"
        )
        .unwrap();
        let mut users_file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            users_file,
            "[pgmoneta-mcp-users]
admin = secret
"
        )
        .unwrap();

        load_configuration(
            conf_file.path().to_str().unwrap(),
            users_file.path().to_str().unwrap(),
        )
    }

    #[test]
    fn test_load_configuration_keeps_compression_and_encryption() {
        let conf = load_main_configuration("compression = lz4\nencryption = none\n").unwrap();

        assert_eq!(conf.pgmoneta.compression, "lz4");
        assert_eq!(conf.pgmoneta.encryption, "none");
    }

    #[test]
    fn test_load_configuration_defaults_to_zstd_and_aes_256_gcm() {
        let conf = load_main_configuration("").unwrap();

        assert_eq!(conf.pgmoneta.compression, "zstd");
        assert_eq!(conf.pgmoneta.encryption, "aes_256_gcm");
    }

    #[test]
    fn test_load_configuration_rejects_unknown_compression() {
        let err = load_main_configuration("compression = banana\n").unwrap_err();

        assert!(err.to_string().contains("compression"), "{err}");
    }

    #[test]
    fn test_load_configuration_rejects_unknown_encryption() {
        let err = load_main_configuration("encryption = banana\n").unwrap_err();

        assert!(err.to_string().contains("encryption"), "{err}");
    }
}
