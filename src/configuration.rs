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
    /// The base directory where pgmoneta stores its data.
    pub base_dir: String,
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
    /// The LLM provider backend. Required when `[llm]` is present.
    pub provider: String,
    /// The endpoint URL for the LLM server. Required when `[llm]` is present.
    pub endpoint: String,
    /// The model name to use for inference. Defaults to a provider-specific value.
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
        .add_source(config::File::with_name(user_path).format(FileFormat::Ini))
        .build()?;
    let conf = conf.try_deserialize::<Configuration>().map_err(|e| {
        anyhow!(
            "Error parsing configuration at path {}, user {}: {:?}",
            config_path,
            user_path,
            e
        )
    })?;
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
    conf.try_deserialize::<UserConf>().map_err(|e| {
        anyhow!(
            "Error parsing user configuration at path {}: {:?}",
            user_path,
            e
        )
    })
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

fn default_log_rotation_age() -> String {
    "0".to_string()
}

fn default_llm_max_tool_rounds() -> usize {
    10
}

fn normalize_configuration(mut conf: Configuration) -> anyhow::Result<Configuration> {
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
    llm.provider = llm.provider.trim().to_string();
    llm.endpoint = llm.endpoint.trim().to_string();
    llm.model = llm.model.trim().to_string();

    if llm.provider.is_empty() {
        return Err(anyhow!("LLM provider must not be empty"));
    }

    if llm.endpoint.is_empty() {
        return Err(anyhow!("LLM endpoint must not be empty"));
    }

    if llm.model.is_empty() {
        return Err(anyhow!("LLM model must not be empty"));
    }

    validate_llm_provider(&llm.provider)
}

fn parse_client_llm_profiles(
    sections: HashMap<String, HashMap<String, String>>,
) -> anyhow::Result<HashMap<String, LlmConfiguration>> {
    sections
        .into_iter()
        .map(|(name, values)| {
            let provider = values.get("provider").cloned().unwrap_or_default();
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
                    provider,
                    endpoint,
                    model,
                    max_tool_rounds,
                },
            ))
        })
        .collect()
}

fn validate_llm_provider(provider: &str) -> anyhow::Result<()> {
    match provider.to_lowercase().as_str() {
        "ollama" | "llama.cpp" | "ramalama" | "vllm" => Ok(()),
        _ => Err(anyhow!("Unsupported LLM provider '{}'", provider)),
    }
}

fn default_compression() -> String {
    "zstd".to_string()
}

fn default_encryption() -> String {
    "aes_256_gcm".to_string()
}

fn default_metrics_port() -> i32 {
    5001
}

fn default_timeout() -> u64 {
    30
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
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\ntimeout = 15\n\n[llm]\nprovider = ollama\nendpoint = http://localhost:11434\nmodel = qwen2.5:3b\nmax_tool_rounds = 7\n"
        )
        .unwrap();

        let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

        assert_eq!(conf.client.url, "http://localhost:8000/mcp");
        assert_eq!(conf.client.timeout, 15);
        assert_eq!(conf.client.model, "llm");

        let llm = conf.llms.get("llm").unwrap();
        assert_eq!(llm.provider, "ollama");
        assert_eq!(llm.endpoint, "http://localhost:11434");
        assert_eq!(llm.model, "qwen2.5:3b");
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
        assert!(conf.llms.is_empty());
    }

    #[test]
    fn test_load_client_configuration_with_named_llm_profiles() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\nmodel = qwen\n\n[qwen]\nprovider = ollama\nendpoint = http://localhost:11434\nmodel = qwen2.5:7b\n\n[gemma]\nprovider = llama.cpp\nendpoint = http://localhost:8100/v1\nmodel = ggml-org/gemma-3-4b-it-GGUF\n"
        )
        .unwrap();

        let conf = load_client_configuration(file.path().to_str().unwrap()).unwrap();

        assert_eq!(conf.client.model, "qwen");
        assert_eq!(conf.llms.len(), 2);
        assert_eq!(conf.llms.get("qwen").unwrap().provider, "ollama");
        assert_eq!(conf.llms.get("gemma").unwrap().provider, "llama.cpp");
    }

    #[test]
    fn test_load_client_configuration_requires_default_model_for_multiple_profiles() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            file,
            "[pgmoneta_mcp_client]\nurl = http://localhost:8000/mcp\n\n[qwen]\nprovider = ollama\nendpoint = http://localhost:11434\nmodel = qwen2.5:7b\n\n[gemma]\nprovider = llama.cpp\nendpoint = http://localhost:8100/v1\nmodel = ggml-org/gemma-3-4b-it-GGUF\n"
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
            "[pgmoneta_mcp]\nport = 8000\n\n[pgmoneta]\nhost = localhost\nport = 5000\n\nbase_dir = /tmp/pgmoneta\n"
        )
        .unwrap();
        writeln!(user_file, "[admins]\nadmin = encrypted-password\n").unwrap();

        let conf = load_configuration(
            config_file.path().to_str().unwrap(),
            user_file.path().to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(conf.pgmoneta.metrics, 5001);
    }

    #[test]
    fn test_load_configuration_with_explicit_metrics_port() {
        let mut config_file = tempfile::NamedTempFile::new().unwrap();
        let mut user_file = tempfile::NamedTempFile::new().unwrap();

        writeln!(
            config_file,
            "[pgmoneta_mcp]\nport = 8000\n\n[pgmoneta]\nhost = localhost\nport = 5000\nbase_dir = /tmp/pgmoneta\nmetrics = 7001\n"
        )
        .unwrap();
        writeln!(user_file, "[admins]\nadmin = encrypted-password\n").unwrap();

        let conf = load_configuration(
            config_file.path().to_str().unwrap(),
            user_file.path().to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(conf.pgmoneta.metrics, 7001);
    }
}
