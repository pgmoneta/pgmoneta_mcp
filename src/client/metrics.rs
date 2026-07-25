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

use super::PgmonetaClient;
use crate::configuration::{CONFIG, Configuration};
use crate::telemetry;
use anyhow::anyhow;
use std::time::Instant;

impl PgmonetaClient {
    pub async fn request_metrics(username: &str) -> anyhow::Result<String> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        Self::ensure_admin_user(config, username)?;

        let metrics_url = Self::build_metrics_url(config);
        let start = Instant::now();
        let response = reqwest::get(&metrics_url).await;

        match response {
            Ok(response) => {
                let status = response.status();
                let outcome = status.as_u16().to_string();
                let body = response.text().await.map_err(|error| {
                    telemetry::metrics().record_pgmoneta_metrics_scrape(&outcome, start.elapsed());
                    anyhow!("Failed to read pgmoneta metrics response from {metrics_url}: {error}")
                })?;

                telemetry::metrics().record_pgmoneta_metrics_scrape(&outcome, start.elapsed());

                if !status.is_success() {
                    return Err(anyhow!(
                        "pgmoneta metrics endpoint {metrics_url} returned HTTP {status}: {body}"
                    ));
                }

                Ok(body)
            }
            Err(error) => {
                telemetry::metrics()
                    .record_pgmoneta_metrics_scrape("request_error", start.elapsed());
                Err(anyhow!(
                    "Failed to query pgmoneta metrics endpoint {metrics_url}: {error}"
                ))
            }
        }
    }

    fn build_metrics_url(config: &Configuration) -> String {
        let host = if config.pgmoneta.host.contains(':')
            && !config.pgmoneta.host.starts_with('[')
            && !config.pgmoneta.host.ends_with(']')
        {
            format!("[{}]", config.pgmoneta.host)
        } else {
            config.pgmoneta.host.clone()
        };

        format!("http://{host}:{}/metrics", config.pgmoneta.metrics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{PgmonetaConfiguration, PgmonetaMcpConfiguration};
    use std::collections::HashMap;

    fn test_configuration(host: &str) -> Configuration {
        Configuration {
            pgmoneta_mcp: PgmonetaMcpConfiguration {
                port: 8000,
                log_path: "test.log".to_string(),
                log_level: "info".to_string(),
                log_type: "console".to_string(),
                log_line_prefix: "%Y-%m-%d %H:%M:%S".to_string(),
                log_mode: "append".to_string(),
                log_rotation_age: "0".to_string(),
            },
            pgmoneta: PgmonetaConfiguration {
                host: host.to_string(),
                port: 5000,
                base_dir: "/tmp/pgmoneta".to_string(),
                metrics: 5001,
                compression: "zstd".to_string(),
                encryption: "aes_256_gcm".to_string(),
            },
            admins: HashMap::new(),
            llm: None,
        }
    }

    #[test]
    fn test_build_metrics_url_uses_configured_metrics_port() {
        let config = test_configuration("localhost");

        assert_eq!(
            PgmonetaClient::build_metrics_url(&config),
            "http://localhost:5001/metrics"
        );
    }

    #[test]
    fn test_build_metrics_url_wraps_ipv6_hosts() {
        let config = test_configuration("::1");

        assert_eq!(
            PgmonetaClient::build_metrics_url(&config),
            "http://[::1]:5001/metrics"
        );
    }
}
