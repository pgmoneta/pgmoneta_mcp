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
use std::time::{Duration, Instant};

/// How long to wait for the pgmoneta metrics endpoint before giving up.
const METRICS_TIMEOUT: Duration = Duration::from_secs(10);

impl PgmonetaClient {
    pub async fn request_metrics(username: &str) -> anyhow::Result<String> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        Self::ensure_admin_user(config, username)?;

        let metrics_url = Self::build_metrics_url(config);
        Self::fetch_metrics(&metrics_url, METRICS_TIMEOUT).await
    }

    /// Fetches the metrics page, giving up once `time_limit` has passed.
    ///
    /// The limit covers the whole request: connecting, waiting for the answer
    /// and reading the body.
    async fn fetch_metrics(metrics_url: &str, time_limit: Duration) -> anyhow::Result<String> {
        let client = reqwest::Client::builder().timeout(time_limit).build()?;
        let start = Instant::now();
        let response = client.get(metrics_url).send().await;

        match response {
            Ok(response) => {
                let status = response.status();
                let body = match response.text().await {
                    Ok(body) => body,
                    Err(error) => {
                        let outcome = if error.is_timeout() {
                            "timeout".to_string()
                        } else {
                            status.as_u16().to_string()
                        };
                        telemetry::metrics()
                            .record_pgmoneta_metrics_scrape(&outcome, start.elapsed());
                        return Err(Self::metrics_error(metrics_url, time_limit, &error));
                    }
                };

                telemetry::metrics()
                    .record_pgmoneta_metrics_scrape(&status.as_u16().to_string(), start.elapsed());

                if !status.is_success() {
                    return Err(anyhow!(
                        "pgmoneta metrics endpoint {metrics_url} returned HTTP {status}: {body}"
                    ));
                }

                Ok(body)
            }
            Err(error) => {
                let outcome = if error.is_timeout() {
                    "timeout"
                } else {
                    "request_error"
                };
                telemetry::metrics().record_pgmoneta_metrics_scrape(outcome, start.elapsed());
                Err(Self::metrics_error(metrics_url, time_limit, &error))
            }
        }
    }

    fn metrics_error(
        metrics_url: &str,
        time_limit: Duration,
        error: &reqwest::Error,
    ) -> anyhow::Error {
        if error.is_timeout() {
            anyhow!(
                "Timed out after {}s waiting for pgmoneta metrics endpoint {metrics_url}",
                time_limit.as_secs_f32()
            )
        } else {
            anyhow!("Failed to query pgmoneta metrics endpoint {metrics_url}: {error}")
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
                metrics: 5001,
                compression: None,
                encryption: None,
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

    /// Starts a server that accepts connections and then never answers.
    async fn silent_server() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut open_connections = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                open_connections.push(socket);
            }
        });
        format!("http://{address}/metrics")
    }

    #[tokio::test]
    async fn test_fetch_metrics_times_out_when_the_server_never_answers() {
        let url = silent_server().await;

        let started = Instant::now();
        let error = PgmonetaClient::fetch_metrics(&url, Duration::from_millis(200))
            .await
            .unwrap_err();

        assert!(error.to_string().contains("Timed out"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn test_fetch_metrics_returns_the_body_on_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = socket.read(&mut request).await;
            let reply = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nup 1";
            socket.write_all(reply.as_bytes()).await.unwrap();
        });

        let body = PgmonetaClient::fetch_metrics(
            &format!("http://{address}/metrics"),
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        assert_eq!(body, "up 1");
    }
}
