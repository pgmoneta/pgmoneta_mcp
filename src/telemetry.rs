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
use axum::extract::State;
use axum::http::{Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use once_cell::sync::Lazy;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::metrics::histogram::Histogram;
use prometheus_client::registry::Registry;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HTTP_DURATION_BUCKETS: [f64; 11] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
];

type Labels = Vec<(String, String)>;
type HistogramFamily = Family<Labels, Histogram, fn() -> Histogram>;

pub struct Metrics {
    registry: Mutex<Registry>,
    http_requests_total: Family<Labels, Counter>,
    http_request_duration_seconds: HistogramFamily,
    http_requests_in_flight: Gauge,
    pgmoneta_metrics_scrapes_total: Family<Labels, Counter>,
    pgmoneta_metrics_scrape_duration_seconds: HistogramFamily,
}

static METRICS: Lazy<Arc<Metrics>> = Lazy::new(|| Arc::new(Metrics::new()));

pub fn metrics() -> Arc<Metrics> {
    Arc::clone(&METRICS)
}

impl Metrics {
    pub fn new() -> Self {
        let http_requests_total = Family::<Labels, Counter>::default();
        let http_request_duration_seconds =
            Family::<Labels, Histogram, fn() -> Histogram>::new_with_constructor(
                http_duration_histogram,
            );
        let http_requests_in_flight = Gauge::default();
        let pgmoneta_metrics_scrapes_total = Family::<Labels, Counter>::default();
        let pgmoneta_metrics_scrape_duration_seconds =
            Family::<Labels, Histogram, fn() -> Histogram>::new_with_constructor(
                http_duration_histogram,
            );

        let mut registry = Registry::default();
        registry.register(
            "pgmoneta_mcp_http_requests",
            "Number of HTTP requests handled by pgmoneta-mcp.",
            http_requests_total.clone(),
        );
        registry.register(
            "pgmoneta_mcp_http_request_duration_seconds",
            "HTTP request latency for pgmoneta-mcp endpoints.",
            http_request_duration_seconds.clone(),
        );
        registry.register(
            "pgmoneta_mcp_http_requests_in_flight",
            "Number of HTTP requests currently being handled by pgmoneta-mcp.",
            http_requests_in_flight.clone(),
        );
        registry.register(
            "pgmoneta_mcp_pgmoneta_metrics_scrapes",
            "Number of scrapes performed against the configured pgmoneta metrics endpoint.",
            pgmoneta_metrics_scrapes_total.clone(),
        );
        registry.register(
            "pgmoneta_mcp_pgmoneta_metrics_scrape_duration_seconds",
            "Latency of scrapes against the configured pgmoneta metrics endpoint.",
            pgmoneta_metrics_scrape_duration_seconds.clone(),
        );

        Self {
            registry: Mutex::new(registry),
            http_requests_total,
            http_request_duration_seconds,
            http_requests_in_flight,
            pgmoneta_metrics_scrapes_total,
            pgmoneta_metrics_scrape_duration_seconds,
        }
    }

    pub fn record_http_request(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        duration: Duration,
    ) {
        let labels = vec![
            ("method".to_string(), method.to_string()),
            ("path".to_string(), path.to_string()),
            ("status".to_string(), status.as_u16().to_string()),
        ];

        self.http_requests_total.get_or_create(&labels).inc();
        self.http_request_duration_seconds
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }

    pub fn increment_http_requests_in_flight(&self) {
        self.http_requests_in_flight.inc();
    }

    pub fn decrement_http_requests_in_flight(&self) {
        self.http_requests_in_flight.dec();
    }

    pub fn record_pgmoneta_metrics_scrape(&self, outcome: &str, duration: Duration) {
        let labels = vec![("outcome".to_string(), outcome.to_string())];

        self.pgmoneta_metrics_scrapes_total
            .get_or_create(&labels)
            .inc();
        self.pgmoneta_metrics_scrape_duration_seconds
            .get_or_create(&labels)
            .observe(duration.as_secs_f64());
    }

    pub fn encode(&self) -> anyhow::Result<String> {
        let registry = self
            .registry
            .lock()
            .map_err(|_| anyhow!("Failed to acquire metrics registry lock"))?;
        let mut buffer = String::new();
        encode(&mut buffer, &registry)
            .map_err(|error| anyhow!("Failed to encode metrics registry: {error}"))?;
        Ok(buffer)
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn metrics_handler(
    State(metrics): State<Arc<Metrics>>,
) -> Result<impl IntoResponse, StatusCode> {
    metrics
        .encode()
        .map(|body| {
            (
                [(
                    header::CONTENT_TYPE,
                    "application/openmetrics-text; version=1.0.0; charset=utf-8",
                )],
                body,
            )
        })
        .map_err(|error| {
            tracing::error!(error = %error, "Failed to encode Prometheus metrics");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

pub async fn metrics_middleware(
    State(metrics): State<Arc<Metrics>>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_string();
    let start = Instant::now();
    metrics.increment_http_requests_in_flight();
    let _guard = InFlightGuard::new(Arc::clone(&metrics));

    let response = next.run(request).await;
    metrics.record_http_request(&method, &path, response.status(), start.elapsed());

    response
}

fn http_duration_histogram() -> Histogram {
    Histogram::new(HTTP_DURATION_BUCKETS)
}

struct InFlightGuard {
    metrics: Arc<Metrics>,
}

impl InFlightGuard {
    fn new(metrics: Arc<Metrics>) -> Self {
        Self { metrics }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.metrics.decrement_http_requests_in_flight();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_encode_records_http_and_scrape_metrics() {
        let metrics = Metrics::new();
        metrics.record_http_request("GET", "/mcp", StatusCode::OK, Duration::from_millis(20));
        metrics.record_pgmoneta_metrics_scrape("200", Duration::from_millis(15));

        let encoded = metrics.encode().unwrap();

        assert!(encoded.contains("pgmoneta_mcp_http_requests_total"));
        assert!(encoded.contains("path=\"/mcp\""));
        assert!(encoded.contains("pgmoneta_mcp_pgmoneta_metrics_scrapes_total"));
        assert!(encoded.contains("outcome=\"200\""));
    }

    #[test]
    fn test_in_flight_guard_increments_and_decrements() {
        let metrics = Arc::new(Metrics::new());
        assert_eq!(metrics.http_requests_in_flight.get(), 0);

        metrics.increment_http_requests_in_flight();
        assert_eq!(metrics.http_requests_in_flight.get(), 1);

        {
            let _guard = InFlightGuard::new(Arc::clone(&metrics));
        }
        assert_eq!(metrics.http_requests_in_flight.get(), 0);
    }

    #[test]
    fn test_metrics_records_multiple_status_codes_and_methods() {
        let metrics = Metrics::new();
        metrics.record_http_request(
            "POST",
            "/mcp",
            StatusCode::INTERNAL_SERVER_ERROR,
            Duration::from_millis(100),
        );
        metrics.record_http_request(
            "GET",
            "/metrics",
            StatusCode::NOT_FOUND,
            Duration::from_millis(5),
        );
        metrics.record_pgmoneta_metrics_scrape("request_error", Duration::from_millis(50));

        let encoded = metrics.encode().unwrap();
        assert!(encoded.contains("method=\"POST\""));
        assert!(encoded.contains("status=\"500\""));
        assert!(encoded.contains("method=\"GET\""));
        assert!(encoded.contains("status=\"404\""));
        assert!(encoded.contains("outcome=\"request_error\""));
    }

    #[tokio::test]
    async fn test_metrics_handler_response() {
        let metrics = Arc::new(Metrics::new());
        metrics.record_http_request("GET", "/mcp", StatusCode::OK, Duration::from_millis(10));

        let response = metrics_handler(State(metrics))
            .await
            .unwrap()
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/openmetrics-text; version=1.0.0; charset=utf-8"
        );
    }
}
