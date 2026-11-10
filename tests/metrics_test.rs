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

use pgmoneta_mcp::handler::PgmonetaHandler;
use pgmoneta_mcp::handler::metrics::{GetMetricsTool, MetricRequest, MetricTool, MetricsRequest};
use rmcp::handler::server::router::tool::AsyncTool;
use serial_test::serial;
use std::collections::HashMap;

mod common;

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn get_metrics_integration_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = MetricsRequest {
        username: "backup_user".to_string(),
    };

    let response = GetMetricsTool::invoke(&handler, request)
        .await
        .expect("get_metrics should succeed");

    assert!(
        response.contains("pgmoneta_")
            || response.contains("# TYPE")
            || response.contains("# HELP"),
        "metrics response should contain Prometheus text format exposition: {response}"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn get_single_metric_integration_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = MetricRequest {
        username: "backup_user".to_string(),
        name: "pgmoneta_version".to_string(),
        attributes: HashMap::new(),
        labels: HashMap::new(),
    };

    let response = MetricTool::invoke(&handler, request)
        .await
        .expect("metric tool should succeed");

    assert!(
        response.contains("pgmoneta_version"),
        "metric response should contain pgmoneta_version sample line: {response}"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn get_metrics_unauthorized_user_fails() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = MetricsRequest {
        username: "unauthorized_user_xyz".to_string(),
    };

    let result = GetMetricsTool::invoke(&handler, request).await;
    assert!(result.is_err(), "unauthorized user must not fetch metrics");
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn get_nonexistent_metric_fails() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = MetricRequest {
        username: "backup_user".to_string(),
        name: "nonexistent_pgmoneta_metric_name_xyz".to_string(),
        attributes: HashMap::new(),
        labels: HashMap::new(),
    };

    let result = MetricTool::invoke(&handler, request).await;
    assert!(
        result.is_err(),
        "nonexistent metric query should return error"
    );
}
