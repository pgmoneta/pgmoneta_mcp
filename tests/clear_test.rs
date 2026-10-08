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
use pgmoneta_mcp::handler::clear::{ClearRequest, ClearTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn clear_data_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = ClearRequest {
        username: "backup_user".to_string(),
    };

    let response = ClearTool::invoke(&handler, request)
        .await
        .expect("clear_tool should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    let header = json
        .get("Header")
        .unwrap_or_else(|| panic!("Header field missing in response: {response}"));
    let command = header
        .get("Command")
        .unwrap_or_else(|| panic!("Command field missing in Header: {response}"));
    assert_eq!(
        command, "clear prometheus",
        "unexpected command in response: {response}"
    );

    let outcome = json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {response}"));
    let status = outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {response}"));
    assert_eq!(status, true, "unexpected status in response: {response}");

    let response_request = json
        .get("Request")
        .unwrap_or_else(|| panic!("Request field missing in response: {response}"));
    assert!(
        response_request.as_object().unwrap().is_empty(),
        "unexpected request in response: {response}"
    );
}
