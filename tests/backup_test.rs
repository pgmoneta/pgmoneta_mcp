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
use pgmoneta_mcp::handler::backup::{BackupRequest, BackupServerTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;

mod common;

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn backup_server_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = BackupRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: None,
        asynchronous: None,
    };

    let response = BackupServerTool::invoke(&handler, request)
        .await
        .expect("backup_server should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    let header = json
        .get("Header")
        .unwrap_or_else(|| panic!("Header field missing in response: {response}"));
    let command = header
        .get("Command")
        .unwrap_or_else(|| panic!("Command field missing in Header: {response}"));
    assert_eq!(
        command, "backup",
        "unexpected command in response: {response}"
    );

    let outcome = json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {response}"));
    let status = outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {response}"));
    assert_eq!(status, true, "unexpected status in response: {response}");
}

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn incremental_backup_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = BackupRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: None,
        asynchronous: None,
    };

    // create initial full backup at first
    let _response = BackupServerTool::invoke(&handler, request)
        .await
        .expect("Full backup should succeed");

    // create incremental backup with identifier
    let incremental_request = BackupRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: Some("oldest".to_string()),
        asynchronous: None,
    };

    let incremental_response = BackupServerTool::invoke(&handler, incremental_request)
        .await
        .expect("Incremental backup should succeed");

    let json: Value =
        serde_json::from_str(&incremental_response).expect("response should be valid json");

    let header = json
        .get("Header")
        .unwrap_or_else(|| panic!("Header field missing in response: {incremental_response}"));
    let command = header
        .get("Command")
        .unwrap_or_else(|| panic!("Command field missing in Header: {incremental_response}"));
    assert_eq!(
        command, "backup",
        "unexpected command in response: {incremental_response}"
    );

    let outcome = json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {incremental_response}"));
    let status = outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {incremental_response}"));
    assert_eq!(
        status, true,
        "unexpected status in response: {incremental_response}"
    );
}
