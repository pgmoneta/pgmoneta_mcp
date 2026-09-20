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
use pgmoneta_mcp::handler::restore::{RestoreRequest, RestoreTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

fn assert_success_restore_response(response: &str) -> Value {
    let json: Value = serde_json::from_str(response).expect("response should be valid json");

    let header = json
        .get("Header")
        .unwrap_or_else(|| panic!("Header field missing in response: {response}"));
    let command = header
        .get("Command")
        .unwrap_or_else(|| panic!("Command field missing in Header: {response}"));
    assert_eq!(
        command, "restore",
        "unexpected command in response: {response}"
    );

    let outcome = json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {response}"));
    let status = outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {response}"));
    assert_eq!(status, true, "unexpected status in response: {response}");

    let request = json
        .get("Request")
        .unwrap_or_else(|| panic!("Request field missing in response: {response}"));

    request.clone()
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn restore_with_current_primary_test() {
    common::init_config();
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let request = RestoreRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        directory: "/tmp/restore".to_string(),
        asynchronous: None,
        current: Some(true),
        primary: Some(true),
        replica: None,
        name: None,
        xid: None,
        time: None,
        lsn: None,
        inclusive: None,
        timeline: None,
        action: None,
    };

    let response = RestoreTool::invoke(&handler, request)
        .await
        .expect("Restore should succeed");

    let request = assert_success_restore_response(&response);

    let position = request
        .get("Position")
        .unwrap_or_else(|| panic!("position field missing in Request: {response}"));

    assert_eq!(
        position, "current,primary",
        "unexpected position in Request: {response}"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn restore_with_primary_action_timeline_test() {
    common::init_config();
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let request = RestoreRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        directory: "/tmp/restore".to_string(),
        asynchronous: None,
        current: None,
        primary: Some(true),
        replica: None,
        name: None,
        xid: None,
        time: None,
        lsn: None,
        inclusive: None,
        timeline: Some("1".to_string()),
        action: Some("pause".to_string()),
    };

    let response = RestoreTool::invoke(&handler, request)
        .await
        .expect("Restore should succeed");

    let request = assert_success_restore_response(&response);

    let position = request
        .get("Position")
        .unwrap_or_else(|| panic!("position field missing in Request: {response}"));

    assert_eq!(
        position, "primary,timeline=1,action=pause",
        "unexpected position in Request: {response}"
    );
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn restore_with_primary_replica_test() {
    common::init_config();
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let request = RestoreRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        directory: "/tmp/restore".to_string(),
        asynchronous: None,
        current: None,
        primary: Some(true),
        replica: Some(true),
        name: None,
        xid: None,
        time: None,
        lsn: None,
        inclusive: None,
        timeline: None,
        action: None,
    };

    let response = RestoreTool::invoke(&handler, request)
        .await
        .expect("Restore should succeed");

    let request = assert_success_restore_response(&response);

    let position = request
        .get("Position")
        .unwrap_or_else(|| panic!("position field missing in Request: {response}"));

    assert_eq!(
        position, "primary,replica",
        "unexpected position in Request: {response}"
    );
}
