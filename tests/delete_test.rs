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

async fn create_backup_for_delete_test(handler: &PgmonetaHandler) -> anyhow::Result<()> {
    // first create a backup to delete
    let request = BackupRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: None,
        asynchronous: None,
    };

    let response = BackupServerTool::invoke(handler, request)
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

    Ok(())
}

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn delete_backup_without_force_test() {
    common::init_config();

    // first create a backup to delete
    let handler = PgmonetaHandler::new();
    create_backup_for_delete_test(&handler)
        .await
        .expect("create backup should succeed");

    // now delete the backup
    let delete_request = pgmoneta_mcp::handler::delete::DeleteRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        force: Some(false),
        asynchronous: None,
    };

    let delete_response =
        pgmoneta_mcp::handler::delete::DeleteTool::invoke(&handler, delete_request)
            .await
            .expect("delete should succeed");

    // validate the delete response
    let delete_json: Value =
        serde_json::from_str(&delete_response).expect("response should be valid json");
    let delete_outcome = delete_json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {delete_response}"));
    let delete_status = delete_outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {delete_response}"));
    assert_eq!(
        delete_status, true,
        "unexpected status in response: {delete_response}"
    );
}

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn delete_backup_with_force_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    create_backup_for_delete_test(&handler)
        .await
        .expect("create backup should succeed");

    // now delete the backup
    let delete_request = pgmoneta_mcp::handler::delete::DeleteRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        force: Some(true),
        asynchronous: None,
    };

    let delete_response =
        pgmoneta_mcp::handler::delete::DeleteTool::invoke(&handler, delete_request)
            .await
            .expect("delete should succeed");

    // validate the delete response
    let delete_json: Value =
        serde_json::from_str(&delete_response).expect("response should be valid json");
    let delete_outcome = delete_json
        .get("Outcome")
        .unwrap_or_else(|| panic!("Outcome field missing in response: {delete_response}"));
    let delete_status = delete_outcome
        .get("Status")
        .unwrap_or_else(|| panic!("Status field missing in Outcome: {delete_response}"));
    assert_eq!(
        delete_status, true,
        "unexpected status in response: {delete_response}"
    );
}
