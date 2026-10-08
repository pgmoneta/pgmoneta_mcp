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
use pgmoneta_mcp::handler::annotate::{AnnotateBackupTool, AnnotateRequest};
use pgmoneta_mcp::handler::info::{GetBackupInfoTool, InfoRequest as GetBackupInfoRequest};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

async fn clean_annotations(key: &str) {
    let handler = PgmonetaHandler::new();
    let request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "remove".to_string(),
        key: key.to_string(),
        comment: None,
    };

    AnnotateBackupTool::invoke(&handler, request)
        .await
        .expect("annotation clean up should succeed");
}

fn assert_success_annotate_response(response: &str) {
    let json: Value = serde_json::from_str(response).expect("response should be valid json");

    let header = json
        .get("Header")
        .unwrap_or_else(|| panic!("Header field missing in response: {response}"));
    let command = header
        .get("Command")
        .unwrap_or_else(|| panic!("Command field missing in Header: {response}"));
    assert_eq!(
        command, "annotate",
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
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn annotate_add_comment_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "add".to_string(),
        key: "mcp-test-key-add".to_string(),
        comment: Some("initial comment".to_string()),
    };

    let response = AnnotateBackupTool::invoke(&handler, request)
        .await
        .expect("annotate add should succeed");
    assert_success_annotate_response(&response);

    let info_request = GetBackupInfoRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
    };
    let info_response = GetBackupInfoTool::invoke(&handler, info_request)
        .await
        .expect("get backup info should succeed");
    let info_json: Value = serde_json::from_str(&info_response)
        .expect("get backup info response should be valid json");
    let comments = info_json
        .get("Response")
        .and_then(|response| response.get("Comments"))
        .unwrap_or_else(|| panic!("Comments field missing in info response: {info_response}"));
    assert_eq!(comments.to_string(), "\"mcp-test-key-add|initial comment\"");

    // clean up
    clean_annotations("mcp-test-key-add").await;
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn annotate_update_comment_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let add_request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "add".to_string(),
        key: "mcp-test-key-add".to_string(),
        comment: Some("old comment".to_string()),
    };

    let _response = AnnotateBackupTool::invoke(&handler, add_request)
        .await
        .expect("annotate add before update should succeed");

    let update_request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "update".to_string(),
        key: "mcp-test-key-add".to_string(),
        comment: Some("new comment".to_string()),
    };

    let response = AnnotateBackupTool::invoke(&handler, update_request)
        .await
        .expect("annotate update should succeed");
    assert_success_annotate_response(&response);

    let info_request = GetBackupInfoRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
    };
    let info_response = GetBackupInfoTool::invoke(&handler, info_request)
        .await
        .expect("get backup info should succeed");
    let info_json: Value = serde_json::from_str(&info_response)
        .expect("get backup info response should be valid json");
    let comments = info_json
        .get("Response")
        .and_then(|response| response.get("Comments"))
        .unwrap_or_else(|| panic!("Comments field missing in info response: {info_response}"));
    assert_eq!(comments.to_string(), "\"mcp-test-key-add|new comment\"");

    // clean up
    clean_annotations("mcp-test-key-add").await;
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn annotate_remove_comment_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let add_request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "add".to_string(),
        key: "mcp".to_string(),
        comment: Some("first_comment".to_string()),
    };

    let _response = AnnotateBackupTool::invoke(&handler, add_request)
        .await
        .expect("annotate add before update should succeed");

    let remove_request = AnnotateRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
        action: "remove".to_string(),
        key: "mcp".to_string(),
        comment: None,
    };

    let response = AnnotateBackupTool::invoke(&handler, remove_request)
        .await
        .expect("annotate remove should succeed");
    assert_success_annotate_response(&response);

    let info_request = GetBackupInfoRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
    };
    let info_response = GetBackupInfoTool::invoke(&handler, info_request)
        .await
        .expect("get backup info should succeed");
    let info_json: Value = serde_json::from_str(&info_response)
        .expect("get backup info response should be valid json");
    let comments = info_json
        .get("Response")
        .and_then(|response| response.get("Comments"))
        .unwrap_or_else(|| panic!("Comments field missing in info response: {info_response}"));
    assert_eq!(comments.to_string(), "\"\"");
}
