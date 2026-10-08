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
use pgmoneta_mcp::handler::verify::{VerifyBackupTool, VerifyRequest};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;
mod common;
#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn verify_test() {
    let _container = common::init_config().await;
    let _guard = common::backup_fixture_lock().await;
    let backup_id = common::ensure_backup("primary")
        .await
        .expect("backup fixture should be created");

    let handler = PgmonetaHandler::new();
    let verify_request = VerifyRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id,
        directory: Some("/tmp".to_string()),
    };

    let response = VerifyBackupTool::invoke(&handler, verify_request)
        .await
        .expect("verify_backup should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert!(command.is_string(), "Command should be a string");
            assert!(command == "verify", "Command should be 'verify'");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };

    if let Some(outcome) = json.get("Outcome") {
        if let Some(status) = outcome.get("Status") {
            assert_eq!(status, true, "unexpected status in response: {response}");
        } else {
            panic!("Status field missing in Outcome: {response}");
        }
    } else {
        panic!("Outcome field missing: {response}");
    };
}
