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
use pgmoneta_mcp::handler::retention::{
    ExpungeBackupTool, ExpungeRequest, RetainBackupTool, RetainRequest,
};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;

mod common;

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn retain_backup_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = RetainRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
    };

    let response = RetainBackupTool::invoke(&handler, request)
        .await
        .expect("retain_backup should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(outcome) = json.get("Outcome") {
        if let Some(command) = outcome.get("Command") {
            assert_eq!(command, "retain");
        } else {
            panic!("Command field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn expunge_backup_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = ExpungeRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        backup_id: "newest".to_string(),
    };

    let response = ExpungeBackupTool::invoke(&handler, request)
        .await
        .expect("expunge_backup should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(outcome) = json.get("Outcome") {
        if let Some(command) = outcome.get("Command") {
            assert_eq!(command, "expunge");
        } else {
            panic!("Command field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}
