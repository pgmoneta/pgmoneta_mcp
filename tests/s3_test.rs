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
use pgmoneta_mcp::handler::s3::{S3LsRequest, S3LsTool, S3RestoreRequest, S3RestoreTool};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn s3_ls_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = S3LsRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        prefix: None,
    };

    let response = S3LsTool::invoke(&handler, request)
        .await
        .expect("s3_ls should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");
    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "s3 ls");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    }
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh )"]
async fn s3_restore_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = S3RestoreRequest {
        username: "backup_user".to_string(),
        server: "primary".to_string(),
        prefix: "backup_prefix".to_string(),
        directory: "/tmp/restore".to_string(),
        current: Some(true),
        name: None,
        xid: None,
        time: None,
        lsn: None,
        inclusive: None,
        timeline: None,
        action: None,
        primary: None,
        replica: None,
    };

    let response = S3RestoreTool::invoke(&handler, request)
        .await
        .expect("s3_restore should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");
    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "s3 restore");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    }
}
