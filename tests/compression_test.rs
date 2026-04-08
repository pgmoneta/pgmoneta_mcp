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
use pgmoneta_mcp::handler::compression::{
    CompressFileTool, CompressRequest, DecompressFileTool, DecompressRequest,
};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;

mod common;

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn compress_file_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = CompressRequest {
        username: "backup_user".to_string(),
        file_path: "/tmp/test_file.txt".to_string(),
    };

    let response = CompressFileTool::invoke(&handler, request)
        .await
        .expect("compress_file should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(outcome) = json.get("Outcome") {
        if let Some(command) = outcome.get("Command") {
            assert_eq!(command, "compress");
        } else {
            panic!("Command field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}

#[tokio::test]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn decompress_file_test() {
    common::init_config();

    let handler = PgmonetaHandler::new();
    let request = DecompressRequest {
        username: "backup_user".to_string(),
        file_path: "/tmp/test_file.txt.zstd".to_string(),
    };

    let response = DecompressFileTool::invoke(&handler, request)
        .await
        .expect("decompress_file should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(outcome) = json.get("Outcome") {
        if let Some(command) = outcome.get("Command") {
            assert_eq!(command, "decompress");
        } else {
            panic!("Command field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}
