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
use pgmoneta_mcp::handler::encryption::{
    DecryptFileTool, DecryptRequest, EncryptFileTool, EncryptRequest,
};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

const ENCRYPT_FIXTURE_PATH: &str = "/tmp/pgmoneta-mcp-encrypt-fixture.txt";
const DECRYPT_FIXTURE_SOURCE: &str = "/tmp/pgmoneta-mcp-decrypt-fixture.txt";
const DECRYPT_FIXTURE_ARCHIVE: &str = "/tmp/pgmoneta-mcp-decrypt-fixture.txt.aes";

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn encrypt_file_test() {
    let _container = common::init_config().await;
    common::prepare_encrypt_fixture(&_container).await;

    let handler = PgmonetaHandler::new();
    let request = EncryptRequest {
        username: "backup_user".to_string(),
        file_path: ENCRYPT_FIXTURE_PATH.to_string(),
    };

    let response = EncryptFileTool::invoke(&handler, request)
        .await
        .expect("encrypt_file should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "encrypt");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };

    if let Some(outcome) = json.get("Outcome") {
        if let Some(status) = outcome.get("Status") {
            assert_eq!(status, true);
        } else {
            panic!("Status field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn decrypt_file_test() {
    let _container = common::init_config().await;
    common::prepare_decrypt_fixture(&_container).await;

    let handler = PgmonetaHandler::new();
    let encrypt_request = EncryptRequest {
        username: "backup_user".to_string(),
        file_path: DECRYPT_FIXTURE_SOURCE.to_string(),
    };
    let encrypt_response = EncryptFileTool::invoke(&handler, encrypt_request)
        .await
        .expect("encrypt_file should succeed before decrypt_file");
    let encrypt_json: Value =
        serde_json::from_str(&encrypt_response).expect("encrypt response should be valid json");
    assert_eq!(encrypt_json["Outcome"]["Status"], true);

    let request = DecryptRequest {
        username: "backup_user".to_string(),
        file_path: DECRYPT_FIXTURE_ARCHIVE.to_string(),
    };

    let response = DecryptFileTool::invoke(&handler, request)
        .await
        .expect("decrypt_file should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "decrypt");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };

    if let Some(outcome) = json.get("Outcome") {
        if let Some(status) = outcome.get("Status") {
            assert_eq!(status, true);
        } else {
            panic!("Status field missing in Outcome");
        }
    } else {
        panic!("Outcome field missing");
    };
}
