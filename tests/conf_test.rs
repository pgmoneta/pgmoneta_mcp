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
use pgmoneta_mcp::handler::conf::{
    ConfGetRequest, ConfGetTool, ConfLsRequest, ConfLsTool, ConfReloadRequest, ConfReloadTool,
    ConfSetRequest, ConfSetTool,
};
use rmcp::handler::server::router::tool::AsyncTool;
use serde_json::Value;
use serial_test::serial;

mod common;

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn conf_reload_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = ConfReloadRequest {
        username: "backup_user".to_string(),
    };

    let response = ConfReloadTool::invoke(&handler, request)
        .await
        .expect("conf_reload should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "conf reload");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn conf_ls_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = ConfLsRequest {
        username: "backup_user".to_string(),
    };

    let response = ConfLsTool::invoke(&handler, request)
        .await
        .expect("conf_ls should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "conf ls");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn conf_get_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = ConfGetRequest {
        username: "backup_user".to_string(),
    };

    let response = ConfGetTool::invoke(&handler, request)
        .await
        .expect("conf_get should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "conf get");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };
}

#[tokio::test]
#[serial]
#[ignore = "requires pgmoneta stack (see test/check.sh and full-test CI job)"]
async fn conf_set_test() {
    let _container = common::init_config().await;

    let handler = PgmonetaHandler::new();
    let request = ConfSetRequest {
        username: "backup_user".to_string(),
        config_key: "log_level".to_string(),
        config_value: "info".to_string(),
    };

    let response = ConfSetTool::invoke(&handler, request)
        .await
        .expect("conf_set should succeed");

    let json: Value = serde_json::from_str(&response).expect("response should be valid json");

    if let Some(header) = json.get("Header") {
        if let Some(command) = header.get("Command") {
            assert_eq!(command, "conf set");
        } else {
            panic!("Command field missing in Header");
        }
    } else {
        panic!("Header field missing");
    };
}
