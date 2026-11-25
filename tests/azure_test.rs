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
use pgmoneta_mcp::handler::azure::{AzureRestoreRequest, translate_azure_error};
use serde_json::{Value, json};

#[test]
fn azure_restore_is_registered_as_destructive() {
    let tools = PgmonetaHandler::tool_router().list_all();
    let tool = tools
        .iter()
        .find(|t| t.name == "azure_restore")
        .expect("azure_restore should be registered");
    let annotations = tool
        .annotations
        .as_ref()
        .expect("annotations should be set");
    assert_eq!(annotations.destructive_hint, Some(true));
}

#[test]
fn azure_restore_request_requires_label() {
    let missing = json!({"username": "admin", "server": "primary", "directory": "/tmp"});
    assert!(serde_json::from_value::<AzureRestoreRequest>(missing).is_err());

    let request: AzureRestoreRequest = serde_json::from_value(json!({
        "username": "admin",
        "server": "primary",
        "label": "20260718173645",
        "directory": "/tmp/restore"
    }))
    .expect("request should deserialize");
    assert_eq!(request.label, "20260718173645");
}

#[test]
fn azure_restore_errors_do_not_translate_as_job_errors() {
    for (code, message) in [
        (3200, "Azure restore: no server"),
        (3201, "Azure restore: no fork"),
        (3202, "Azure restore: download failed"),
        (3203, "Azure restore: network error"),
        (3204, "Azure restore: error"),
    ] {
        let response =
            json!({"Header": {"Command": 202}, "Outcome": {"Status": false, "Error": code}});
        let result = PgmonetaHandler::generate_call_tool_result_string(&translate_azure_error(
            &response.to_string(),
        ))
        .expect("response should translate");
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["Outcome"]["Error"], message);
        assert_eq!(parsed["Header"]["Command"], "azure restore");
    }
}
