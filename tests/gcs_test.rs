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
use pgmoneta_mcp::handler::gcs::GcsRestoreRequest;
use serde_json::{Value, json};

#[test]
fn gcs_restore_is_registered_as_destructive() {
    let tools = PgmonetaHandler::tool_router().list_all();
    let tool = tools
        .iter()
        .find(|t| t.name == "gcs_restore")
        .expect("gcs_restore should be registered");
    let annotations = tool
        .annotations
        .as_ref()
        .expect("annotations should be set");
    assert_eq!(annotations.destructive_hint, Some(true));
}

#[test]
fn gcs_restore_request_requires_label() {
    let missing = json!({"username": "admin", "server": "primary", "directory": "/tmp"});
    assert!(serde_json::from_value::<GcsRestoreRequest>(missing).is_err());
}

#[test]
fn gcs_restore_errors_translate() {
    for (code, message) in [
        (3300, "GCS restore: no server"),
        (3301, "GCS restore: no fork"),
        (3302, "GCS restore: download failed"),
        (3303, "GCS restore: network error"),
        (3304, "GCS restore: error"),
    ] {
        let response =
            json!({"Header": {"Command": 203}, "Outcome": {"Status": false, "Error": code}});
        let result = PgmonetaHandler::generate_call_tool_result_string(&response.to_string())
            .expect("response should translate");
        let parsed: Value = serde_json::from_str(&result).unwrap();
        assert_eq!(parsed["Outcome"]["Error"], message);
        assert_eq!(parsed["Header"]["Command"], "gcs restore");
    }
}
