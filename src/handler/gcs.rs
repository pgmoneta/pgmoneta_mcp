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

use std::borrow::Cow;
use std::sync::Arc;

use super::restore::build_position;
use super::{PgmonetaHandler, hints};
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct GcsRestoreRequest {
    pub username: String,
    pub server: String,
    /// Label of the backup stored in Google Cloud Storage
    pub label: String,
    pub directory: String,
    /// Restore to the first stable checkpoint
    pub current: Option<bool>,
    /// Restore to the specified label
    pub name: Option<String>,
    /// Restore to the specified transaction ID
    pub xid: Option<String>,
    /// Restore to the specified timestamp
    pub time: Option<String>,
    /// Restore to the specified LSN
    pub lsn: Option<String>,
    /// Restore is inclusive of the specified information
    pub inclusive: Option<String>,
    /// Restore to the specified timeline
    pub timeline: Option<String>,
    /// Action to execute after the restore (pause, shutdown)
    pub action: Option<String>,
    /// Indicates if the cluster is set up as a primary
    pub primary: Option<bool>,
    /// Indicates if the cluster is set up as a replica
    pub replica: Option<bool>,
}

pub struct GcsRestoreTool;

impl ToolBase for GcsRestoreTool {
    type Parameter = GcsRestoreRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "gcs_restore".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Restore a backup stored in Google Cloud Storage (GCS) to a local directory. \
            Requires server name, the GCS backup label, and directory. \
            Optional positions are the same as for restore: current, name, xid, time, lsn, \
            inclusive, timeline, action, primary, replica. Defaults to current. \
            This runs synchronously; async is not supported for GCS restores. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for GcsRestoreTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: GcsRestoreRequest,
    ) -> Result<String, McpError> {
        let position = build_position(
            [request.current, request.primary, request.replica],
            [
                ("name", request.name.as_deref()),
                ("xid", request.xid.as_deref()),
                ("time", request.time.as_deref()),
                ("lsn", request.lsn.as_deref()),
                ("inclusive", request.inclusive.as_deref()),
                ("timeline", request.timeline.as_deref()),
                ("action", request.action.as_deref()),
            ],
        );
        let result: String = PgmonetaClient::request_gcs_restore(
            &request.username,
            &request.server,
            &request.label,
            &position,
            &request.directory,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to restore GCS backup: {:?}", e), None)
        })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn test_gcs_restore_tool_metadata() {
        assert_eq!(GcsRestoreTool::name(), "gcs_restore");
        assert!(GcsRestoreTool::description().unwrap().contains("GCS"));
        assert_eq!(
            GcsRestoreTool::annotations().unwrap().destructive_hint,
            Some(true)
        );
    }

    #[test]
    fn test_gcs_error_translation() {
        let response = r#"{"Header":{"Command":203},"Outcome":{"Status":false,"Error":3302}}"#;
        let out = PgmonetaHandler::generate_call_tool_result_string(response).unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["Outcome"]["Error"], "GCS restore: download failed");
        assert_eq!(parsed["Header"]["Command"], "gcs restore");
    }
}
