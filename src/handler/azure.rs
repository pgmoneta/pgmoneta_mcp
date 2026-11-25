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
use crate::constant::{MANAGEMENT_CATEGORY_OUTCOME, ManagementError};
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;
use serde_json::Value;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct AzureRestoreRequest {
    pub username: String,
    pub server: String,
    /// Label of the backup stored in Azure Blob Storage
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

pub struct AzureRestoreTool;

impl ToolBase for AzureRestoreTool {
    type Parameter = AzureRestoreRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "azure_restore".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Restore a backup stored in Azure Blob Storage to a local directory. \
            Requires server name, the Azure backup label, and directory. \
            Optional positions are the same as for restore: current, name, xid, time, lsn, \
            inclusive, timeline, action, primary, replica. Defaults to current. \
            This runs synchronously; async is not supported for Azure restores. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for AzureRestoreTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: AzureRestoreRequest,
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
        let result: String = PgmonetaClient::request_azure_restore(
            &request.username,
            &request.server,
            &request.label,
            &position,
            &request.directory,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to restore Azure backup: {:?}", e), None)
        })?;
        PgmonetaHandler::generate_call_tool_result_string(&translate_azure_error(&result))
    }
}

// pgmoneta reuses 3200-3204 for both Azure restore and job errors
pub fn translate_azure_error(result: &str) -> String {
    let Ok(mut json) = serde_json::from_str::<Value>(result) else {
        return result.to_string();
    };
    let Some(error) = json
        .get_mut(MANAGEMENT_CATEGORY_OUTCOME)
        .and_then(|outcome| outcome.get_mut("Error"))
    else {
        return result.to_string();
    };
    match error
        .as_u64()
        .and_then(|code| ManagementError::translate_azure_restore_error(code as u32))
    {
        Some(message) => {
            *error = Value::from(message);
            json.to_string()
        }
        None => result.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_azure_restore_tool_metadata() {
        assert_eq!(AzureRestoreTool::name(), "azure_restore");
        assert!(AzureRestoreTool::description().unwrap().contains("Azure"));
        assert_eq!(
            AzureRestoreTool::annotations().unwrap().destructive_hint,
            Some(true)
        );
    }

    #[test]
    fn test_azure_error_is_not_reported_as_job_error() {
        let response = r#"{"Header":{"Command":202},"Outcome":{"Status":false,"Error":3202}}"#;
        let out =
            PgmonetaHandler::generate_call_tool_result_string(&translate_azure_error(response))
                .unwrap();
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["Outcome"]["Error"], "Azure restore: download failed");
        assert_eq!(parsed["Header"]["Command"], "azure restore");
    }

    #[test]
    fn test_other_errors_pass_through() {
        let response = r#"{"Outcome":{"Status":false,"Error":600}}"#;
        assert_eq!(translate_azure_error(response), response);
    }
}
