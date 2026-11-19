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

use super::{PgmonetaHandler, hints, optional_text};
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct S3LsRequest {
    pub username: String,
    pub server: String,
    pub prefix: Option<String>,
}

/// Tool for listing remote S3 objects for a server.
pub struct S3LsTool;

impl ToolBase for S3LsTool {
    type Parameter = S3LsRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "s3_ls".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::read_only())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "List remote S3 objects for a server. \
            Accepts an optional prefix filter. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for S3LsTool {
    async fn invoke(_service: &PgmonetaHandler, request: S3LsRequest) -> Result<String, McpError> {
        let prefix = optional_text(request.prefix.as_deref());
        let result = PgmonetaClient::request_s3_ls(&request.username, &request.server, prefix)
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to list S3 objects: {:?}", e), None)
            })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct S3RestoreRequest {
    pub username: String,
    pub server: String,
    pub prefix: String,
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

/// Tool for restoring a backup from S3 storage.
pub struct S3RestoreTool;

impl ToolBase for S3RestoreTool {
    type Parameter = S3RestoreRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "s3_restore".into()
    }

    fn annotations() -> Option<ToolAnnotations> {
        Some(hints::destructive())
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Restore a backup from S3 storage for a server. \
            Requires server name, S3 prefix, and directory. \
            A set of optional positions can be specified as current, name, xid, time, lsn, inclusive, timeline, action, primary, or replica. \
            Position \"current\" means copy the WAL and restore to first stable checkpoint. \
            Position \"primary\" means the cluster is setup as a primary. \
            Position \"replica\" means the cluster is setup as a replica. \
            Position \"name\" means copy the WAL and restore to the specified label. \
            Position \"xid\" means copy the WAL and restore to the specified transaction ID. \
            Position \"time\" means copy the WAL and restore to the specified timestamp. \
            Position \"lsn\" means copy the WAL and restore to the specified LSN. \
            Position \"inclusive\" means the restore is inclusive of the specified information. \
            Position \"timeline\" means copy the WAL and restore to the specified timeline. \
            Position \"action\" means which action will be executed after the restore (pause, shutdown). \
            Choose the position that best fits. \
            The directory specifies where to restore the backup. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for S3RestoreTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: S3RestoreRequest,
    ) -> Result<String, McpError> {
        let position = normalize_s3_position(&request);
        let result = PgmonetaClient::request_s3_restore(
            &request.username,
            &request.server,
            &request.prefix,
            Some(&position),
            &request.directory,
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to restore S3 backup: {:?}", e), None)
        })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

fn normalize_s3_position(req: &S3RestoreRequest) -> String {
    let mut result = Vec::new();
    if let Some(current) = req.current
        && current
    {
        result.push("current".to_string());
    }
    if let Some(primary) = req.primary
        && primary
    {
        result.push("primary".to_string());
    }
    if let Some(replica) = req.replica
        && replica
    {
        result.push("replica".to_string());
    }
    let fields = [
        ("name", &req.name),
        ("xid", &req.xid),
        ("time", &req.time),
        ("lsn", &req.lsn),
        ("inclusive", &req.inclusive),
        ("timeline", &req.timeline),
        ("action", &req.action),
    ];
    for (key, value) in fields {
        if let Some(value) = optional_text(value.as_deref()) {
            result.push(format!("{key}={value}"));
        }
    }

    let position = result.join(",");
    if position.is_empty() {
        "current".to_string()
    } else {
        position
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_s3_ls_tool_metadata() {
        assert_eq!(S3LsTool::name(), "s3_ls");
        let desc = S3LsTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("List remote S3 objects"));
        let annotations = S3LsTool::annotations().unwrap();
        assert_eq!(annotations.read_only_hint, Some(true));
        assert_eq!(annotations.destructive_hint, None);
    }

    #[test]
    fn test_s3_restore_tool_metadata() {
        assert_eq!(S3RestoreTool::name(), "s3_restore");
        let desc = S3RestoreTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("Restore a backup from S3"));
        let annotations = S3RestoreTool::annotations().unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.destructive_hint, Some(true));
    }

    #[test]
    fn test_handler_has_s3_tools() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"s3_ls"),
            "s3_ls tool should be registered, found: {:?}",
            tool_names
        );
        assert!(
            tool_names.contains(&"s3_restore"),
            "s3_restore tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_normalize_s3_position_empty() {
        let req = S3RestoreRequest {
            username: "user".to_string(),
            server: "primary".to_string(),
            prefix: "backup_prefix".to_string(),
            directory: "/tmp/restore".to_string(),
            current: None,
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
        assert_eq!(normalize_s3_position(&req), "current");
    }

    #[test]
    fn test_normalize_s3_position_populated() {
        let req = S3RestoreRequest {
            username: "user".to_string(),
            server: "primary".to_string(),
            prefix: "backup_prefix".to_string(),
            directory: "/tmp/restore".to_string(),
            current: Some(true),
            name: Some("test_label".to_string()),
            xid: Some("100".to_string()),
            time: Some("2026-01-01T00:00:00Z".to_string()),
            lsn: Some("0/12345678".to_string()),
            inclusive: Some("true".to_string()),
            timeline: Some("1".to_string()),
            action: Some("pause".to_string()),
            primary: None,
            replica: None,
        };
        assert_eq!(
            normalize_s3_position(&req),
            "current,name=test_label,xid=100,time=2026-01-01T00:00:00Z,lsn=0/12345678,inclusive=true,timeline=1,action=pause"
        );
    }

    #[test]
    fn test_normalize_s3_position_ignores_empty_and_null_values() {
        let req = S3RestoreRequest {
            username: "user".to_string(),
            server: "server".to_string(),
            prefix: "prefix".to_string(),
            directory: "/tmp/restore".to_string(),
            name: Some("".to_string()),
            xid: Some("null".to_string()),
            time: Some("  ".to_string()),
            lsn: Some("NULL".to_string()),
            inclusive: Some("".to_string()),
            timeline: Some("null".to_string()),
            action: Some("".to_string()),
            ..Default::default()
        };
        assert_eq!(normalize_s3_position(&req), "current");
    }

    #[test]
    fn test_normalize_s3_position_keeps_real_values_next_to_empty_ones() {
        let req = S3RestoreRequest {
            username: "user".to_string(),
            server: "server".to_string(),
            prefix: "prefix".to_string(),
            directory: "/tmp/restore".to_string(),
            name: Some("".to_string()),
            xid: Some("1234".to_string()),
            time: Some("null".to_string()),
            action: Some(" pause ".to_string()),
            ..Default::default()
        };
        assert_eq!(normalize_s3_position(&req), "xid=1234,action=pause");
    }
}
