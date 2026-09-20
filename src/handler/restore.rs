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

use super::PgmonetaHandler;
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use rmcp::schemars;

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct RestoreRequest {
    pub username: String,
    pub server: String,
    pub backup_id: String,
    pub directory: String,
    /// Return immediately with a job identifier and run the restore in the background.
    #[serde(rename = "async")]
    #[schemars(rename = "async")]
    pub asynchronous: Option<bool>,

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

/// Tool for restoring a backup to a PostgreSQL server.
pub struct RestoreTool;

impl ToolBase for RestoreTool {
    type Parameter = RestoreRequest;
    type Output = String;
    type Error = McpError;

    fn name() -> Cow<'static, str> {
        "restore".into()
    }

    fn description() -> Option<Cow<'static, str>> {
        Some(
            "Restore a backup from a server. \
            Requires server name, backup ID, and directory. \
            \"newest\", \"latest\" or \"oldest\" are also accepted as backup identifier. \
            a set of optional positions can be specified as name, xid, time, lsn, inclusive, timeline, action, primary, replica, or current. \
            Position \"current\" means copy the WAL and restore to first stable checkpoint (This is different from the server name). \
            Position \"primary\" means the cluster is setup as a primary (This is different from the server name, primary server is different from position of primary, don't mix between them). \
            Position \"replica\" means the cluster is setup as a replica (This is different from the server name). \
            Position \"name\" means copy the WAL and restore to the specified label. \
            Position \"xid\" means copy the WAL and restore to the specified transaction ID. \
            Position \"time\" means copy the WAL and restore to the specified timestamp. \
            Position \"lsn\" means copy the WAL and restore to the specified LSN. \
            Position \"inclusive\" means the restore is inclusive of the specified information. \
            Position \"timeline\" means copy the WAL and restore to the specified timeline. \
            Position \"action\" means which action will be executed after the restore (pause, shutdown). \
            Choose the position that best fits. \
            The directory specifies where to restore the backup. \
            Set async to true to return immediately with a job identifier and run the restore in the background. \
            The username has to be one of the pgmoneta admins to be able to access pgmoneta."
                .into(),
        )
    }

    // input_schema is NOT overridden — the default generates the correct JSON schema
    // automatically from `type Parameter = RetainRequest` via its JsonSchema derive.

    // output_schema must be overridden to return None because our Output type is String
    // (dynamically-translated JSON), and the MCP spec requires output schema root type
    // to be 'object', which String does not satisfy.
    fn output_schema() -> Option<Arc<JsonObject>> {
        None
    }
}

impl AsyncTool<PgmonetaHandler> for RestoreTool {
    async fn invoke(
        _service: &PgmonetaHandler,
        request: RestoreRequest,
    ) -> Result<String, McpError> {
        let position = normalize_position(&request);
        let result: String = PgmonetaClient::request_restore(
            &request.username,
            &request.server,
            &request.backup_id,
            &position,
            &request.directory,
            request.asynchronous.unwrap_or(false),
        )
        .await
        .map_err(|e| {
            McpError::internal_error(format!("Failed to restore backup: {:?}", e), None)
        })?;
        PgmonetaHandler::generate_call_tool_result_string(&result)
    }
}

fn normalize_position(req: &RestoreRequest) -> String {
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
    if let Some(name) = &req.name {
        result.push(format!("name={}", name));
    }
    if let Some(xid) = &req.xid {
        result.push(format!("xid={}", xid));
    }
    if let Some(time) = &req.time {
        result.push(format!("time={}", time));
    }
    if let Some(lsn) = &req.lsn {
        result.push(format!("lsn={}", lsn));
    }
    if let Some(inclusive) = &req.inclusive {
        result.push(format!("inclusive={}", inclusive));
    }
    if let Some(timeline) = &req.timeline {
        result.push(format!("timeline={}", timeline));
    }
    if let Some(action) = &req.action {
        result.push(format!("action={}", action));
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
    use serde_json::{Map, Value};

    #[test]
    fn test_restore_tool_metadata() {
        assert_eq!(RestoreTool::name(), "restore");
        let desc = RestoreTool::description();
        assert!(desc.is_some());
        assert!(desc.unwrap().contains("Restore a backup"));
    }

    #[test]
    fn test_handler_has_restore_tool() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let tool_names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        assert!(
            tool_names.contains(&"restore"),
            "restore tool should be registered, found: {:?}",
            tool_names
        );
    }

    #[test]
    fn test_normalize_position() {
        let req = RestoreRequest {
            username: "user".to_string(),
            server: "server".to_string(),
            backup_id: "backup".to_string(),
            directory: "/tmp/restore".to_string(),
            current: Some(true),
            name: Some("label1".to_string()),
            xid: Some("12345".to_string()),
            time: Some("2024-01-01T00:00:00Z".to_string()),
            lsn: Some("0/12345678".to_string()),
            inclusive: Some("true".to_string()),
            timeline: Some("2".to_string()),
            action: Some("pause".to_string()),
            primary: None,
            replica: None,
            asynchronous: None,
        };
        let position = normalize_position(&req);
        assert_eq!(
            position,
            "current,name=label1,xid=12345,time=2024-01-01T00:00:00Z,lsn=0/12345678,inclusive=true,timeline=2,action=pause"
        );
    }

    #[test]
    fn test_normalize_position_empty() {
        let req = RestoreRequest {
            username: "user".to_string(),
            server: "server".to_string(),
            backup_id: "backup".to_string(),
            directory: "/tmp/restore".to_string(),
            current: None,
            asynchronous: None,
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
        let position = normalize_position(&req);
        assert_eq!(position, "current");
    }

    #[test]
    fn test_normalize_position_primary_replica() {
        let req = RestoreRequest {
            username: "user".to_string(),
            server: "server".to_string(),
            backup_id: "backup".to_string(),
            directory: "/tmp/restore".to_string(),
            current: None,
            asynchronous: None,
            name: None,
            xid: None,
            time: None,
            lsn: None,
            inclusive: None,
            timeline: None,
            action: None,
            primary: Some(true),
            replica: Some(true),
        };
        let position = normalize_position(&req);
        assert_eq!(position, "primary,replica");
    }

    #[test]
    fn test_parse_restore_success_response() {
        let response = r#"{"Outcome": {"Command": 3, "Status": "OK"}, "Server": "primary", "Position": "current,primary"}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let map = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&map).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(outcome.get("Status").unwrap(), "OK");
        assert_eq!(parsed.get("Server").unwrap(), "primary");
        assert_eq!(parsed.get("Position").unwrap(), "current,primary");
        assert_eq!(outcome.get("Command").unwrap(), "restore");
    }

    #[test]
    fn test_parse_restore_error_response() {
        let response = r#"{"Outcome": {"Command": 3, "Error": 600}}"#;
        let result = PgmonetaHandler::generate_call_tool_result_string(response);
        assert!(result.is_ok());
        let map = result.unwrap();
        let parsed: Map<String, Value> = serde_json::from_str(&map).unwrap();
        let outcome = parsed["Outcome"].as_object().unwrap();
        assert_eq!(
            outcome.get("Error").unwrap(),
            "Restore: no backup available"
        );
    }
}
