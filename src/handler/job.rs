// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::borrow::Cow;
use std::sync::Arc;

use super::{PgmonetaHandler, hints};
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::{JsonObject, ToolAnnotations};
use rmcp::schemars;

macro_rules! job_tool {
    ($tool:ident, $request:ty, $name:literal, $hints:expr, $description:literal, $invoke:expr) => {
        pub struct $tool;

        impl ToolBase for $tool {
            type Parameter = $request;
            type Output = String;
            type Error = McpError;

            fn name() -> Cow<'static, str> {
                $name.into()
            }

            fn annotations() -> Option<ToolAnnotations> {
                Some($hints)
            }

            fn description() -> Option<Cow<'static, str>> {
                Some($description.into())
            }

            fn output_schema() -> Option<Arc<JsonObject>> {
                None
            }
        }

        impl AsyncTool<PgmonetaHandler> for $tool {
            async fn invoke(
                _service: &PgmonetaHandler,
                request: $request,
            ) -> Result<String, McpError> {
                let result: anyhow::Result<String> = ($invoke)(request).await;
                let result = result.map_err(|e| {
                    McpError::internal_error(format!("Job request failed: {e:?}"), None)
                })?;
                PgmonetaHandler::generate_call_tool_result_string(&result)
            }
        }
    };
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobRequest {
    pub username: String,
    pub job_id: String,
}

/// Operation whose async job status is requested.
/// Serialized as the lowercase names pgmoneta expects.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum JobCommand {
    #[default]
    Backup,
    Restore,
    Archive,
    Delete,
}

impl JobCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backup => "backup",
            Self::Restore => "restore",
            Self::Archive => "archive",
            Self::Delete => "delete",
        }
    }
}

/// Async job state used to filter job listings.
/// Serialized as the capitalized names pgmoneta expects.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
pub enum JobState {
    #[default]
    Running,
    Completed,
    Failed,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "Running",
            Self::Completed => "Completed",
            Self::Failed => "Failed",
        }
    }
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobStatusRequest {
    pub username: String,
    pub server: String,
    /// The operation to report on.
    pub command: JobCommand,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobListAllRequest {
    pub username: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobListByServerRequest {
    pub username: String,
    pub server: String,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobListByStateRequest {
    pub username: String,
    /// The job state to filter by.
    pub state: JobState,
}

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobRemoveRequest {
    pub username: String,
    /// Omit to remove all persisted job records.
    pub job_id: Option<String>,
}

job_tool!(
    JobTool,
    JobRequest,
    "job",
    hints::read_only(),
    "Get an async job. \
    Requires a job identifier returned by an async backup, restore, archive, or delete operation. \
    Returns the active job if it is still running, or its persisted result after it finishes. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobRequest| async move {
        PgmonetaClient::request_job(&request.username, &request.job_id).await
    }
);

job_tool!(
    JobStatusTool,
    JobStatusRequest,
    "job_status",
    hints::read_only(),
    "Get the status of an async job for a server operation. \
    Requires a server name and a command. \
    The command must be backup, restore, archive, or delete. \
    Returns the running job when one exists, or the latest persisted job for that server and command. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobStatusRequest| async move {
        PgmonetaClient::request_job_status(
            &request.username,
            &request.server,
            request.command.as_str(),
        )
        .await
    }
);

job_tool!(
    JobListAllTool,
    JobListAllRequest,
    "job_list_all",
    hints::read_only(),
    "List all active and persisted async jobs. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobListAllRequest| async move {
        PgmonetaClient::request_job_list_all(&request.username).await
    }
);

job_tool!(
    JobListServerTool,
    JobListByServerRequest,
    "job_list_server",
    hints::read_only(),
    "List active and persisted async jobs for a server. \
    Requires a server name. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobListByServerRequest| async move {
        PgmonetaClient::request_job_list_server(&request.username, &request.server).await
    }
);

job_tool!(
    JobListStatusTool,
    JobListByStateRequest,
    "job_list_status",
    hints::read_only(),
    "List async jobs by state. \
    Requires a state of Running, Completed, or Failed. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobListByStateRequest| async move {
        PgmonetaClient::request_job_list_status(&request.username, request.state.as_str()).await
    }
);

job_tool!(
    JobRemoveTool,
    JobRemoveRequest,
    "job_remove",
    hints::destructive(),
    "Remove persisted async job records. \
    Specify a job identifier to remove one record, or omit it to remove all persisted job records. \
    Active jobs cannot be removed. Removing a record does not remove the backup or output created by the operation. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobRemoveRequest| async move {
        PgmonetaClient::request_job_remove(&request.username, request.job_id.as_deref()).await
    }
);

#[cfg(test)]
mod tests {
    use super::*;
    use rmcp::handler::server::router::tool::ToolBase;

    #[test]
    fn test_job_tool_descriptions() {
        let descriptions = [
            JobTool::description().unwrap(),
            JobStatusTool::description().unwrap(),
            JobListAllTool::description().unwrap(),
            JobListServerTool::description().unwrap(),
            JobListStatusTool::description().unwrap(),
            JobRemoveTool::description().unwrap(),
        ];

        for description in descriptions {
            assert!(description.contains("username"));
        }

        assert!(JobTool::description().unwrap().contains("job identifier"));
        assert!(JobStatusTool::description().unwrap().contains("command"));
        assert!(
            JobListStatusTool::description()
                .unwrap()
                .contains("Running, Completed, or Failed")
        );
        assert!(
            JobRemoveTool::description()
                .unwrap()
                .contains("Active jobs cannot be removed")
        );
    }

    /// Returns the `enum` values advertised for `field`, following a `$ref` into `$defs`.
    fn enum_values(schema: &serde_json::Value, field: &str) -> Vec<String> {
        let property = &schema["properties"][field];
        let target = match property["$ref"].as_str() {
            Some(reference) => {
                let name = reference.rsplit('/').next().unwrap();
                &schema["$defs"][name]
            }
            None => property,
        };
        target["enum"]
            .as_array()
            .unwrap_or_else(|| panic!("no enum for {field} in {schema}"))
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn test_job_status_command_schema_is_enum() {
        let schema = serde_json::to_value(schemars::schema_for!(JobStatusRequest)).unwrap();
        assert_eq!(
            enum_values(&schema, "command"),
            ["backup", "restore", "archive", "delete"]
        );
    }

    #[test]
    fn test_job_list_status_state_schema_is_enum() {
        let schema = serde_json::to_value(schemars::schema_for!(JobListByStateRequest)).unwrap();
        assert_eq!(
            enum_values(&schema, "state"),
            ["Running", "Completed", "Failed"]
        );
    }

    #[test]
    fn test_job_command_wire_values() {
        for (input, expected) in [
            ("backup", JobCommand::Backup),
            ("restore", JobCommand::Restore),
            ("archive", JobCommand::Archive),
            ("delete", JobCommand::Delete),
        ] {
            let parsed: JobCommand = serde_json::from_value(serde_json::json!(input)).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), input);
        }
        for bad in ["Backup", "backups", "BACKUP", "verify"] {
            assert!(serde_json::from_value::<JobCommand>(serde_json::json!(bad)).is_err());
        }
    }

    #[test]
    fn test_job_state_wire_values() {
        for (input, expected) in [
            ("Running", JobState::Running),
            ("Completed", JobState::Completed),
            ("Failed", JobState::Failed),
        ] {
            let parsed: JobState = serde_json::from_value(serde_json::json!(input)).unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), input);
        }
        // "Starting" is a real job state but pgmoneta rejects it as a list filter.
        for bad in ["running", "RUNNING", "Starting", "Done"] {
            assert!(serde_json::from_value::<JobState>(serde_json::json!(bad)).is_err());
        }
    }

    #[test]
    fn test_job_tools_are_registered() {
        let tools = PgmonetaHandler::tool_router().list_all();
        let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        for expected in [
            "job",
            "job_status",
            "job_list_all",
            "job_list_server",
            "job_list_status",
            "job_remove",
        ] {
            assert!(names.contains(&expected), "missing MCP tool {expected}");
        }
    }
}
