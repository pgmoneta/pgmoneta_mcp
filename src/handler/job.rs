// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use std::borrow::Cow;
use std::sync::Arc;

use super::PgmonetaHandler;
use crate::client::PgmonetaClient;
use rmcp::ErrorData as McpError;
use rmcp::handler::server::router::tool::{AsyncTool, ToolBase};
use rmcp::model::JsonObject;
use rmcp::schemars;

macro_rules! job_tool {
    ($tool:ident, $request:ty, $name:literal, $description:literal, $invoke:expr) => {
        pub struct $tool;

        impl ToolBase for $tool {
            type Parameter = $request;
            type Output = String;
            type Error = McpError;

            fn name() -> Cow<'static, str> {
                $name.into()
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

#[derive(Debug, Default, serde::Deserialize, schemars::JsonSchema)]
pub struct JobStatusRequest {
    pub username: String,
    pub server: String,
    /// One of: backup, restore, archive, delete.
    pub command: String,
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
    /// One of: Running, Completed, Failed.
    pub state: String,
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
    "Get the status of an async job for a server operation. \
    Requires a server name and a command. \
    The command must be backup, restore, archive, or delete. \
    Returns the running job when one exists, or the latest persisted job for that server and command. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobStatusRequest| async move {
        PgmonetaClient::request_job_status(&request.username, &request.server, &request.command)
            .await
    }
);

job_tool!(
    JobListAllTool,
    JobListAllRequest,
    "job_list_all",
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
    "List async jobs by state. \
    Requires a state of Running, Completed, or Failed. \
    The username has to be one of the pgmoneta admins to be able to access pgmoneta.",
    |request: JobListByStateRequest| async move {
        PgmonetaClient::request_job_list_status(&request.username, &request.state).await
    }
);

job_tool!(
    JobRemoveTool,
    JobRemoveRequest,
    "job_remove",
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
