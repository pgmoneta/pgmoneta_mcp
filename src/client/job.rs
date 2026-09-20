// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

use super::PgmonetaClient;
use crate::constant::{Command, JobAction};
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
struct JobGetRequest {
    #[serde(rename = "Action")]
    action: u32,
    #[serde(rename = "JobId")]
    job_id: String,
}

#[derive(Serialize, Clone, Debug)]
struct JobStatusRequest {
    #[serde(rename = "Action")]
    action: u32,
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Command")]
    command: String,
}

#[derive(Serialize, Clone, Debug)]
struct JobListRequest {
    #[serde(rename = "Action")]
    action: u32,
    #[serde(rename = "All", skip_serializing_if = "Option::is_none")]
    all: Option<bool>,
    #[serde(rename = "Server", skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(rename = "JobState", skip_serializing_if = "Option::is_none")]
    state: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct JobRemoveRequest {
    #[serde(rename = "Action")]
    action: u32,
    #[serde(rename = "JobId", skip_serializing_if = "Option::is_none")]
    job_id: Option<String>,
    #[serde(rename = "All", skip_serializing_if = "Option::is_none")]
    all: Option<bool>,
}

impl PgmonetaClient {
    pub async fn request_job(username: &str, job_id: &str) -> anyhow::Result<String> {
        let request = JobGetRequest {
            action: JobAction::GET,
            job_id: job_id.to_string(),
        };
        Self::forward_request(username, Command::JOB, request).await
    }

    pub async fn request_job_status(
        username: &str,
        server: &str,
        command: &str,
    ) -> anyhow::Result<String> {
        let request = JobStatusRequest {
            action: JobAction::STATUS,
            server: server.to_string(),
            command: command.to_string(),
        };
        Self::forward_request(username, Command::JOB, request).await
    }

    pub async fn request_job_list_all(username: &str) -> anyhow::Result<String> {
        let request = JobListRequest {
            action: JobAction::LIST,
            all: Some(true),
            server: None,
            state: None,
        };
        Self::forward_request(username, Command::JOB, request).await
    }

    pub async fn request_job_list_server(username: &str, server: &str) -> anyhow::Result<String> {
        let request = JobListRequest {
            action: JobAction::LIST,
            all: None,
            server: Some(server.to_string()),
            state: None,
        };
        Self::forward_request(username, Command::JOB, request).await
    }

    pub async fn request_job_list_status(username: &str, state: &str) -> anyhow::Result<String> {
        let request = JobListRequest {
            action: JobAction::LIST,
            all: None,
            server: None,
            state: Some(state.to_string()),
        };
        Self::forward_request(username, Command::JOB, request).await
    }

    pub async fn request_job_remove(
        username: &str,
        job_id: Option<&str>,
    ) -> anyhow::Result<String> {
        let request = JobRemoveRequest {
            action: JobAction::REMOVE,
            job_id: job_id.map(str::to_string),
            all: job_id.is_none().then_some(true),
        };
        Self::forward_request(username, Command::JOB, request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_requests_follow_management_protocol() {
        let get = JobGetRequest {
            action: JobAction::GET,
            job_id: "s0-backup-20260920010101".to_string(),
        };
        let get = serde_json::to_value(get).unwrap();
        assert_eq!(get["Action"], JobAction::GET);
        assert_eq!(get["JobId"], "s0-backup-20260920010101");

        let list = JobListRequest {
            action: JobAction::LIST,
            all: Some(true),
            server: None,
            state: None,
        };
        let list = serde_json::to_value(list).unwrap();
        assert_eq!(list["Action"], JobAction::LIST);
        assert_eq!(list["All"], true);
        assert!(list.get("Server").is_none());

        let remove = JobRemoveRequest {
            action: JobAction::REMOVE,
            job_id: None,
            all: Some(true),
        };
        let remove = serde_json::to_value(remove).unwrap();
        assert_eq!(remove["Action"], JobAction::REMOVE);
        assert_eq!(remove["All"], true);
    }
}
