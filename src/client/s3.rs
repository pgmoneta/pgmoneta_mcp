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

use super::PgmonetaClient;
use crate::constant::Command;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
struct S3LsRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "S3Prefix", skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
struct S3RestoreRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "S3Prefix")]
    prefix: String,
    #[serde(rename = "Position", skip_serializing_if = "Option::is_none")]
    position: Option<String>,
    #[serde(rename = "Directory")]
    directory: String,
}

impl PgmonetaClient {
    pub async fn request_s3_ls(
        username: &str,
        server: &str,
        prefix: Option<&str>,
    ) -> anyhow::Result<String> {
        let request = S3LsRequest {
            server: server.to_string(),
            prefix: prefix.map(|s| s.to_string()),
        };
        Self::forward_request(username, Command::S3_LS, request).await
    }

    pub async fn request_s3_restore(
        username: &str,
        server: &str,
        prefix: &str,
        position: Option<&str>,
        directory: &str,
    ) -> anyhow::Result<String> {
        let request = S3RestoreRequest {
            server: server.to_string(),
            prefix: prefix.to_string(),
            position: position.map(|s| s.to_string()),
            directory: directory.to_string(),
        };
        Self::forward_request(username, Command::S3_RESTORE, request).await
    }
}
