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
struct RetainRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Backup")]
    backup: String,
}

impl PgmonetaClient {
    pub async fn request_retain(
        username: &str,
        server: &str,
        backup: &str,
    ) -> anyhow::Result<String> {
        let retain_request = RetainRequest {
            server: server.to_string(),
            backup: backup.to_string(),
        };
        Self::forward_request(username, Command::RETAIN, retain_request).await
    }

    pub async fn request_expunge(
        username: &str,
        server: &str,
        backup: &str,
    ) -> anyhow::Result<String> {
        let retain_request = RetainRequest {
            server: server.to_string(),
            backup: backup.to_string(),
        };
        Self::forward_request(username, Command::EXPUNGE, retain_request).await
    }
}
