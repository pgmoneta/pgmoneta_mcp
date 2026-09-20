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
struct DeleteRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Backup")]
    backup: String,
    #[serde(rename = "Force")]
    force: bool,
}

impl PgmonetaClient {
    pub async fn request_delete(
        username: &str,
        server: &str,
        backup_id: &str,
        force: bool,
        asynchronous: bool,
    ) -> anyhow::Result<String> {
        let request = DeleteRequest {
            server: server.to_string(),
            backup: backup_id.to_string(),
            force,
        };
        Self::forward_request_with_async(username, Command::DELETE, request, asynchronous).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_delete_request_serialization() {
        let request = DeleteRequest {
            server: "primary".to_string(),
            backup: "20260101120000".to_string(),
            force: false,
        };
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(serialized.contains("\"Server\":\"primary\""));
        assert!(serialized.contains("\"Backup\":\"20260101120000\""));
        assert!(serialized.contains("\"Force\":false"));
    }

    #[test]
    fn test_delete_request_serialization_with_force() {
        let request = DeleteRequest {
            server: "primary".to_string(),
            backup: "oldest".to_string(),
            force: true,
        };
        let serialized = serde_json::to_string(&request).unwrap();
        assert!(serialized.contains("\"Force\":true"));
        assert!(serialized.contains("\"Backup\":\"oldest\""));
    }
}
