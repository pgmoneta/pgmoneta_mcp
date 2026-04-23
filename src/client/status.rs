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
struct StatusRequest {}

impl PgmonetaClient {
    pub async fn request_status(username: &str) -> anyhow::Result<String> {
        let status_request = StatusRequest {};
        Self::forward_request(username, Command::STATUS, status_request).await
    }

    pub async fn request_status_details(username: &str) -> anyhow::Result<String> {
        let status_request = StatusRequest {};
        Self::forward_request(username, Command::STATUS_DETAILS, status_request).await
    }
}
