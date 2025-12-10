// Copyright (C) 2025 The pgmoneta community
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

use anyhow::anyhow;
use serde_json::Value;
use serde::Serialize;
use super::constant::*;
use chrono::Local;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::collections::HashMap;
use super::security::SecurityUtil;
use super::configuration::CONFIG;

#[derive(Serialize, Clone)]
struct RequestHeader {
    #[serde(rename = "Command")]
    command: u32,
    #[serde(rename = "ClientVersion")]
    client_version: String,
    #[serde(rename = "Output")]
    output_format: u8,
    #[serde(rename = "Timestamp")]
    timestamp: String,
    #[serde(rename = "Compression")]
    compression: u8,
    #[serde(rename = "Encryption")]
    encryption: u8,
}

#[derive(Serialize, Clone)]
struct PgmonetaRequest<R>
where
    R: Serialize + Clone,
{
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: R,
}

#[derive(Serialize, Clone)]
struct InfoRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Backup")]
    backup: String,
}

pub struct PgmonetaClient;

impl PgmonetaClient {
    pub async fn request_backup_info(username: &str, server: &str, backup: &str) -> anyhow::Result<HashMap<String, Value>> {
        let info_request = InfoRequest {
            server: server.to_string(),
            backup: backup.to_string(),
        };
        let mut stream = Self::connect_to_server(username).await?;
        let header = Self::build_request_header(Command::INFO);
        let request = PgmonetaRequest {
            request: info_request,
            header,
        };
        let request_str = serde_json::to_string(&request)?;
        stream.write_all(request_str.as_bytes()).await?;

        let mut response_str = String::new();
        stream.read_to_string(&mut response_str).await?;

        let response: HashMap<String, Value> = serde_json::from_str(&response_str)?;
        Ok(response)
    }
}

impl PgmonetaClient {
    fn build_request_header(command: u32) -> RequestHeader {
        let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
        RequestHeader {
            command,
            client_version: CLIENT_VERSION.to_string(),
            output_format: Format::JSON,
            timestamp,
            compression: Compression::NONE,
            encryption: Encryption::NONE,
        }
    }

    async fn connect_to_server(username: &str) -> anyhow::Result<TcpStream> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        let security_util = SecurityUtil::new();

        if !config.admins.contains_key(username) {
            return Err(anyhow!("request_backup_info: unable to find user {username}"));
        }

        let password_encrypted = config.admins.get(username).expect("Username should be found");
        let master_key = security_util.load_master_key()?;
        let password = String::from_utf8(security_util.decrypt_from_base64_string(password_encrypted, &master_key[..])?)?;
        let stream =
            SecurityUtil::connect_to_server(&config.pgmoneta.host, config.pgmoneta.port, username, &password).await?;
        Ok(stream)
    }
}