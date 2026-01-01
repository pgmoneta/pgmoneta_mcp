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

mod info;

use super::configuration::CONFIG;
use super::constant::*;
use super::security::SecurityUtil;
use anyhow::anyhow;
use chrono::Local;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

pub struct PgmonetaClient;
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
            return Err(anyhow!(
                "request_backup_info: unable to find user {username}"
            ));
        }

        let password_encrypted = config
            .admins
            .get(username)
            .expect("Username should be found");
        let master_key = security_util.load_master_key()?;
        let password = String::from_utf8(
            security_util.decrypt_from_base64_string(password_encrypted, &master_key[..])?,
        )?;
        let stream = SecurityUtil::connect_to_server(
            &config.pgmoneta.host,
            config.pgmoneta.port,
            username,
            &password,
        )
        .await?;
        Ok(stream)
    }

    async fn write_request(request_str: &str, stream: &mut TcpStream) -> anyhow::Result<()> {
        let mut request_buf = Vec::new();
        request_buf.write_i32(request_str.len() as i32).await?;
        request_buf.write_all(request_str.as_bytes()).await?;

        stream.write_u8(Compression::NONE).await?;
        stream.write_u8(Encryption::NONE).await?;
        stream.write_all(request_buf.as_slice()).await?;
        Ok(())
    }

    async fn read_response(stream: &mut TcpStream) -> anyhow::Result<String> {
        let _compression = stream.read_u8().await?;
        let _encryption = stream.read_u8().await?;
        let _len = stream.read_u32().await?;
        let mut response = [0u8; 1024];
        let n = stream.read(&mut response).await?;
        let response_str = String::from_utf8(Vec::from(&response[..n]))?;
        Ok(response_str)
    }
}
