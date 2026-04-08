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

mod compression;
mod conf;
mod info;
mod mode;
mod retention;
mod shutdown;

use super::compression::CompressionUtil;
use super::configuration::CONFIG;
use super::constant::*;
use super::security::SecurityUtil;
use anyhow::anyhow;
use chrono::Local;
use serde::Serialize;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

fn parse_compression(compression: &str) -> u8 {
    match compression.to_lowercase().as_str() {
        "gzip" => Compression::GZIP,
        "zstd" => Compression::ZSTD,
        "lz4" => Compression::LZ4,
        "bzip2" => Compression::BZIP2,
        _ => Compression::NONE,
    }
}

fn parse_encryption(encryption: &str) -> anyhow::Result<u8> {
    match encryption.to_lowercase().as_str() {
        "aes_256_gcm" | "aes" | "aes_256" => Ok(Encryption::AES_256_GCM),
        "aes_192_gcm" | "aes_192" => Ok(Encryption::AES_192_GCM),
        "aes_128_gcm" | "aes_128" => Ok(Encryption::AES_128_GCM),
        // Explicitly allowed disabled encryption
        "none" | "" | "off" => Ok(Encryption::NONE),
        // Unrecognized values fail fast to prevent silent security regressions
        unknown => Err(anyhow!(
            "Unrecognized encryption mode: {}. Supported modes: none, aes_256_gcm, aes_192_gcm, aes_128_gcm.",
            unknown
        )),
    }
}

/// Represents the header of a request sent to the pgmoneta server.
///
/// Contains metadata such as the command code, client version,
/// formatting preferences, and security settings.
#[derive(Serialize, Clone, Debug)]
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

/// A wrapper structure that combines a request header with its specific payload.
///
/// This is the final serialized object sent over the TCP connection to pgmoneta.
#[derive(Serialize, Clone, Debug)]
struct PgmonetaRequest<R>
where
    R: Serialize + Clone + Debug,
{
    #[serde(rename = "Header")]
    header: RequestHeader,
    #[serde(rename = "Request")]
    request: R,
}

/// Handles network communication with the backend pgmoneta server.
///
/// This client manages the lifecycle of a request: building headers,
/// authenticating, opening a TCP stream, writing the payload, and reading the response.
pub struct PgmonetaClient;
impl PgmonetaClient {
    const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

    fn is_known_compression(value: u8) -> bool {
        matches!(
            value,
            Compression::NONE
                | Compression::GZIP
                | Compression::ZSTD
                | Compression::LZ4
                | Compression::BZIP2
                | Compression::SERVER_GZIP
                | Compression::SERVER_ZSTD
                | Compression::SERVER_LZ4
        )
    }

    fn is_known_encryption(value: u8) -> bool {
        matches!(
            value,
            Encryption::NONE
                | Encryption::AES_256_GCM
                | Encryption::AES_192_GCM
                | Encryption::AES_128_GCM
        )
    }

    async fn read_legacy_response_with_prefix<R>(
        stream: &mut R,
        first_byte: u8,
    ) -> anyhow::Result<String>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        let mut buf = vec![first_byte];

        loop {
            match timeout(Duration::from_secs(2), stream.read_u8()).await {
                Ok(Ok(0)) => break,
                Ok(Ok(byte)) => buf.push(byte),
                Ok(Err(e)) if e.kind() == ErrorKind::UnexpectedEof => break,
                Ok(Err(e)) => return Err(anyhow!("Failed while reading legacy response: {e}")),
                Err(_) => break,
            }
        }

        let response = String::from_utf8(buf).map_err(|e| anyhow!("Invalid UTF-8: {e}"))?;
        Ok(response)
    }

    /// Constructs a standard request header for a given command.
    ///
    /// The header includes the current local timestamp and defaults to
    /// no encryption or compression, expecting a JSON response.
    fn build_request_header(command: u32) -> anyhow::Result<RequestHeader> {
        let config = CONFIG.get().expect("Configuration should be enabled");
        let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
        Ok(RequestHeader {
            command,
            client_version: CLIENT_VERSION.to_string(),
            output_format: Format::JSON,
            timestamp,
            compression: parse_compression(&config.pgmoneta.compression),
            encryption: parse_encryption(&config.pgmoneta.encryption)?,
        })
    }

    /// Establishes an authenticated TCP connection to the pgmoneta server.
    ///
    /// Looks up the provided `username` in the configuration to find the encrypted
    /// password, decrypts it using the master key, and initiates the connection.
    ///
    /// # Arguments
    /// * `username` - The admin username requesting the connection.
    ///
    /// # Returns
    /// An authenticated `TcpStream` ready for read/write operations.
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
        let (master_password, master_salt) = security_util.load_master_key()?;
        let password = String::from_utf8(security_util.decrypt_from_base64_string(
            password_encrypted,
            &master_password,
            &master_salt,
        )?)?;
        let stream = SecurityUtil::connect_to_server(
            &config.pgmoneta.host,
            config.pgmoneta.port,
            username,
            &password,
        )
        .await?;
        Ok(stream)
    }

    /// Writes a management request to the provided stream.
    ///
    /// Handles compression, encryption, and base64 encoding of the payload
    /// if configured, and then frames the message according to the
    /// pgmoneta management protocol.
    async fn write_request<W>(
        request_str: &str,
        stream: &mut W,
        compression: u8,
        encryption: u8,
    ) -> anyhow::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let security_util = SecurityUtil::new();

        let payload = if compression != Compression::NONE || encryption != Encryption::NONE {
            let mut data = request_str.as_bytes().to_vec();

            if compression != Compression::NONE {
                data = CompressionUtil::compress(&data, compression)?;
            }

            if encryption != Encryption::NONE {
                data = security_util.encrypt_text_aes_gcm_bundle(&data, encryption)?;
            }

            security_util.base64_encode(&data)?
        } else {
            request_str.to_string()
        };

        if payload.len() > u32::MAX as usize {
            return Err(anyhow!(
                "Payload size {} exceeds 32-bit protocol limit",
                payload.len()
            ));
        }

        // pgmoneta management protocol:
        // 1 byte compression + 1 byte encryption + 4 bytes length + payload

        // Write compression
        stream.write_u8(compression).await?;

        // Write encryption
        stream.write_u8(encryption).await?;

        // Write payload length (4 bytes, Big Endian)
        stream.write_u32(payload.len() as u32).await?;

        // Write payload
        stream.write_all(payload.as_bytes()).await?;
        stream.flush().await?;

        tracing::debug!(
            compression = compression,
            encryption = encryption,
            len = payload.len(),
            "Request sent"
        );
        Ok(())
    }

    async fn read_response<R>(stream: &mut R) -> anyhow::Result<String>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        // Read compression
        let compression = match timeout(Duration::from_secs(10), stream.read_u8()).await {
            Ok(Ok(c)) => c,
            Ok(Err(e)) => {
                return Err(anyhow!("Failed to read compression byte: {e}"));
            }
            Err(_) => {
                return Err(anyhow!("Reading compression byte timed out"));
            }
        };

        if !Self::is_known_compression(compression) {
            tracing::warn!(
                first_byte = compression,
                "Response did not start with a known compression code; falling back to legacy/null-terminated parser"
            );
            return Self::read_legacy_response_with_prefix(stream, compression).await;
        }

        // Read encryption
        let encryption = match timeout(Duration::from_secs(2), stream.read_u8()).await {
            Ok(Ok(e)) => e,
            Ok(Err(e)) => {
                return Err(anyhow!("Failed to read encryption byte: {e}"));
            }
            Err(_) => {
                return Err(anyhow!("Reading encryption byte timed out"));
            }
        };

        if !Self::is_known_encryption(encryption) {
            return Err(anyhow!(
                "Unsupported encryption code from server: {}",
                encryption
            ));
        }

        // Read length
        let len = match timeout(Duration::from_secs(2), stream.read_u32()).await {
            Ok(Ok(l)) => l as usize,
            Ok(Err(e)) => {
                return Err(anyhow!("Failed to read message length: {e}"));
            }
            Err(_) => {
                return Err(anyhow!("Reading message length timed out"));
            }
        };

        if len > Self::MAX_FRAME_LEN {
            return Err(anyhow!("Refusing oversized response frame: {} bytes", len));
        }

        tracing::debug!(
            compression = compression,
            encryption = encryption,
            len = len,
            "Response frame header received"
        );

        // Read payload
        let mut buf = vec![0u8; len];
        match timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {
                tracing::debug!(len = buf.len(), "Full response payload received");
            }
            Ok(Err(e)) => {
                return Err(anyhow!("Failed to read response payload: {e}"));
            }
            Err(_) => {
                return Err(anyhow!("Reading response payload timed out"));
            }
        }

        // Remove trailing null terminator if present
        if buf.last() == Some(&0) {
            buf.pop();
        }

        let security_util = SecurityUtil::new();

        if compression != Compression::NONE || encryption != Encryption::NONE {
            let secure_parse = || -> anyhow::Result<String> {
                let data = security_util.base64_decode(std::str::from_utf8(&buf)?)?;
                let mut decrypted = data.clone();

                if encryption != Encryption::NONE {
                    decrypted = security_util.decrypt_text_aes_gcm_bundle(&data, encryption)?;
                }

                let mut decompressed = decrypted;
                if compression != Compression::NONE {
                    decompressed = CompressionUtil::decompress(&decompressed, compression)?;
                }

                let response =
                    String::from_utf8(decompressed).map_err(|e| anyhow!("Invalid UTF-8: {}", e))?;
                Ok(response)
            };

            match secure_parse() {
                Ok(response) => Ok(response),
                Err(primary_error) => {
                    tracing::error!(
                        error = %primary_error,
                        "Encrypted/compressed response parsing failed; rejecting insecure fallback"
                    );
                    Err(primary_error)
                }
            }
        } else {
            let response_str =
                String::from_utf8(buf).map_err(|e| anyhow!("Invalid UTF-8: {}", e))?;
            Ok(response_str)
        }
    }

    /// End-to-end wrapper for sending a request to the pgmoneta server and awaiting its response.
    ///
    /// # Arguments
    /// * `username` - The admin username making the request.
    /// * `command` - The numeric command code (e.g., `Command::INFO`).
    /// * `request` - The specific request payload object.
    ///
    /// # Returns
    /// The raw string response from the pgmoneta server.
    async fn forward_request<R>(username: &str, command: u32, request: R) -> anyhow::Result<String>
    where
        R: Serialize + Clone + Debug,
    {
        let header = Self::build_request_header(command)?;
        let compression = header.compression;
        let encryption = header.encryption;
        let request = PgmonetaRequest { request, header };

        let mut stream = Self::connect_to_server(username).await?;
        tracing::info!(username = username, "Connected to server");

        let request_str = serde_json::to_string(&request)?;
        Self::write_request(&request_str, &mut stream, compression, encryption).await?;
        tracing::debug!(username = username, request = ?request, "Sent request to server");
        Self::read_response(&mut stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{Configuration, PgmonetaConfiguration, PgmonetaMcpConfiguration};
    use std::collections::HashMap;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_config() {
        INIT.call_once(|| {
            let config = Configuration {
                pgmoneta_mcp: PgmonetaMcpConfiguration {
                    port: 8000,
                    log_path: "test.log".to_string(),
                    log_level: "info".to_string(),
                    log_type: "console".to_string(),
                    log_line_prefix: "%Y-%m-%d %H:%M:%S".to_string(),
                    log_mode: "append".to_string(),
                    log_rotation_age: "0".to_string(),
                },
                pgmoneta: PgmonetaConfiguration {
                    host: "127.0.0.1".to_string(),
                    port: 5001,
                    compression: "zstd".to_string(),
                    encryption: "aes_256_gcm".to_string(),
                },
                admins: HashMap::new(),
                llm: None,
            };
            let _ = CONFIG.set(config);
        });
    }

    #[test]
    fn test_build_request_header() {
        init_test_config();
        let header = PgmonetaClient::build_request_header(Command::INFO)
            .expect("Header building should succeed");

        assert_eq!(header.command, Command::INFO);
        assert_eq!(header.client_version, CLIENT_VERSION);
        assert_eq!(header.output_format, Format::JSON);
        assert_eq!(header.compression, Compression::ZSTD);
        assert_eq!(header.encryption, Encryption::AES_256_GCM);

        // Timestamp should be in YYYYMMDDHHmmss format (14 characters)
        assert_eq!(header.timestamp.len(), 14);
        assert!(header.timestamp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_build_request_header_different_commands() {
        init_test_config();
        let header1 = PgmonetaClient::build_request_header(Command::INFO).unwrap();
        let header2 = PgmonetaClient::build_request_header(Command::LIST_BACKUP).unwrap();

        assert_eq!(header1.command, Command::INFO);
        assert_eq!(header2.command, Command::LIST_BACKUP);
        assert_ne!(header1.command, header2.command);
    }

    #[test]
    fn test_request_serialization() {
        init_test_config();
        #[derive(Serialize, Clone, Debug)]
        struct TestRequest {
            field1: String,
            field2: i32,
        }

        let test_request = TestRequest {
            field1: "test".to_string(),
            field2: 42,
        };

        let header = PgmonetaClient::build_request_header(Command::INFO).unwrap();
        let request = PgmonetaRequest {
            header,
            request: test_request,
        };

        let serialized = serde_json::to_string(&request).expect("Serialization should succeed");

        // Verify JSON contains expected fields
        assert!(serialized.contains("\"Header\""));
        assert!(serialized.contains("\"Request\""));
        assert!(serialized.contains("\"Command\""));
        assert!(serialized.contains("\"ClientVersion\""));
        assert!(serialized.contains("\"field1\""));
        assert!(serialized.contains("\"field2\""));
        assert!(serialized.contains("\"test\""));
        assert!(serialized.contains("42"));
    }

    #[test]
    fn test_request_header_serialization() {
        let header = RequestHeader {
            command: 1,
            client_version: "0.2.0".to_string(),
            output_format: Format::JSON,
            timestamp: "20260304123045".to_string(),
            compression: Compression::NONE,
            encryption: Encryption::NONE,
        };

        let serialized = serde_json::to_string(&header).expect("Serialization should succeed");
        let deserialized: serde_json::Value =
            serde_json::from_str(&serialized).expect("Deserialization should succeed");

        assert_eq!(deserialized["Command"], 1);
        assert_eq!(deserialized["ClientVersion"], "0.2.0");
        assert_eq!(deserialized["Output"], Format::JSON);
        assert_eq!(deserialized["Timestamp"], "20260304123045");
        assert_eq!(deserialized["Compression"], Compression::NONE);
        assert_eq!(deserialized["Encryption"], Encryption::NONE);
    }

    #[tokio::test]
    async fn test_write_request_format() {
        use std::io::Cursor;
        // Create a mock buffer
        let mut buffer = Cursor::new(Vec::new());
        let request_str = r#"{"test":"data"}"#;

        PgmonetaClient::write_request(
            request_str,
            &mut buffer,
            Compression::NONE,
            Encryption::NONE,
        )
        .await
        .unwrap();

        let buffer = buffer.into_inner();

        // Verify the format: Comp(1) + Enc(1) + Len(4) + Payload
        assert_eq!(buffer[0], Compression::NONE);
        assert_eq!(buffer[1], Encryption::NONE);

        // Read length (4 bytes)
        let length = u32::from_be_bytes([buffer[2], buffer[3], buffer[4], buffer[5]]);
        assert_eq!(length as usize, request_str.len());

        // Verify payload
        let payload = String::from_utf8(buffer[6..].to_vec()).unwrap();
        assert_eq!(payload, request_str);
    }

    #[tokio::test]
    async fn test_read_response_format() {
        use std::io::Cursor;
        let response_str = r#"{"outcome":"success"}"#;

        // Prepare mock buffer: Comp(1) + Enc(1) + Len(4) + Payload
        let mut buffer = Vec::new();
        buffer.push(Compression::NONE);
        buffer.push(Encryption::NONE);
        buffer.extend_from_slice(&(response_str.len() as u32).to_be_bytes());
        buffer.extend_from_slice(response_str.as_bytes());

        let mut cursor = Cursor::new(buffer);
        let result = PgmonetaClient::read_response(&mut cursor)
            .await
            .expect("Read should succeed");

        assert_eq!(result, response_str);
    }

    #[test]
    fn test_timestamp_format() {
        init_test_config();
        let header = PgmonetaClient::build_request_header(Command::INFO).unwrap();
        let timestamp = &header.timestamp;

        // Should be exactly 14 digits
        assert_eq!(timestamp.len(), 14);

        // Parse components
        let year: i32 = timestamp[0..4].parse().expect("Year should be valid");
        let month: i32 = timestamp[4..6].parse().expect("Month should be valid");
        let day: i32 = timestamp[6..8].parse().expect("Day should be valid");
        let hour: i32 = timestamp[8..10].parse().expect("Hour should be valid");
        let minute: i32 = timestamp[10..12].parse().expect("Minute should be valid");
        let second: i32 = timestamp[12..14].parse().expect("Second should be valid");

        // Validate ranges
        assert!((2020..=2100).contains(&year));
        assert!((1..=12).contains(&month));
        assert!((1..=31).contains(&day));
        assert!((0..24).contains(&hour));
        assert!((0..60).contains(&minute));
        assert!((0..60).contains(&second));
    }

    #[test]
    fn test_request_clone() {
        init_test_config();
        #[derive(Serialize, Clone, Debug)]
        struct TestRequest {
            data: String,
        }

        let test_request = TestRequest {
            data: "test".to_string(),
        };

        let header = PgmonetaClient::build_request_header(Command::INFO).unwrap();
        let request1 = PgmonetaRequest {
            header: header.clone(),
            request: test_request.clone(),
        };
        let request2 = request1.clone();

        let serialized1 = serde_json::to_string(&request1).unwrap();
        let serialized2 = serde_json::to_string(&request2).unwrap();

        assert_eq!(serialized1, serialized2);
    }

    #[test]
    fn parse_encryption_gcm_and_aliases() {
        assert_eq!(
            Encryption::AES_256_GCM,
            parse_encryption("aes_256_gcm").unwrap()
        );
        assert_eq!(Encryption::AES_256_GCM, parse_encryption("aes").unwrap());
        assert_eq!(
            Encryption::AES_256_GCM,
            parse_encryption("AES_256").unwrap()
        );
        assert_eq!(
            Encryption::AES_192_GCM,
            parse_encryption("aes_192_gcm").unwrap()
        );
        assert_eq!(
            Encryption::AES_192_GCM,
            parse_encryption("aes_192").unwrap()
        );
        assert_eq!(
            Encryption::AES_128_GCM,
            parse_encryption("aes_128_gcm").unwrap()
        );
        assert_eq!(
            Encryption::AES_128_GCM,
            parse_encryption("aes_128").unwrap()
        );
    }

    #[test]
    fn parse_encryption_none_variants() {
        assert_eq!(Encryption::NONE, parse_encryption("none").unwrap());
        assert_eq!(Encryption::NONE, parse_encryption("off").unwrap());
        assert_eq!(Encryption::NONE, parse_encryption("").unwrap());
    }

    #[test]
    fn parse_encryption_unknown_fails() {
        assert!(parse_encryption("some_weird_mode").is_err());
    }
}
