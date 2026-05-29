#![allow(dead_code)]

use anyhow::anyhow;
use chrono::Local;
use pgmoneta_mcp::compression::CompressionUtil;
use pgmoneta_mcp::configuration::{
    CONFIG, Configuration, PgmonetaConfiguration, PgmonetaMcpConfiguration,
};
use pgmoneta_mcp::constant::{CLIENT_VERSION, Command, Compression, Encryption, Format};
use pgmoneta_mcp::security::SecurityUtil;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Once, OnceLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::{Duration, timeout};

static INIT_CONFIG: Once = Once::new();
static BACKUP_FIXTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

const MAX_FRAME_LEN: usize = 64 * 1024 * 1024;

pub fn init_config() {
    INIT_CONFIG.call_once(|| {
        let force_plain = std::env::var("PGMONETA_MCP_FORCE_PLAIN")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let requested_compression =
            std::env::var("PGMONETA_MCP_COMPRESSION").unwrap_or_else(|_| "zstd".to_string());
        let requested_encryption =
            std::env::var("PGMONETA_MCP_ENCRYPTION").unwrap_or_else(|_| "aes_256_gcm".to_string());

        let compression = if force_plain {
            "none".to_string()
        } else {
            requested_compression
        };

        let encryption = if force_plain {
            "none".to_string()
        } else {
            requested_encryption
        };

        let security: SecurityUtil = SecurityUtil::new();
        let (master_password, master_salt) =
            security.load_master_key().expect("master key must exist");
        let encrypted = security
            .encrypt_to_base64_string(b"backup_pass", &master_password, &master_salt)
            .expect("password encryption should succeed");

        let mut admins: HashMap<String, String> = HashMap::new();
        admins.insert("backup_user".to_string(), encrypted);

        let config = Configuration {
            pgmoneta_mcp: PgmonetaMcpConfiguration {
                port: 8000,
                log_path: "pgmoneta_mcp.log".to_string(),
                log_level: "info".to_string(),
                log_type: "console".to_string(),
                log_line_prefix: "%Y-%m-%d %H:%M:%S".to_string(),
                log_mode: "append".to_string(),
                log_rotation_age: "0".to_string(),
            },
            pgmoneta: PgmonetaConfiguration {
                host: "127.0.0.1".to_string(),
                port: 5002,
                base_dir: "/tmp/pgmoneta".to_string(),
                metrics: 5001,
                compression,
                encryption,
            },
            admins,
            llm: None,
        };

        CONFIG
            .set(config)
            .expect("CONFIG should be initialized once");
    });
}

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

#[derive(Serialize, Clone, Debug)]
struct BackupRequest {
    #[serde(rename = "Server")]
    server: String,
}

#[derive(Serialize, Clone, Debug)]
struct ListBackupsRequest {
    #[serde(rename = "Server")]
    server: String,
    #[serde(rename = "Sort")]
    sort: String,
}

pub async fn backup_fixture_lock() -> MutexGuard<'static, ()> {
    BACKUP_FIXTURE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .await
}

pub async fn ensure_backup(server: &str) -> anyhow::Result<String> {
    let backup_response = send_management_request(
        "backup_user",
        Command::BACKUP,
        BackupRequest {
            server: server.to_string(),
        },
    )
    .await?;

    let backup_json: Value = serde_json::from_str(&backup_response)?;
    if backup_json["Outcome"]["Status"] != true {
        return Err(anyhow!("backup request failed: {backup_response}"));
    }

    latest_backup_id(server).await
}

async fn latest_backup_id(server: &str) -> anyhow::Result<String> {
    let list_response = send_management_request(
        "backup_user",
        Command::LIST_BACKUP,
        ListBackupsRequest {
            server: server.to_string(),
            sort: "desc".to_string(),
        },
    )
    .await?;

    let list_json: Value = serde_json::from_str(&list_response)?;
    if list_json["Outcome"]["Status"] != true {
        return Err(anyhow!("list-backup request failed: {list_response}"));
    }

    let backups = list_json["Response"]["Backups"]
        .as_array()
        .ok_or_else(|| anyhow!("list-backup response missing backups array: {list_response}"))?;
    let backup = backups
        .first()
        .ok_or_else(|| anyhow!("list-backup response had no backups: {list_response}"))?;
    let backup_value = &backup["Backup"];

    if let Some(id) = backup_value.as_str() {
        Ok(id.to_string())
    } else if let Some(id) = backup_value.as_u64() {
        Ok(id.to_string())
    } else if let Some(id) = backup_value.as_i64() {
        Ok(id.to_string())
    } else {
        Err(anyhow!(
            "list-backup response had unexpected backup id shape: {list_response}"
        ))
    }
}

async fn send_management_request<R>(
    username: &str,
    command: u32,
    request: R,
) -> anyhow::Result<String>
where
    R: Serialize + Clone + Debug,
{
    let config = CONFIG.get().expect("Configuration should be enabled");
    let security = SecurityUtil::new();
    let encrypted_password = config
        .admins
        .get(username)
        .ok_or_else(|| anyhow!("unable to find configured user {username}"))?;
    let (master_password, master_salt) = security.load_master_key()?;
    let decrypted_password =
        security.decrypt_from_base64_string(encrypted_password, &master_password, &master_salt)?;
    let password = String::from_utf8(decrypted_password)?;

    let compression = parse_compression(&config.pgmoneta.compression)?;
    let encryption = parse_encryption(&config.pgmoneta.encryption)?;
    let header = RequestHeader {
        command,
        client_version: CLIENT_VERSION.to_string(),
        output_format: Format::JSON,
        timestamp: Local::now().format("%Y%m%d%H%M%S").to_string(),
        compression,
        encryption,
    };
    let request = PgmonetaRequest { header, request };

    let mut stream = SecurityUtil::connect_to_server(
        &config.pgmoneta.host,
        config.pgmoneta.port,
        username,
        &password,
    )
    .await?;

    let request_json = serde_json::to_string(&request)?;
    write_request(&request_json, &mut stream, compression, encryption).await?;
    read_response(&mut stream).await
}

fn parse_compression(compression: &str) -> anyhow::Result<u8> {
    match compression.to_lowercase().as_str() {
        "gzip" | "server-gzip" | "server_gzip" => Ok(Compression::GZIP),
        "zstd" | "server-zstd" | "server_zstd" => Ok(Compression::ZSTD),
        "lz4" | "server-lz4" | "server_lz4" => Ok(Compression::LZ4),
        "bzip2" | "bz2" => Ok(Compression::BZIP2),
        "none" | "" | "off" => Ok(Compression::NONE),
        unknown => Err(anyhow!("unsupported test compression mode: {unknown}")),
    }
}

fn parse_encryption(encryption: &str) -> anyhow::Result<u8> {
    match encryption.to_lowercase().as_str() {
        "aes_256_gcm" | "aes-256-gcm" | "aes_256" | "aes-256" | "aes" => {
            Ok(Encryption::AES_256_GCM)
        }
        "aes_192_gcm" | "aes-192-gcm" | "aes_192" | "aes-192" => Ok(Encryption::AES_192_GCM),
        "aes_128_gcm" | "aes-128-gcm" | "aes_128" | "aes-128" => Ok(Encryption::AES_128_GCM),
        "none" | "" | "off" => Ok(Encryption::NONE),
        unknown => Err(anyhow!("unsupported test encryption mode: {unknown}")),
    }
}

async fn write_request<W>(
    request_json: &str,
    stream: &mut W,
    compression: u8,
    encryption: u8,
) -> anyhow::Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let security = SecurityUtil::new();
    let payload = if compression != Compression::NONE || encryption != Encryption::NONE {
        let mut data = request_json.as_bytes().to_vec();
        if compression != Compression::NONE {
            data = CompressionUtil::compress(&data, compression)?;
        }
        if encryption != Encryption::NONE {
            data = security.encrypt_text_aes_gcm_bundle(&data, encryption)?;
        }
        security.base64_encode(&data)?
    } else {
        request_json.to_string()
    };

    stream.write_u8(compression).await?;
    stream.write_u8(encryption).await?;
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(payload.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_response<R>(stream: &mut R) -> anyhow::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let compression = timeout(Duration::from_secs(10), stream.read_u8()).await??;
    let encryption = timeout(Duration::from_secs(2), stream.read_u8()).await??;
    let len = timeout(Duration::from_secs(2), stream.read_u32()).await?? as usize;

    if len > MAX_FRAME_LEN {
        return Err(anyhow!("response frame too large: {len}"));
    }

    let mut buf = vec![0u8; len];
    timeout(Duration::from_secs(10), stream.read_exact(&mut buf)).await??;
    if buf.last() == Some(&0) {
        buf.pop();
    }

    if compression == Compression::NONE && encryption == Encryption::NONE {
        return String::from_utf8(buf).map_err(Into::into);
    }

    let security = SecurityUtil::new();
    let data = security.base64_decode(std::str::from_utf8(&buf)?)?;
    let mut decoded = data;

    if encryption != Encryption::NONE {
        decoded = security.decrypt_text_aes_gcm_bundle(&decoded, encryption)?;
    }
    if compression != Compression::NONE {
        decoded = CompressionUtil::decompress(&decoded, compression)?;
    }

    String::from_utf8(decoded).map_err(Into::into)
}
