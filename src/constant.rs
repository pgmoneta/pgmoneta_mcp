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

use anyhow::anyhow;

/// This client version is to match pgmoneta-cli
pub const CLIENT_VERSION: &str = "0.20.0";

pub const MANAGEMENT_CATEGORY_OUTCOME: &str = "Outcome";
pub const MANAGEMENT_ARGUMENT_STATUS: &str = "Status";
pub const MASTER_KEY_PATH: &str = ".pgmoneta-mcp/master.key";

pub struct Command;
pub struct Format;
pub struct Compression;
pub struct Encryption;
impl Command {
    pub const LIST_BACKUP: u32 = 2;
    pub const INFO: u32 = 18;

    pub fn translate_command_enum(command: u32) -> anyhow::Result<&'static str> {
        match command {
            Self::LIST_BACKUP => Ok("list-backup"),
            Self::INFO => Ok("info"),
            default => Err(anyhow!("Unrecognized command enum: {default}")),
        }
    }
}
impl Format {
    pub const JSON: u8 = 0;

    pub fn translate_format_enum(format: u8) -> anyhow::Result<&'static str> {
        match format {
            Self::JSON => Ok("json"),
            default => Err(anyhow!("Unrecognized format enum: {default}")),
        }
    }
}

impl Compression {
    pub const NONE: u8 = 0;
    pub const GZIP: u8 = 1;
    pub const ZSTD: u8 = 2;
    pub const LZ4: u8 = 3;
    pub const BZIP2: u8 = 4;
    pub const SERVER_GZIP: u8 = 5;
    pub const SERVER_ZSTD: u8 = 6;
    pub const SERVER_LZ4: u8 = 7;

    pub fn translate_compression_enum(compression: u8) -> anyhow::Result<&'static str> {
        match compression {
            Self::NONE => Ok("none"),
            Self::GZIP => Ok("gzip"),
            Self::ZSTD => Ok("zstd"),
            Self::LZ4 => Ok("lz4"),
            Self::BZIP2 => Ok("bzip2"),
            Self::SERVER_GZIP => Ok("server-side gzip"),
            Self::SERVER_ZSTD => Ok("server-side zstd"),
            Self::SERVER_LZ4 => Ok("server-side lz4"),
            default => Err(anyhow!("Unrecognized compression enum: {default}")),
        }
    }
}

impl Encryption {
    pub const NONE: u8 = 0;
    pub const AES_256_CBC: u8 = 1;
    pub const AES_192_CBC: u8 = 2;
    pub const AES_128_CBC: u8 = 3;
    pub const AES_256_CTR: u8 = 4;
    pub const AES_192_CTR: u8 = 5;
    pub const AES_128_CTR: u8 = 6;

    pub fn translate_encryption_enum(encryption: u8) -> anyhow::Result<&'static str> {
        match encryption {
            Encryption::NONE => Ok("none"),
            Encryption::AES_256_CBC => Ok("aes_256_cbc"),
            Encryption::AES_192_CBC => Ok("aes_192_cbc"),
            Encryption::AES_128_CBC => Ok("aes_128_cbc"),
            Encryption::AES_256_CTR => Ok("aes_256_ctr"),
            Encryption::AES_192_CTR => Ok("aes_192_ctr"),
            Encryption::AES_128_CTR => Ok("aes_128_ctr"),
            default => Err(anyhow!("Unrecognized encryption enum: {default}")),
        }
    }
}
