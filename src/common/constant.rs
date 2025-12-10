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

/// This client version is to match pgmoneta-cli
pub const CLIENT_VERSION: &str = "0.20.0";

pub struct Command;
pub struct Format;
pub struct Compression;
pub struct Encryption;
impl Command {
    pub const LIST_BACKUP: u32 = 2;
    pub const INFO: u32 = 18;
}
impl Format {
    pub const JSON: u8 = 0;
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
}

impl Encryption {
    pub const NONE: u8 = 0;
    pub const AES_256_CBC: u8 = 1;
    pub const AES_192_CBC: u8 = 2;
    pub const AES_128_CBC: u8 = 3;
    pub const AES_256_CTR: u8 = 4;
    pub const AES_192_CTR: u8 = 5;
    pub const AES_128_CTR: u8 = 6;
}