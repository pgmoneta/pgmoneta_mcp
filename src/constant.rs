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
pub struct ManagementError;

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

impl ManagementError {
    pub const MANAGEMENT_ERROR_BAD_PAYLOAD: u32 = 1;
    pub const MANAGEMENT_ERROR_UNKNOWN_COMMAND: u32 = 2;
    pub const MANAGEMENT_ERROR_ALLOCATION: u32 = 3;

    pub const MANAGEMENT_ERROR_BACKUP_INVALID: u32 = 100;
    pub const MANAGEMENT_ERROR_BACKUP_WAL: u32 = 101;
    pub const MANAGEMENT_ERROR_BACKUP_ACTIVE: u32 = 102;
    pub const MANAGEMENT_ERROR_BACKUP_NOBACKUPS: u32 = 103;
    pub const MANAGEMENT_ERROR_BACKUP_NOCHILD: u32 = 104;
    pub const MANAGEMENT_ERROR_BACKUP_ALREADYCHILD: u32 = 105;
    pub const MANAGEMENT_ERROR_BACKUP_SETUP: u32 = 106;
    pub const MANAGEMENT_ERROR_BACKUP_EXECUTE: u32 = 107;
    pub const MANAGEMENT_ERROR_BACKUP_TEARDOWN: u32 = 108;
    pub const MANAGEMENT_ERROR_BACKUP_NETWORK: u32 = 109;
    pub const MANAGEMENT_ERROR_BACKUP_OFFLINE: u32 = 110;
    pub const MANAGEMENT_ERROR_BACKUP_NOSERVER: u32 = 111;
    pub const MANAGEMENT_ERROR_BACKUP_ERROR: u32 = 112;

    pub const MANAGEMENT_ERROR_INCREMENTAL_BACKUP_SETUP: u32 = 200;
    pub const MANAGEMENT_ERROR_INCREMENTAL_BACKUP_EXECUTE: u32 = 201;
    pub const MANAGEMENT_ERROR_INCREMENTAL_BACKUP_TEARDOWN: u32 = 202;

    pub const MANAGEMENT_ERROR_LIST_BACKUP_DEQUE_CREATE: u32 = 300;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_BACKUPS: u32 = 301;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE: u32 = 302;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_NETWORK: u32 = 303;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_NOSERVER: u32 = 304;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_NOFORK: u32 = 305;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_INVALID_SORT: u32 = 306;
    pub const MANAGEMENT_ERROR_LIST_BACKUP_ERROR: u32 = 307;

    pub const MANAGEMENT_ERROR_DELETE_SETUP: u32 = 400;
    pub const MANAGEMENT_ERROR_DELETE_EXECUTE: u32 = 401;
    pub const MANAGEMENT_ERROR_DELETE_TEARDOWN: u32 = 402;
    pub const MANAGEMENT_ERROR_DELETE_NOSERVER: u32 = 403;
    pub const MANAGEMENT_ERROR_DELETE_NOFORK: u32 = 404;
    pub const MANAGEMENT_ERROR_DELETE_NETWORK: u32 = 405;
    pub const MANAGEMENT_ERROR_DELETE_ERROR: u32 = 406;

    pub const MANAGEMENT_ERROR_DELETE_BACKUP_SETUP: u32 = 500;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_EXECUTE: u32 = 501;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_TEARDOWN: u32 = 502;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_NOBACKUPS: u32 = 503;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_NOBACKUP: u32 = 504;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_RETAINED: u32 = 505;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_ROLLUP: u32 = 506;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_FULL: u32 = 507;
    pub const MANAGEMENT_ERROR_DELETE_BACKUP_ERROR: u32 = 508;

    pub const MANAGEMENT_ERROR_RESTORE_NOBACKUP: u32 = 600;
    pub const MANAGEMENT_ERROR_RESTORE_NODISK: u32 = 601;
    pub const MANAGEMENT_ERROR_RESTORE_ACTIVE: u32 = 602;
    pub const MANAGEMENT_ERROR_RESTORE_NOSERVER: u32 = 603;
    pub const MANAGEMENT_ERROR_RESTORE_SETUP: u32 = 604;
    pub const MANAGEMENT_ERROR_RESTORE_EXECUTE: u32 = 605;
    pub const MANAGEMENT_ERROR_RESTORE_TEARDOWN: u32 = 606;
    pub const MANAGEMENT_ERROR_RESTORE_NOFORK: u32 = 607;
    pub const MANAGEMENT_ERROR_RESTORE_NETWORK: u32 = 608;
    pub const MANAGEMENT_ERROR_RESTORE_ERROR: u32 = 609;

    pub const MANAGEMENT_ERROR_COMBINE_SETUP: u32 = 700;
    pub const MANAGEMENT_ERROR_COMBINE_EXECUTE: u32 = 701;
    pub const MANAGEMENT_ERROR_COMBINE_TEARDOWN: u32 = 702;

    pub const MANAGEMENT_ERROR_VERIFY_NOSERVER: u32 = 800;
    pub const MANAGEMENT_ERROR_VERIFY_SETUP: u32 = 801;
    pub const MANAGEMENT_ERROR_VERIFY_EXECUTE: u32 = 802;
    pub const MANAGEMENT_ERROR_VERIFY_TEARDOWN: u32 = 803;
    pub const MANAGEMENT_ERROR_VERIFY_NOFORK: u32 = 804;
    pub const MANAGEMENT_ERROR_VERIFY_NETWORK: u32 = 805;
    pub const MANAGEMENT_ERROR_VERIFY_ERROR: u32 = 806;

    pub const MANAGEMENT_ERROR_ARCHIVE_NOBACKUP: u32 = 900;
    pub const MANAGEMENT_ERROR_ARCHIVE_NOSERVER: u32 = 901;
    pub const MANAGEMENT_ERROR_ARCHIVE_ACTIVE: u32 = 902;
    pub const MANAGEMENT_ERROR_ARCHIVE_SETUP: u32 = 903;
    pub const MANAGEMENT_ERROR_ARCHIVE_EXECUTE: u32 = 904;
    pub const MANAGEMENT_ERROR_ARCHIVE_TEARDOWN: u32 = 905;
    pub const MANAGEMENT_ERROR_ARCHIVE_NOFORK: u32 = 906;
    pub const MANAGEMENT_ERROR_ARCHIVE_NETWORK: u32 = 907;
    pub const MANAGEMENT_ERROR_ARCHIVE_ERROR: u32 = 908;

    pub const MANAGEMENT_ERROR_STATUS_NOFORK: u32 = 1000;
    pub const MANAGEMENT_ERROR_STATUS_NETWORK: u32 = 1001;

    pub const MANAGEMENT_ERROR_STATUS_DETAILS_NOFORK: u32 = 1100;
    pub const MANAGEMENT_ERROR_STATUS_DETAILS_NETWORK: u32 = 1101;

    pub const MANAGEMENT_ERROR_RETAIN_NOBACKUP: u32 = 1200;
    pub const MANAGEMENT_ERROR_RETAIN_NOSERVER: u32 = 1201;
    pub const MANAGEMENT_ERROR_RETAIN_NOFORK: u32 = 1202;
    pub const MANAGEMENT_ERROR_RETAIN_NETWORK: u32 = 1203;
    pub const MANAGEMENT_ERROR_RETAIN_ERROR: u32 = 1204;

    pub const MANAGEMENT_ERROR_EXPUNGE_NOBACKUP: u32 = 1300;
    pub const MANAGEMENT_ERROR_EXPUNGE_NOSERVER: u32 = 1301;
    pub const MANAGEMENT_ERROR_EXPUNGE_NOFORK: u32 = 1302;
    pub const MANAGEMENT_ERROR_EXPUNGE_NETWORK: u32 = 1303;
    pub const MANAGEMENT_ERROR_EXPUNGE_ERROR: u32 = 1304;

    pub const MANAGEMENT_ERROR_DECRYPT_NOFILE: u32 = 1400;
    pub const MANAGEMENT_ERROR_DECRYPT_NOFORK: u32 = 1401;
    pub const MANAGEMENT_ERROR_DECRYPT_NETWORK: u32 = 1402;
    pub const MANAGEMENT_ERROR_DECRYPT_ERROR: u32 = 1403;

    pub const MANAGEMENT_ERROR_ENCRYPT_NOFILE: u32 = 1500;
    pub const MANAGEMENT_ERROR_ENCRYPT_NOFORK: u32 = 1501;
    pub const MANAGEMENT_ERROR_ENCRYPT_NETWORK: u32 = 1502;
    pub const MANAGEMENT_ERROR_ENCRYPT_ERROR: u32 = 1503;

    pub const MANAGEMENT_ERROR_GZIP_NOFILE: u32 = 1600;
    pub const MANAGEMENT_ERROR_GZIP_NOFORK: u32 = 1601;
    pub const MANAGEMENT_ERROR_GZIP_NETWORK: u32 = 1602;
    pub const MANAGEMENT_ERROR_GZIP_ERROR: u32 = 1603;

    pub const MANAGEMENT_ERROR_ZSTD_NOFILE: u32 = 1700;
    pub const MANAGEMENT_ERROR_ZSTD_NOFORK: u32 = 1701;
    pub const MANAGEMENT_ERROR_ZSTD_NETWORK: u32 = 1702;
    pub const MANAGEMENT_ERROR_ZSTD_ERROR: u32 = 1703;

    pub const MANAGEMENT_ERROR_LZ4_NOFILE: u32 = 1800;
    pub const MANAGEMENT_ERROR_LZ4_NOFORK: u32 = 1801;
    pub const MANAGEMENT_ERROR_LZ4_NETWORK: u32 = 1802;
    pub const MANAGEMENT_ERROR_LZ4_ERROR: u32 = 1803;

    pub const MANAGEMENT_ERROR_BZIP2_NOFILE: u32 = 1900;
    pub const MANAGEMENT_ERROR_BZIP2_NOFORK: u32 = 1901;
    pub const MANAGEMENT_ERROR_BZIP2_NETWORK: u32 = 1902;
    pub const MANAGEMENT_ERROR_BZIP2_ERROR: u32 = 1903;

    pub const MANAGEMENT_ERROR_DECOMPRESS_NOFORK: u32 = 2000;
    pub const MANAGEMENT_ERROR_DECOMPRESS_UNKNOWN: u32 = 2001;

    pub const MANAGEMENT_ERROR_COMPRESS_NOFORK: u32 = 2100;
    pub const MANAGEMENT_ERROR_COMPRESS_UNKNOWN: u32 = 2101;

    pub const MANAGEMENT_ERROR_INFO_NOBACKUP: u32 = 2200;
    pub const MANAGEMENT_ERROR_INFO_NOSERVER: u32 = 2201;
    pub const MANAGEMENT_ERROR_INFO_NOFORK: u32 = 2202;
    pub const MANAGEMENT_ERROR_INFO_NETWORK: u32 = 2203;
    pub const MANAGEMENT_ERROR_INFO_ERROR: u32 = 2204;

    pub const MANAGEMENT_ERROR_RETENTION_SETUP: u32 = 2302;
    pub const MANAGEMENT_ERROR_RETENTION_EXECUTE: u32 = 2303;
    pub const MANAGEMENT_ERROR_RETENTION_TEARDOWN: u32 = 2304;
    pub const MANAGEMENT_ERROR_RETENTION_ERROR: u32 = 2305;

    pub const MANAGEMENT_ERROR_WAL_SHIPPING_SETUP: u32 = 2402;
    pub const MANAGEMENT_ERROR_WAL_SHIPPING_EXECUTE: u32 = 2403;
    pub const MANAGEMENT_ERROR_WAL_SHIPPING_TEARDOWN: u32 = 2404;

    pub const MANAGEMENT_ERROR_ANNOTATE_NOBACKUP: u32 = 2500;
    pub const MANAGEMENT_ERROR_ANNOTATE_NOSERVER: u32 = 2501;
    pub const MANAGEMENT_ERROR_ANNOTATE_NOFORK: u32 = 2502;
    pub const MANAGEMENT_ERROR_ANNOTATE_FAILED: u32 = 2503;
    pub const MANAGEMENT_ERROR_ANNOTATE_NETWORK: u32 = 2504;
    pub const MANAGEMENT_ERROR_ANNOTATE_ERROR: u32 = 2505;
    pub const MANAGEMENT_ERROR_ANNOTATE_UNKNOWN_ACTION: u32 = 2506;

    pub const MANAGEMENT_ERROR_CONF_GET_NOFORK: u32 = 2600;
    pub const MANAGEMENT_ERROR_CONF_GET_NETWORK: u32 = 2602;
    pub const MANAGEMENT_ERROR_CONF_GET_ERROR: u32 = 2603;

    pub const MANAGEMENT_ERROR_CONF_SET_NOFORK: u32 = 2700;
    pub const MANAGEMENT_ERROR_CONF_SET_NOREQUEST: u32 = 2701;
    pub const MANAGEMENT_ERROR_CONF_SET_NOCONFIG_KEY_OR_VALUE: u32 = 2702;
    pub const MANAGEMENT_ERROR_CONF_SET_NORESPONSE: u32 = 2703;
    pub const MANAGEMENT_ERROR_CONF_SET_UNKNOWN_CONFIGURATION_KEY: u32 = 2704;
    pub const MANAGEMENT_ERROR_CONF_SET_UNKNOWN_SERVER: u32 = 2705;
    pub const MANAGEMENT_ERROR_CONF_SET_NETWORK: u32 = 2706;
    pub const MANAGEMENT_ERROR_CONF_SET_ERROR: u32 = 2707;

    pub const MANAGEMENT_ERROR_MODE_NOSERVER: u32 = 2800;
    pub const MANAGEMENT_ERROR_MODE_NOFORK: u32 = 2801;
    pub const MANAGEMENT_ERROR_MODE_FAILED: u32 = 2802;
    pub const MANAGEMENT_ERROR_MODE_NETWORK: u32 = 2803;
    pub const MANAGEMENT_ERROR_MODE_ERROR: u32 = 2804;
    pub const MANAGEMENT_ERROR_MODE_UNKNOWN_ACTION: u32 = 2805;

    pub fn translate_error_enum(error: u32) -> &'static str {
        match error {
            Self::MANAGEMENT_ERROR_BAD_PAYLOAD => "Bad request payload",
            Self::MANAGEMENT_ERROR_UNKNOWN_COMMAND => "Unknown command",
            Self::MANAGEMENT_ERROR_ALLOCATION => "Memory allocation failure",

            Self::MANAGEMENT_ERROR_BACKUP_INVALID => "Backup: invalid request",
            Self::MANAGEMENT_ERROR_BACKUP_WAL => "Backup: WAL error",
            Self::MANAGEMENT_ERROR_BACKUP_ACTIVE => "Backup: another active process happening",
            Self::MANAGEMENT_ERROR_BACKUP_NOBACKUPS => "Backup: no backups available",
            Self::MANAGEMENT_ERROR_BACKUP_NOCHILD => "Backup: no child process",
            Self::MANAGEMENT_ERROR_BACKUP_ALREADYCHILD => "Backup: child already exists",
            Self::MANAGEMENT_ERROR_BACKUP_SETUP => "Backup: setup failed",
            Self::MANAGEMENT_ERROR_BACKUP_EXECUTE => "Backup: execution failed",
            Self::MANAGEMENT_ERROR_BACKUP_TEARDOWN => "Backup: teardown failed",
            Self::MANAGEMENT_ERROR_BACKUP_NETWORK => "Backup: network error",
            Self::MANAGEMENT_ERROR_BACKUP_OFFLINE => "Backup: server offline",
            Self::MANAGEMENT_ERROR_BACKUP_NOSERVER => "Backup: server not found",
            Self::MANAGEMENT_ERROR_BACKUP_ERROR => "Backup: error",

            Self::MANAGEMENT_ERROR_INCREMENTAL_BACKUP_SETUP => "Incremental backup: setup failed",
            Self::MANAGEMENT_ERROR_INCREMENTAL_BACKUP_EXECUTE => {
                "Incremental backup: execution failed"
            }
            Self::MANAGEMENT_ERROR_INCREMENTAL_BACKUP_TEARDOWN => {
                "Incremental backup: teardown failed"
            }

            Self::MANAGEMENT_ERROR_LIST_BACKUP_DEQUE_CREATE => {
                "List backup: internal deque creation failed"
            }
            Self::MANAGEMENT_ERROR_LIST_BACKUP_BACKUPS => "List backup: failed to retrieve backups",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_JSON_VALUE => "List backup: invalid JSON value",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_NETWORK => "List backup: network error",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_NOSERVER => "List backup: no server",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_NOFORK => "List backup: no fork",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_INVALID_SORT => "List backup: invalid sort option",
            Self::MANAGEMENT_ERROR_LIST_BACKUP_ERROR => "List backup: error",

            Self::MANAGEMENT_ERROR_DELETE_SETUP => "Delete: setup failed",
            Self::MANAGEMENT_ERROR_DELETE_EXECUTE => "Delete: execution failed",
            Self::MANAGEMENT_ERROR_DELETE_TEARDOWN => "Delete: teardown failed",
            Self::MANAGEMENT_ERROR_DELETE_NOSERVER => "Delete: no server",
            Self::MANAGEMENT_ERROR_DELETE_NOFORK => "Delete: no fork",
            Self::MANAGEMENT_ERROR_DELETE_NETWORK => "Delete: network error",
            Self::MANAGEMENT_ERROR_DELETE_ERROR => "Delete: error",

            Self::MANAGEMENT_ERROR_DELETE_BACKUP_SETUP => "Delete backup: setup failed",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_EXECUTE => "Delete backup: execution failed",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_TEARDOWN => "Delete backup: teardown failed",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_NOBACKUPS => "Delete backup: no backups available",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_NOBACKUP => "Delete backup: backup not found",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_RETAINED => "Delete backup: backup is retained",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_ROLLUP => "Delete backup: rollup failed",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_FULL => "Delete backup: full backup required",
            Self::MANAGEMENT_ERROR_DELETE_BACKUP_ERROR => "Delete backup: error",

            Self::MANAGEMENT_ERROR_RESTORE_NOBACKUP => "Restore: no backup available",
            Self::MANAGEMENT_ERROR_RESTORE_NODISK => "Restore: no disk available",
            Self::MANAGEMENT_ERROR_RESTORE_ACTIVE => "Restore: already active",
            Self::MANAGEMENT_ERROR_RESTORE_NOSERVER => "Restore: no server",
            Self::MANAGEMENT_ERROR_RESTORE_SETUP => "Restore: setup failed",
            Self::MANAGEMENT_ERROR_RESTORE_EXECUTE => "Restore: execution failed",
            Self::MANAGEMENT_ERROR_RESTORE_TEARDOWN => "Restore: teardown failed",
            Self::MANAGEMENT_ERROR_RESTORE_NOFORK => "Restore: no fork",
            Self::MANAGEMENT_ERROR_RESTORE_NETWORK => "Restore: network error",
            Self::MANAGEMENT_ERROR_RESTORE_ERROR => "Restore: error",

            Self::MANAGEMENT_ERROR_COMBINE_SETUP => "Combine: setup failed",
            Self::MANAGEMENT_ERROR_COMBINE_EXECUTE => "Combine: execution failed",
            Self::MANAGEMENT_ERROR_COMBINE_TEARDOWN => "Combine: teardown failed",

            Self::MANAGEMENT_ERROR_VERIFY_NOSERVER => "Verify: no server",
            Self::MANAGEMENT_ERROR_VERIFY_SETUP => "Verify: setup failed",
            Self::MANAGEMENT_ERROR_VERIFY_EXECUTE => "Verify: execution failed",
            Self::MANAGEMENT_ERROR_VERIFY_TEARDOWN => "Verify: teardown failed",
            Self::MANAGEMENT_ERROR_VERIFY_NOFORK => "Verify: no fork",
            Self::MANAGEMENT_ERROR_VERIFY_NETWORK => "Verify: network error",
            Self::MANAGEMENT_ERROR_VERIFY_ERROR => "Verify: error",

            Self::MANAGEMENT_ERROR_ARCHIVE_NOBACKUP => "Archive: no backup available",
            Self::MANAGEMENT_ERROR_ARCHIVE_NOSERVER => "Archive: no server",
            Self::MANAGEMENT_ERROR_ARCHIVE_ACTIVE => "Archive: already active",
            Self::MANAGEMENT_ERROR_ARCHIVE_SETUP => "Archive: setup failed",
            Self::MANAGEMENT_ERROR_ARCHIVE_EXECUTE => "Archive: execution failed",
            Self::MANAGEMENT_ERROR_ARCHIVE_TEARDOWN => "Archive: teardown failed",
            Self::MANAGEMENT_ERROR_ARCHIVE_NOFORK => "Archive: no fork",
            Self::MANAGEMENT_ERROR_ARCHIVE_NETWORK => "Archive: network error",
            Self::MANAGEMENT_ERROR_ARCHIVE_ERROR => "Archive: error",

            Self::MANAGEMENT_ERROR_STATUS_NOFORK => "Status: no fork",
            Self::MANAGEMENT_ERROR_STATUS_NETWORK => "Status: network error",

            Self::MANAGEMENT_ERROR_STATUS_DETAILS_NOFORK => "Status details: no fork",
            Self::MANAGEMENT_ERROR_STATUS_DETAILS_NETWORK => "Status details: network error",

            Self::MANAGEMENT_ERROR_RETAIN_NOBACKUP => "Retention: no backup available",
            Self::MANAGEMENT_ERROR_RETAIN_NOSERVER => "Retention: no server",
            Self::MANAGEMENT_ERROR_RETAIN_NOFORK => "Retention: no fork",
            Self::MANAGEMENT_ERROR_RETAIN_NETWORK => "Retention: network error",
            Self::MANAGEMENT_ERROR_RETAIN_ERROR => "Retention: error",

            Self::MANAGEMENT_ERROR_EXPUNGE_NOBACKUP => "Expunge: no backup available",
            Self::MANAGEMENT_ERROR_EXPUNGE_NOSERVER => "Expunge: no server",
            Self::MANAGEMENT_ERROR_EXPUNGE_NOFORK => "Expunge: no fork",
            Self::MANAGEMENT_ERROR_EXPUNGE_NETWORK => "Expunge: network error",
            Self::MANAGEMENT_ERROR_EXPUNGE_ERROR => "Expunge: error",

            Self::MANAGEMENT_ERROR_DECRYPT_NOFILE => "Decrypt: file not found",
            Self::MANAGEMENT_ERROR_DECRYPT_NOFORK => "Decrypt: no fork",
            Self::MANAGEMENT_ERROR_DECRYPT_NETWORK => "Decrypt: network error",
            Self::MANAGEMENT_ERROR_DECRYPT_ERROR => "Decrypt: error",

            Self::MANAGEMENT_ERROR_ENCRYPT_NOFILE => "Encrypt: file not found",
            Self::MANAGEMENT_ERROR_ENCRYPT_NOFORK => "Encrypt: no fork",
            Self::MANAGEMENT_ERROR_ENCRYPT_NETWORK => "Encrypt: network error",
            Self::MANAGEMENT_ERROR_ENCRYPT_ERROR => "Encrypt: error",

            Self::MANAGEMENT_ERROR_GZIP_NOFILE => "Gzip: file not found",
            Self::MANAGEMENT_ERROR_GZIP_NOFORK => "Gzip: no fork",
            Self::MANAGEMENT_ERROR_GZIP_NETWORK => "Gzip: network error",
            Self::MANAGEMENT_ERROR_GZIP_ERROR => "Gzip: error",

            Self::MANAGEMENT_ERROR_ZSTD_NOFILE => "Zstd: file not found",
            Self::MANAGEMENT_ERROR_ZSTD_NOFORK => "Zstd: no fork",
            Self::MANAGEMENT_ERROR_ZSTD_NETWORK => "Zstd: network error",
            Self::MANAGEMENT_ERROR_ZSTD_ERROR => "Zstd: error",

            Self::MANAGEMENT_ERROR_LZ4_NOFILE => "LZ4: file not found",
            Self::MANAGEMENT_ERROR_LZ4_NOFORK => "LZ4: no fork",
            Self::MANAGEMENT_ERROR_LZ4_NETWORK => "LZ4: network error",
            Self::MANAGEMENT_ERROR_LZ4_ERROR => "LZ4: error",

            Self::MANAGEMENT_ERROR_BZIP2_NOFILE => "Bzip2: file not found",
            Self::MANAGEMENT_ERROR_BZIP2_NOFORK => "Bzip2: no fork",
            Self::MANAGEMENT_ERROR_BZIP2_NETWORK => "Bzip2: network error",
            Self::MANAGEMENT_ERROR_BZIP2_ERROR => "Bzip2: error",

            Self::MANAGEMENT_ERROR_DECOMPRESS_NOFORK => "Decompress: no fork",
            Self::MANAGEMENT_ERROR_DECOMPRESS_UNKNOWN => "Decompress: unknown format",

            Self::MANAGEMENT_ERROR_COMPRESS_NOFORK => "Compress: no fork",
            Self::MANAGEMENT_ERROR_COMPRESS_UNKNOWN => "Compress: unknown format",

            Self::MANAGEMENT_ERROR_INFO_NOBACKUP => "Info: no backup available",
            Self::MANAGEMENT_ERROR_INFO_NOSERVER => "Info: no server",
            Self::MANAGEMENT_ERROR_INFO_NOFORK => "Info: no fork",
            Self::MANAGEMENT_ERROR_INFO_NETWORK => "Info: network error",
            Self::MANAGEMENT_ERROR_INFO_ERROR => "Info: error",

            Self::MANAGEMENT_ERROR_RETENTION_SETUP => "Retention: setup failed",
            Self::MANAGEMENT_ERROR_RETENTION_EXECUTE => "Retention: execution failed",
            Self::MANAGEMENT_ERROR_RETENTION_TEARDOWN => "Retention: teardown failed",
            Self::MANAGEMENT_ERROR_RETENTION_ERROR => "Retention: error",

            Self::MANAGEMENT_ERROR_WAL_SHIPPING_SETUP => "WAL shipping: setup failed",
            Self::MANAGEMENT_ERROR_WAL_SHIPPING_EXECUTE => "WAL shipping: execution failed",
            Self::MANAGEMENT_ERROR_WAL_SHIPPING_TEARDOWN => "WAL shipping: teardown failed",

            Self::MANAGEMENT_ERROR_ANNOTATE_NOBACKUP => "Annotate: no backup available",
            Self::MANAGEMENT_ERROR_ANNOTATE_NOSERVER => "Annotate: no server",
            Self::MANAGEMENT_ERROR_ANNOTATE_NOFORK => "Annotate: no fork",
            Self::MANAGEMENT_ERROR_ANNOTATE_FAILED => "Annotate: failed",
            Self::MANAGEMENT_ERROR_ANNOTATE_NETWORK => "Annotate: network error",
            Self::MANAGEMENT_ERROR_ANNOTATE_ERROR => "Annotate: error",
            Self::MANAGEMENT_ERROR_ANNOTATE_UNKNOWN_ACTION => "Annotate: unknown action",

            Self::MANAGEMENT_ERROR_CONF_GET_NOFORK => "Config get: no fork",
            Self::MANAGEMENT_ERROR_CONF_GET_NETWORK => "Config get: network error",
            Self::MANAGEMENT_ERROR_CONF_GET_ERROR => "Config get: error",

            Self::MANAGEMENT_ERROR_CONF_SET_NOFORK => "Config set: no fork",
            Self::MANAGEMENT_ERROR_CONF_SET_NOREQUEST => "Config set: no request",
            Self::MANAGEMENT_ERROR_CONF_SET_NOCONFIG_KEY_OR_VALUE => {
                "Config set: missing key or value"
            }
            Self::MANAGEMENT_ERROR_CONF_SET_NORESPONSE => "Config set: no response",
            Self::MANAGEMENT_ERROR_CONF_SET_UNKNOWN_CONFIGURATION_KEY => {
                "Config set: unknown configuration key"
            }
            Self::MANAGEMENT_ERROR_CONF_SET_UNKNOWN_SERVER => "Config set: unknown server",
            Self::MANAGEMENT_ERROR_CONF_SET_NETWORK => "Config set: network error",
            Self::MANAGEMENT_ERROR_CONF_SET_ERROR => "Config set: error",

            Self::MANAGEMENT_ERROR_MODE_NOSERVER => "Mode: no server",
            Self::MANAGEMENT_ERROR_MODE_NOFORK => "Mode: no fork",
            Self::MANAGEMENT_ERROR_MODE_FAILED => "Mode: failed",
            Self::MANAGEMENT_ERROR_MODE_NETWORK => "Mode: network error",
            Self::MANAGEMENT_ERROR_MODE_ERROR => "Mode: error",
            Self::MANAGEMENT_ERROR_MODE_UNKNOWN_ACTION => "Mode: unknown action",

            _ => "Unknown error",
        }
    }
}
