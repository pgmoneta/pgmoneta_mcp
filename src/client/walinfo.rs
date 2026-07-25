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
use crate::configuration::CONFIG;
use chrono::{Duration, NaiveTime};
use serde_json::Value;

impl PgmonetaClient {
    /// Runs pgmoneta-walinfo for the WAL directory of the given server and returns either a human-readable timeline ("user" mode, default) or raw JSON ("developer" mode).  An optional time filter narrows results to records within `window_minutes` minutes of the requested time.
    pub async fn request_walinfo(
        _username: &str,
        server: &str,
        mode: Option<String>,
        time: Option<String>,
        window_minutes: Option<u32>,
    ) -> anyhow::Result<String> {
        let config = CONFIG.get().expect("Configuration should be initialized");
        let base_dir = &config.pgmoneta.base_dir;

        // WAL files are stored under <base_dir>/<server>/wal/
        let wal_dir = format!("{}/{}/wal", base_dir, server);

        // Pre-flight: verify the WAL directory exists before spawning the tool.
        if !std::path::Path::new(&wal_dir).exists() {
            return Err(anyhow::anyhow!(
                "WAL directory '{}' does not exist for server '{}'.\n\
                Possible causes:\n\
                  - No backups have been taken yet for this server\n\
                  - The server name '{}' is incorrect\n\
                  - 'base_dir' is set incorrectly in the configuration (current value: '{}')",
                wal_dir,
                server,
                server,
                base_dir
            ));
        }

        let all_records = collect_wal_records(&wal_dir, server).await?;

        // Parse optional time filter.
        let time_filter = time.as_deref().map(parse_time_filter).transpose()?;
        let window = window_minutes.unwrap_or(5);

        let filtered: Vec<&Value> = match time_filter {
            Some(target) => filter_records_by_time(&all_records, target, window),
            None => all_records.iter().collect(),
        };

        let is_developer = mode
            .as_deref()
            .map(|m| m.eq_ignore_ascii_case("developer"))
            .unwrap_or(false);

        if is_developer {
            // Developer mode: filtered records as a wrapped JSON blob.
            let response = serde_json::json!({
                "Outcome": { "Status": true, "Command": "walinfo" },
                "Response": {
                    "WAL": filtered.to_vec()
                }
            });
            Ok(response.to_string())
        } else {
            // User mode: readable transaction timeline.
            Ok(format_user_mode(
                &filtered,
                server,
                &wal_dir,
                time.as_deref(),
                window,
            ))
        }
    }
}

// pgmoneta-walinfo execution

/// Collects WAL records by running pgmoneta-walinfo on each segment file && Falls back to directory-level invocation when per-file processing yields nothing or cannot process a segment.
async fn collect_wal_records(wal_dir: &str, server: &str) -> anyhow::Result<Vec<Value>> {
    match collect_wal_records_per_file(wal_dir).await? {
        Some(records) if !records.is_empty() => Ok(records),
        Some(_) | None => collect_wal_records_from_directory(wal_dir, server).await,
    }
}

/// Returns `None` when a segment cannot be processed, so callers do not use a partial record set.
async fn collect_wal_records_per_file(wal_dir: &str) -> anyhow::Result<Option<Vec<Value>>> {
    let mut entries = tokio::fs::read_dir(wal_dir)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read WAL directory '{}': {}", wal_dir, e))?;

    let mut wal_files = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_file() {
            wal_files.push(path);
        }
    }
    wal_files.sort();

    let mut records = Vec::new();
    for path in wal_files {
        let Some(path_str) = path.to_str() else {
            continue;
        };
        let output = tokio::process::Command::new("pgmoneta-walinfo")
            .args([path_str, "--format", "json"])
            .output()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to execute pgmoneta-walinfo: {}", e))?;

        if !output.status.success() {
            tracing::warn!(
                "pgmoneta-walinfo exited with {} for WAL segment '{}'; falling back to directory mode: {}",
                output.status,
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim(),
            );
            return Ok(None);
        }

        if !output.stdout.is_empty() {
            records.extend(parse_walinfo_stdout(&String::from_utf8_lossy(
                &output.stdout,
            )));
        }
    }

    Ok(Some(records))
}

async fn collect_wal_records_from_directory(
    wal_dir: &str,
    server: &str,
) -> anyhow::Result<Vec<Value>> {
    // Directory mode can emit one JSON object per segment concatenated together.
    let output = tokio::process::Command::new("pgmoneta-walinfo")
        .args([wal_dir, "--format", "json"])
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to execute pgmoneta-walinfo: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let records = parse_walinfo_stdout(&stdout);

    if records.is_empty() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!(
            "pgmoneta-walinfo produced no WAL records for server '{}' (WAL dir: {}).\n\
            exit code: {}\nstderr: {}\nstdout: {}",
            server,
            wal_dir,
            output.status,
            stderr,
            stdout
        ));
    }

    if !output.status.success() {
        tracing::warn!(
            "pgmoneta-walinfo exited with {} for server '{}' but {} records were parsed",
            output.status,
            server,
            records.len()
        );
    }

    Ok(records)
}

/// Parses pgmoneta-walinfo stdout, including multiple concatenated JSON objects.
fn parse_walinfo_stdout(stdout: &str) -> Vec<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    if let Ok(json) = serde_json::from_str::<Value>(trimmed) {
        return extract_records(&json);
    }

    let mut records = Vec::new();
    let bytes = trimmed.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'{' {
            i += 1;
            continue;
        }

        let start = i;
        let mut depth = 0;
        let mut end = None;
        for (j, byte) in bytes.iter().enumerate().skip(i) {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(j);
                        break;
                    }
                }
                _ => {}
            }
        }

        let Some(end) = end else {
            break;
        };

        if let Ok(json) = serde_json::from_str::<Value>(&trimmed[start..=end]) {
            records.extend(extract_records(&json));
        }

        i = end + 1;
    }

    records
}

// Record extraction

fn extract_records(wal_json: &Value) -> Vec<Value> {
    wal_json
        .get("WAL")
        .and_then(|v| v.as_array())
        .map(|arr| arr.to_vec())
        .unwrap_or_default()
}

// Time parsing

/// Parses a natural-language time string into a `NaiveTime`. Accepted formats: "4:02pm", "4pm", "16:02", "13:24:57", "4:02:30pm".
pub fn parse_time_filter(time_str: &str) -> anyhow::Result<NaiveTime> {
    let s = time_str.trim();

    // Normalise am/pm suffix to uppercase so chrono's %p matches.
    let normalised =
        if s.to_ascii_lowercase().ends_with("am") || s.to_ascii_lowercase().ends_with("pm") {
            let body = &s[..s.len() - 2];
            let suffix = &s[s.len() - 2..];
            format!("{}{}", body.trim(), suffix.to_uppercase())
        } else {
            s.to_string()
        };

    // 24-hour formats (try first — no ambiguity).
    for fmt in &["%H:%M:%S", "%H:%M"] {
        if let Ok(t) = NaiveTime::parse_from_str(&normalised, fmt) {
            return Ok(t);
        }
    }

    // 12-hour formats.
    for fmt in &["%I:%M:%S%p", "%I:%M%p", "%I%p"] {
        if let Ok(t) = NaiveTime::parse_from_str(&normalised, fmt) {
            return Ok(t);
        }
    }

    Err(anyhow::anyhow!(
        "Could not parse time '{}'. Supported formats: \"4:02pm\", \"4pm\", \"16:02\", \"13:24:57\"",
        time_str
    ))
}

/// Returns the timestamp string for a WAL record, if present && pgmoneta-walinfo stores commit timestamps in `Data` for Transaction records.
fn record_timestamp(rec: &Value) -> Option<&str> {
    rec.get("Timestamp").and_then(|v| v.as_str()).or_else(|| {
        rec.get("Data")
            .and_then(|v| v.as_str())
            .filter(|data| data.starts_with("20") && data.len() >= 19)
    })
}

/// Parses the timestamp string embedded in a WAL record (e.g. `"2026-06-26 13:24:57.671196 EEST"`) and returns just the time part.
fn parse_record_time(ts: &str) -> Option<NaiveTime> {
    // Field 1 (0-indexed) is the time portion.
    let time_part = ts.split_whitespace().nth(1)?;
    NaiveTime::parse_from_str(time_part, "%H:%M:%S%.f")
        .or_else(|_| NaiveTime::parse_from_str(time_part, "%H:%M:%S"))
        .ok()
}

// Time filtering

fn filter_records_by_time(
    records: &[Value],
    target: NaiveTime,
    window_minutes: u32,
) -> Vec<&Value> {
    let half = Duration::minutes(window_minutes as i64);

    let lo = target.overflowing_sub_signed(half).0;
    let hi = target.overflowing_add_signed(half).0;

    let matching_xids = records
        .iter()
        .filter_map(|rec| {
            let record = rec.get("Record")?;
            let xid = record.get("Xid").and_then(Value::as_u64)?;

            if xid != 0
                && record_timestamp(record)
                    .and_then(parse_record_time)
                    .is_some_and(|time| time_in_window(time, lo, hi))
            {
                Some(xid)
            } else {
                None
            }
        })
        .collect::<std::collections::HashSet<_>>();

    records
        .iter()
        .filter(|rec| {
            rec.get("Record")
                .and_then(|record| record.get("Xid"))
                .and_then(Value::as_u64)
                .is_some_and(|xid| matching_xids.contains(&xid))
        })
        .collect()
}

/// Returns true when `t` falls within [lo, hi], handling midnight wrap-around.
fn time_in_window(t: NaiveTime, lo: NaiveTime, hi: NaiveTime) -> bool {
    if lo <= hi {
        t >= lo && t <= hi
    } else {
        // Window wraps midnight.
        t >= lo || t <= hi
    }
}

// User-mode formatter

/// Renders WAL records as a human-readable transaction timeline.
fn format_user_mode(
    records: &[&Value],
    server: &str,
    wal_dir: &str,
    time_filter: Option<&str>,
    window_minutes: u32,
) -> String {
    // Collect per-transaction groups (preserve insertion order via Vec)
    let mut txn_order: Vec<u64> = Vec::new();
    // (xid → (first_ts, ops, commit_ts))
    type Transaction = (Option<String>, Vec<String>, Option<String>);
    let mut txns: std::collections::HashMap<u64, Transaction> = std::collections::HashMap::new();

    let mut system_count = 0usize;
    let mut first_ts: Option<&str> = None;
    let mut last_ts: Option<&str> = None;

    for rec_wrap in records {
        let rec = match rec_wrap.get("Record") {
            Some(r) => r,
            None => continue,
        };

        let xid = rec.get("Xid").and_then(|v| v.as_u64()).unwrap_or(0);
        let ts = record_timestamp(rec);
        let rm = rec
            .get("ResourceManager")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let data = rec.get("Data").and_then(|v| v.as_str());
        let desc = rec.get("Description").and_then(|v| v.as_str());
        let info = rec.get("Info").and_then(|v| v.as_u64()).unwrap_or(0);

        // Track overall time range for the header.
        if let Some(t) = ts {
            if first_ts.is_none() {
                first_ts = Some(t);
            }
            last_ts = Some(t);
        }

        // Xid 0 = internal/system record (checkpoint, standby, etc.)
        if xid == 0 {
            system_count += 1;
            continue;
        }

        let entry = txns.entry(xid).or_insert_with(|| {
            txn_order.push(xid);
            (ts.map(String::from), Vec::new(), None)
        });

        // Detect COMMIT (Transaction RM, Info & 0xF0 == 0 or data is a timestamp string).
        let is_commit = rm == "Transaction"
            && (info & 0xF0 == 0 || info == 128)
            && data.is_some_and(|d| d.starts_with("20") || d.contains("inval msgs"));

        if is_commit {
            entry.2 = ts.map(String::from);
        } else {
            let op = describe_op(rm, info, data, desc);
            entry.1.push(op);
        }
    }

    // Build output
    let mut out = String::with_capacity(2048);

    // Header
    out.push_str(&format!("WAL Activity — server: {}\n", server));
    out.push_str(&format!("Directory : {}\n", wal_dir));
    if let Some(tf) = time_filter {
        out.push_str(&format!(
            "Filter    : ±{} min around {}\n",
            window_minutes, tf
        ));
    }
    if first_ts.is_some() || last_ts.is_some() {
        let f = first_ts
            .and_then(|t| t.split_whitespace().nth(1))
            .unwrap_or("?");
        let l = last_ts
            .and_then(|t| t.split_whitespace().nth(1))
            .unwrap_or("?");
        out.push_str(&format!("Period    : {} → {}\n", f, l));
    }
    out.push_str(&format!(
        "Records   : {} transactions, {} system records\n",
        txn_order.len(),
        system_count
    ));
    out.push_str(&"═".repeat(62));
    out.push('\n');

    if txn_order.is_empty() {
        if time_filter.is_some() {
            out.push_str("\n  No transactions found in this time window.\n");
        } else {
            out.push_str("\n  No user transactions found in WAL.\n");
        }
    }

    // Transactions
    let mut committed = 0usize;
    let mut open = 0usize;

    for xid in &txn_order {
        let (first_ts_opt, ops, commit_ts_opt) = &txns[xid];

        let time_label = first_ts_opt
            .as_deref()
            .and_then(|t| t.split_whitespace().nth(1))
            .unwrap_or("?");

        let status = if commit_ts_opt.is_some() {
            committed += 1;
            "COMMIT"
        } else {
            open += 1;
            "OPEN  "
        };

        out.push_str(&format!(
            "\n  {}  Xid {:>8}  [{}]  {} operation{}\n",
            time_label,
            xid,
            status,
            ops.len(),
            if ops.len() == 1 { "" } else { "s" }
        ));

        for op in ops {
            out.push_str(&format!("            {}\n", op));
        }
        if let Some(cts) = commit_ts_opt {
            let ct = cts.split_whitespace().nth(1).unwrap_or(cts);
            out.push_str(&format!("            COMMIT  {}\n", ct));
        }
    }

    // Footer
    out.push('\n');
    out.push_str(&"─".repeat(62));
    out.push('\n');
    out.push_str(&format!(
        "  {} committed  |  {} open  |  {} system records skipped\n",
        committed, open, system_count
    ));

    out
}

/// Returns a short, readable description of a single WAL record.
fn describe_op(rm: &str, info: u64, data: Option<&str>, desc: Option<&str>) -> String {
    // The upper nibble of xl_info encodes the sub-operation type.
    let subtype = info & 0xF0;

    // Extract the relation from the Description field (e.g. "rel 1663/16486/1247 forknum 0 blk 14")
    let rel = desc
        .and_then(|d| {
            let after = d.strip_prefix("blkref #0: rel ")?;
            Some(after.split_whitespace().next().unwrap_or("?").to_string())
        })
        .unwrap_or_else(|| "?".to_string());

    // Extract block number
    let blk = desc.and_then(|d| {
        let i = d.find(" blk ")?;
        d[i + 5..]
            .split_whitespace()
            .next()
            .map(|s| s.trim_matches(|c: char| !c.is_ascii_digit()).to_string())
    });

    // Extract offset from data ("off 116 flags …")
    let off = data.and_then(|d| {
        if let Some(stripped) = d.strip_prefix("off ") {
            stripped.split_whitespace().next().map(String::from)
        } else {
            None
        }
    });

    let loc = match (blk, off) {
        (Some(b), Some(o)) => format!(" rel {} blk {} off {}", rel, b, o),
        (Some(b), None) => format!(" rel {} blk {}", rel, b),
        _ => {
            if rel != "?" {
                format!(" rel {}", rel)
            } else {
                String::new()
            }
        }
    };

    let keys_updated = data.map(|d| d.contains("KEYS_UPDATED")).unwrap_or(false);
    let ku_tag = if keys_updated { " [KEYS_UPDATED]" } else { "" };

    match rm {
        "Heap" => {
            let op = match subtype {
                0x00 => "INSERT",
                0x10 => "DELETE",
                0x20 | 0x40 => "UPDATE",
                0x70 | 0x80 => "INPLACE",
                _ => "HEAP",
            };
            format!("{:<10}{}{}", op, loc, ku_tag)
        }
        "Heap2" => {
            let n = data
                .and_then(|d| d.split_whitespace().next())
                .unwrap_or("?");
            match subtype {
                0x10 => format!("{:<10}{}", "VACUUM", loc),
                0x40 | 0x50 => format!("{:<10}{} ({} tuples)", "MULTI_INS", loc, n),
                0x70 | 0xD0 => format!("{:<10}{}", "PRUNE", loc),
                _ => format!("{:<10}{}", "HEAP2", loc),
            }
        }
        "Btree" => format!("{:<10}{}", "IDX_UPD", loc),
        "Hash" => format!("{:<10}{}", "HASH_UPD", loc),
        "Storage" => format!("{:<10}{}", "CREATE", data.unwrap_or("?")),
        "Standby" => {
            // "xid 297179 db 16486 rel 756091872"
            let rel_id = data
                .and_then(|d| d.split("rel ").nth(1))
                .and_then(|s| s.split_whitespace().next())
                .unwrap_or("?");
            format!("{:<10}rel {}", "LOCK", rel_id)
        }
        "XLOG" => format!("{:<10}{}", "XLOG", data.unwrap_or("")),
        _ => format!("{:<10}{}", rm, data.unwrap_or("")),
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_parse_time_24h_hms() {
        let t = parse_time_filter("13:24:57").unwrap();
        assert_eq!(t.hour(), 13);
        assert_eq!(t.minute(), 24);
        assert_eq!(t.second(), 57);
    }

    #[test]
    fn test_parse_time_24h_hm() {
        let t = parse_time_filter("16:02").unwrap();
        assert_eq!(t.hour(), 16);
        assert_eq!(t.minute(), 2);
    }

    #[test]
    fn test_parse_time_12h_pm() {
        let t = parse_time_filter("4:02pm").unwrap();
        assert_eq!(t.hour(), 16);
        assert_eq!(t.minute(), 2);
    }

    #[test]
    fn test_parse_time_12h_am() {
        let t = parse_time_filter("9:30am").unwrap();
        assert_eq!(t.hour(), 9);
        assert_eq!(t.minute(), 30);
    }

    #[test]
    fn test_parse_time_hour_only() {
        let t = parse_time_filter("4:00pm").unwrap();
        assert_eq!(t.hour(), 16);
        assert_eq!(t.minute(), 0);
    }

    #[test]
    fn test_parse_time_invalid() {
        assert!(parse_time_filter("not-a-time").is_err());
    }

    #[test]
    fn test_parse_time_uppercase_pm() {
        let t = parse_time_filter("4:02PM").unwrap();
        assert_eq!(t.hour(), 16);
        assert_eq!(t.minute(), 2);
    }

    #[test]
    fn test_time_in_window_simple() {
        let lo = NaiveTime::from_hms_opt(16, 0, 0).unwrap();
        let hi = NaiveTime::from_hms_opt(16, 10, 0).unwrap();
        assert!(time_in_window(
            NaiveTime::from_hms_opt(16, 5, 0).unwrap(),
            lo,
            hi
        ));
        assert!(!time_in_window(
            NaiveTime::from_hms_opt(15, 59, 0).unwrap(),
            lo,
            hi
        ));
    }

    #[test]
    fn test_time_in_window_midnight_wrap() {
        let lo = NaiveTime::from_hms_opt(23, 58, 0).unwrap();
        let hi = NaiveTime::from_hms_opt(0, 2, 0).unwrap();
        assert!(time_in_window(
            NaiveTime::from_hms_opt(23, 59, 0).unwrap(),
            lo,
            hi
        ));
        assert!(time_in_window(
            NaiveTime::from_hms_opt(0, 1, 0).unwrap(),
            lo,
            hi
        ));
        assert!(!time_in_window(
            NaiveTime::from_hms_opt(12, 0, 0).unwrap(),
            lo,
            hi
        ));
    }

    #[test]
    fn test_filter_records_by_time_keeps_matching() {
        let records = vec![
            serde_json::json!({"Record": {"Xid": 1, "ResourceManager": "Heap", "Data": "off 1"}}),
            serde_json::json!({"Record": {"Timestamp": "2026-06-26 13:24:57.671 EEST", "Xid": 1}}),
            serde_json::json!({"Record": {"Timestamp": "2026-06-26 16:00:00.000 EEST", "Xid": 2}}),
        ];
        let target = parse_time_filter("1:24pm").unwrap(); // 13:24
        let filtered = filter_records_by_time(&records, target, 5);
        assert_eq!(filtered.len(), 2);
        assert_eq!(filtered[0]["Record"]["Xid"], 1);
        assert_eq!(filtered[1]["Record"]["Xid"], 1);
    }

    #[test]
    fn test_filter_records_excludes_no_timestamp() {
        let records = vec![
            serde_json::json!({"Record": {"Xid": 0}}), // no Timestamp
            serde_json::json!({"Record": {"Timestamp": "2026-06-26 13:25:00.000 EEST", "Xid": 1}}),
        ];
        let target = parse_time_filter("13:25").unwrap();
        let filtered = filter_records_by_time(&records, target, 5);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_parse_walinfo_stdout_concatenated_json() {
        let stdout = r#"{ "WAL": [
{"Record": {"Xid": 1, "Data": "2026-06-08 21:07:13.425730 EEST"}}
]}{ "WAL": [
{"Record": {"Xid": 2, "Data": "2026-06-26 13:24:57.671196 EEST"}}
]}"#;
        let records = parse_walinfo_stdout(stdout);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0]["Record"]["Xid"], 1);
        assert_eq!(records[1]["Record"]["Xid"], 2);
    }

    #[test]
    fn test_record_timestamp_from_data_field() {
        let rec = serde_json::json!({
            "Data": "2026-06-26 13:24:57.671196 EEST",
            "ResourceManager": "Transaction"
        });
        assert_eq!(
            record_timestamp(&rec),
            Some("2026-06-26 13:24:57.671196 EEST")
        );
    }

    #[test]
    fn test_filter_records_by_time_uses_data_timestamp() {
        let records = vec![serde_json::json!({
            "Record": {
                "Xid": 297179,
                "Data": "2026-06-26 13:24:57.671196 EEST",
                "ResourceManager": "Transaction"
            }
        })];
        let target = parse_time_filter("1:24pm").unwrap();
        let filtered = filter_records_by_time(&records, target, 5);
        assert_eq!(filtered.len(), 1);
    }
}
