\newpage

# Status

**Natural language description**

Get the current pgmoneta status.

**Example**

```text
Show detailed status for pgmoneta
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "status details",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185112
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0114"
    },
    "Request": {},
    "Response": {
        "FreeSpace": "15.63 GB",
        "NumberOfServers": 1,
        "PgmonetaFips": false,
        "ServerVersion": "0.22.0",
        "Servers": [
            {
                "ActiveArchive": false,
                "ActiveBackup": false,
                "ActiveDelete": false,
                "ActiveRestore": false,
                "ActiveRetention": false,
                "Backups": [
                    {
                        "Backup": 20260718183113,
                        "BackupSize": 13045760,
                        "BiggestFileSize": 5959680,
                        "Comments": "ticket|before release",
                        "Compression": 18,
                        "Delta": 0,
                        "Encryption": 1,
                        "Keep": false,
                        "RestoreSize": 13037568,
                        "Valid": 1,
                        "WAL": 33554432
                    }
                ],
                "Checksums": true,
                "Fips": false,
                "HotStandbySize": 0,
                "NumberOfBackups": 1,
                "Online": true,
                "Primary": true,
                "RetentionDays": 7,
                "RetentionMonths": -1,
                "RetentionWeeks": -1,
                "RetentionYears": -1,
                "Server": "primary",
                "ServerSize": 30121984,
                "Workers": 0,
                "WorkspaceFreeSpace": 0
            }
        ],
        "TotalSpace": "179.01 GB",
        "UsedSpace": "28.73 MB",
        "Workers": 0
    }
}
```

## Tool: /status

**Tool description**

Get status in compact or detailed view.

**Arguments**

- `in_details`: `false` for summary output, `true` for detailed output.

**Behavior**

- Summary mode returns high-level information such as version and storage totals.
- Detailed mode adds operational data such as backup sizes, WAL, retention, hot standby size, and workers.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
status {"in_details":false}
status {"in_details":true}
```

