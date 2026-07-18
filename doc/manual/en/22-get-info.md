\newpage

# Get Info

**Natural language description**

Retrieve detailed metadata for a backup.

**Example**

```text
Get detailed information about the latest backup for the primary server
```
Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "info",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184036
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0068"
    },
    "Request": {
        "Backup": "latest",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718183113,
        "BackupSize": "12.44 MB",
        "BiggestFileSize": "5.68 MB",
        "CheckpointHiLSN": "0x3",
        "CheckpointLoLSN": "0x50000080",
        "Comments": "ticket|before release",
        "Compression": "zstd",
        "Elapsed": 0.0,
        "Encryption": "aes_256_gcm",
        "EndHiLSN": "0x3",
        "EndLoLSN": "0x50000120",
        "EndTimeline": 1,
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "NumberOfTablespaces": 0,
        "RestoreSize": "12.43 MB",
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "StartHiLSN": "0x3",
        "StartLoLSN": "0x50000028",
        "StartTimeline": 1,
        "Tablespaces": {},
        "Valid": 1,
        "WAL": "000000010000000300000050"
    }
}
```

## Tool: /get_info

**Tool description**

Retrieve detailed backup metadata.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.

**Behavior**

- Returns translated fields such as human-readable sizes and decoded compression and encryption names.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
get_info {"server":"primary","backup_id":"latest"}
get_info {"server":"primary","backup_id":"oldest"}
get_info {"server":"primary","backup_id":"20260706113507"}
```

