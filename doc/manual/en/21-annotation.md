\newpage

# Annotation

**Natural language description**

Annotate a backup with a comment key.

**Example**

```text
Add the ticket with annotation 'before release' to the latest backup of the primary server
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "annotate",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718183906
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0118"
    },
    "Request": {
        "Action": "add",
        "Backup": "latest",
        "Comment": "before release",
        "Key": "ticket",
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

## Tool: /annotate_backup

**Tool description**

Add, update, or remove a backup annotation.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- `action`: One of `add`, `update`, `remove`.
- `key`: Annotation key.
- `comment`: Required for `add` and `update`; omitted for `remove`.

**Behavior**

- The tool normalizes the action name before execution.
- `add` and `update` fail if `comment` is missing or empty.
- `remove` ignores any comment value.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
annotate_backup {"server":"primary","backup_id":"latest","action":"add","key":"ticket","comment":"before release"}
annotate_backup {"server":"primary","backup_id":"latest","action":"update","key":"ticket","comment":"after validation"}
annotate_backup {"server":"primary","backup_id":"latest","action":"remove","key":"ticket"}
```

