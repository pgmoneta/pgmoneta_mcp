\newpage

# Archive

**Natural language description**

Archive a backup to a directory.

**Example**

```text
Archive the latest backup for the primary server into /tmp/archive
```
Example Output:
```         
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "archive",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718183231
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:5.1568"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp/archive",
        "Position": "current",
        "Server": "primary"
    },
    "Response": {
        "Backup": "",
        "FileName": "/tmp/archive/archive-primary-20260718183113.tar.zstd.aes",
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /archive

**Tool description**

Archive a backup to a directory. Position defaults to `current` when not provided.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- `directory`: Target archive directory.
- Optional position controls: `current`, `name`, `xid`, `time`, `lsn`, `inclusive`, `timeline`, `action`, `primary`, `replica`.

**Behavior**

- If no position controls are supplied, pgmoneta_mcp uses `current`.
- `action` controls what happens after archive processing, for example `pause`.
- `primary` and `replica` describe the target role.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","name":"recovery-label"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","xid":"734560"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","time":"2026-07-06 11:30:00"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","lsn":"0/5000000"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","timeline":"2","inclusive":"true","action":"pause"}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","primary":true}
archive {"server":"primary","backup_id":"latest","directory":"/tmp/archive","replica":true}
```

