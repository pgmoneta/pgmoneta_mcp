\newpage

# Verify

**Natural language description**

Verify the integrity of a backup.

**Example**

```text
Verify the latest backup for the primary server
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "verify",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718175831
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:4.7336"
    },
    "Request": {
        "Backup": "latest",
        "Directory": "/tmp",
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718173645,
        "Files": {
            "All": {},
            "Failed": {}
        },
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /verify

**Tool description**

Verify backup integrity, with optional output directory.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `directory`: Verification target directory, default `/tmp`.

**Behavior**

- If `directory` is omitted, pgmoneta_mcp uses `/tmp`.
- Use an explicit directory when verification artifacts should be kept in a controlled location.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
verify {"server":"primary","backup_id":"latest"}
verify {"server":"primary","backup_id":"latest","directory":"/tmp/verify"}
```

