\newpage

# Retain

**Natural language description**

Protect a backup from retention cleanup.

**Example**

```text
Retain the latest backup for the primary server and include dependent backups
```
Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "retain",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184231
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0116"
    },
    "Request": {
        "Backup": "latest",
        "Cascade": true,
        "Server": "primary"
    },
    "Response": {
        "Backups": [
            20260718183113
        ],
        "Cascade": true,
        "Comments": "ticket|before release",
        "Keep": true,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "Valid": 1
    }
}
```

## Tool: /retain

**Tool description**

Mark a backup as retained (protected).

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `cascade`: Whether dependent backups should also be retained.

**Behavior**

- If `cascade` is omitted, it defaults to `false`.
- `cascade=true` retains dependent backups as well.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
retain {"server":"primary","backup_id":"latest","cascade":false}
retain {"server":"primary","backup_id":"latest","cascade":true}
retain {"server":"primary","backup_id":"latest"}
```

