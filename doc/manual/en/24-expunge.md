\newpage

# Expunge

**Natural language description**

Expunge a backup.

**Example**

```text
Expunge the latest backup on the primary server
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "expunge",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718184752
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0119"
    },
    "Request": {
        "Backup": "latest",
        "Cascade": false,
        "Server": "primary"
    },
    "Response": {
        "Backups": [
            20260718183113
        ],
        "Cascade": false,
        "Comments": "ticket|before release",
        "Keep": false,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0",
        "Valid": 1
    }
}
```

## Tool: /expunge

**Tool description**

Remove retention protection from a backup.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `cascade`: Whether dependent backups should also be expunged.

**Behavior**

- If `cascade` is omitted, it defaults to `false`.
- `cascade=true` applies expunge to dependent backups as well.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
expunge {"server":"primary","backup_id":"latest","cascade":false}
expunge {"server":"primary","backup_id":"latest","cascade":true}
expunge {"server":"primary","backup_id":"latest"}
```

