\newpage

# Delete

**Natural language description**

Delete a backup from pgmoneta.

**Example**

```text
Delete the oldest backup for the primary server
```

Example Output: 
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "delete",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718181152
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0225"
    },
    "Request": {
        "Backup": "oldest",
        "Force": false,
        "Server": "primary"
    },
    "Response": {
        "Backup": 20260718181132,
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}

```

## Tool: /delete

**Tool description**

Delete a backup. `force` defaults to `false`.

**Arguments**

- `server`: The pgmoneta server name.
- `backup_id`: Backup label or one of `newest`, `latest`, `oldest`.
- Optional `force`: Force deletion, default `false`.

**Behavior**

- If `force` is omitted, pgmoneta_mcp sends `false`.
- Use `force` only when you want to override normal deletion safeguards.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
delete {"server":"primary","backup_id":"oldest"}
delete {"server":"primary","backup_id":"oldest","force":true}
```

