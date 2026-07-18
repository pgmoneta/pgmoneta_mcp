\newpage

# Backup

**Natural language description**

Take a backup of a pgmoneta server.

**Example**

```text
Take a full backup of the primary server
```

Example Output:

```
primary (pgmoneta 0.22.0 w/ PostgreSQL 18.1)
• 20260718173237 | Full, Backup: 12.44 MB, Restore: 12.43 MB, Valid
```

## Tool: /backup

**Tool description**

Create a full or incremental backup.

**Arguments**

- `server`: The pgmoneta server name.
- Optional `backup_id`: Base backup label for incremental backup.

**Behavior**

- Without `backup_id`, the tool creates a full backup.
- With `backup_id`, the tool creates an incremental backup based on that backup.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
backup {"server":"primary"}
backup {"server":"primary","backup_id":"latest"}
backup {"server":"primary","backup_id":"20260706113507"}
```

