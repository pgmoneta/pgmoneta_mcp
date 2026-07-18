\newpage

# List Backups

**Natural language description**

Show the backups available for a server.

**Example**

```text
List the backups for the primary server in descending order
```

Example Output:

```
primary (pgmoneta 0.22.0 w/ PostgreSQL 18.1)
• 20260718173645 | Full, Backup: 12.44 MB, Restore: 12.43 MB, Valid
• 20260718173502 | Full, Backup: 0 B, Restore: 12.43 MB, Valid
• 20260718173237 | Full, Backup: 12.44 MB, Restore: 12.43 MB, Valid
```

## Tool: /list_backups

**Tool description**

List backups with sort control. Default sort is ascending.

**Arguments**

- `server`: The pgmoneta server name.
- Optional `sort`: `asc` or `desc`.

**Behavior**

- If `sort` is omitted, empty, or effectively null, pgmoneta_mcp uses `asc`.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
list_backups {"server":"primary"}
list_backups {"server":"primary","sort":"asc"}
list_backups {"server":"primary","sort":"desc"}
```

