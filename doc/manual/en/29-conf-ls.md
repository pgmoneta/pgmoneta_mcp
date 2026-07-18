\newpage

# Conf

## List

**Natural language description**

List available runtime configuration entries.

**Example**

```text
List available pgmoneta configuration entries
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "conf ls",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185510
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0001"
    },
    "Request": {},
    "Response": {
        "ServerVersion": "0.22.0",
        "admin_configuration_path": "pgmoneta_users.conf",
        "main_configuration_path": "pgmoneta.conf",
        "users_configuration_path": "pgmoneta_users.conf"
    }
}
```

## Tool: /conf_ls

**Tool description**

List available configuration entries.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Use this when you want an overview of configuration entries before calling `conf_get` or `conf_set`.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_ls {}
```

