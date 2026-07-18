## Reload

**Natural language description**

Reload configuration from server files.

**Example**

```text
Reload pgmoneta configuration files now
```
Example Output:
```

{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "conf reload",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718190236
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0521"
    },
    "Request": {},
    "Response": {
        "Restart": false,
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /conf_reload

**Tool description**

Reload configuration from server files.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Reloads the active pgmoneta configuration without changing tool input.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
conf_reload {}
```

