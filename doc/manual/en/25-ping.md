\newpage

# Ping

**Natural language description**

Check pgmoneta server reachability.

**Example**

```text
Check whether pgmoneta is reachable
```

Example Output:

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "ping",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185013
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": "",
    "Response": {
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /ping

**Tool description**

Check server reachability.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- Use this as the simplest health check before backup or restore operations.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
ping {}
```

