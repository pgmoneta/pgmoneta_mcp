\newpage

# Set Mode

**Natural language description**

Switch a pgmoneta server between online and offline mode.

**Example**

```text
Set server primary to offline mode
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "mode",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718185343
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": {
        "Action": "offline",
        "Server": "primary"
    },
    "Response": {
        "MajorVersion": 18,
        "MinorVersion": 1,
        "Online": false,
        "Server": "primary",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /set_mode

**Tool description**

Set server mode.

**Arguments**

- `server`: The pgmoneta server name.
- `action`: Must be `online` or `offline`.

**Behavior**

- This switches the pgmoneta server mode for the named server.
- Invalid action names are rejected by pgmoneta.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
set_mode {"server":"primary","action":"online"}
set_mode {"server":"primary","action":"offline"}
```

