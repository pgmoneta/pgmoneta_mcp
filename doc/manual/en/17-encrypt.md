\newpage

# Encrypt

**Natural language description**

Encrypt a file on the pgmoneta host.

**Example**

```text
Encrypt /tmp/base.tar on the server
```
Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "encrypt",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182743
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0021"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar.aes",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /encrypt

**Tool description**

Encrypt a file.

**Arguments**

- `file_path`: Path of the file to encrypt on the pgmoneta host.

**Behavior**

- Encryption uses the configured pgmoneta encryption settings.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
encrypt {"file_path":"/tmp/base.tar"}
```

