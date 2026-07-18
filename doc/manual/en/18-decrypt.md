\newpage

# Decrypt

**Natural language description**

Decrypt a file on the pgmoneta host.

**Example**

```text
Decrypt /tmp/base.tar.aes on the server
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "decrypt",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182908
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0018"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar.aes"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /decrypt

**Tool description**

Decrypt a file.

**Arguments**

- `file_path`: Path of the file to decrypt on the pgmoneta host.

**Behavior**

- Decryption uses the encryption setup configured on the pgmoneta side.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
decrypt {"file_path":"/tmp/base.tar.aes"}
```

