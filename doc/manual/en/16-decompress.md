\newpage

# Decompress

**Natural language description**

Decompress a file on the pgmoneta host.

**Example**

```text
Decompress /tmp/base.tar.zstd on the server
```

Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "decompress",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182652
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0005"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar.zstd"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar",
        "ServerVersion": "0.22.0"
    }
}

```

## Tool: /decompress

**Tool description**

Decompress a file.

**Arguments**

- `file_path`: Path of the file to decompress on the pgmoneta host.

**Behavior**

- The decompression method follows the file and configured server behavior.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
decompress {"file_path":"/tmp/base.tar.zstd"}
```

