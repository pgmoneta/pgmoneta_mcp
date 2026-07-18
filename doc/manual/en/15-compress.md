\newpage

# Compress

**Natural language description**

Compress a file using the configured pgmoneta algorithm.

**Example**

```text
Compress /tmp/base.tar on the server
```
Example Output:

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "compress",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718182311
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0005"
    },
    "Request": {
        "SourceFile": "/tmp/base.tar"
    },
    "Response": {
        "DestinationFile": "/tmp/base.tar.zstd",
        "ServerVersion": "0.22.0"
    }
}
```

## Tool: /compress

**Tool description**

Compress a file using configured compression.

**Arguments**

- `file_path`: Path of the file to compress on the pgmoneta host.

**Behavior**

- The compression algorithm comes from the server-side pgmoneta configuration.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
compress {"file_path":"/tmp/base.tar"}
```

