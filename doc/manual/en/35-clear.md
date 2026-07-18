\newpage

# Clear

**Natural language description**

Reset Prometheus-related statistics.

**Example**

```text
Clear pgmoneta metrics statistics
```
Example Output:
```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "clear prometheus",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718174927
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": {}
}
```

## Tool: /clear

**Tool description**

Clear Prometheus-related statistics.

**Arguments**

- No tool-specific arguments beyond `username`.

**Behavior**

- This tool resets the pgmoneta statistics exposed through the metrics endpoint.
- `username` is required by the MCP API and is typically injected by `pgmoneta-mcp-client`.

**Examples**

```text
clear {}
```

Example Output:

```
{
    "Header": {
        "ClientVersion": "0.21.0",
        "Command": "clear prometheus",
        "Compression": "zstd",
        "Encryption": "aes_256_gcm",
        "Output": 1,
        "Timestamp": 20260718174827
    },
    "Outcome": {
        "Status": true,
        "Time": "00:00:0.0000"
    },
    "Request": {}
}
```

