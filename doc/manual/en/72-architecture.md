\newpage

## Architecture

The pgmoneta MCP server is designed as a secure bridge between MCP clients and the pgmoneta backup server. This document outlines the architectural components and security features.

### Overview

```text
+--------------+          +--------------+          +--------------+
| MCP Client   | -------- | MCP Server   | -------- | pgmoneta     |
| (AI Tools)   |   MCP    | (pgmoneta-   |   TCP    | Server       |
|              |  Protocol|  mcp-server) |   Socket |              |
+--------------+          +--------------+          +--------------+
                                 |
                                 V
                          +--------------+
                          | Configuration|
                          | Files        |
                          +--------------+
```

Browser-based MCP clients (e.g., llama.cpp Web UI) connect over HTTP.
The server uses an axum HTTP router with a CORS layer so that
cross-origin requests from web clients are accepted without a proxy.

### Communication Flow

1. **Authentication Phase**: The MCP server uses SCRAM-SHA-256 to authenticate with the pgmoneta server
2. **Request Phase**: MCP client sends a request via the MCP protocol
3. **Transformation Phase**: The server applies compression and/or encryption to the request
4. **Transmission Phase**: Secure transmission over TCP to pgmoneta
5. **Response Phase**: Reverse transformation of the response

### Security Layer

The security module provides the following capabilities:

#### Compression Algorithms

| Algorithm | Identifier | Description |
|-----------|------------|-------------|
| None | 0 | No compression |
| Gzip | 1 | DEFLATE compression |
| **Zstd** | **2** | **Facebook Zstandard (default)** |
| LZ4 | 3 | Fast compression |
| Bzip2 | 4 | High compression ratio |

**Default**: `zstd` - provides excellent compression ratios with fast decompression

#### Encryption Algorithms

| Algorithm | Identifier | Description |
|-----------|------------|-------------|
| None | 0 | No encryption |
| **AES-256-GCM** | **1** | **256-bit AES in GCM mode (default)** |
| AES-192-GCM | 2 | 192-bit AES in GCM mode |
| AES-128-GCM | 3 | 128-bit AES in GCM mode |

**Default**: `aes_256_gcm` - industry standard authenticated encryption with PBKDF2 key derivation

### Configuration

Security settings are configured in the `[pgmoneta]` section of the configuration file:

```ini
[pgmoneta]
host = localhost
port = 5001
compression = zstd
encryption = aes_256_gcm
```

### Data Protection

1. **Key Management**: Master key is stored in `~/.pgmoneta/mcp-master.key` with 0600 permissions
2. **Key Derivation**: PBKDF2-HMAC-SHA256 with 600,000 iterations
3. **Password Storage**: Admin passwords are encrypted using AES-256-GCM
4. **Transport Security**: Full encryption of all communication payloads

### Request/Response Format

Each request includes a header specifying compression and encryption modes:

```json
{
  "Header": {
    "Command": 0,
    "ClientVersion": "0.2.0",
    "Output": 0,
    "Timestamp": "20260315120000",
    "Compression": 2,
    "Encryption": 1
  },
  "Request": { ... }
}
```

The payload is transformed as follows:
1. Serialize to JSON
2. Apply compression if enabled
3. Apply encryption if enabled
4. Base64 encode
5. Send with compression/encryption flags prepended
