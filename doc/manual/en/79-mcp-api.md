\newpage

## MCP API

### Overview

**pgmoneta_mcp** implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to enable AI assistants and language models to interact with pgmoneta backup servers. The MCP server exposes pgmoneta's backup management capabilities through a standardized interface that can be consumed by MCP clients.

The MCP implementation is built on top of the [rmcp](https://docs.rs/rmcp/latest/rmcp/) Rust library and provides:

- **Tool-based interface**: Exposes pgmoneta operations as MCP tools
- **SCRAM-SHA-256 authentication**: Secure authentication with pgmoneta server
- **JSON-based communication**: Structured request/response format
- **Automatic data translation**: Converts raw pgmoneta responses into human-readable formats

### Architecture

The MCP server architecture consists of several key components:

``` text
+-----------------+
|   MCP Client    | (Claude, ChatGPT, etc.)
|  (AI Assistant) |
+--------+--------+
         | MCP Protocol
         | (JSON-RPC)
         v
+-----------------+
| PgmonetaHandler | <--- Handles MCP requests
|   (handler.rs)  |      Routes to appropriate tools
+--------+--------+
         |
         v
+-----------------+
| PgmonetaClient  | <--- Manages communication
|   (client.rs)   |      with pgmoneta server
+--------+--------+
         | TCP + SCRAM-SHA-256
         |
         v
+-----------------+
| pgmoneta server | <--- Backup/restore operations
+-----------------+
```

### Core Components

#### PgmonetaHandler

**Location**: `src/handler.rs`

The `PgmonetaHandler` is the main entry point for MCP requests. It implements the `ServerHandler` trait from rmcp and routes incoming tool calls to the appropriate internal methods.

**Key responsibilities**:
- Implements MCP server initialization and handshake
- Defines available MCP tools using the `#[tool]` macro
- Parses and validates pgmoneta server responses
- Translates raw numeric values into human-readable formats
- Returns standardized `CallToolResult` responses

**Example tool definition**:
```rust
#[tool(
    description = "Get information of a backup using given backup ID and server name"
)]
async fn get_backup_info(
    &self,
    Parameters(args): Parameters<InfoRequest>,
) -> Result<CallToolResult, McpError> {
    let result = self._get_backup_info(args).await?;
    Self::_generate_call_tool_result(&result)
}
```

#### PgmonetaClient

**Location**: `src/client.rs`

The `PgmonetaClient` handles low-level TCP communication with the pgmoneta server. It manages the request/response lifecycle including authentication, payload serialization, and response parsing.

**Key responsibilities**:
- Builds request headers with metadata (command, timestamp, format, etc.)
- Establishes authenticated TCP connections using SCRAM-SHA-256
- Serializes requests to JSON and writes to TCP stream
- Reads and deserializes responses from TCP stream
- Manages connection lifecycle

**Request structure**:
```rust
struct PgmonetaRequest<R> {
    header: RequestHeader,  // Metadata
    request: R,             // Tool-specific payload
}

struct RequestHeader {
    command: u32,           // Command code (e.g., Command::INFO)
    client_version: String, // MCP client version
    output_format: u8,      // Response format (JSON)
    timestamp: String,      // Request timestamp
    compression: u8,        // Compression type (NONE)
    encryption: u8,         // Encryption type (NONE)
}
```

### Available MCP Tools

#### get_backup_info

**Description**: Retrieves detailed information about a specific backup.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")

**Returns**: Comprehensive backup information including:
- Backup label and timestamp
- Backup size and restore size
- Compression and encryption settings
- LSN (Log Sequence Number) information
- WAL file details
- Checkpoint information
- Server configuration

**Example**:
```json
{
  "tool": "get_backup_info",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest"
  }
}
```

**Response structure**:
```json
{
  "Outcome": "Success",
  "BackupInfo": {
    "Server": "primary",
    "Label": "20260304123045",
    "BackupSize": "1.2 GB",
    "RestoreSize": "1.5 GB",
    "Compression": "zstd",
    "Encryption": "aes_256_gcm",
    "StartHiLSN": "0x1A2B3C4D",
    "StartLoLSN": "0x5E6F7890",
    ...
  }
}
```

#### list_backups

**Description**: Lists all available backups for a specified server.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `sort_order` (string, optional): Sort order - "asc" (default) or "desc"

**Returns**: Array of backup summaries with key information for each backup.

**Example**:
```json
{
  "tool": "list_backups",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "sort_order": "desc"
  }
}
```

**Response structure**:
```json
{
  "Outcome": "Success",
  "Backups": [
    {
      "Label": "20260304123045",
      "BackupSize": "1.2 GB",
      "RestoreSize": "1.5 GB",
      "Compression": "zstd",
      "Encryption": "aes_256_gcm"
    },
    ...
  ]
}
```

### Data Translation

The MCP server automatically translates raw pgmoneta responses into human-readable formats:

#### File Size Translation

Raw byte counts are converted to human-readable formats:
- `BackupSize`: `1234567890` → `"1.2 GB"`
- `RestoreSize`: `1610612736` → `"1.5 GB"`
- `TotalSpace`, `FreeSpace`, `UsedSpace`, etc.

#### LSN Translation

Log Sequence Numbers are converted to hexadecimal strings:
- `StartHiLSN`: `439041101` → `"0x1A2B3C4D"`
- `StartLoLSN`: `1583691920` → `"0x5E6F7890"`
- `CheckpointHiLSN`, `CheckpointLoLSN`, `EndHiLSN`, `EndLoLSN`

#### Enum Translation

Numeric enum values are translated to descriptive strings:

**Compression types**:
- `0` → `"none"`
- `1` → `"gzip"`
- `2` → `"zstd"`
- `3` → `"lz4"`
- `4` → `"bzip2"`

**Encryption types**:
- `0` → `"none"`
- `1` → `"aes_256_gcm"`
- `2` → `"aes_192_gcm"`
- `3` → `"aes_128_gcm"`

**Error codes**:
- `0` → `"Success"`
- `1` → `"Error"`
- `2` → `"Allocation error"`
- And many more (see `constant.rs` for full list)

### Error Handling

The MCP server uses the `McpError` type from rmcp for standardized error responses:

**Error types**:
- `ParseError`: Failed to parse pgmoneta response
- `InternalError`: Internal server error
- `InvalidParams`: Invalid tool parameters
- `MethodNotFound`: Unknown tool requested

**Example error response**:
```json
{
  "error": {
    "code": -32603,
    "message": "Failed to parse result",
    "data": {
      "details": "Invalid JSON format"
    }
  }
}
```

### Authentication

The MCP server uses SCRAM-SHA-256 for authentication with the pgmoneta server:

1. **User configuration**: Admin users are configured in `pgmoneta-mcp-users.conf`
2. **Password encryption**: Passwords are encrypted using AES-256-GCM with a master key
3. **Master key**: Stored in `~/.pgmoneta-mcp/master.key` with 0600 permissions
4. **SCRAM handshake**: Performed during TCP connection establishment

See [Security API documentation](80-security-api.md) for detailed information.

### Configuration

The MCP server requires two configuration files:

**pgmoneta-mcp.conf**:
```ini
[pgmoneta_mcp]
port = 8000
log_type = file
log_level = info
log_path = /tmp/pgmoneta-mcp.log

[pgmoneta]
host = localhost
port = 5000
```

**pgmoneta-mcp-users.conf**:
```ini
[admin]
password = <encrypted_password_base64>
```

See [Configuration documentation](../CONFIGURATION.md) for complete details.

### Usage Example

**Starting the MCP server**:
```bash
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

**MCP client interaction** (pseudo-code):
```python
# Connect to MCP server
client = MCPClient("http://localhost:8000/mcp")

# Initialize connection
client.initialize()

# Call tool to get backup info
result = client.call_tool(
    "get_backup_info",
    {
        "username": "admin",
        "server": "primary",
        "backup_id": "latest"
    }
)

# Process result
print(f"Latest backup: {result['BackupInfo']['Label']}")
print(f"Size: {result['BackupInfo']['BackupSize']}")
```

### Extending the MCP Server

To add a new MCP tool:

1. **Define request structure** in `src/handler/` (e.g., `new_tool.rs`):
```rust
#[derive(Deserialize, JsonSchema)]
pub struct NewToolRequest {
    pub username: String,
    pub param1: String,
    // ... other parameters
}
```

2. **Implement internal method** in `PgmonetaHandler`:
```rust
async fn _new_tool(&self, args: NewToolRequest) -> Result<String, McpError> {
    let result = PgmonetaClient::forward_request(
        &args.username,
        Command::NEW_COMMAND,
        args
    ).await?;
    Ok(result)
}
```

3. **Add tool definition** with `#[tool]` macro:
```rust
#[tool(description = "Description of new tool")]
async fn new_tool(
    &self,
    Parameters(args): Parameters<NewToolRequest>,
) -> Result<CallToolResult, McpError> {
    let result = self._new_tool(args).await?;
    Self::_generate_call_tool_result(&result)
}
```

4. **Add command constant** in `src/constant.rs`:
```rust
impl Command {
    pub const NEW_COMMAND: u32 = 123;
}
```

### Debugging

Enable debug logging to see detailed request/response information:

**In configuration** (`pgmoneta-mcp.conf`):
```ini
[pgmoneta_mcp]
log_level = debug
```

**Debug output includes**:
- TCP connection establishment
- SCRAM authentication handshake
- Request serialization
- Response parsing
- Data translation steps

**Example debug log**:
```
DEBUG Connected to server, username=admin
DEBUG Sent request to server, request=PgmonetaRequest { ... }
DEBUG Received response, length=1234
DEBUG Translated compression: 2 -> "zstd"
DEBUG Translated backup size: 1234567890 -> "1.2 GB"
```

### Performance Considerations

- **Connection pooling**: Each tool call establishes a new TCP connection. For high-frequency usage, consider implementing connection pooling.
- **Response caching**: Backup information changes infrequently. Consider caching responses with appropriate TTL.
- **Timeout handling**: Configure appropriate timeouts for long-running operations.
- **Concurrent requests**: The server handles concurrent MCP requests safely.

### Security Considerations

- **Master key protection**: The master key file must have 0600 permissions
- **Password encryption**: All passwords are encrypted at rest using AES-256-GCM
- **SCRAM-SHA-256**: Strong authentication mechanism prevents password sniffing
- **Admin-only access**: Only configured admin users can access pgmoneta operations
- **CORS support**: The HTTP server allows cross-origin requests so that browser-based MCP clients can connect directly
- **Audit logging**: All operations are logged with username and timestamp

### References

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [rmcp Documentation](https://docs.rs/rmcp/latest/rmcp/)
- [SCRAM-SHA-256 RFC](https://datatracker.ietf.org/doc/html/rfc7677)
- [pgmoneta Documentation](https://pgmoneta.github.io/)
