\newpage

# MCP API

**Overview**

**pgmoneta_mcp** implements the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to enable AI assistants and language models to interact with pgmoneta backup servers. The MCP server exposes pgmoneta's backup management capabilities through a standardized interface that can be consumed by MCP clients.

The MCP implementation is built on top of the [rmcp](https://docs.rs/rmcp/latest/rmcp/) Rust library and provides:

- **Tool-based interface**: Exposes pgmoneta operations as MCP tools
- **SCRAM-SHA-256 authentication**: Secure authentication with pgmoneta server
- **JSON-based communication**: Structured request/response format
- **Automatic data translation**: Converts raw pgmoneta responses into human-readable formats

**Architecture**

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

**Core Components**

**PgmonetaHandler**

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
async fn get_info(
    &self,
    Parameters(args): Parameters<InfoRequest>,
) -> Result<CallToolResult, McpError> {
    let result = self._get_info(args).await?;
    Self::_generate_call_tool_result(&result)
}
```

**PgmonetaClient**

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

**Available MCP Tools**

**say_hello**

**Description**: Simple ping tool to verify MCP server connectivity.

**Parameters**: None

**Returns**: Greeting message

**Example**:
```json
{
  "tool": "say_hello"
}
```

**backup**

**Description**: Creates a backup for a specified server.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, optional): Base backup identifier for incremental backup

If `backup_id` is omitted, the tool creates a full backup.
If `backup_id` is provided, the tool creates an incremental backup based on that backup.

**Examples**:

Create a full backup:

```json
{
  "tool": "backup",
  "arguments": {
    "username": "admin",
    "server": "primary"
  }
}
```

Create an incremental backup:

```json
{
  "tool": "backup",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest"
  }
}
```

**annotate_backup**

**Description**: Adds, updates, or removes a comment annotation on a backup.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `action` (string, required): Annotation action. Supported values: `add`, `update`, `remove`
- `key` (string, required): Annotation key
- `comment` (string, required for `add` and `update` actions, not required for `remove` action): Annotation text

**Examples**:

Add a comment:

```json
{
  "tool": "annotate_backup",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "action": "add",
    "key": "mykey",
    "comment": "mycomment"
  }
}
```

Update a comment:

```json
{
  "tool": "annotate_backup",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "action": "update",
    "key": "mykey",
    "comment": "mynewcomment"
  }
}
```

Remove a comment:

```json
{
  "tool": "annotate_backup",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "action": "remove",
    "key": "mykey"
  }
}
```

**get_info**

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
  "tool": "get_info",
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
    "Encryption": "aes-256-cbc",
    "StartHiLSN": "0x1A2B3C4D",
    "StartLoLSN": "0x5E6F7890",
    ...
  }
}
```

**delete**

**Description**: Deletes a specified backup from the pgmoneta server.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `force` (boolean, optional): If true, forces deletion of the backup.

**Returns**: Confirmation of deletion or error message.
**Example**:
```json
{
  "tool": "delete",
  "arguments": {
    "username": "repl",
    "server": "primary",
    "backup_id": "newest",
    "force": true
  }
}
```

**list_backups**

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

**clear**

**Description**: Clears/Resets the data/statistics of prometheus.

**Parameters**:
- `username` (string, required): pgmoneta admin username

**Example**:
```json
{
  "tool": "clear",
  "arguments": {
    "username": "admin"
  }
}
```

**metric**

**Description**: Returns Prometheus metric samples exposed by pgmoneta.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `name` (string, required): Exact Prometheus metric name
- `attributes` (object, optional): Label filters to match against the metric sample
- `labels` (object, optional): Alias for `attributes`

Use either `attributes` or `labels`, not both. Label values are matched exactly.
If the filter is omitted, all samples with the given metric name are returned.

**Examples**:

Fetch all samples for a metric:

```json
{
  "tool": "metric",
  "arguments": {
    "username": "admin",
    "name": "pgmoneta_retention_server"
  }
}
```

Fetch a single sample by label:

```json
{
  "tool": "metric",
  "arguments": {
    "username": "admin",
    "name": "pgmoneta_retention_server",
    "attributes": {
      "server": "primary"
    }
  }
}
```

**Response examples**:

```text
pgmoneta_version{version="0.22.0"} 1
```

```text
pgmoneta_retention_server{server="primary"} 7
pgmoneta_retention_server{server="standby"} 14
```

**get_metrics**

**Description**: Returns the full Prometheus/OpenMetrics exposition exposed by pgmoneta.

**Parameters**:
- `username` (string, required): pgmoneta admin username

**Example**:

```json
{
  "tool": "get_metrics",
  "arguments": {
    "username": "admin"
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
      "Encryption": "aes-256-cbc"
    },
    ...
  ]
}
```

**restore**
**Description**: Restores a backup to a specified directory.
**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `directory` (string, required): Target directory for restore
- `current` (boolean, optional) To restore to the first stable checkpoint.
- `name` (string, optional) To restore to the specified label.
- `xid` (string, optional) To restore to the specified transaction ID.
- `time` (string, optional) To restore to the specified timestamp.
- `lsn` (string, optional) To restore to the specified LSN.
- `inclusive` (string, optional) To restore inclusively of the specified information.
- `timeline` (string, optional) To restore to the specified timeline.
- `action` (string, optional): Action to perform on the primary server after restore (eg. `pause`, `shutdown`)
- `primary` (boolean, optional) for cluster setup as primary.
- `replica` (boolean, optional) for cluster setup as replica.

**Example**:
```json
{
  "tool": "restore",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "directory": "/tmp/restore",
    "current": true,
    "timeline": "1",
    "action": "pause",
    "primary": true,
  }
}
```

**archive (Similar to restore, but for archiving backups)**
**Description**: Archives a backup to a specified directory.
**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `directory` (string, required): Target directory for archive
- `current` (boolean, optional) To archive the backup of the first stable checkpoint.
- `name` (string, optional) To archive the backup of the specified label.
- `xid` (string, optional) To archive the backup of the specified transaction ID.
- `time` (string, optional) To archive the backup of the specified timestamp.
- `lsn` (string, optional) To archive the backup of the specified LSN.
- `inclusive` (string, optional) To archive inclusively of the specified information.
- `timeline` (string, optional) To archive the backup of the specified timeline.
- `action` (string, optional): Action to perform on the primary server after archive (eg. `pause`, `shutdown`)
- `primary` (boolean, optional) for cluster setup as primary.
- `replica` (boolean, optional) for cluster setup as replica.

**Example**:
```json
{
  "tool": "archive",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "directory": "/tmp/restore",
    "current": true,
    "timeline": "1",
    "action": "pause",
    "primary": true,
  }
}
```

**retain**
**Description**: Retains a backup and optionally cascades retention to dependent backups.
**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `cascade` (boolean, optional): If true, retains dependent backups as well.

**Example**:
```json
{
  "tool": "retain",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "cascade": true
  }
}
```

**expunge**
**Description**: Expunges a backup and optionally cascades expunging to dependent backups.
**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `backup_id` (string, required): Backup identifier (can be backup label, "newest", "latest", or "oldest")
- `cascade` (boolean, optional): If true, expunges dependent backups as well.

**Example**:
```json
{
  "tool": "expunge",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "backup_id": "latest",
    "cascade": true
  }
}
```

**ping**
**Description**: Ping pgmoneta to check if pgmoneta is alive.
**Parameters**:
- `username` (string, required): pgmoneta admin username
**Example**:
```json
{
  "tool": "ping",
  "arguments": {
    "username": "admin"
  }
}
```

**status**
**Description**: Get the status of pgmoneta server.
**Parameters**:
- `username` (string, required): pgmoneta admin username
- `in_details` (boolean, required): If true, returns detailed status information.
**Example**:
```json
{
  "tool": "status",
  "arguments": {
    "username": "admin",
    "in_details": false
  }
}
```

**Data Translation**

The MCP server automatically translates raw pgmoneta responses into human-readable formats:

**File Size Translation**

Raw byte counts are converted to human-readable formats:
- `BackupSize`: `1234567890` → `"1.2 GB"`
- `RestoreSize`: `1610612736` → `"1.5 GB"`
- `TotalSpace`, `FreeSpace`, `UsedSpace`, etc.

**LSN Translation**

Log Sequence Numbers are converted to hexadecimal strings:
- `StartHiLSN`: `439041101` → `"0x1A2B3C4D"`
- `StartLoLSN`: `1583691920` → `"0x5E6F7890"`
- `CheckpointHiLSN`, `CheckpointLoLSN`, `EndHiLSN`, `EndLoLSN`

**Enum Translation**

Numeric enum values are translated to descriptive strings:

**Compression types**:
- `0` → `"none"`
- `1` → `"gzip"`
- `2` → `"zstd"`
- `3` → `"lz4"`
- `4` → `"bzip2"`

**Encryption types**:
- `0` → `"none"`
- `1` → `"aes-256-cbc"`
- `2` → `"aes-192-cbc"`
- `3` → `"aes-128-cbc"`
- `4` → `"aes-256-ctr"`
- `5` → `"aes-192-ctr"`
- `6` → `"aes-128-ctr"`

**Error codes**:
- `0` → `"Success"`
- `1` → `"Error"`
- `2` → `"Allocation error"`
- And many more (see `constant.rs` for full list)

**walinfo**

**Description**: Inspects PostgreSQL Write-Ahead Log (WAL) activity stored by pgmoneta.

**Parameters**:
- `username` (string, required): pgmoneta admin username
- `server` (string, required): Server name as configured in pgmoneta
- `mode` (string, optional): `user` for a transaction timeline (default), or `developer` for raw JSON
- `time` (string, optional): Time of day to filter around, for example `4:02pm` or `16:02`
- `window_minutes` (integer, optional): Minutes on either side of `time`; defaults to `5`

`walinfo` reads `<base_dir>/<server>/wal`, so `[pgmoneta].base_dir` must match the pgmoneta data directory.

**Example**:
```json
{
  "tool": "walinfo",
  "arguments": {
    "username": "admin",
    "server": "primary",
    "mode": "developer",
    "time": "16:02",
    "window_minutes": 10
  }
}
```

**Error Handling**

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

**Authentication**

The MCP server uses SCRAM-SHA-256 for authentication with the pgmoneta server:

1. **User configuration**: Admin users are configured in `pgmoneta-mcp-users.conf`
2. **Password encryption**: Passwords are encrypted using AES-256-GCM with a master key
3. **Master key**: Stored in `~/.pgmoneta-mcp/master.key` with 0600 permissions
4. **SCRAM handshake**: Performed during TCP connection establishment

See [Security API documentation](80-security-api.md) for detailed information.

**Configuration**

The MCP server requires two configuration files:

**pgmoneta-mcp.conf**:
```ini
[pgmoneta]
host = localhost
port = 2345

[log]
type = file
level = info
path = /tmp/pgmoneta-mcp.log
```

**pgmoneta-mcp-users.conf**:
```ini
[admin]
password = <encrypted_password_base64>
```

See [Configuration documentation](../CONFIGURATION.md) for complete details.

**Usage Example**

**Starting the MCP server**:
```bash
pgmoneta-mcp-server -c pgmoneta-mcp.conf -u pgmoneta-mcp-users.conf
```

**MCP client interaction** (pseudo-code):
```python
# Connect to MCP server
client = MCPClient("http://localhost:8080/mcp")

# Initialize connection
client.initialize()

# Call tool to get backup info
result = client.call_tool(
    "get_info",
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

**Extending the MCP Server**

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

**Debugging**

Enable debug logging to see detailed request/response information:

**In configuration**:
```ini
[log]
level = debug
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

**Performance Considerations**

- **Connection pooling**: Each tool call establishes a new TCP connection. For high-frequency usage, consider implementing connection pooling.
- **Response caching**: Backup information changes infrequently. Consider caching responses with appropriate TTL.
- **Timeout handling**: Configure appropriate timeouts for long-running operations.
- **Concurrent requests**: The server handles concurrent MCP requests safely.

**Security Considerations**

- **Master key protection**: The master key file must have 0600 permissions
- **Password encryption**: All passwords are encrypted at rest using AES-256-GCM
- **SCRAM-SHA-256**: Strong authentication mechanism prevents password sniffing
- **Admin-only access**: Only configured admin users can access pgmoneta operations
- **Audit logging**: All operations are logged with username and timestamp

**References**

- [Model Context Protocol Specification](https://modelcontextprotocol.io/)
- [rmcp Documentation](https://docs.rs/rmcp/latest/rmcp/)
- [SCRAM-SHA-256 RFC](https://datatracker.ietf.org/doc/html/rfc7677)
- [pgmoneta Documentation](https://pgmoneta.github.io/)
