\newpage

## Client API

### Overview

The **Client API** provides low-level communication with the pgmoneta server. It handles TCP connection management, request serialization, response parsing, and the complete request/response lifecycle.

The client module is defined and implemented in `src/client.rs` and `src/handler/info.rs`.

**Key responsibilities**:
- Build and serialize request headers and payloads
- Establish authenticated TCP connections
- Write requests to TCP stream
- Read and parse responses from TCP stream
- Forward requests to pgmoneta server

### Architecture

``` text
+-----------------------------------------+
|         PgmonetaClient                  |
+-----------------------------------------+
|  Connection Management                  |
|  - connect_to_server()                  |
|  - Uses SecurityUtil for auth           |
|                                         |
|  Request Building                       |
|  - build_request_header()               |
|  - PgmonetaRequest<R> wrapper           |
|                                         |
|  Communication                          |
|  - write_request()                      |
|  - read_response()                      |
|  - forward_request()                    |
+-----------------------------------------+
```

### PgmonetaClient Structure

The `PgmonetaClient` is a zero-sized type that provides static methods for communicating with the pgmoneta server:

```rust
pub struct PgmonetaClient;
```

All methods are associated functions (not instance methods), so no instance creation is needed.

### Request Structure

#### RequestHeader

The `RequestHeader` contains metadata about the request:

```rust
struct RequestHeader {
    command: u32,           // Command code (e.g., Command::INFO)
    client_version: String, // MCP client version
    output_format: u8,      // Response format (JSON)
    timestamp: String,      // Request timestamp (YYYYMMDDHHmmss)
    compression: u8,        // Compression type (ZSTD by default)
    encryption: u8,         // Encryption type (AES-256-GCM by default)
}
```

**Field details**:

- **command**: Numeric command code from `Command` constants
  - `Command::INFO` (1): Get backup information
  - `Command::LIST_BACKUP` (2): List backups
  - See `src/constant.rs` for complete list

- **client_version**: Version string (e.g., "0.2.0")
  - Defined in `constant::CLIENT_VERSION`

- **output_format**: Response format
  - `Format::JSON` (1): JSON format (default)
  - `Format::TEXT` (2): Plain text format

- **timestamp**: Local timestamp when request was created
  - Format: `YYYYMMDDHHmmss`
  - Example: `"20260304123045"`

- **compression**: Compression algorithm
  - `Compression::NONE` (0): No compression
  - `Compression::GZIP` (1): gzip compression
  - `Compression::ZSTD` (2): zstd compression (default)
  - `Compression::LZ4` (3): lz4 compression
  - `Compression::BZIP2` (4): bzip2 compression

- **encryption**: Encryption algorithm
  - `Encryption::NONE` (0): No encryption
  - `Encryption::AES_256_GCM` (1): AES-256-GCM (default)
  - `Encryption::AES_192_GCM` (2): AES-192-GCM
  - `Encryption::AES_128_GCM` (3): AES-128-GCM

#### PgmonetaRequest

The `PgmonetaRequest` wraps the header and request payload:

```rust
struct PgmonetaRequest<R>
where
    R: Serialize + Clone + Debug,
{
    header: RequestHeader,
    request: R,
}
```

**Generic parameter**:
- `R`: Request payload type (must be serializable to JSON)

**Serialized JSON format**:
```json
{
  "Header": {
    "Command": 1,
    "ClientVersion": "0.2.0",
    "Output": 1,
    "Timestamp": "20260304123045",
    "Compression": 2,
    "Encryption": 1
  },
  "Request": {
    // Request-specific fields
  }
}
```

### Request Payloads

#### InfoRequest

Request structure for getting backup information:

```rust
pub struct InfoRequest {
    pub server: String,
    pub backup_id: String,
}
```

**Fields**:
- `server`: Server name as configured in pgmoneta
- `backup_id`: Backup identifier
  - Backup label (e.g., "20260304123045")
  - "newest" or "latest": Most recent backup
  - "oldest": Oldest backup

**Example**:
```rust
let request = InfoRequest {
    server: "primary".to_string(),
    backup_id: "latest".to_string(),
};
```

**Serialized JSON**:
```json
{
  "Server": "primary",
  "BackupId": "latest"
}
```

#### ListBackupsRequest

Request structure for listing backups:

```rust
pub struct ListBackupsRequest {
    pub server: String,
    pub sort_order: Option<String>,
}
```

**Fields**:
- `server`: Server name as configured in pgmoneta
- `sort_order`: Optional sort order
  - `"asc"`: Ascending order (oldest first)
  - `"desc"`: Descending order (newest first)
  - `None`: Default to ascending

**Example**:
```rust
let request = ListBackupsRequest {
    server: "primary".to_string(),
    sort_order: Some("desc".to_string()),
};
```

**Serialized JSON**:
```json
{
  "Server": "primary",
  "SortOrder": "desc"
}
```

### Core Methods

#### build_request_header

**Signature**:
```rust
fn build_request_header(command: u32) -> RequestHeader
```

**Description**: Constructs a standard request header for the given command.

**Parameters**:
- `command`: Command code (e.g., `Command::INFO`)

**Returns**: Populated `RequestHeader` with current timestamp

**Default values**:
- `client_version`: From `CLIENT_VERSION` constant
- `output_format`: `Format::JSON`
- `compression`: always `Compression::ZSTD`
- `encryption`: always `Encryption::AES_256_GCM`

**Usage** (internal):
```rust
let header = Self::build_request_header(Command::INFO);
```

**Timestamp format**:
```rust
let timestamp = Local::now().format("%Y%m%d%H%M%S").to_string();
// Example: "20260304123045"
```

#### connect_to_server

**Signature**:
```rust
async fn connect_to_server(username: &str) -> anyhow::Result<TcpStream>
```

**Description**: Establishes an authenticated TCP connection to the pgmoneta server.

**Process**:
1. Load configuration to get host and port
2. Look up username in admin configuration
3. Load master key from filesystem
4. Decrypt admin password using master key
5. Connect to server using SCRAM-SHA-256 authentication

**Parameters**:
- `username`: Admin username from MCP request

**Returns**: Authenticated `TcpStream` ready for communication

**Usage** (internal):
```rust
let stream = Self::connect_to_server("admin").await?;
```

**Error conditions**:
- Configuration not initialized
- Username not found in admin configuration
- Master key cannot be loaded
- Password decryption fails
- SCRAM-SHA-256 authentication fails

**Dependencies**:
- `CONFIG`: Global configuration (must be initialized)
- `SecurityUtil::load_master_key()`: Load master key
- `SecurityUtil::decrypt_from_base64_string()`: Decrypt password
- `SecurityUtil::connect_to_server()`: SCRAM authentication

#### write_request

**Signature**:
```rust
async fn write_request(request_str: &str, stream: &mut TcpStream) -> anyhow::Result<()>
```

**Description**: Writes a serialized JSON request to the TCP stream.

**Protocol**:
1. Write compression flag (1 byte)
2. Write encryption flag (1 byte)
3. Write payload length (4 bytes, i32)
4. Write payload bytes

**Parameters**:
- `request_str`: JSON-serialized request string
- `stream`: Mutable reference to TCP stream

**Wire format**:
```
+-------------+-------------+----------------+------------------+
| Compression | Encryption  | Length (i32)   | Payload (JSON)   |
| (1 byte)    | (1 byte)    | (4 bytes)      | (variable)       |
+-------------+-------------+----------------+------------------+
```

**Usage** (internal):
```rust
let request_str = serde_json::to_string(&request)?;
Self::write_request(&request_str, &mut stream).await?;
```

**Example wire data**:
```
00                    // Compression: NONE
00                    // Encryption: NONE
00 00 00 5A           // Length: 90 bytes
7B 22 48 65 61 64...  // JSON payload: {"Header":...}
```

#### read_response

**Signature**:
```rust
async fn read_response(stream: &mut TcpStream) -> anyhow::Result<String>
```

**Description**: Reads the response payload from the TCP stream.

**Protocol**:
1. Read compression flag (1 byte)
2. Read encryption flag (1 byte)
3. Read payload length (4 bytes, u32)
4. Read exact number of payload bytes

**Parameters**:
- `stream`: Mutable reference to TCP stream

**Returns**: JSON response string

**Wire format**:
```
+-------------+-------------+----------------+------------------+
| Compression | Encryption  | Length (u32)   | Payload (JSON)   |
| (1 byte)    | (1 byte)    | (4 bytes)      | (variable)       |
+-------------+-------------+----------------+------------------+
```

**Usage** (internal):
```rust
let response_str = Self::read_response(&mut stream).await?;
```

**Example response**:
```json
{
  "Outcome": "Success",
  "BackupInfo": {
    "Server": "primary",
    "Label": "20260304123045",
    ...
  }
}
```

**Error conditions**:
- TCP read error
- Invalid payload length
- Incomplete payload read

#### forward_request

**Signature**:
```rust
async fn forward_request<R>(
    username: &str,
    command: u32,
    request: R
) -> anyhow::Result<String>
where
    R: Serialize + Clone + Debug,
```

**Description**: End-to-end request forwarding to pgmoneta server.

**Process**:
1. Connect to server (with authentication)
2. Build request header
3. Wrap request with header
4. Serialize to JSON
5. Write request to stream
6. Read response from stream
7. Return response string

**Parameters**:
- `username`: Admin username for authentication
- `command`: Command code (e.g., `Command::INFO`)
- `request`: Request payload (must be serializable)

**Returns**: JSON response string from pgmoneta server

**Usage**:
```rust
let request = InfoRequest {
    server: "primary".to_string(),
    backup_id: "latest".to_string(),
};

let response = PgmonetaClient::forward_request(
    "admin",
    Command::INFO,
    request
).await?;

println!("Response: {}", response);
```

**Logging**:
```rust
tracing::info!(username = username, "Connected to server");
tracing::debug!(username = username, request = ?request, "Sent request to server");
```

**Error handling**:
```rust
match PgmonetaClient::forward_request("admin", Command::INFO, request).await {
    Ok(response) => {
        // Parse and process response
        let result: serde_json::Value = serde_json::from_str(&response)?;
        println!("Result: {}", result);
    }
    Err(e) => {
        eprintln!("Request failed: {}", e);
    }
}
```

### Usage Examples

#### Getting Backup Information

```rust
use pgmoneta_mcp::client::PgmonetaClient;
use pgmoneta_mcp::handler::info::InfoRequest;
use pgmoneta_mcp::constant::Command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create request
    let request = InfoRequest {
        server: "primary".to_string(),
        backup_id: "latest".to_string(),
    };

    // Forward request to pgmoneta server
    let response = PgmonetaClient::forward_request(
        "admin",
        Command::INFO,
        request
    ).await?;

    // Parse response
    let result: serde_json::Value = serde_json::from_str(&response)?;
    
    // Extract backup info
    if let Some(backup_info) = result.get("BackupInfo") {
        println!("Backup Label: {}", backup_info["Label"]);
        println!("Backup Size: {}", backup_info["BackupSize"]);
        println!("Compression: {}", backup_info["Compression"]);
    }

    Ok(())
}
```

#### Listing Backups

```rust
use pgmoneta_mcp::client::PgmonetaClient;
use pgmoneta_mcp::handler::info::ListBackupsRequest;
use pgmoneta_mcp::constant::Command;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create request
    let request = ListBackupsRequest {
        server: "primary".to_string(),
        sort_order: Some("desc".to_string()),
    };

    // Forward request to pgmoneta server
    let response = PgmonetaClient::forward_request(
        "admin",
        Command::LIST_BACKUP,
        request
    ).await?;

    // Parse response
    let result: serde_json::Value = serde_json::from_str(&response)?;
    
    // Extract backups list
    if let Some(backups) = result.get("Backups").and_then(|v| v.as_array()) {
        for backup in backups {
            println!("Label: {}", backup["Label"]);
            println!("Size: {}", backup["BackupSize"]);
            println!("---");
        }
    }

    Ok(())
}
```

### Response Format

All responses from pgmoneta follow a standard format:

**Success response**:
```json
{
  "Outcome": "Success",
  "BackupInfo": {
    // Response-specific data
  }
}
```

**Error response**:
```json
{
  "Outcome": "Error",
  "Error": 1,
  "ErrorMessage": "Backup not found"
}
```

**Response fields**:
- `Outcome`: "Success" or "Error"
- `Error`: Error code (if outcome is "Error")
- `ErrorMessage`: Human-readable error message (if outcome is "Error")
- Additional fields: Response-specific data (varies by command)

### Error Handling

The client API uses `anyhow::Result<T>` for error handling:

**Common errors**:
- **Connection errors**: Cannot connect to pgmoneta server
  - Check host and port in configuration
  - Ensure pgmoneta server is running
  - Check firewall rules

- **Authentication errors**: SCRAM-SHA-256 authentication fails
  - Verify username exists in admin configuration
  - Verify password is correct
  - Check master key is correct

- **Protocol errors**: Invalid message format
  - Ensure pgmoneta server version is compatible
  - Check for network corruption

- **Serialization errors**: Cannot serialize request or parse response
  - Verify request structure matches expected format
  - Check response is valid JSON

**Error handling example**:
```rust
match PgmonetaClient::forward_request("admin", Command::INFO, request).await {
    Ok(response) => {
        // Success - process response
        println!("Response: {}", response);
    }
    Err(e) => {
        // Error - handle appropriately
        if e.to_string().contains("Authentication failed") {
            eprintln!("Authentication error: Check username and password");
        } else if e.to_string().contains("Connection refused") {
            eprintln!("Connection error: Is pgmoneta server running?");
        } else {
            eprintln!("Request failed: {}", e);
        }
    }
}
```

### Configuration Requirements

The client API requires the global configuration to be initialized:

**Configuration structure**:
```rust
pub struct Configuration {
    pub pgmoneta: PgmonetaConfiguration,
    pub admins: HashMap<String, String>,
}

pub struct PgmonetaConfiguration {
    pub host: String,
    pub port: i32,
}
```

**Initialization**:
```rust
use pgmoneta_mcp::configuration::{load_configuration, CONFIG};

// Load configuration files
let config = load_configuration(
    "pgmoneta-mcp.conf",
    "pgmoneta-mcp-users.conf"
)?;

// Initialize global configuration
CONFIG.set(config).expect("Configuration already initialized");
```

**Configuration files**:

`pgmoneta-mcp.conf`:
```ini
[pgmoneta_mcp]
port = 8000

[pgmoneta]
host = localhost
port = 5000
```

`pgmoneta-mcp-users.conf`:
```ini
[admin]
password = <encrypted_password_base64>
```

### Performance Considerations

#### Connection Management

- **New connection per request**: Each `forward_request()` call establishes a new TCP connection
- **Authentication overhead**: SCRAM-SHA-256 handshake adds latency (~10-50ms)
- **Connection pooling**: Consider implementing connection pooling for high-frequency requests

**Potential optimization**:
```rust
// Future enhancement: Connection pool
pub struct ConnectionPool {
    connections: Vec<TcpStream>,
    max_size: usize,
}

impl ConnectionPool {
    pub async fn get_connection(&mut self) -> anyhow::Result<TcpStream> {
        // Reuse existing connection or create new one
    }
}
```

#### Request Serialization

- **JSON serialization**: Uses `serde_json` for efficient serialization
- **Small payloads**: Most requests are < 1 KB
- **No compression**: Currently no compression is used (could be added)

#### Response Parsing

- **Streaming**: Response is read in one operation
- **Memory efficient**: No intermediate buffering
- **JSON parsing**: Deferred to caller (allows streaming processing)

### Security Considerations

#### Authentication

- **SCRAM-SHA-256**: Strong authentication mechanism
- **No password in logs**: Passwords are never logged
- **Encrypted storage**: Passwords encrypted at rest in configuration

#### Network Security

- **Plaintext protocol**: Currently no TLS/SSL support
- **Local network**: Designed for localhost or trusted network
- **Firewall**: Restrict access to pgmoneta port

**Future enhancement**:
```rust
// Add TLS support
use tokio_native_tls::TlsConnector;

pub async fn connect_to_server_tls(
    host: &str,
    port: i32,
    username: &str,
    password: &str,
) -> anyhow::Result<TlsStream<TcpStream>> {
    // Establish TLS connection
}
```

#### Data Validation

- **Input validation**: Request fields are validated before sending
- **Response validation**: Response format is checked before parsing
- **Error handling**: All errors are properly propagated

### Debugging

Enable debug logging to see detailed client operations:

**Configuration** (in `pgmoneta-mcp.conf`):
```ini
[pgmoneta_mcp]
log_level = debug
```

**Debug output**:
```
INFO Connected to server, username=admin
DEBUG Sent request to server, request=PgmonetaRequest { 
    header: RequestHeader { 
        command: 1, 
        client_version: "0.2.0", 
        output_format: 1, 
        timestamp: "20260304123045", 
        compression: 0, 
        encryption: 0 
    }, 
    request: InfoRequest { 
        server: "primary", 
        backup_id: "latest" 
    } 
}
```

**Tracing spans**:
```rust
use tracing::{info, debug, instrument};

#[instrument(skip(stream))]
async fn write_request(request_str: &str, stream: &mut TcpStream) -> anyhow::Result<()> {
    debug!(length = request_str.len(), "Writing request");
    // ... write logic
    Ok(())
}
```

### Testing

The client module should be tested with integration tests:

**Test structure**:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_forward_request_info() {
        // Requires running pgmoneta server
        let request = InfoRequest {
            server: "primary".to_string(),
            backup_id: "latest".to_string(),
        };

        let response = PgmonetaClient::forward_request(
            "admin",
            Command::INFO,
            request
        ).await;

        assert!(response.is_ok());
    }
}
```

**Mock server for testing**:
```rust
// Create mock pgmoneta server for unit tests
pub struct MockPgmonetaServer {
    listener: TcpListener,
}

impl MockPgmonetaServer {
    pub async fn new() -> anyhow::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    pub async fn accept_and_respond(&self, response: &str) -> anyhow::Result<()> {
        let (mut stream, _) = self.listener.accept().await?;
        // Handle authentication...
        // Read request...
        // Write response...
        Ok(())
    }
}
```

### References

- [pgmoneta Protocol Documentation](https://pgmoneta.github.io/)
- [SCRAM-SHA-256 RFC 7677](https://datatracker.ietf.org/doc/html/rfc7677)
- [PostgreSQL Protocol](https://www.postgresql.org/docs/current/protocol.html)
- [Tokio TCP Documentation](https://docs.rs/tokio/latest/tokio/net/struct.TcpStream.html)
- [serde_json Documentation](https://docs.rs/serde_json/)
