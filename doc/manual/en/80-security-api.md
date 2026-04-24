\newpage

## Security API

### Overview

The **Security API** provides cryptographic operations, authentication mechanisms, and secure key management for **pgmoneta_mcp**. It implements industry-standard security practices to protect sensitive data at rest and in transit.

The security module is defined and implemented in `src/security.rs` and provides:

- **AES-256-GCM encryption**: For encrypting passwords and sensitive data at rest
- **SCRAM-SHA-256 authentication**: For secure authentication with pgmoneta server
- **Password generation**: Cryptographically secure password generation
- **Base64 encoding/decoding**: For encoding binary data in configuration files

### Architecture

``` text
+--------------------------------------+
|         SecurityUtil                 |
+--------------------------------------+
|  Master Key Management               |
|  - load_master_key()                 |
|                                      |
|  Encryption/Decryption               |
|  - encrypt_to_base64_string()        |
|  - decrypt_from_base64_string()      |
|  - encrypt_text()                    |
|  - decrypt_text()                    |
|                                      |
|  Authentication                      |
|  - connect_to_server()               |
|  - SCRAM-SHA-256 handshake           |
|                                      |
|  Utilities                           |
|  - base64_encode()                   |
|  - base64_decode()                   |
+--------------------------------------+
```

### SecurityUtil Structure

The `SecurityUtil` struct is the main entry point for all security operations:

```rust
pub struct SecurityUtil {
    base64_engine: engine::GeneralPurpose,
}
```

**Creating an instance**:
```rust
let security_util = SecurityUtil::new();
```

### Master Key Management

The master key is used to encrypt/decrypt admin passwords stored in the user configuration file. It is stored in `~/.pgmoneta-mcp/master.key` with strict file permissions (0600 on Unix systems).

#### load_master_key

**Signature**:
```rust
pub fn load_master_key(&self) -> anyhow::Result<MasterKey>
```

**Description**: Loads the master key and salt from the filesystem and returns a `MasterKey` (tuple of `Zeroizing<Vec<u8>>`) that automatically zeros the memory when dropped.

**Location**: `~/.pgmoneta-mcp/master.key`

**Security features**:
- Automatically enforces 0600 permissions on Unix systems
- Returns key wrapped in `Zeroizing` to prevent key material from remaining in memory
- Base64 decodes the stored key

**Usage**:
```rust
let security_util = SecurityUtil::new();
let master_key = security_util.load_master_key()?;
// Use master_key for encryption/decryption
// Key is automatically zeroed when master_key goes out of scope
```

**Error conditions**:
- Home directory cannot be determined
- Master key file does not exist
- File permissions are too permissive (automatically corrected)
- Invalid Base64 encoding

### Encryption and Decryption

The security module uses **AES-256-GCM** (Galois/Counter Mode) for authenticated encryption, which provides both confidentiality and integrity protection.

#### Encryption Process

1. **Key derivation**: Master key is derived using **PBKDF2-HMAC-SHA256** (600,000 + 1 iterations)
2. **Nonce generation**: Random 12-byte nonce is generated
3. **Encryption**: Plaintext is encrypted using AES-256-GCM
4. **Packaging**: Nonce + Salt + Ciphertext are concatenated and Base64 encoded

#### encrypt_to_base64_string

**Signature**:
```rust
pub fn encrypt_to_base64_string(
    &self,
    plain_text: &[u8],
    master_key: &[u8],
) -> anyhow::Result<String>
```

**Description**: Encrypts plaintext and returns a Base64-encoded string containing nonce, salt, and ciphertext.

**Parameters**:
- `plain_text`: Data to encrypt (typically a password)
- `master_key`: Master key for encryption (typically 32 bytes)

**Returns**: Base64-encoded string in format: `base64(nonce || salt || ciphertext)`

**Usage**:
```rust
let security_util = SecurityUtil::new();
let master_key = security_util.load_master_key()?;
let password = "admin_password";

let encrypted = security_util.encrypt_to_base64_string(
    password.as_bytes(),
    &master_key
)?;

// Store encrypted in configuration file
println!("Encrypted password: {}", encrypted);
```

#### decrypt_from_base64_string

**Signature**:
```rust
pub fn decrypt_from_base64_string(
    &self,
    cipher_text: &str,
    master_key: &[u8],
) -> anyhow::Result<Vec<u8>>
```

**Description**: Decrypts a Base64-encoded ciphertext string back to plaintext.

**Parameters**:
- `cipher_text`: Base64-encoded string from `encrypt_to_base64_string()`
- `master_key`: Same master key used for encryption

**Returns**: Decrypted plaintext as bytes

**Usage**:
```rust
let security_util = SecurityUtil::new();
let master_key = security_util.load_master_key()?;
let encrypted = "base64_encoded_ciphertext_here";

let decrypted = security_util.decrypt_from_base64_string(
    encrypted,
    &master_key
)?;

let password = String::from_utf8(decrypted)?;
println!("Decrypted password: {}", password);
```

**Error conditions**:
- Ciphertext exceeds maximum length (1 MB)
- Invalid Base64 encoding
- Insufficient bytes (less than nonce + salt length)
- Decryption failure (wrong key or corrupted data)

#### Low-level Encryption Functions

**encrypt_text**:
```rust
pub fn encrypt_text(
    plaintext: &[u8],
    master_key: &[u8],
) -> anyhow::Result<(Vec<u8>, [u8; NONCE_LEN], [u8; SALT_LEN])>
```

Returns raw ciphertext, nonce, and salt separately. Used internally by `encrypt_to_base64_string()`.

**decrypt_text**:
```rust
pub fn decrypt_text(
    ciphertext: &[u8],
    master_key: &[u8],
    nonce_bytes: &[u8],
    salt: &[u8],
) -> anyhow::Result<Vec<u8>>
```

Decrypts raw ciphertext with provided nonce and salt. Used internally by `decrypt_from_base64_string()`.

The security module uses **PBKDF2-HMAC-SHA256** for key derivation, matching the server-side implementation.

**Parameters**:
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations (Master): 600,000
- Iterations (File): 1
- Output: 32 bytes (256 bits)

**Process**:
```rust
fn derive_key(master_key: &[u8], salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    let params = Params::recommended();
    let mut derived_key = [0u8; 32];
    scrypt(master_key, salt, &params, &mut derived_key)?;
    Ok(derived_key)
}
```

**Security considerations**:
- Random salt is generated for each encryption operation
- Salt is stored alongside ciphertext (not secret)
- Derived key is automatically zeroed after use using `Zeroizing`

### SCRAM-SHA-256 Authentication

SCRAM-SHA-256 (Salted Challenge Response Authentication Mechanism) is used for authenticating with the pgmoneta server. It provides:

- **Password protection**: Password is never sent over the network
- **Mutual authentication**: Both client and server prove knowledge of password
- **Replay attack protection**: Uses nonces to prevent replay attacks

#### connect_to_server

**Signature**:
```rust
pub async fn connect_to_server(
    host: &str,
    port: i32,
    username: &str,
    password: &str,
) -> anyhow::Result<TcpStream>
```

**Description**: Establishes an authenticated TCP connection to the pgmoneta server using SCRAM-SHA-256.

**Parameters**:
- `host`: pgmoneta server hostname or IP address
- `port`: pgmoneta server port
- `username`: Admin username
- `password`: Admin password (plaintext, will be hashed)

**Returns**: Authenticated `TcpStream` ready for communication

**Authentication flow**:

1. **TCP connection**: Establish TCP connection to server
2. **Startup message**: Send startup message with username and database
3. **Server challenge**: Receive SASL authentication methods
4. **Client first**: Send SCRAM-SHA-256 client-first message
5. **Server first**: Receive server-first message with salt and iteration count
6. **Client final**: Send client-final message with proof
7. **Server final**: Receive server-final message with server proof
8. **Auth success**: Receive authentication success confirmation

**Usage**:
```rust
let stream = SecurityUtil::connect_to_server(
    "localhost",
    5000,
    "admin",
    "admin_password"
).await?;

// Use stream for communication with pgmoneta
```

**Error conditions**:
- Cannot connect to server (network error)
- Server does not support SCRAM-SHA-256
- Invalid username or password
- Authentication protocol error
- Unexpected server response

**Protocol details**:

**Startup message format**:
```
Length (4 bytes) | Magic (4 bytes) | Parameters (null-terminated strings)
```

**Parameters**:
- `user`: Username
- `database`: "admin"
- `application_name`: "pgmoneta"

**Message types**:
- `R`: Authentication request/response
- `p`: Password message (SASL)
- `E`: Error message

**Authentication types**:
- `0`: AUTH_OK (authentication successful)
- `10`: AUTH_SASL (SASL authentication required)
- `11`: AUTH_SASL_CONTINUE (continue SASL authentication)
- `12`: AUTH_SASL_FINAL (final SASL message)

### Base64 Encoding

#### base64_encode

**Signature**:
```rust
pub fn base64_encode(&self, bytes: &[u8]) -> anyhow::Result<String>
```

**Description**: Encodes binary data to Base64 string using standard alphabet with padding.

**Usage**:
```rust
let security_util = SecurityUtil::new();
let data = b"Hello, World!";
let encoded = security_util.base64_encode(data)?;
println!("Encoded: {}", encoded);
```

#### base64_decode

**Signature**:
```rust
pub fn base64_decode(&self, text: &str) -> anyhow::Result<Vec<u8>>
```

**Description**: Decodes Base64 string back to binary data.

**Usage**:
```rust
let security_util = SecurityUtil::new();
let encoded = "SGVsbG8sIFdvcmxkIQ==";
let decoded = security_util.base64_decode(encoded)?;
println!("Decoded: {}", String::from_utf8(decoded)?);
```

### Memory Safety

The security module uses Rust's `zeroize` crate to ensure sensitive data is securely erased from memory:

**Zeroizing types**:
- `Zeroizing<Vec<u8>>`: Automatically zeros vector contents when dropped
- Used for master keys, derived keys, and passwords

**Example**:
```rust
{
    let master_key = security_util.load_master_key()?;
    // Use master_key...
} // master_key is automatically zeroed here
```

**Manual zeroing**:
```rust
use zeroize::Zeroize;

let mut sensitive_data = vec![1, 2, 3, 4];
// Use sensitive_data...
sensitive_data.zeroize(); // Explicitly zero the data
```

### Security Best Practices

#### Master Key Management

3. **Backup**: Keep secure offline backup of master key
4. **Rotation**: Rotate master key periodically and re-encrypt all passwords
5. **Never commit**: Never commit master key to version control

#### Password Management

1. **Strong passwords**: Use at least 32 characters for admin passwords
2. **Unique passwords**: Use different passwords for each admin user
3. **Encryption**: Always encrypt passwords before storing in configuration
4. **No plaintext**: Never store passwords in plaintext
5. **Secure transmission**: Use SCRAM-SHA-256 for authentication

#### File Permissions

On Unix systems, ensure proper file permissions:

```bash
# Master key file
chmod 600 ~/.pgmoneta-mcp/master.key

# User configuration file (contains encrypted passwords)
chmod 600 /path/to/pgmoneta-mcp-users.conf

# Server configuration file (contains connection details)
chmod 600 /path/to/pgmoneta-mcp.conf
```

#### Network Security

1. **TLS/SSL**: Consider using TLS for pgmoneta connections in production
2. **Firewall**: Restrict access to pgmoneta port (typically 5000)
3. **Authentication**: Always use SCRAM-SHA-256 (never trust authentication)
4. **Monitoring**: Monitor authentication failures and suspicious activity

### Testing

The security module includes comprehensive unit tests:

**Test coverage**:
- Base64 encoding/decoding
- Encryption/decryption round-trip
- Password generation (length and character set)
- Master key operations

**Running tests**:
```bash
cargo test security
```

**Example test**:
```rust
#[test]
fn test_encrypt_decrypt() {
    let sutil = SecurityUtil::new();
    let master_key = "test_master_key_!@#$~<>?/".as_bytes();
    let text = "test_text_123_!@#$~<>?/";

    let encrypted = sutil
        .encrypt_to_base64_string(text.as_bytes(), master_key)
        .expect("Encryption should succeed");
    
    let decrypted = sutil
        .decrypt_from_base64_string(&encrypted, master_key)
        .expect("Decryption should succeed");
    
    assert_eq!(decrypted, text.as_bytes());
}
```

### Error Handling

All security functions return `anyhow::Result<T>` for comprehensive error handling:

**Common errors**:
- `"Unable to find home path"`: Home directory cannot be determined
- `"Cipher text is too large"`: Encrypted data exceeds 1 MB limit
- `"Not enough bytes to decrypt the text"`: Corrupted ciphertext
- `"AES encryption failed"`: Encryption operation failed
- `"AES decryption failed"`: Decryption failed (wrong key or corrupted data)
- `"Invalid message length"`: Protocol error during authentication
- `"Server does not offer SCRAM-SHA-256"`: Server doesn't support SCRAM
- `"Authentication failed"`: Invalid username or password

**Error handling example**:
```rust
match security_util.decrypt_from_base64_string(&encrypted, &master_key) {
    Ok(decrypted) => {
        let password = String::from_utf8(decrypted)?;
        println!("Password: {}", password);
    }
    Err(e) => {
        eprintln!("Decryption failed: {}", e);
        // Handle error (wrong master key, corrupted data, etc.)
    }
}
```

### Constants

**Cryptographic constants**:
```rust
const NONCE_LEN: usize = 12;           // AES-GCM nonce length
const SALT_LEN: usize = 16;            // scrypt salt length
const MAX_CIPHERTEXT_B64_LEN: usize = 1024 * 1024;  // Max encrypted data size
```

**Protocol constants**:
```rust
const MAGIC: i32 = 196608;             // PostgreSQL protocol magic number
const AUTH_OK: i32 = 0;                // Authentication successful
const AUTH_SASL: i32 = 10;             // SASL authentication required
const AUTH_SASL_CONTINUE: i32 = 11;    // Continue SASL handshake
const AUTH_SASL_FINAL: i32 = 12;       // Final SASL message
const MAX_PG_MESSAGE_LEN: usize = 64 * 1024;  // Max PostgreSQL message size
```

### References

- [AES-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
- [scrypt](https://en.wikipedia.org/wiki/Scrypt)
- [SCRAM-SHA-256 RFC 7677](https://datatracker.ietf.org/doc/html/rfc7677)
- [PostgreSQL SCRAM Authentication](https://www.postgresql.org/docs/current/sasl-authentication.html)
- [Rust zeroize crate](https://docs.rs/zeroize/)
- [Base64 RFC 4648](https://datatracker.ietf.org/doc/html/rfc4648)
