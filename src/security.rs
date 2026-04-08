// Copyright (C) 2026 The pgmoneta community
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::constant::{Encryption, MASTER_KEY_PATH};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm, Nonce};
use anyhow::anyhow;
type Aes192Gcm = AesGcm<aes::Aes192, U12>;
use base64::{
    Engine as _, alphabet,
    engine::{self, general_purpose},
};
use hmac::Hmac;
use home::home_dir;
use pbkdf2::pbkdf2;
use rand::TryRngCore;
use scram::ScramClient;
use sha2::Sha256;
use std::fs;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

struct CachedMasterKey {
    password: Zeroizing<Vec<u8>>,
    salt: Zeroizing<Vec<u8>>,
    derived_key: Zeroizing<Vec<u8>>,
}

static MASTER_KEY_CACHE: Mutex<Option<CachedMasterKey>> = Mutex::new(None);

/// Represents a master key composition: (password, salt)
pub type MasterKey = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;
/// Iterations for the first KDF step (Master Password + Master Salt -> Derived Master Key)
const MASTER_PBKDF2_ITERATIONS: u32 = 600_000;
/// Iterations for the second KDF step (Derived Master Key + File Salt -> Final Key)
const FILE_PBKDF2_ITERATIONS: u32 = 1;
const MAX_CIPHERTEXT_B64_LEN: usize = 1024 * 1024;

use std::path::PathBuf;

/// Handles cryptographic operations and secure communication.
///
/// This utility manages Base64 encoding/decoding, AES-256-GCM encryption/decryption
/// of stored credentials, master key lifecycle management, and SCRAM-SHA-256
/// authentication over the PostgreSQL wire protocol.
pub struct SecurityUtil {
    base64_engine: engine::GeneralPurpose,
    master_key_path: Option<PathBuf>,
}

impl SecurityUtil {
    /// Creates a new `SecurityUtil` with a standard Base64 engine and default master key path.
    ///
    /// This constructor is infallible; it will target the user's home directory if resolvable,
    /// otherwise it will defer the error to when a master key operation is actually attempted.
    pub fn new() -> Self {
        let master_key_path = home_dir().map(|h| h.join(MASTER_KEY_PATH));
        Self {
            base64_engine: engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD),
            master_key_path,
        }
    }

    /// Creates a new `SecurityUtil` with a custom master key path.
    pub fn new_with_path(path: PathBuf) -> Self {
        Self {
            base64_engine: engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD),
            master_key_path: Some(path),
        }
    }

    /// Encodes a byte slice into a Base64 string.
    pub fn base64_encode(&self, bytes: &[u8]) -> anyhow::Result<String> {
        Ok(self.base64_engine.encode(bytes))
    }

    /// Decodes a Base64 string back into a byte vector.
    pub fn base64_decode(&self, text: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.base64_engine.decode(text)?)
    }

    /// Loads the master key (password) and salt from the user's home directory (`~/.pgmoneta-mcp/master.key`).
    ///
    /// The file is expected to have two lines:
    /// 1. Base64-encoded master password
    /// 2. Base64-encoded master salt
    ///
    /// On Unix systems, this also ensures the key file has strict `0600` permissions.
    ///
    /// Returns a `MasterKey` (tuple of `Zeroizing<Vec<u8>>`) to ensure sensitive
    /// material is wiped from memory when dropped.
    pub fn load_master_key(&self) -> anyhow::Result<MasterKey> {
        let key_path = self
            .master_key_path
            .as_ref()
            .ok_or_else(|| anyhow!("Unable to find home path. Set HOME environment variable or use a custom master key path."))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(key_path)?.permissions().mode() & 0o777;
            if (mode & 0o077) != 0 {
                fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
            }
        }

        let content = fs::read_to_string(key_path)?;
        let mut lines = content.lines();

        let pass_b64 = lines
            .next()
            .ok_or_else(|| anyhow!("Master key file is empty"))?;
        let salt_b64 = lines.next().ok_or_else(|| {
            anyhow!(
                "Master salt (line 2) not found in key file. Please regenerate your master key."
            )
        })?;

        let password = self.base64_decode(pass_b64.trim())?;
        let salt = self.base64_decode(salt_b64.trim())?;

        if salt.len() != SALT_LEN {
            return Err(anyhow!(
                "Master salt must be exactly {} bytes (found {}). Please regenerate your master key.",
                SALT_LEN,
                salt.len()
            ));
        }

        // Validate that there are no extra non-empty lines
        for (idx, line) in lines.enumerate() {
            if !line.trim().is_empty() {
                return Err(anyhow!(
                    "Master key file must contain exactly two non-empty lines (password and salt). \
                     Unexpected data found on line {}.",
                    idx + 3
                ));
            }
        }

        Ok((Zeroizing::new(password), Zeroizing::new(salt)))
    }

    /// Base64 encodes and writes a new master key and salt to the user's home directory.
    ///
    /// On Unix systems, this ensures the file is created with secure `0600` permissions.
    pub fn write_master_key(&self, key: &str, salt: &[u8]) -> anyhow::Result<()> {
        let key_path = self
            .master_key_path
            .as_ref()
            .ok_or_else(|| anyhow!("Unable to find home path. Set HOME environment variable or use a custom master key path."))?;
        let key_encoded = self.base64_encode(key.as_bytes())?;
        let salt_encoded = self.base64_encode(salt)?;
        let content = format!("{}\n{}\n", key_encoded, salt_encoded);

        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }

        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(key_path)?;
            file.write_all(content.as_bytes())?;
            fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::write(key_path, &content)?;
            Ok(())
        }
    }

    /// Encrypts plaintext using AES-256-GCM and encodes the result (including nonce and salt) to Base64.
    pub fn encrypt_to_base64_string(
        &self,
        plain_text: &[u8],
        master_password: &[u8],
        master_salt: &[u8],
    ) -> anyhow::Result<String> {
        let (cipher_text, nonce_bytes, salt) = Self::encrypt_text_aes_gcm(
            plain_text,
            master_password,
            master_salt,
            Encryption::AES_256_GCM,
        )?;
        let mut bytes = Vec::new();
        // salt + nonce (IV) + cipher text (includes GCM tag)
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend(cipher_text.iter());
        self.base64_encode(bytes.as_slice())
    }

    /// Decodes a Base64 string and decrypts the underlying AES-256-GCM ciphertext.
    pub fn decrypt_from_base64_string(
        &self,
        cipher_text: &str,
        master_password: &[u8],
        master_salt: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        if cipher_text.len() > MAX_CIPHERTEXT_B64_LEN {
            return Err(anyhow!("Cipher text is too large"));
        }
        let cipher_text_bytes = self.base64_decode(cipher_text)?;
        if cipher_text_bytes.len() < SALT_LEN + NONCE_LEN {
            return Err(anyhow!("Not enough bytes to decrypt the text"));
        }
        let salt: &[u8] = &cipher_text_bytes[..SALT_LEN];
        let nonce: &[u8] = &cipher_text_bytes[SALT_LEN..SALT_LEN + NONCE_LEN];
        Self::decrypt_text_aes_gcm(
            &cipher_text_bytes[(SALT_LEN + NONCE_LEN)..],
            master_password,
            master_salt,
            nonce,
            salt,
            Encryption::AES_256_GCM,
        )
    }

    /// Generate a random password of the specified length.
    /// Uses alphanumeric characters and common special characters.
    pub fn generate_password(&self, length: usize) -> anyhow::Result<String> {
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                              abcdefghijklmnopqrstuvwxyz\
                              0123456789\
                              !@$%^&*()-_=+[{]}\\|:'\",<.>/?";

        let mut password = vec![0u8; length];
        let mut random_bytes = vec![0u8; length];

        rand::rngs::OsRng.try_fill_bytes(&mut random_bytes)?;

        for (i, byte) in random_bytes.iter().enumerate() {
            password[i] = CHARS[*byte as usize % CHARS.len()];
        }

        // Zero out random bytes for security
        random_bytes.zeroize();

        String::from_utf8(password)
            .map_err(|e| anyhow!("Generated password contains invalid UTF-8: {:?}", e))
    }
}

impl SecurityUtil {
    const KEY_USER: &'static str = "user";
    const KEY_DATABASE: &'static str = "database";
    const KEY_APP_NAME: &'static str = "application_name";
    const APP_PGMONETA: &'static str = "pgmoneta";
    const DB_ADMIN: &'static str = "admin";
    const MAGIC: i32 = 196608;
    const HEADER_OFFSET: usize = 9;

    const AUTH_OK: i32 = 0;
    const AUTH_SASL: i32 = 10;
    const AUTH_SASL_CONTINUE: i32 = 11;
    const AUTH_SASL_FINAL: i32 = 12;

    const MAX_PG_MESSAGE_LEN: usize = 64 * 1024;

    /// Reads a raw message frame from the PostgreSQL wire protocol stream.
    ///
    /// Extracts the 1-byte message type and the 4-byte length, then reads
    /// the corresponding payload payload.
    async fn read_message(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
        let msg_type = stream.read_u8().await?;

        let len = stream.read_u32().await? as usize;

        if !(4..=Self::MAX_PG_MESSAGE_LEN).contains(&len) {
            return Err(anyhow!("Invalid message length {}", len));
        }

        let mut payload = vec![0u8; len - 4];
        stream.read_exact(&mut payload).await?;

        let mut msg = Vec::with_capacity(1 + 4 + payload.len());
        msg.push(msg_type);
        msg.write_u32(len as u32).await?;
        msg.extend(&payload);
        Ok(msg)
    }

    /// Derives the intermediate 64-byte Master Key from the user's master password
    /// and salt using 600,000 PBKDF2 iterations.
    ///
    /// The result is cached globally to avoid expensive re-calculations.
    fn get_or_derive_master_key(
        master_password: &[u8],
        master_salt: &[u8],
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        {
            let cache = MASTER_KEY_CACHE
                .lock()
                .map_err(|e| anyhow!("Master Key cache Mutex poisoned: {:?}", e))?;

            // Check if the cache is valid for the given inputs
            #[allow(clippy::collapsible_if)]
            if let Some(entry) = &*cache {
                if *entry.password == master_password && *entry.salt == master_salt {
                    return Ok(entry.derived_key.clone());
                }
            }
        } // Lock is dropped here

        // Cache miss or invalid cache - perform the expensive derivation
        tracing::info!(
            "Deriving Master Key using {} iterations (this may take a few seconds)...",
            MASTER_PBKDF2_ITERATIONS
        );

        let mut master_key = Zeroizing::new(vec![0u8; 64]);
        pbkdf2::<Hmac<Sha256>>(
            master_password,
            master_salt,
            MASTER_PBKDF2_ITERATIONS,
            &mut master_key,
        )
        .map_err(|e| anyhow!("Step 1 PBKDF2 failed: {:?}", e))?;

        // Re-acquire the lock and update the cache
        let mut cache = MASTER_KEY_CACHE
            .lock()
            .map_err(|e| anyhow!("Master Key cache Mutex poisoned: {:?}", e))?;

        let new_entry = CachedMasterKey {
            password: Zeroizing::new(master_password.to_vec()),
            salt: Zeroizing::new(master_salt.to_vec()),
            derived_key: master_key.clone(),
        };
        *cache = Some(new_entry);

        Ok(master_key)
    }

    /// Derives an encryption key using the server's two-step KDF process.
    ///
    /// The length of the derived key is determined by the `key_len` parameter (16, 24, or 32 bytes).
    /// Returns the derived key wrapped in `Zeroizing<Vec<u8>>` for security.
    fn derive_key_two_step(
        master_password: &[u8],
        master_salt: &[u8],
        file_salt: &[u8],
        key_len: usize,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        // Step 1: Password + Master Salt -> Derived Master Key (600,000 iterations)
        // This step is computationally expensive and uses the global cache.
        let master_key = Self::get_or_derive_master_key(master_password, master_salt)?;

        // Step 2: Derived Master Key (64 bytes) + File Salt -> Final File Key (1 iteration)
        // Note: Server derives EVP_MAX_KEY_LENGTH + EVP_MAX_IV_LENGTH (80 bytes) but takes first key_len
        let mut final_key = Zeroizing::new(vec![0u8; key_len]);
        pbkdf2::<Hmac<Sha256>>(
            &master_key,
            file_salt,
            FILE_PBKDF2_ITERATIONS,
            &mut final_key,
        )
        .map_err(|e| anyhow!("Step 2 PBKDF2 failed: {:?}", e))?;

        Ok(final_key)
    }

    /// Derives a key from a master key and salt using a single-iteration PBKDF2-HMAC-SHA256.
    ///
    /// This is typically used as the second step in a two-stage KDF (see `derive_key_two_step`).
    /// It is NOT recommended for general-purpose password hashing or key derivation
    /// from low-entropy inputs due to the low iteration count.
    pub fn derive_file_key(
        master_key: &[u8],
        salt: &[u8],
        key_len: usize,
    ) -> anyhow::Result<Zeroizing<Vec<u8>>> {
        let mut derived_key = Zeroizing::new(vec![0u8; key_len]);
        pbkdf2::<Hmac<Sha256>>(master_key, salt, FILE_PBKDF2_ITERATIONS, &mut derived_key)
            .map_err(|e| anyhow!("PBKDF2 failed: {:?}", e))?;
        Ok(derived_key)
    }

    /// Encrypts raw bytes using AES-GCM (128, 192, or 256-bit).
    ///
    /// AES-GCM (Galois/Counter Mode) is the recommended encryption method for native
    /// pgmoneta-mcp use cases. It provides both confidentiality and authentication,
    /// is more efficient, and is resistant to certain attacks that affect CBC mode.
    ///
    /// Automatically generates a secure random nonce and salt, derives the encryption key
    /// using a two-step PBKDF2 (600,000 + 1 iterations), and returns the ciphertext
    /// alongside the generated nonce and salt. The bit-length is selected via `encryption_mode`.
    pub fn encrypt_text_aes_gcm(
        plaintext: &[u8],
        master_password: &[u8],
        master_salt: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<(Vec<u8>, [u8; NONCE_LEN], [u8; SALT_LEN])> {
        let key_len = match encryption_mode {
            Encryption::AES_128_GCM => 16,
            Encryption::AES_192_GCM => 24,
            Encryption::AES_256_GCM => 32,
            _ => {
                return Err(anyhow!(
                    "Unsupported or invalid encryption mode: {}",
                    encryption_mode
                ));
            }
        };
        // derive the key
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes)?;

        let derived_key_bytes =
            Self::derive_key_two_step(master_password, master_salt, &salt, key_len)?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = match encryption_mode {
            Encryption::AES_128_GCM => {
                let cipher = Aes128Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| anyhow!("AES encryption failed {:?}", e))
            }
            Encryption::AES_192_GCM => {
                let cipher = Aes192Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| anyhow!("AES encryption failed {:?}", e))
            }
            Encryption::AES_256_GCM => {
                let cipher = Aes256Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .encrypt(nonce, plaintext)
                    .map_err(|e| anyhow!("AES encryption failed {:?}", e))
            }
            _ => Err(anyhow!(
                "Unsupported or invalid encryption mode: {}",
                encryption_mode
            )),
        }?;

        Ok((ciphertext, nonce_bytes, salt))
    }

    /// Decrypts AES-GCM ciphertext using the provided master password, master salt,
    /// nonce, and file salt.
    ///
    /// This function decrypts data that was encrypted with `encrypt_text_aes_gcm`.
    /// AES-GCM provides authenticated encryption, ensuring both confidentiality
    /// and integrity of the data. The bit-length is selected via `encryption_mode`.
    pub fn decrypt_text_aes_gcm(
        ciphertext: &[u8],
        master_password: &[u8],
        master_salt: &[u8],
        nonce_bytes: &[u8],
        file_salt: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let key_len = match encryption_mode {
            Encryption::AES_128_GCM => 16,
            Encryption::AES_192_GCM => 24,
            Encryption::AES_256_GCM => 32,
            _ => {
                return Err(anyhow!(
                    "Unsupported or invalid encryption mode: {}",
                    encryption_mode
                ));
            }
        };
        let derived_key_bytes =
            Self::derive_key_two_step(master_password, master_salt, file_salt, key_len)?;
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = match encryption_mode {
            Encryption::AES_128_GCM => {
                let cipher = Aes128Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("AES decryption failed {:?}", e))
            }
            Encryption::AES_192_GCM => {
                let cipher = Aes192Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("AES decryption failed {:?}", e))
            }
            Encryption::AES_256_GCM => {
                let cipher = Aes256Gcm::new_from_slice(&derived_key_bytes)
                    .map_err(|e| anyhow!("Key initialization failed: {:?}", e))?;
                cipher
                    .decrypt(nonce, ciphertext)
                    .map_err(|e| anyhow!("AES decryption failed {:?}", e))
            }
            _ => Err(anyhow!(
                "Unsupported or invalid encryption mode: {}",
                encryption_mode
            )),
        }?;

        Ok(plaintext)
    }

    /// Connect to pgmoneta server using SCRAM-SHA-256 authentication.
    ///
    /// # Protocol Flow:
    /// 1. Sends the initial StartupMessage.
    /// 2. Receives an AuthenticationSASL response offering SCRAM-SHA-256.
    /// 3. Sends the SASLInitialResponse (`client_first`).
    /// 4. Receives the AuthenticationSASLContinue response (`server_first`).
    /// 5. Sends the SASLResponse (`client_final`).
    /// 6. Receives the AuthenticationSASLFinal response.
    /// 7. Awaits the final AuthenticationOk signal.
    pub async fn connect_to_server(
        host: &str,
        port: i32,
        username: &str,
        password: &str,
    ) -> anyhow::Result<TcpStream> {
        let scram = ScramClient::new(username, password, None);
        let address = format!("{}:{}", host, port);
        tracing::debug!(host = host, port = port, "Beginning SASL handshake");
        let mut stream = match timeout(Duration::from_secs(5), TcpStream::connect(address)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(anyhow!("Failed to connect to {host}:{port}: {e}")),
            Err(_) => return Err(anyhow!("Connection to {host}:{port} timed out after 5s")),
        };
        tracing::debug!(host = host, port = port, "Connected to server");

        let startup_msg = Self::create_startup_message(username).await?;
        match timeout(
            Duration::from_secs(2),
            stream.write_all(startup_msg.as_slice()),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => return Err(anyhow!("Failed to send startup message: {e}")),
            Err(_) => return Err(anyhow!("Sending startup message timed out")),
        }
        tracing::debug!("Sent startup message");

        let startup_resp =
            match timeout(Duration::from_secs(5), Self::read_message(&mut stream)).await {
                Ok(res) => res?,
                Err(_) => return Err(anyhow!("Waiting for startup response timed out")),
            };
        tracing::debug!("Received startup response");
        let n = startup_resp.len();
        if n < Self::HEADER_OFFSET || startup_resp[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid startup response from server {:?}",
                &startup_resp[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            startup_resp[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid startup auth_type"))?,
        );
        match auth_type {
            Self::AUTH_OK => return Ok(stream),
            Self::AUTH_SASL => {
                let payload = &startup_resp[Self::HEADER_OFFSET..n];
                if !payload
                    .windows("SCRAM-SHA-256".len())
                    .any(|w| w == b"SCRAM-SHA-256")
                {
                    return Err(anyhow!("Server does not offer SCRAM-SHA-256"));
                }
            }
            _ => return Err(anyhow!("Unsupported auth type {}", auth_type)),
        }

        let (scram, client_first) = scram.client_first();
        let mut client_first_msg = Vec::new();
        let mechanism = "SCRAM-SHA-256\0";
        let size = 4 + mechanism.len() + 4 + client_first.len();
        client_first_msg.write_u8(b'p').await?;
        client_first_msg.write_i32(size as i32).await?;
        client_first_msg.write_all(mechanism.as_bytes()).await?;
        client_first_msg
            .write_i32(client_first.len() as i32)
            .await?;
        client_first_msg.write_all(client_first.as_bytes()).await?;
        match timeout(
            Duration::from_secs(2),
            stream.write_all(client_first_msg.as_slice()),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => return Err(anyhow!("Failed to send client-first: {e}")),
            Err(_) => return Err(anyhow!("Sending client-first timed out")),
        }
        tracing::debug!("Sent client-first");

        let server_first =
            match timeout(Duration::from_secs(5), Self::read_message(&mut stream)).await {
                Ok(res) => res?,
                Err(_) => return Err(anyhow!("Waiting for server-first timed out")),
            };
        tracing::debug!("Received server-first");
        let n = server_first.len();
        if n <= Self::HEADER_OFFSET || server_first[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid server first message {:?}",
                &server_first[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            server_first[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid server first auth_type"))?,
        );
        if auth_type != Self::AUTH_SASL_CONTINUE {
            return Err(anyhow!("Unexpected auth type {}", auth_type));
        }
        let server_first_str = String::from_utf8(Vec::from(&server_first[Self::HEADER_OFFSET..n]))?;
        let scram = scram.handle_server_first(&server_first_str)?;

        let (scram, client_final) = scram.client_final();
        let mut client_final_msg = Vec::new();
        let size = 4 + client_final.len();
        client_final_msg.write_u8(b'p').await?;
        client_final_msg.write_i32(size as i32).await?;
        client_final_msg.write_all(client_final.as_bytes()).await?;
        match timeout(
            Duration::from_secs(2),
            stream.write_all(client_final_msg.as_slice()),
        )
        .await
        {
            Ok(Ok(_)) => (),
            Ok(Err(e)) => return Err(anyhow!("Failed to send client-final: {e}")),
            Err(_) => return Err(anyhow!("Sending client-final timed out")),
        }
        tracing::debug!("Sent client-final");

        let server_final =
            match timeout(Duration::from_secs(5), Self::read_message(&mut stream)).await {
                Ok(res) => res?,
                Err(_) => return Err(anyhow!("Waiting for server-final timed out")),
            };
        tracing::debug!("Received server-final");
        let n = server_final.len();
        if n <= Self::HEADER_OFFSET || server_final[0] != b'R' {
            return Err(anyhow!(
                "Getting invalid server final message {:?}",
                &server_final[..]
            ));
        }
        let auth_type = i32::from_be_bytes(
            server_final[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid server final auth_type"))?,
        );
        if auth_type != Self::AUTH_SASL_FINAL {
            return Err(anyhow!("Unexpected auth type {}", auth_type));
        }
        let server_final_str = String::from_utf8(Vec::from(&server_final[Self::HEADER_OFFSET..n]))?;
        scram.handle_server_final(&server_final_str)?;

        let auth_success =
            match timeout(Duration::from_secs(5), Self::read_message(&mut stream)).await {
                Ok(res) => res?,
                Err(_) => return Err(anyhow!("Waiting for Auth success response timed out")),
            };
        tracing::debug!("Auth result received");
        let n = auth_success.len();
        if n == 0 || auth_success[0] == b'E' {
            return Err(anyhow!("Authentication failed"));
        }
        if n < Self::HEADER_OFFSET || auth_success[0] != b'R' {
            return Err(anyhow!("Unexpected auth success response"));
        }
        let auth_type = i32::from_be_bytes(
            auth_success[5..9]
                .try_into()
                .map_err(|_| anyhow!("Invalid auth success auth_type"))?,
        );
        if auth_type != Self::AUTH_OK {
            return Err(anyhow!(
                "Authentication did not succeed (auth_type={})",
                auth_type
            ));
        }
        tracing::info!(
            host = host,
            port = port,
            username = username,
            "Authenticated with server"
        );
        Ok(stream)
    }

    /// Constructs the raw PostgreSQL wire protocol StartupMessage.
    ///
    /// The message includes protocol version identifiers alongside the user,
    /// database (`admin`), and application name (`pgmoneta`) parameters.
    async fn create_startup_message(username: &str) -> anyhow::Result<Vec<u8>> {
        let mut msg = Vec::new();
        let us = username.len();
        let ds = Self::DB_ADMIN.len();
        let size = 4 + 4 + 4 + 1 + us + 1 + 8 + 1 + ds + 1 + 17 + 9 + 1;
        msg.write_i32(size as i32).await?;
        msg.write_i32(Self::MAGIC).await?;
        msg.write_all(Self::KEY_USER.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(username.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::KEY_DATABASE.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::DB_ADMIN.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::KEY_APP_NAME.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_all(Self::APP_PGMONETA.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_u8(b'\0').await?;
        Ok(msg)
    }
}

impl Default for SecurityUtil {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityUtil {
    /// Encrypts a byte slice into an AES-GCM bundle.
    ///
    /// The resulting bundle follows the format:
    /// `[Salt (16 bytes)][IV/Nonce (12 bytes)][Ciphertext (variable)][Tag (16 bytes)]`
    ///
    /// Note: `aes-gcm` tags are appended to the ciphertext automatically.
    pub fn encrypt_text_aes_gcm_bundle(
        &self,
        plaintext: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<Vec<u8>> {
        let (master_password, master_salt) = self.load_master_key()?;
        let (cipher_text, nonce_bytes, salt) =
            Self::encrypt_text_aes_gcm(plaintext, &master_password, &master_salt, encryption_mode)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&salt);
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend(cipher_text.iter());
        Ok(bytes)
    }

    /// Decrypts an AES-GCM bundle back into a plain byte vector.
    ///
    /// This method expects the bundle format:
    /// `[Salt (16 bytes)][IV/Nonce (12 bytes)][Ciphertext (variable)][Tag (16 bytes)]`
    pub fn decrypt_text_aes_gcm_bundle(
        &self,
        ciphertext: &[u8],
        encryption_mode: u8,
    ) -> anyhow::Result<Vec<u8>> {
        if ciphertext.len() < SALT_LEN + NONCE_LEN {
            return Err(anyhow!("Not enough bytes to decrypt the text"));
        }
        let (master_password, master_salt) = self.load_master_key()?;
        let salt = &ciphertext[..SALT_LEN];
        let nonce = &ciphertext[SALT_LEN..SALT_LEN + NONCE_LEN];
        Self::decrypt_text_aes_gcm(
            &ciphertext[(SALT_LEN + NONCE_LEN)..],
            &master_password,
            &master_salt,
            nonce,
            salt,
            encryption_mode,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encode_decode() {
        let sutil = SecurityUtil::new();
        let s = "123abc !@#$~<>?/";
        let text = s.as_bytes();
        let res = sutil.base64_encode(text).expect("Encode should succeed");
        let decoded_text = sutil.base64_decode(&res).expect("Decode should succeed");
        assert_eq!(decoded_text, text)
    }

    #[test]
    fn test_encrypt_decrypt() {
        let sutil = SecurityUtil::new();
        let master_password = "test_master_password_!@#$~<>?/".as_bytes();
        let master_salt = "test_master_salt_!@#$~<>?/".as_bytes();
        let text = "test_text_123_!@#$~<>?/";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_password, master_salt)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_password, master_salt)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes())
    }

    #[test]
    fn test_generate_password_default_length() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(64)
            .expect("Password generation should succeed");
        assert_eq!(password.len(), 64);
    }

    #[test]
    fn test_generate_password_custom_length() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(32)
            .expect("Password generation should succeed");
        assert_eq!(password.len(), 32);
    }

    #[test]
    fn test_generate_password_contains_valid_chars() {
        let sutil = SecurityUtil::new();
        let password = sutil
            .generate_password(100)
            .expect("Password generation should succeed");
        // Should only contain alphanumeric and special chars from the defined set.
        let valid_chars: std::collections::HashSet<char> =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@$%^&*()-_=+[{]}\\|:'\"<,. />?"
                .chars()
                .collect();
        assert!(password.chars().all(|c| valid_chars.contains(&c)));
    }

    #[test]
    fn test_encrypt_decrypt_empty_string() {
        let sutil = SecurityUtil::new();
        let master_password = "test_master_password".as_bytes();
        let master_salt = "test_master_salt".as_bytes();
        let text = "";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_password, master_salt)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_password, master_salt)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_large_text() {
        let sutil = SecurityUtil::new();
        let master_password = "test_master_password".as_bytes();
        let master_salt = "test_master_salt".as_bytes();
        let text = "a".repeat(10000);
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_password, master_salt)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_password, master_salt)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_encrypt_decrypt_unicode() {
        let sutil = SecurityUtil::new();
        let master_password = "test_master_password".as_bytes();
        let master_salt = "test_master_salt".as_bytes();
        let text = "Hello 世界 🌍 Привет";
        let res = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_password, master_salt)
            .expect("Encryption should succeed");
        let decrypted_text = sutil
            .decrypt_from_base64_string(&res, master_password, master_salt)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let sutil = SecurityUtil::new();
        let master_password1 = "correct_password".as_bytes();
        let master_salt1 = "correct_salt".as_bytes();
        let master_password2 = "wrong_password".as_bytes();
        let master_salt2 = "wrong_salt".as_bytes();
        let text = "secret_data";
        let encrypted = sutil
            .encrypt_to_base64_string(text.as_bytes(), master_password1, master_salt1)
            .expect("Encryption should succeed");

        // Decryption with wrong password/salt should fail (tag mismatch)
        let result = sutil.decrypt_from_base64_string(&encrypted, master_password2, master_salt2);
        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_bundle() {
        // Use a temporary path for the master key to ensure hermeticity
        let temp_dir = std::env::temp_dir();
        let key_path = temp_dir.join(format!("pgmoneta_test_{}.key", rand::random::<u32>()));
        let sutil = SecurityUtil::new_with_path(key_path.clone());

        // Ensure we clean up after the test
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.0);
            }
        }
        let _cleanup = Cleanup(key_path);

        sutil
            .write_master_key("ci_test_master_key", b"ci_test_salt_16b")
            .expect("Failed to write a temporary master key for testing");

        let plaintext: &[u8] = b"Hello, World! This is a test for AES-GCM encryption.";
        let encryption_modes = vec![
            Encryption::AES_128_GCM,
            Encryption::AES_192_GCM,
            Encryption::AES_256_GCM,
        ];

        for mode in encryption_modes {
            let bundle = sutil
                .encrypt_text_aes_gcm_bundle(plaintext, mode)
                .expect("AES-GCM bundle encryption should succeed");

            // Verify bundle format: [SALT(16) | NONCE(12) | CIPHERTEXT+TAG]
            assert!(bundle.len() >= SALT_LEN + NONCE_LEN);
            let salt = &bundle[..SALT_LEN];
            let nonce = &bundle[SALT_LEN..SALT_LEN + NONCE_LEN];
            let cipher_at_rest = &bundle[SALT_LEN + NONCE_LEN..];

            // Manually verify decryption with raw decrypt function to ensure format is what we think it is
            let (master_password, master_salt) = sutil.load_master_key().unwrap();
            let decrypted = SecurityUtil::decrypt_text_aes_gcm(
                cipher_at_rest,
                &master_password,
                &master_salt,
                nonce,
                salt,
                mode,
            )
            .expect("Decryption should succeed");
            assert_eq!(decrypted, plaintext.to_vec());

            // verify round-trip via bundle API
            let decrypted_bundle = sutil
                .decrypt_text_aes_gcm_bundle(&bundle, mode)
                .expect("AES-GCM bundle decryption should succeed");
            assert_eq!(decrypted_bundle, plaintext.to_vec());
        }
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_empty_data() {
        let plaintext: &[u8] = b"";
        let master_password = b"gcm_test_master_password";
        let master_salt = b"gcm_test_salt_!!";

        let (cipher_text, nonce_bytes, salt) = SecurityUtil::encrypt_text_aes_gcm(
            plaintext,
            master_password,
            master_salt,
            Encryption::AES_256_GCM,
        )
        .expect("AES-GCM encryption should succeed");

        let decrypted = SecurityUtil::decrypt_text_aes_gcm(
            &cipher_text,
            master_password,
            master_salt,
            &nonce_bytes,
            &salt,
            Encryption::AES_256_GCM,
        )
        .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext.to_vec());
    }

    #[test]
    fn test_encrypt_decrypt_aes_gcm_large_data() {
        let plaintext: Vec<u8> = vec![b'A'; 10000];
        let master_password = b"gcm_test_master_password";
        let master_salt = b"gcm_test_salt_!!";

        let (cipher_text, nonce_bytes, salt) = SecurityUtil::encrypt_text_aes_gcm(
            &plaintext,
            master_password,
            master_salt,
            Encryption::AES_256_GCM,
        )
        .expect("AES-GCM encryption should succeed");

        let decrypted = SecurityUtil::decrypt_text_aes_gcm(
            &cipher_text,
            master_password,
            master_salt,
            &nonce_bytes,
            &salt,
            Encryption::AES_256_GCM,
        )
        .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext);
    }
}
