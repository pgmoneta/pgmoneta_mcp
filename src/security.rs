// Copyright (C) 2025 The pgmoneta community
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

use anyhow::anyhow;
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use home::home_dir;
use rand::TryRngCore;
use scram::ScramClient;
use scrypt::{scrypt, Params};
use std::fs;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::TcpStream;
use zeroize::Zeroize;
use crate::constant::MASTER_KEY_PATH;

const NONCE_LEN: usize = 12;
const SALT_LEN: usize = 16;

pub struct SecurityUtil {
    base64_engine: engine::GeneralPurpose,
}

impl SecurityUtil {
    pub fn new() -> Self {
        Self {
            base64_engine: engine::GeneralPurpose::new(&alphabet::STANDARD, general_purpose::PAD),
        }
    }

    pub fn base64_encode(&self, bytes: &[u8]) -> anyhow::Result<String> {
        Ok(self.base64_engine.encode(bytes))
    }

    pub fn base64_decode(&self, text: &str) -> anyhow::Result<Vec<u8>> {
        Ok(self.base64_engine.decode(&text)?)
    }

    pub fn load_master_key(&self) -> anyhow::Result<Vec<u8>> {
        let home_path = home_dir();
        if home_path.is_none() {
            return Err(anyhow!("Unable to find home path"))
        }
        let key_path = home_path.unwrap().join(MASTER_KEY_PATH);
        let key = fs::read_to_string(key_path)?;
        Ok(self.base64_decode(&key)?)
    }

    pub fn write_master_key(&self, key: &str) -> anyhow::Result<()> {
        let home_path = home_dir();
        if home_path.is_none() {
            return Err(anyhow!("Unable to find home path"))
        }
        let key_path = home_path.unwrap().join(MASTER_KEY_PATH);
        let key_encoded = self.base64_encode(key.as_bytes())?;
        if let Some(parent) = key_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(key_path, &key_encoded)?;
        Ok(())
    }

    pub fn encrypt_to_base64_string(&self, plain_text: &[u8], master_key: &[u8]) -> anyhow::Result<String> {
        let (cipher_text, nonce_bytes, salt) = Self::encrypt_text(plain_text, master_key)?;
        let mut bytes = Vec::new();
        // nonce + salt + cipher text
        bytes.extend_from_slice(&nonce_bytes);
        bytes.extend_from_slice(&salt);
        bytes.extend(cipher_text.iter());
        self.base64_encode(bytes.as_slice())
    }

    pub fn decrypt_from_base64_string(&self, cipher_text: &str, master_key: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher_text_bytes = self.base64_decode(cipher_text)?;
        if cipher_text_bytes.len() < SALT_LEN + NONCE_LEN {
            return Err(anyhow!("Not enough bytes to decrypt the text"))
        }
        let nonce: &[u8] = &cipher_text_bytes[..NONCE_LEN];
        let salt: &[u8] = &cipher_text_bytes[NONCE_LEN..NONCE_LEN+SALT_LEN];
        Self::decrypt_text(&cipher_text_bytes[(NONCE_LEN + SALT_LEN)..], master_key, nonce, salt)
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
    fn derive_key(master_key: &[u8], salt: &[u8]) -> [u8; 32] {
        let params = Params::recommended();
        let mut derived_key = [0u8; 32];
        scrypt(master_key, salt, &params, &mut derived_key).expect("scrypt should not fail");
        derived_key
    }

    pub fn encrypt_text(plaintext: &[u8], master_key: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; NONCE_LEN], [u8; SALT_LEN])> {
        // derive the key
        let mut salt = [0u8; SALT_LEN];
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::rngs::OsRng.try_fill_bytes(&mut salt)?;
        rand::rngs::OsRng.try_fill_bytes(&mut nonce_bytes)?;
        let mut derived_key_bytes = Self::derive_key(master_key, &salt);
        let derived_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key_bytes);

        let cipher = Aes256Gcm::new(derived_key);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|e| { anyhow!("AES encryption failed {:?}", e) });

        derived_key_bytes.zeroize();

        Ok((ciphertext?, nonce_bytes, salt))
    }

    pub fn decrypt_text(ciphertext: &[u8], master_key: &[u8], nonce_bytes: &[u8], salt: &[u8]) -> anyhow::Result<Vec<u8>> {
        let mut derived_key_bytes = Self::derive_key(master_key, &salt);
        let derived_key = aes_gcm::Key::<Aes256Gcm>::from_slice(&derived_key_bytes);
        let cipher = Aes256Gcm::new(derived_key);

        let nonce = Nonce::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| { anyhow!("AES decryption failed {:?}", e) });
        derived_key_bytes.zeroize();

        Ok(plaintext?)
    }

    /// Connect to pgmoneta server using SCRAM-SHA-256 authentication.
    pub async fn connect_to_server(host: &str, port: i32, username: &str, password: &str) -> anyhow::Result<TcpStream> {
        let scram = ScramClient::new(username, password, None);
        let address = format!("{}:{}", host, port);
        let mut stream = TcpStream::connect(address).await?;

        let startup_msg = Self::create_startup_message(username).await?;
        stream.write_all(startup_msg.as_slice()).await?;

        let mut startup_resp = [0u8; 256];
        let n = stream.read(&mut startup_resp).await?;
        if n == 0 || startup_resp[0] != b'R' {
            return Err(anyhow!("Getting invalid startup response from server {:?}", startup_resp))
        }

        let (scram, client_first) = scram.client_first();
        let mut client_first_msg = Vec::new();
        let size = 1 + 4 + 13 + 4 + 1 + client_first.len();
        client_first_msg.write_u8(b'p').await?;
        client_first_msg.write_i32(size as i32).await?;
        client_first_msg.write("SCRAM-SHA-256".as_bytes()).await?;
        client_first_msg.write("\0\0\0\0 ".as_bytes()).await?;
        client_first_msg.write(client_first.as_bytes()).await?;
        stream.write_all(client_first_msg.as_slice()).await?;

        let mut server_first = [0u8; 256];
        let n = stream.read(&mut server_first).await?;
        if n == 0 || server_first[0] != b'R' {
            return Err(anyhow!("Getting invalid server first message {:?}", server_first))
        }
        let server_first_str = String::from_utf8(Vec::from(&server_first[Self::HEADER_OFFSET..n]))?;
        let scram = scram.handle_server_first(&server_first_str)?;
        
        let (scram, client_final) = scram.client_final();
        let mut client_final_msg = Vec::new();
        let size = 1 + 4 + client_final.len();
        client_final_msg.write_u8(b'p').await?;
        client_final_msg.write_i32(size as i32).await?;
        client_final_msg.write(client_final.as_bytes()).await?;
        stream.write_all(client_final_msg.as_slice()).await?;

        let mut server_final = [0u8; 256];
        let n = stream.read(&mut server_final).await?;
        if n == 0 || server_final[0] != b'R' {
            return Err(anyhow!("Getting invalid server final message {:?}", server_first))
        }
        let server_final_str = String::from_utf8(Vec::from(&server_final[Self::HEADER_OFFSET..n]))?;
        scram.handle_server_final(&server_final_str)?;
        Ok(stream)
    }

    async fn create_startup_message(username: &str) -> anyhow::Result<Vec<u8>> {
        let mut msg = Vec::new();
        let us = username.len();
        let ds = Self::DB_ADMIN.len();
        let size = 4 + 4 + 4 + 1 + us + 1 + 8 + 1 + ds + 1 + 17 + 9 + 1;
        msg.write_i32(size as i32).await?;
        msg.write_i32(Self::MAGIC).await?;
        msg.write(Self::KEY_USER.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write(username.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write(Self::KEY_DATABASE.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write(Self::DB_ADMIN.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write(Self::KEY_APP_NAME.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write(Self::APP_PGMONETA.as_bytes()).await?;
        msg.write_u8(b'\0').await?;
        msg.write_u8(b'\0').await?;
        Ok(msg)
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
        let master_key = "test_master_key_!@#$~<>?/".as_bytes();
        let text = "test_text_123_!@#$~<>?/";
        let res = sutil.encrypt_to_base64_string(text.as_bytes(), master_key)
            .expect("Encryption should succeed");
        let decrypted_text = sutil.decrypt_from_base64_string(&res, master_key)
            .expect("Decryption should succeed");
        assert_eq!(decrypted_text, text.as_bytes())
    }
}
