// Copyright (C) 2025 The pgmoneta community
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list
// of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this
// list of conditions and the following disclaimer in the documentation and/or other
// materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may
// be used to endorse or promote products derived from this software without specific
// prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
// OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
// OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
// TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
        let key_path = home_path.unwrap().join(".pgmoneta-mcp/master.key");
        let key = fs::read_to_string(key_path)?;
        Ok(self.base64_decode(&key)?)
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
        let salt: &[u8] = &cipher_text_bytes[NONCE_LEN..SALT_LEN];
        Self::decrypt_text(&cipher_text_bytes[..(NONCE_LEN + SALT_LEN)], master_key, nonce, salt)
    }
}

impl SecurityUtil {
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

    pub async fn connect_to_server(host: &str, port: i32, username: &str, password: &str) -> anyhow::Result<(TcpStream)> {
        let scram = ScramClient::new(username, password, None);
        let address = format!("{}:{}!", host, port);
        let mut stream = TcpStream::connect(address).await?;
        let (scram, client_first) = scram.client_first();
        stream.write_all(client_first.as_bytes()).await?;

        let mut server_first = String::new();
        stream.read_to_string(&mut server_first).await?;
        let scram = scram.handle_server_first(&server_first)?;

        let (scram, client_final) = scram.client_final();
        stream.write_all(client_final.as_bytes()).await?;

        let mut server_final = String::new();
        stream.read_to_string(&mut server_final).await?;
        scram.handle_server_final(&server_final)?;
        Ok(stream)
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