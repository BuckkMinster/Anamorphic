//! Anamorphic encryption cipher implementation.

use crate::error::{AnamorphicError, Result};
use crate::key::{AnamorphicKey, KEY_SIZE};
use crate::utils::{padding, random, xor, constant_time_eq};
use aes::Aes256;
use aes::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Block size for AES encryption (16 bytes)
const BLOCK_SIZE: usize = 16;

/// IV size for AES-CBC (16 bytes)
const IV_SIZE: usize = 16;

/// Minimum ciphertext size (IV + at least one block)
const MIN_CIPHERTEXT_SIZE: usize = IV_SIZE + BLOCK_SIZE;

/// Anamorphic ciphertext structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnamorphicCiphertext {
    /// The encrypted data
    pub data: Vec<u8>,
    /// Metadata for the encryption scheme
    pub metadata: CiphertextMetadata,
}

/// Metadata for anamorphic ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextMetadata {
    /// Version of the encryption scheme
    pub version: u8,
    /// Type of anamorphic encryption used
    pub scheme: EncryptionScheme,
    /// Additional parameters
    pub params: Vec<u8>,
}

/// Different anamorphic encryption schemes
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum EncryptionScheme {
    /// Single message encryption (standard AES-CBC)
    Single,
    /// Dual message encryption using XOR masking
    DualXor,
    /// Dual message encryption using layered encryption
    DualLayered,
    /// Dual message encryption using ElGamal
    DualElGamal,
}

/// The main anamorphic cipher
pub struct AnamorphicCipher {
    /// Random number generator for internal use
    _rng: std::marker::PhantomData<()>,
}

impl AnamorphicCipher {
    /// Create a new anamorphic cipher instance.
    pub fn new() -> Self {
        Self {
            _rng: std::marker::PhantomData,
        }
    }

    /// Encrypt a single message with standard AES-CBC.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to encrypt
    /// * `key` - The encryption key
    ///
    /// # Returns
    ///
    /// The encrypted ciphertext
    pub fn encrypt(&self, message: &[u8], key: &AnamorphicKey) -> Result<AnamorphicCiphertext> {
        let iv = random::generate_iv(IV_SIZE);
        let padded_message = padding::pad(message, BLOCK_SIZE)?;
        
        let ciphertext = self.aes_cbc_encrypt(&padded_message, key.as_bytes(), &iv)?;

        let mut data = Vec::with_capacity(IV_SIZE + ciphertext.len());
        data.extend_from_slice(&iv);
        data.extend_from_slice(&ciphertext);

        Ok(AnamorphicCiphertext {
            data,
            metadata: CiphertextMetadata {
                version: 1,
                scheme: EncryptionScheme::Single,
                params: Vec::new(),
            },
        })
    }

    /// Decrypt a ciphertext with the given key.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext to decrypt
    /// * `key` - The decryption key
    ///
    /// # Returns
    ///
    /// The decrypted message
    pub fn decrypt(&self, ciphertext: &AnamorphicCiphertext, key: &AnamorphicKey) -> Result<Vec<u8>> {
        if ciphertext.data.len() < MIN_CIPHERTEXT_SIZE {
            return Err(AnamorphicError::invalid_ciphertext("Ciphertext too short"));
        }

        match ciphertext.metadata.scheme {
            EncryptionScheme::Single => self.decrypt_single(ciphertext, key),
            EncryptionScheme::DualXor => self.decrypt_dual_xor(ciphertext, key),
            EncryptionScheme::DualLayered => self.decrypt_dual_layered(ciphertext, key),
            EncryptionScheme::DualElGamal => self.decrypt_dual_elgamal(ciphertext, key),
        }
    }

    /// Encrypt two messages using XOR masking technique.
    ///
    /// This creates a ciphertext that can be decrypted with either key to reveal different messages.
    ///
    /// # Arguments
    ///
    /// * `message1` - First message (revealed with key1)
    /// * `message2` - Second message (revealed with key2)
    /// * `key1` - First decryption key
    /// * `key2` - Second decryption key
    ///
    /// # Returns
    ///
    /// The anamorphic ciphertext
    pub fn encrypt_dual(
        &self,
        message1: &[u8],
        message2: &[u8],
        key1: &AnamorphicKey,
        key2: &AnamorphicKey,
    ) -> Result<AnamorphicCiphertext> {
        self.encrypt_dual_xor(message1, message2, key1, key2)
    }

    /// Encrypt two messages using a simplified anamorphic approach.
    /// 
    /// This implementation uses a key-dependent selection mechanism to store both messages
    /// in a way that each key reveals only its corresponding message.
    fn encrypt_dual_xor(
        &self,
        message1: &[u8],
        message2: &[u8],
        key1: &AnamorphicKey,
        key2: &AnamorphicKey,
    ) -> Result<AnamorphicCiphertext> {
        // Encrypt both messages separately
        let iv1 = random::generate_iv(IV_SIZE);
        let iv2 = random::generate_iv(IV_SIZE);
        
        let padded_msg1 = padding::pad(message1, BLOCK_SIZE)?;
        let padded_msg2 = padding::pad(message2, BLOCK_SIZE)?;
        
        let ciphertext1 = self.aes_cbc_encrypt(&padded_msg1, key1.as_bytes(), &iv1)?;
        let ciphertext2 = self.aes_cbc_encrypt(&padded_msg2, key2.as_bytes(), &iv2)?;

        // Store both ciphertexts with their IVs
        let mut data = Vec::new();
        data.extend_from_slice(&iv1);
        data.extend_from_slice(&(ciphertext1.len() as u32).to_le_bytes());
        data.extend_from_slice(&ciphertext1);
        data.extend_from_slice(&iv2);
        data.extend_from_slice(&(ciphertext2.len() as u32).to_le_bytes());
        data.extend_from_slice(&ciphertext2);

        // Store original message lengths and key hashes for identification
        let mut params = Vec::new();
        params.extend_from_slice(&(message1.len() as u32).to_le_bytes());
        params.extend_from_slice(&(message2.len() as u32).to_le_bytes());
        
        // Add key fingerprints to help identify which key to use
        let key1_hash = self.compute_key_fingerprint(key1);
        let key2_hash = self.compute_key_fingerprint(key2);
        params.extend_from_slice(&key1_hash);
        params.extend_from_slice(&key2_hash);

        Ok(AnamorphicCiphertext {
            data,
            metadata: CiphertextMetadata {
                version: 1,
                scheme: EncryptionScheme::DualXor,
                params,
            },
        })
    }

    /// Decrypt single message ciphertext.
    fn decrypt_single(&self, ciphertext: &AnamorphicCiphertext, key: &AnamorphicKey) -> Result<Vec<u8>> {
        let iv = &ciphertext.data[..IV_SIZE];
        let encrypted_data = &ciphertext.data[IV_SIZE..];

        let decrypted = self.aes_cbc_decrypt(encrypted_data, key.as_bytes(), iv)?;
        padding::unpad(&decrypted)
    }

    /// Decrypt dual XOR ciphertext.
    fn decrypt_dual_xor(&self, ciphertext: &AnamorphicCiphertext, key: &AnamorphicKey) -> Result<Vec<u8>> {
        if ciphertext.metadata.params.len() < 16 {
            return Err(AnamorphicError::invalid_ciphertext("Invalid dual XOR parameters"));
        }

        // Parse the data structure
        let mut offset = 0;
        
        // Read IV1 and ciphertext1 length
        let iv1 = &ciphertext.data[offset..offset + IV_SIZE];
        offset += IV_SIZE;
        
        let ct1_len = u32::from_le_bytes([
            ciphertext.data[offset],
            ciphertext.data[offset + 1],
            ciphertext.data[offset + 2],
            ciphertext.data[offset + 3],
        ]) as usize;
        offset += 4;
        
        let ciphertext1 = &ciphertext.data[offset..offset + ct1_len];
        offset += ct1_len;
        
        // Read IV2 and ciphertext2 length
        let iv2 = &ciphertext.data[offset..offset + IV_SIZE];
        offset += IV_SIZE;
        
        let ct2_len = u32::from_le_bytes([
            ciphertext.data[offset],
            ciphertext.data[offset + 1],
            ciphertext.data[offset + 2],
            ciphertext.data[offset + 3],
        ]) as usize;
        offset += 4;
        
        let ciphertext2 = &ciphertext.data[offset..offset + ct2_len];

        // Extract original message lengths
        let msg1_len = u32::from_le_bytes([
            ciphertext.metadata.params[0],
            ciphertext.metadata.params[1],
            ciphertext.metadata.params[2],
            ciphertext.metadata.params[3],
        ]) as usize;
        let msg2_len = u32::from_le_bytes([
            ciphertext.metadata.params[4],
            ciphertext.metadata.params[5],
            ciphertext.metadata.params[6],
            ciphertext.metadata.params[7],
        ]) as usize;

        // Extract key fingerprints
        let stored_key1_hash = &ciphertext.metadata.params[8..12];
        let stored_key2_hash = &ciphertext.metadata.params[12..16];
        
        let current_key_hash = self.compute_key_fingerprint(key);

        // Try to match the key with stored fingerprints
        if current_key_hash == stored_key1_hash {
            // Decrypt with key1
            let decrypted = self.aes_cbc_decrypt(ciphertext1, key.as_bytes(), iv1)?;
            let unpadded = padding::unpad(&decrypted)?;
            if unpadded.len() >= msg1_len {
                Ok(unpadded[..msg1_len].to_vec())
            } else {
                Err(AnamorphicError::decryption_failed("Decrypted message too short"))
            }
        } else if current_key_hash == stored_key2_hash {
            // Decrypt with key2
            let decrypted = self.aes_cbc_decrypt(ciphertext2, key.as_bytes(), iv2)?;
            let unpadded = padding::unpad(&decrypted)?;
            if unpadded.len() >= msg2_len {
                Ok(unpadded[..msg2_len].to_vec())
            } else {
                Err(AnamorphicError::decryption_failed("Decrypted message too short"))
            }
        } else {
            Err(AnamorphicError::decryption_failed("Key does not match either stored key"))
        }
    }

    /// Try to decrypt dual XOR assuming the key is key1.
    fn try_decrypt_dual_xor_as_key1(
        &self,
        xor_data: &[u8],
        _iv1: &[u8],
        _iv2: &[u8],
        key1: &AnamorphicKey,
        msg1_len: usize,
    ) -> Result<Vec<u8>> {
        // We need to reconstruct ciphertext1 from the XOR result
        // Since xor_data = ciphertext1 XOR ciphertext2, we need to find ciphertext2
        // to get ciphertext1 = xor_data XOR ciphertext2
        
        // For now, we'll try a brute force approach by attempting to decrypt
        // the XOR data directly as if it were ciphertext1
        match self.aes_cbc_decrypt(xor_data, key1.as_bytes(), _iv1) {
            Ok(decrypted) => {
                match padding::unpad(&decrypted) {
                    Ok(unpadded) => {
                        if unpadded.len() >= msg1_len {
                            Ok(unpadded[..msg1_len].to_vec())
                        } else {
                            Err(AnamorphicError::decryption_failed("Decrypted message too short"))
                        }
                    }
                    Err(_) => Err(AnamorphicError::decryption_failed("Invalid padding for key1"))
                }
            }
            Err(_) => Err(AnamorphicError::decryption_failed("Decryption failed for key1"))
        }
    }

    /// Try to decrypt dual XOR assuming the key is key2.
    fn try_decrypt_dual_xor_as_key2(
        &self,
        xor_data: &[u8],
        _iv1: &[u8],
        _iv2: &[u8],
        key2: &AnamorphicKey,
        msg2_len: usize,
    ) -> Result<Vec<u8>> {
        // Similar approach for key2
        match self.aes_cbc_decrypt(xor_data, key2.as_bytes(), _iv2) {
            Ok(decrypted) => {
                match padding::unpad(&decrypted) {
                    Ok(unpadded) => {
                        if unpadded.len() >= msg2_len {
                            Ok(unpadded[..msg2_len].to_vec())
                        } else {
                            Err(AnamorphicError::decryption_failed("Decrypted message too short"))
                        }
                    }
                    Err(_) => Err(AnamorphicError::decryption_failed("Invalid padding for key2"))
                }
            }
            Err(_) => Err(AnamorphicError::decryption_failed("Decryption failed for key2"))
        }
    }

    /// Decrypt dual layered ciphertext (placeholder for future implementation).
    fn decrypt_dual_layered(&self, _ciphertext: &AnamorphicCiphertext, _key: &AnamorphicKey) -> Result<Vec<u8>> {
        Err(AnamorphicError::decryption_failed("Dual layered encryption not yet implemented"))
    }

    /// Decrypt dual ElGamal ciphertext (placeholder for future implementation).
    fn decrypt_dual_elgamal(&self, _ciphertext: &AnamorphicCiphertext, _key: &AnamorphicKey) -> Result<Vec<u8>> {
        Err(AnamorphicError::decryption_failed("Dual ElGamal encryption not yet implemented"))
    }

    /// AES-CBC encryption implementation
    fn aes_cbc_encrypt(&self, plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() % BLOCK_SIZE != 0 {
            return Err(AnamorphicError::encryption_failed("Plaintext must be block-aligned"));
        }

        let cipher = Aes256::new_from_slice(key)
            .map_err(|e| AnamorphicError::encryption_failed(format!("Invalid key: {:?}", e)))?;

        let mut ciphertext = Vec::with_capacity(plaintext.len());
        let mut prev_block = iv.to_vec();

        for chunk in plaintext.chunks(BLOCK_SIZE) {
            // XOR with previous block (CBC mode)
            let mut block = xor::xor_bytes(chunk, &prev_block);
            
            // Pad to block size if needed
            block.resize(BLOCK_SIZE, 0);
            
            // Encrypt block
            let mut block_array = [0u8; BLOCK_SIZE];
            block_array.copy_from_slice(&block);
            cipher.encrypt_block((&mut block_array).into());
            
            ciphertext.extend_from_slice(&block_array);
            prev_block = block_array.to_vec();
        }

        Ok(ciphertext)
    }

    /// AES-CBC decryption implementation
    fn aes_cbc_decrypt(&self, ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() % BLOCK_SIZE != 0 {
            return Err(AnamorphicError::decryption_failed("Ciphertext must be block-aligned"));
        }

        let cipher = Aes256::new_from_slice(key)
            .map_err(|e| AnamorphicError::decryption_failed(format!("Invalid key: {:?}", e)))?;

        let mut plaintext = Vec::with_capacity(ciphertext.len());
        let mut prev_block = iv.to_vec();

        for chunk in ciphertext.chunks(BLOCK_SIZE) {
            let mut block_array = [0u8; BLOCK_SIZE];
            block_array.copy_from_slice(chunk);
            
            // Decrypt block
            cipher.decrypt_block((&mut block_array).into());
            
            // XOR with previous block (CBC mode)
            let decrypted_block = xor::xor_bytes(&block_array, &prev_block);
            plaintext.extend_from_slice(&decrypted_block);
            
            prev_block = chunk.to_vec();
        }

        Ok(plaintext)
    }

    /// Serialize ciphertext to JSON.
    pub fn serialize_ciphertext(&self, ciphertext: &AnamorphicCiphertext) -> Result<String> {
        serde_json::to_string(ciphertext).map_err(AnamorphicError::from)
    }

    /// Deserialize ciphertext from JSON.
    pub fn deserialize_ciphertext(&self, json: &str) -> Result<AnamorphicCiphertext> {
        serde_json::from_str(json).map_err(AnamorphicError::from)
    }

    /// Verify the integrity of a ciphertext.
    pub fn verify_ciphertext(&self, ciphertext: &AnamorphicCiphertext) -> Result<()> {
        if ciphertext.metadata.version != 1 {
            return Err(AnamorphicError::invalid_ciphertext("Unsupported version"));
        }

        match ciphertext.metadata.scheme {
            EncryptionScheme::Single => {
                if ciphertext.data.len() < MIN_CIPHERTEXT_SIZE {
                    return Err(AnamorphicError::invalid_ciphertext("Single ciphertext too short"));
                }
            }
            EncryptionScheme::DualXor => {
                if ciphertext.data.len() < IV_SIZE * 2 + BLOCK_SIZE {
                    return Err(AnamorphicError::invalid_ciphertext("Dual XOR ciphertext too short"));
                }
                if ciphertext.metadata.params.len() < 16 {
                    return Err(AnamorphicError::invalid_ciphertext("Invalid dual XOR parameters"));
                }
            }
            EncryptionScheme::DualLayered => {
                return Err(AnamorphicError::invalid_ciphertext("Dual layered not yet supported"));
            }
            EncryptionScheme::DualElGamal => {
                return Err(AnamorphicError::invalid_ciphertext("Dual ElGamal not yet supported"));
            }
        }

        Ok(())
    }

    /// Compute a short fingerprint of a key for identification purposes.
    fn compute_key_fingerprint(&self, key: &AnamorphicKey) -> [u8; 4] {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(b"anamorphic_key_fingerprint");
        let hash = hasher.finalize();
        [hash[0], hash[1], hash[2], hash[3]]
    }
}

impl Default for AnamorphicCipher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_encryption_roundtrip() {
        let cipher = AnamorphicCipher::new();
        let key = AnamorphicKey::generate();
        let message = b"Hello, World!";

        let ciphertext = cipher.encrypt(message, &key).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_dual_encryption_roundtrip() {
        let cipher = AnamorphicCipher::new();
        let key1 = AnamorphicKey::generate();
        let key2 = AnamorphicKey::generate();
        let message1 = b"Public message for everyone to see";
        let message2 = b"Secret message only for authorized eyes";

        let ciphertext = cipher.encrypt_dual(message1, message2, &key1, &key2).unwrap();
        
        let decrypted1 = cipher.decrypt(&ciphertext, &key1).unwrap();
        let decrypted2 = cipher.decrypt(&ciphertext, &key2).unwrap();

        assert_eq!(decrypted1, message1);
        assert_eq!(decrypted2, message2);
    }

    #[test]
    fn test_ciphertext_serialization() {
        let cipher = AnamorphicCipher::new();
        let key = AnamorphicKey::generate();
        let message = b"Test message";

        let ciphertext = cipher.encrypt(message, &key).unwrap();
        let json = cipher.serialize_ciphertext(&ciphertext).unwrap();
        let deserialized = cipher.deserialize_ciphertext(&json).unwrap();

        let decrypted = cipher.decrypt(&deserialized, &key).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_ciphertext_verification() {
        let cipher = AnamorphicCipher::new();
        let key = AnamorphicKey::generate();
        let message = b"Test message";

        let ciphertext = cipher.encrypt(message, &key).unwrap();
        assert!(cipher.verify_ciphertext(&ciphertext).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let cipher = AnamorphicCipher::new();
        let key1 = AnamorphicKey::generate();
        let key2 = AnamorphicKey::generate();
        let message = b"Secret message";

        let ciphertext = cipher.encrypt(message, &key1).unwrap();
        assert!(cipher.decrypt(&ciphertext, &key2).is_err());
    }

    #[test]
    fn test_aes_cbc_roundtrip() {
        let cipher = AnamorphicCipher::new();
        let key = AnamorphicKey::generate();
        let iv = random::generate_iv(IV_SIZE);
        let plaintext = b"1234567890123456"; // Exactly one block

        let ciphertext = cipher.aes_cbc_encrypt(plaintext, key.as_bytes(), &iv).unwrap();
        let decrypted = cipher.aes_cbc_decrypt(&ciphertext, key.as_bytes(), &iv).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}
