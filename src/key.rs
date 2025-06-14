//! Key management for anamorphic encryption.

use crate::error::{AnamorphicError, Result};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Size of an anamorphic key in bytes (256 bits)
pub const KEY_SIZE: usize = 32;

/// An anamorphic encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnamorphicKey {
    /// The raw key bytes
    key: [u8; KEY_SIZE],
}

impl AnamorphicKey {
    /// Generate a new random key.
    ///
    /// # Example
    ///
    /// ```rust
    /// use anamorphic::AnamorphicKey;
    ///
    /// let key = AnamorphicKey::generate();
    /// ```
    pub fn generate() -> Self {
        let mut key = [0u8; KEY_SIZE];
        thread_rng().fill_bytes(&mut key);
        Self { key }
    }

    /// Create a key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - The key bytes (must be exactly 32 bytes)
    ///
    /// # Errors
    ///
    /// Returns an error if the byte slice is not exactly 32 bytes long.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != KEY_SIZE {
            return Err(AnamorphicError::invalid_key(format!(
                "Key must be {} bytes, got {}",
                KEY_SIZE,
                bytes.len()
            )));
        }

        let mut key = [0u8; KEY_SIZE];
        key.copy_from_slice(bytes);
        Ok(Self { key })
    }

    /// Create a key from a password using PBKDF2-like key derivation.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to derive the key from
    /// * `salt` - Salt for key derivation (should be unique per key)
    /// * `iterations` - Number of iterations for key stretching
    ///
    /// # Example
    ///
    /// ```rust
    /// use anamorphic::AnamorphicKey;
    ///
    /// let salt = b"unique_salt_12345678";
    /// let key = AnamorphicKey::from_password("my_password", salt, 10000);
    /// ```
    pub fn from_password(password: &str, salt: &[u8], iterations: u32) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let mut key = hasher.finalize().into();

        // Simple key stretching
        for _ in 1..iterations {
            let mut hasher = Sha256::new();
            hasher.update(&key);
            hasher.update(salt);
            key = hasher.finalize().into();
        }

        Self { key }
    }

    /// Create a key from a hexadecimal string.
    ///
    /// # Arguments
    ///
    /// * `hex_str` - Hexadecimal string representation of the key
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or not the correct length.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let bytes = hex::decode(hex_str)?;
        Self::from_bytes(&bytes)
    }

    /// Get the raw key bytes.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.key
    }

    /// Convert the key to a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.key)
    }

    /// Derive a subkey from this key using a label.
    ///
    /// This is useful for creating related keys for different purposes.
    ///
    /// # Arguments
    ///
    /// * `label` - A label to distinguish this subkey
    pub fn derive_subkey(&self, label: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(label);
        let key = hasher.finalize().into();
        Self { key }
    }

    /// XOR this key with another key to create a combined key.
    ///
    /// This is used in some anamorphic encryption schemes.
    pub fn xor_with(&self, other: &AnamorphicKey) -> Self {
        let mut result = [0u8; KEY_SIZE];
        for i in 0..KEY_SIZE {
            result[i] = self.key[i] ^ other.key[i];
        }
        Self { key: result }
    }

    /// Check if this key is all zeros (weak key).
    pub fn is_weak(&self) -> bool {
        self.key.iter().all(|&b| b == 0)
    }

    /// Securely clear the key from memory.
    ///
    /// Note: This provides best-effort clearing but cannot guarantee
    /// that the key won't remain in memory due to compiler optimizations.
    pub fn clear(&mut self) {
        self.key.fill(0);
    }
}

impl Drop for AnamorphicKey {
    fn drop(&mut self) {
        self.clear();
    }
}

impl std::fmt::Display for AnamorphicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnamorphicKey({}...)", &self.to_hex()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        let key1 = AnamorphicKey::generate();
        let key2 = AnamorphicKey::generate();
        
        // Keys should be different
        assert_ne!(key1, key2);
        
        // Keys should not be weak
        assert!(!key1.is_weak());
        assert!(!key2.is_weak());
    }

    #[test]
    fn test_key_from_bytes() {
        let bytes = [42u8; KEY_SIZE];
        let key = AnamorphicKey::from_bytes(&bytes).unwrap();
        assert_eq!(key.as_bytes(), &bytes);
    }

    #[test]
    fn test_key_from_bytes_invalid_length() {
        let bytes = [42u8; 16]; // Wrong length
        assert!(AnamorphicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn test_key_from_password() {
        let key1 = AnamorphicKey::from_password("password", b"salt", 1000);
        let key2 = AnamorphicKey::from_password("password", b"salt", 1000);
        let key3 = AnamorphicKey::from_password("password", b"different_salt", 1000);
        
        // Same password and salt should produce same key
        assert_eq!(key1, key2);
        
        // Different salt should produce different key
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_key_hex_roundtrip() {
        let key = AnamorphicKey::generate();
        let hex = key.to_hex();
        let restored = AnamorphicKey::from_hex(&hex).unwrap();
        assert_eq!(key, restored);
    }

    #[test]
    fn test_derive_subkey() {
        let key = AnamorphicKey::generate();
        let subkey1 = key.derive_subkey(b"label1");
        let subkey2 = key.derive_subkey(b"label2");
        let subkey1_again = key.derive_subkey(b"label1");
        
        // Different labels should produce different subkeys
        assert_ne!(subkey1, subkey2);
        
        // Same label should produce same subkey
        assert_eq!(subkey1, subkey1_again);
        
        // Subkeys should be different from parent key
        assert_ne!(key, subkey1);
        assert_ne!(key, subkey2);
    }

    #[test]
    fn test_xor_keys() {
        let key1 = AnamorphicKey::from_bytes(&[0x55u8; KEY_SIZE]).unwrap();
        let key2 = AnamorphicKey::from_bytes(&[0xAAu8; KEY_SIZE]).unwrap();
        let xor_key = key1.xor_with(&key2);
        
        // XOR of 0x55 and 0xAA should be 0xFF
        assert_eq!(xor_key.as_bytes(), &[0xFFu8; KEY_SIZE]);
    }

    #[test]
    fn test_weak_key_detection() {
        let weak_key = AnamorphicKey::from_bytes(&[0u8; KEY_SIZE]).unwrap();
        let strong_key = AnamorphicKey::generate();
        
        assert!(weak_key.is_weak());
        assert!(!strong_key.is_weak());
    }
}
