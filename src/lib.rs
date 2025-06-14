//! # Anamorphic Encryption Library
//!
//! This library provides anamorphic encryption capabilities, allowing for plausible deniability
//! in cryptographic communications. Anamorphic encryption enables a single ciphertext to be
//! decrypted with different keys to reveal different plaintexts.
//!
//! ## Features
//!
//! - Cross-platform support (Linux and Windows)
//! - Multiple encryption schemes
//! - Key derivation and management
//! - Secure random number generation
//! - JSON serialization support
//!
//! ## Example
//!
//! ```rust
//! use anamorphic::{AnamorphicCipher, AnamorphicKey};
//!
//! // Create keys
//! let key1 = AnamorphicKey::generate();
//! let key2 = AnamorphicKey::generate();
//!
//! // Create cipher
//! let cipher = AnamorphicCipher::new();
//!
//! // Encrypt with dual messages
//! let message1 = b"Public message";
//! let message2 = b"Secret message";
//! let ciphertext = cipher.encrypt_dual(message1, message2, &key1, &key2).unwrap();
//!
//! // Decrypt with different keys reveals different messages
//! let decrypted1 = cipher.decrypt(&ciphertext, &key1).unwrap();
//! let decrypted2 = cipher.decrypt(&ciphertext, &key2).unwrap();
//!
//! assert_eq!(decrypted1, message1);
//! assert_eq!(decrypted2, message2);
//! ```

pub mod cipher;
pub mod elgamal;
pub mod error;
pub mod key;
pub mod utils;

pub use cipher::AnamorphicCipher;
pub use error::{AnamorphicError, Result};
pub use key::AnamorphicKey;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_dual_encryption() {
        let key1 = AnamorphicKey::generate();
        let key2 = AnamorphicKey::generate();
        let cipher = AnamorphicCipher::new();

        let message1 = b" public message";
        let message2 = b"secret message";

        let ciphertext = cipher.encrypt_dual(message1, message2, &key1, &key2).unwrap();

        let decrypted1 = cipher.decrypt(&ciphertext, &key1).unwrap();
        let decrypted2 = cipher.decrypt(&ciphertext, &key2).unwrap();

        assert_eq!(decrypted1, message1);
        assert_eq!(decrypted2, message2);
    }

    #[test]
    fn test_single_encryption() {
        let key = AnamorphicKey::generate();
        let cipher = AnamorphicCipher::new();

        let message = b"Message encryption test";
        let ciphertext = cipher.encrypt(message, &key).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key).unwrap();

        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_key_serialization() {
        let key = AnamorphicKey::generate();
        let serialized = key.to_hex();
        let deserialized = AnamorphicKey::from_hex(&serialized).unwrap();

        assert_eq!(key.as_bytes(), deserialized.as_bytes());
    }
}
