//! Error types for the anamorphic encryption library.

use thiserror::Error;

/// Result type alias for anamorphic operations.
pub type Result<T> = std::result::Result<T, AnamorphicError>;

/// Error types that can occur during anamorphic encryption operations.
#[derive(Error, Debug)]
pub enum AnamorphicError {
    /// Invalid key format or size
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Encryption operation failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption operation failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid ciphertext format
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Invalid input data
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Random number generation error
    #[error("Random generation error: {0}")]
    RandomError(String),

    /// Padding error
    #[error("Padding error: {0}")]
    PaddingError(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

impl AnamorphicError {
    /// Create a new InvalidKey error
    pub fn invalid_key<S: Into<String>>(msg: S) -> Self {
        AnamorphicError::InvalidKey(msg.into())
    }

    /// Create a new EncryptionFailed error
    pub fn encryption_failed<S: Into<String>>(msg: S) -> Self {
        AnamorphicError::EncryptionFailed(msg.into())
    }

    /// Create a new DecryptionFailed error
    pub fn decryption_failed<S: Into<String>>(msg: S) -> Self {
        AnamorphicError::DecryptionFailed(msg.into())
    }

    /// Create a new InvalidCiphertext error
    pub fn invalid_ciphertext<S: Into<String>>(msg: S) -> Self {
        AnamorphicError::InvalidCiphertext(msg.into())
    }

    /// Create a new InvalidInput error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        AnamorphicError::InvalidInput(msg.into())
    }
}
