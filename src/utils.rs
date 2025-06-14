//! Utility functions for anamorphic encryption.

use crate::error::{AnamorphicError, Result};
use rand::{RngCore, thread_rng};

/// PKCS#7 padding implementation
pub mod padding {
    use super::*;

    /// Add PKCS#7 padding to data.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to pad
    /// * `block_size` - The block size for padding (must be between 1 and 255)
    ///
    /// # Returns
    ///
    /// The padded data
    pub fn pad(data: &[u8], block_size: usize) -> Result<Vec<u8>> {
        if block_size == 0 || block_size > 255 {
            return Err(AnamorphicError::invalid_input(
                "Block size must be between 1 and 255"
            ));
        }

        let padding_len = block_size - (data.len() % block_size);
        let mut padded = Vec::with_capacity(data.len() + padding_len);
        padded.extend_from_slice(data);
        padded.resize(data.len() + padding_len, padding_len as u8);
        Ok(padded)
    }

    /// Remove PKCS#7 padding from data.
    ///
    /// # Arguments
    ///
    /// * `data` - The padded data
    ///
    /// # Returns
    ///
    /// The unpadded data
    pub fn unpad(data: &[u8]) -> Result<Vec<u8>> {
        if data.is_empty() {
            return Err(AnamorphicError::PaddingError("Empty data".to_string()));
        }

        let padding_len = *data.last().unwrap() as usize;
        
        if padding_len == 0 || padding_len > data.len() {
            return Err(AnamorphicError::PaddingError("Invalid padding length".to_string()));
        }

        // Verify padding
        let padding_start = data.len() - padding_len;
        for &byte in &data[padding_start..] {
            if byte != padding_len as u8 {
                return Err(AnamorphicError::PaddingError("Invalid padding bytes".to_string()));
            }
        }

        Ok(data[..padding_start].to_vec())
    }
}

/// Random number generation utilities
pub mod random {
    use super::*;

    /// Generate random bytes.
    ///
    /// # Arguments
    ///
    /// * `len` - Number of bytes to generate
    ///
    /// # Returns
    ///
    /// A vector of random bytes
    pub fn generate_bytes(len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        thread_rng().fill_bytes(&mut bytes);
        bytes
    }

    /// Generate a random initialization vector (IV).
    ///
    /// # Arguments
    ///
    /// * `size` - Size of the IV in bytes
    ///
    /// # Returns
    ///
    /// A random IV
    pub fn generate_iv(size: usize) -> Vec<u8> {
        generate_bytes(size)
    }

    /// Generate random padding for anamorphic encryption.
    ///
    /// This creates random data that can be used to hide the real message length.
    ///
    /// # Arguments
    ///
    /// * `min_len` - Minimum length of padding
    /// * `max_len` - Maximum length of padding
    ///
    /// # Returns
    ///
    /// Random padding bytes
    pub fn generate_padding(min_len: usize, max_len: usize) -> Result<Vec<u8>> {
        if min_len > max_len {
            return Err(AnamorphicError::invalid_input(
                "min_len cannot be greater than max_len"
            ));
        }

        let mut rng = thread_rng();
        let len = if min_len == max_len {
            min_len
        } else {
            min_len + (rng.next_u32() as usize % (max_len - min_len + 1))
        };

        Ok(generate_bytes(len))
    }
}

/// XOR utilities
pub mod xor {
    /// XOR two byte slices.
    ///
    /// # Arguments
    ///
    /// * `a` - First byte slice
    /// * `b` - Second byte slice
    ///
    /// # Returns
    ///
    /// XOR result (length is minimum of both inputs)
    pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| x ^ y)
            .collect()
    }

    /// XOR a byte slice with a repeating key.
    ///
    /// # Arguments
    ///
    /// * `data` - Data to XOR
    /// * `key` - Key to XOR with (will be repeated as needed)
    ///
    /// # Returns
    ///
    /// XOR result
    pub fn xor_with_key(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }

        data.iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ key[i % key.len()])
            .collect()
    }
}

/// Encoding utilities
pub mod encoding {
    use super::*;

    /// Encode bytes as base64.
    pub fn to_base64(data: &[u8]) -> String {
        base64_encode(data)
    }

    /// Decode base64 to bytes.
    pub fn from_base64(data: &str) -> Result<Vec<u8>> {
        base64_decode(data).map_err(|e| AnamorphicError::invalid_input(format!("Base64 decode error: {}", e)))
    }

    // Simple base64 implementation
    const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn base64_encode(input: &[u8]) -> String {
        let mut result = String::new();
        let mut i = 0;

        while i < input.len() {
            let b1 = input[i];
            let b2 = if i + 1 < input.len() { input[i + 1] } else { 0 };
            let b3 = if i + 2 < input.len() { input[i + 2] } else { 0 };

            let bitmap = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);

            result.push(BASE64_CHARS[((bitmap >> 18) & 63) as usize] as char);
            result.push(BASE64_CHARS[((bitmap >> 12) & 63) as usize] as char);
            
            if i + 1 < input.len() {
                result.push(BASE64_CHARS[((bitmap >> 6) & 63) as usize] as char);
            } else {
                result.push('=');
            }
            
            if i + 2 < input.len() {
                result.push(BASE64_CHARS[(bitmap & 63) as usize] as char);
            } else {
                result.push('=');
            }

            i += 3;
        }

        result
    }

    fn base64_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
        let mut result = Vec::new();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            let mut bitmap = 0u32;
            let mut valid_chars = 0;

            // Process 4 characters at a time
            for j in 0..4 {
                if i + j < chars.len() {
                    let c = chars[i + j];
                    if c == '=' {
                        break;
                    }
                    
                    let val = match c {
                        'A'..='Z' => (c as u8 - b'A') as u32,
                        'a'..='z' => (c as u8 - b'a' + 26) as u32,
                        '0'..='9' => (c as u8 - b'0' + 52) as u32,
                        '+' => 62,
                        '/' => 63,
                        _ => return Err(format!("Invalid character: {}", c)),
                    };
                    
                    bitmap |= val << (18 - j * 6);
                    valid_chars += 1;
                } else {
                    break;
                }
            }

            // Extract bytes based on how many valid characters we had
            if valid_chars >= 2 {
                result.push((bitmap >> 16) as u8);
            }
            if valid_chars >= 3 {
                result.push((bitmap >> 8) as u8);
            }
            if valid_chars >= 4 {
                result.push(bitmap as u8);
            }

            i += 4;
        }

        Ok(result)
    }
}

/// Constant-time comparison to prevent timing attacks
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// Secure memory clearing (best effort)
pub fn secure_clear(data: &mut [u8]) {
    data.fill(0);
    // Note: This doesn't guarantee the memory is actually cleared
    // due to compiler optimizations, but it's better than nothing
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding() {
        let data = b"hello";
        let padded = padding::pad(data, 8).unwrap();
        assert_eq!(padded.len(), 8);
        assert_eq!(padded[5..], [3, 3, 3]); // 3 bytes of padding with value 3

        let unpadded = padding::unpad(&padded).unwrap();
        assert_eq!(unpadded, data);
    }

    #[test]
    fn test_xor_with_key() {
        let data = &[0x01, 0x02, 0x03, 0x04];
        let key = &[0xFF, 0xFE];
        let result = xor::xor_with_key(data, key);
        assert_eq!(result, vec![0xFE, 0xFC, 0xFC, 0xFA]);
    }

    #[test]
    fn test_xor_bytes() {
        let a = &[0x01, 0x02, 0x03];
        let b = &[0xFF, 0xFE, 0xFD];
        let result = xor::xor_bytes(a, b);
        assert_eq!(result, vec![0xFE, 0xFC, 0xFE]);
    }

    #[test]
    fn test_base64_roundtrip() {
        let data = b"Hello, World!";
        let encoded = encoding::to_base64(data);
        let decoded = encoding::from_base64(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = &[1, 2, 3, 4];
        let b = &[1, 2, 3, 4];
        let c = &[1, 2, 3, 5];
        let d = &[1, 2, 3];

        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(a, d));
    }

    #[test]
    fn test_random_generation() {
        let bytes1 = random::generate_bytes(32);
        let bytes2 = random::generate_bytes(32);
        
        assert_eq!(bytes1.len(), 32);
        assert_eq!(bytes2.len(), 32);
        assert_ne!(bytes1, bytes2); // Very unlikely to be equal
    }

    #[test]
    fn test_random_padding() {
        let padding = random::generate_padding(10, 20).unwrap();
        assert!(padding.len() >= 10 && padding.len() <= 20);
    }
}
