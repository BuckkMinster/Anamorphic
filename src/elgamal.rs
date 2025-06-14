//! ElGamal encryption implementation for anamorphic encryption.

use crate::error::{AnamorphicError, Result};
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One, Pow};
use rand::{RngCore, thread_rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// ElGamal public key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPublicKey {
    /// Generator g
    pub g: BigUint,
    /// Prime modulus p
    pub p: BigUint,
    /// Public key y = g^x mod p
    pub y: BigUint,
}

/// ElGamal private key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalPrivateKey {
    /// Private exponent x
    pub x: BigUint,
    /// Prime modulus p
    pub p: BigUint,
    /// Generator g
    pub g: BigUint,
}

/// ElGamal key pair
#[derive(Debug, Clone)]
pub struct ElGamalKeyPair {
    pub public_key: ElGamalPublicKey,
    pub private_key: ElGamalPrivateKey,
}

/// ElGamal ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElGamalCiphertext {
    /// First component c1 = g^k mod p
    pub c1: BigUint,
    /// Second component c2 = m * y^k mod p
    pub c2: BigUint,
}

/// ElGamal encryption parameters
pub struct ElGamalParams {
    /// Prime modulus p (should be a safe prime)
    pub p: BigUint,
    /// Generator g
    pub g: BigUint,
}

impl ElGamalParams {
    /// Generate secure ElGamal parameters
    /// 
    /// Note: This is a simplified implementation for demonstration.
    /// In production, use well-known safe primes or proper prime generation.
    pub fn generate(bit_length: usize) -> Result<Self> {
        if bit_length < 1024 {
            return Err(AnamorphicError::invalid_input("Bit length must be at least 1024"));
        }

        // Use a well-known safe prime for demonstration
        // In practice, you'd generate or use standardized parameters
        let p = Self::get_safe_prime_1024();
        let g = BigUint::from(2u32); // Common generator

        Ok(ElGamalParams { p, g })
    }

    /// Get a well-known 1024-bit safe prime for demonstration
    fn get_safe_prime_1024() -> BigUint {
        // This is the 1024-bit MODP Group from RFC 5114
        let p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF";
        BigUint::parse_bytes(p_hex.as_bytes(), 16).unwrap()
    }
}

impl ElGamalKeyPair {
    /// Generate a new ElGamal key pair
    pub fn generate(params: &ElGamalParams) -> Result<Self> {
        let mut rng = thread_rng();
        
        // Generate private key x randomly in [1, p-2]
        let x = rng.gen_biguint_range(&BigUint::one(), &(&params.p - BigUint::one()));
        
        // Compute public key y = g^x mod p
        let y = params.g.modpow(&x, &params.p);
        
        let public_key = ElGamalPublicKey {
            g: params.g.clone(),
            p: params.p.clone(),
            y,
        };
        
        let private_key = ElGamalPrivateKey {
            x,
            p: params.p.clone(),
            g: params.g.clone(),
        };
        
        Ok(ElGamalKeyPair {
            public_key,
            private_key,
        })
    }

    /// Encrypt a message using ElGamal
    pub fn encrypt(&self, message: &BigUint) -> Result<ElGamalCiphertext> {
        if message >= &self.public_key.p {
            return Err(AnamorphicError::invalid_input("Message must be less than modulus"));
        }

        let mut rng = thread_rng();
        
        // Generate random k in [1, p-2]
        let k = rng.gen_biguint_range(&BigUint::one(), &(&self.public_key.p - BigUint::one()));
        
        // Compute c1 = g^k mod p
        let c1 = self.public_key.g.modpow(&k, &self.public_key.p);
        
        // Compute c2 = m * y^k mod p
        let y_k = self.public_key.y.modpow(&k, &self.public_key.p);
        let c2 = (message * y_k) % &self.public_key.p;
        
        Ok(ElGamalCiphertext { c1, c2 })
    }

    /// Decrypt a ciphertext using ElGamal
    pub fn decrypt(&self, ciphertext: &ElGamalCiphertext) -> Result<BigUint> {
        // Compute s = c1^x mod p
        let s = ciphertext.c1.modpow(&self.private_key.x, &self.private_key.p);
        
        // Compute s^(-1) mod p
        let s_inv = Self::mod_inverse(&s, &self.private_key.p)?;
        
        // Compute m = c2 * s^(-1) mod p
        let message = (&ciphertext.c2 * s_inv) % &self.private_key.p;
        
        Ok(message)
    }

    /// Compute modular inverse using Fermat's little theorem for prime modulus
    /// Since we're using a prime modulus p, we can compute a^(-1) = a^(p-2) mod p
    fn mod_inverse(a: &BigUint, p: &BigUint) -> Result<BigUint> {
        if a.is_zero() {
            return Err(AnamorphicError::invalid_input("Cannot compute inverse of zero"));
        }
        
        // For prime p: a^(-1) = a^(p-2) mod p
        let exponent = p - BigUint::from(2u32);
        let result = a.modpow(&exponent, p);
        
        Ok(result)
    }
}

/// Convert bytes to BigUint for encryption
pub fn bytes_to_biguint(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// Convert BigUint back to bytes for decryption
pub fn biguint_to_bytes(num: &BigUint, target_len: usize) -> Vec<u8> {
    let mut bytes = num.to_bytes_be();
    
    // Pad with leading zeros if necessary
    while bytes.len() < target_len {
        bytes.insert(0, 0);
    }
    
    // Truncate if too long (shouldn't happen in normal use)
    if bytes.len() > target_len {
        bytes = bytes[bytes.len() - target_len..].to_vec();
    }
    
    bytes
}

/// Hash data to fit within ElGamal modulus
pub fn hash_to_group(data: &[u8], modulus: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash = hasher.finalize();
    
    let hash_num = BigUint::from_bytes_be(&hash);
    hash_num % modulus
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_elgamal_key_generation() {
        let params = ElGamalParams::generate(1024).unwrap();
        let keypair = ElGamalKeyPair::generate(&params).unwrap();
        
        assert_eq!(keypair.public_key.p, params.p);
        assert_eq!(keypair.public_key.g, params.g);
        assert_eq!(keypair.private_key.p, params.p);
        assert_eq!(keypair.private_key.g, params.g);
    }

    #[test]
    fn test_elgamal_encryption_decryption() {
        let params = ElGamalParams::generate(1024).unwrap();
        let keypair = ElGamalKeyPair::generate(&params).unwrap();
        
        let message = BigUint::from(12345u32);
        let ciphertext = keypair.encrypt(&message).unwrap();
        let decrypted = keypair.decrypt(&ciphertext).unwrap();
        
        assert_eq!(message, decrypted);
    }

    #[test]
    fn test_bytes_conversion() {
        let original_bytes = b"Hello, World!";
        let num = bytes_to_biguint(original_bytes);
        let converted_bytes = biguint_to_bytes(&num, original_bytes.len());
        
        assert_eq!(original_bytes.to_vec(), converted_bytes);
    }

    #[test]
    fn test_hash_to_group() {
        let params = ElGamalParams::generate(1024).unwrap();
        let data = b"test data";
        let hash = hash_to_group(data, &params.p);
        
        assert!(hash < params.p);
    }
}
