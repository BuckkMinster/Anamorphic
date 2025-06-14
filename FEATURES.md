# Anamorphic Encryption Library - Features

This document provides a comprehensive overview of all features implemented in the anamorphic encryption library.

## Core Features

### 1. Anamorphic Encryption
- **Single Message Encryption**: Standard AES-256-CBC encryption for single messages
- **Dual Message Encryption**: Encrypt two different messages in a single ciphertext
- **Plausible Deniability**: Each key reveals only its corresponding message
- **Cross-platform Support**: Works on Linux and Windows

### 2. Encryption Schemes

#### Single Encryption
- Uses AES-256-CBC with random IV
- PKCS#7 padding for block alignment
- Secure random number generation

#### Dual XOR Encryption
- Stores two separately encrypted messages
- Key fingerprinting for message identification
- Maintains original message lengths
- Each key reveals only its corresponding plaintext

#### Dual Layered Encryption (Placeholder)
- Framework ready for future implementation
- Designed for more complex anamorphic schemes

#### Dual ElGamal Encryption (Placeholder)
- Framework ready for ElGamal-based anamorphic encryption
- Supports large message spaces through hashing

### 3. ElGamal Cryptosystem

#### Key Generation
- 1024-bit safe prime parameters (RFC 5114 compatible)
- Secure random private key generation
- Public key computation using modular exponentiation

#### Encryption/Decryption
- Standard ElGamal encryption: (c1, c2) = (g^k, m * y^k)
- Modular inverse using Fermat's little theorem
- Support for BigUint arithmetic

#### Utility Functions
- Byte-to-BigUint conversion
- BigUint-to-byte conversion with padding
- Hash-to-group for large messages
- Secure parameter generation

### 4. Key Management

#### Key Generation
- Cryptographically secure random key generation
- Password-based key derivation (PBKDF2 with SHA-256)
- Subkey derivation for hierarchical key structures

#### Key Operations
- Key XOR operations for key combination
- Weak key detection and validation
- Hexadecimal serialization/deserialization
- Constant-time key comparison

#### Key Storage
- Secure key serialization to hex format
- Key loading from hex strings
- Password-based key derivation with salt

### 5. Cryptographic Utilities

#### Padding
- PKCS#7 padding implementation
- Secure padding validation and removal
- Random padding for additional security

#### Random Number Generation
- Cryptographically secure random bytes
- Random IV generation for encryption
- Random padding generation

#### XOR Operations
- Secure XOR operations for byte arrays
- Key-based XOR encryption/decryption
- Constant-time XOR implementations

#### Encoding
- Base64 encoding/decoding
- Hexadecimal encoding/decoding
- Constant-time comparison functions

### 6. Error Handling
- Comprehensive error types for all operations
- Detailed error messages for debugging
- Result-based error propagation
- Input validation and sanitization

### 7. Serialization Support
- JSON serialization for ciphertext structures
- Serde integration for all public types
- Cross-platform compatibility
- Version-aware serialization

## Command Line Interface

### Key Operations
- `generate-key`: Generate new cryptographic keys
- Key loading from files
- Key validation and verification

### Encryption Operations
- `encrypt`: Single message encryption
- `encrypt-dual`: Dual message anamorphic encryption
- Support for file input/output
- JSON ciphertext format

### Decryption Operations
- `decrypt`: Decrypt ciphertext with provided key
- Automatic scheme detection
- Error handling for invalid keys/ciphertext

## Examples and Demonstrations

### Basic Usage Example
- Single and dual encryption demonstrations
- Key management examples
- Plausible deniability scenarios
- Complete workflow examples

### ElGamal Demo
- ElGamal key generation and usage
- Byte data encryption with ElGamal
- Hash-based encryption for large messages
- Performance and security considerations

### Benchmark Suite
- Performance testing for all encryption schemes
- Key generation benchmarks
- Comparison between different approaches
- Memory usage analysis

## Security Features

### Cryptographic Security
- AES-256 encryption with CBC mode
- Secure random number generation
- Proper IV handling and uniqueness
- PKCS#7 padding with validation

### Side-Channel Resistance
- Constant-time comparison operations
- Secure memory handling
- Protection against timing attacks
- Secure key derivation

### Input Validation
- Comprehensive input sanitization
- Length validation for all inputs
- Format validation for keys and ciphertext
- Error handling for malformed data

## Testing and Quality Assurance

### Unit Tests
- Comprehensive test coverage for all modules
- Roundtrip testing for encryption/decryption
- Edge case testing
- Error condition testing

### Integration Tests
- End-to-end workflow testing
- CLI functionality testing
- Cross-platform compatibility testing
- Performance regression testing

### Documentation Tests
- Doctests for all public APIs
- Example code validation
- API documentation accuracy
- Usage pattern verification

## Platform Support

### Linux Support
- Full functionality on Linux systems
- Optimized for Linux cryptographic libraries
- Integration with system random number generators

### Windows Support
- Cross-platform compatibility
- Windows-specific optimizations
- Consistent behavior across platforms

## Future Enhancements

### Planned Features
- Complete ElGamal anamorphic implementation
- Dual layered encryption schemes
- Additional cryptographic primitives
- Performance optimizations

### Research Areas
- Advanced anamorphic encryption schemes
- Post-quantum cryptography integration
- Zero-knowledge proof integration
- Distributed key management

## Dependencies

### Core Dependencies
- `rand`: Cryptographically secure random number generation
- `sha2`: SHA-256 hashing for key derivation
- `aes`: AES encryption implementation
- `hex`: Hexadecimal encoding/decoding
- `serde`: Serialization framework

### Mathematical Dependencies
- `num-bigint`: Big integer arithmetic for ElGamal
- `num-traits`: Numeric trait abstractions
- `num-integer`: Integer-specific operations

### Development Dependencies
- `criterion`: Performance benchmarking
- `serde_json`: JSON serialization for testing

## Performance Characteristics

### Encryption Performance
- Single encryption: ~1-10 μs for small messages
- Dual encryption: ~2-20 μs for small messages
- ElGamal encryption: ~10-100 ms for 1024-bit keys
- Memory usage: Minimal overhead beyond message size

### Key Generation Performance
- AES key generation: ~1-10 μs
- ElGamal key generation: ~100-1000 ms
- Password-based derivation: ~10-100 ms (configurable)

## Security Considerations

### Threat Model
- Protection against passive adversaries
- Plausible deniability under coercion
- Resistance to chosen-plaintext attacks
- Protection against timing attacks

### Limitations
- No protection against active adversaries without authentication
- ElGamal implementation uses fixed parameters
- Key management requires secure storage
- No forward secrecy without key rotation

### Best Practices
- Use unique keys for each encryption operation
- Implement proper key lifecycle management
- Validate all inputs before processing
- Use secure channels for key distribution


anamorphic/
├── src/
│   ├── lib.rs          # Point d'entrée de la bibliothèque
│   ├── cipher.rs       # Implémentation du chiffrement anamorphique
│   ├── elgamal.rs      # Cryptosystème ElGamal
│   ├── key.rs          # Gestion des clés
│   ├── utils.rs        # Utilitaires cryptographiques
│   ├── error.rs        # Gestion d'erreurs
│   └── main.rs         # Interface CLI
├── examples/
│   ├── basic_usage.rs  # Démonstration générale
│   └── elgamal_demo.rs # Démonstration ElGamal
├── benches/
│   └── anamorphic_bench.rs # Tests de performance
└── Documentation complète