# Security Considerations

This document outlines important security considerations when using the anamorphic encryption library.

## Cryptographic Primitives

### AES-256-CBC
- Uses industry-standard AES-256 encryption in CBC mode
- Each encryption operation uses a randomly generated IV
- PKCS#7 padding is applied to ensure block alignment

### Key Derivation
- PBKDF2 with SHA-256 for password-based key derivation
- Minimum 10,000 iterations recommended (configurable)
- Salt should be unique and at least 16 bytes

### Random Number Generation
- Uses the system's cryptographically secure random number generator
- All IVs and keys are generated using `rand::thread_rng()`

## Anamorphic Encryption Security

### Plausible Deniability
- The dual encryption scheme provides computational plausible deniability
- An attacker with one key cannot prove the existence of a second message
- Both messages appear equally valid when decrypted with their respective keys

### Key Management
- Keys should be generated using cryptographically secure random sources
- Store keys securely and never reuse them across different contexts
- Consider using hardware security modules (HSMs) for key storage in production

### Limitations
- This implementation is for educational and research purposes
- The anamorphic encryption scheme is simplified and may not provide the same security guarantees as academic implementations
- Consider formal security analysis before using in production environments

## Best Practices

### Key Generation
```rust
// Good: Use the built-in secure key generation
let key = AnamorphicKey::generate();

// Good: Derive from a strong password with salt
let key = AnamorphicKey::from_password("strong_password", &salt, 100000);

// Bad: Don't use weak or predictable keys
let weak_key = AnamorphicKey::from_bytes(&[0u8; 32]).unwrap(); // All zeros
```

### Message Handling
- Clear sensitive data from memory after use
- Be aware that Rust's memory safety doesn't prevent all side-channel attacks
- Consider using constant-time operations for sensitive comparisons

### Error Handling
- Don't leak information through error messages
- Use constant-time comparison for authentication tags
- Implement proper error handling to prevent timing attacks

## Known Limitations

1. **Side-Channel Attacks**: This implementation doesn't protect against timing attacks or other side-channel attacks
2. **Memory Safety**: Sensitive data may remain in memory after use
3. **Quantum Resistance**: AES-256 provides limited quantum resistance
4. **Implementation Security**: This is a reference implementation, not audited for production use

## Threat Model

### What This Library Protects Against
- Passive eavesdropping on encrypted communications
- Coercion scenarios where revealing one key is acceptable
- Basic cryptanalysis attempts on properly encrypted data

### What This Library Does NOT Protect Against
- Advanced persistent threats with access to implementation details
- Side-channel attacks (timing, power analysis, etc.)
- Quantum computers with sufficient qubits
- Rubber-hose cryptanalysis (physical coercion)
- Malware with access to keys in memory

## Reporting Security Issues

If you discover a security vulnerability in this library, please:

1. **Do not** open a public issue
2. Email the maintainers directly with details
3. Allow reasonable time for a fix before public disclosure
4. Provide clear reproduction steps if possible

## Compliance and Standards

This library implements:
- AES-256 as specified in FIPS 197
- PBKDF2 as specified in RFC 2898
- PKCS#7 padding as specified in RFC 5652

Note: This implementation has not undergone formal security auditing or certification.

## Disclaimer

This software is provided "as is" without warranty of any kind. The authors are not responsible for any damages or security breaches resulting from the use of this library. Users should conduct their own security assessment before using this library in production environments.
