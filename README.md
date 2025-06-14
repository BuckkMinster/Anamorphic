# Anamorphic Encryption Library

A complete Rust library for anamorphic encryption, enabling plausible deniability in cryptographic communications.

## What is anamorphic encryption?

Anamorphic encryption is an advanced cryptographic technique that allows the same ciphertext to be decrypted with different keys to reveal different plaintext messages. This unique property provides **plausible deniability**—the ability to credibly deny the existence of a secret message.

## Features

- ✅ **Single Encryption**: Standard AES-256-CBC encryption
- ✅ **Dual Encryption**: One ciphertext, two different messages
- ✅ **Plausible Deniability**: Protection against coercion
- ✅ **Cross-platform**: Linux and Windows compatible
- ✅ **JSON Serialization**: Easy export/import of encrypted data
- ✅ **CLI Interface**: Command-line tool included
- ✅ **Secure Key Management**: Generation, derivation, and storage
- ✅ **Comprehensive Testing**: Test suite and benchmarks

## Installation
Add this dependency to your `Cargo.toml`:

```toml
[dependencies]
anamorphic = "0.1.0"
```

## Quick Start

### Simple encryption

```rust
use anamorphic::{AnamorphicCipher, AnamorphicKey};

// Generate Key
let key = AnamorphicKey::generate();

//  Create cipher
let cipher = AnamorphicCipher::new();

//  Encrypt message
let message = b"Message secret";
let ciphertext = cipher.encrypt(message, &key)?;

// decrypt
let decrypted = cipher.decrypt(&ciphertext, &key)?;
assert_eq!(decrypted, message);
```

### Anamorphic encryption (dual)

```rust
use anamorphic::{AnamorphicCipher, AnamorphicKey};

// Generate 2 keys
let key1 = AnamorphicKey::generate();
let key2 = AnamorphicKey::generate();

let cipher = AnamorphicCipher::new();

// Generate 2 different messages
let public_msg = b"Innocent public message";
let secret_msg = b"Secret hidden message";

// Encrypt the 2 messages into 1 encrypted message
let ciphertext = cipher.encrypt_dual(public_msg, secret_msg, &key1, &key2)?;

// Decrypt with the first key to get the first message
let decrypted1 = cipher.decrypt(&ciphertext, &key1)?;
assert_eq!(decrypted1, public_msg);

// Decrypt with the second key to get the second message
let decrypted2 = cipher.decrypt(&ciphertext, &key2)?;
assert_eq!(decrypted2, secret_msg);
```

### Generate key

```bash
# Generate and print key
cargo run --bin anamorphic-cli generate-key

# Save key to a file
cargo run --bin anamorphic-cli generate-key my_key.hex
```

### Simple encryption

```bash
# Encrypt a message
cargo run --bin anamorphic-cli encrypt my_key.hex "My secret message"

# Decrypt
cargo run --bin anamorphic-cli decrypt my_key.hex ciphertext.json
```

### Dual encryption

```bash
# Encrypt two messages
cargo run --bin anamorphic-cli encrypt-dual key1.hex key2.hex "Public message" "Secret message"

# Decrypt with the first key
cargo run --bin anamorphic-cli decrypt key1.hex dual_ciphertext.json

# Decrypt with the second key
cargo run --bin anamorphic-cli decrypt key2.hex dual_ciphertext.json
```

## Key Management

### Key Generation

```rust
use anamorphic::AnamorphicKey;

// Random generation
let key = AnamorphicKey::generate();

// From a password
let salt = b"unique_salt_123456789";
let key = AnamorphicKey::from_password("my_password", salt, 10000);

// From bytes
let bytes = [42u8; 32];
let key = AnamorphicKey::from_bytes(&bytes)?;

// From a hexadecimal string
let hex_key = "1234567890abcdef...";
let key = AnamorphicKey::from_hex(hex_key)?;
```

### Key Operations

```rust
// Serialization
let hex_string = key.to_hex();

// Subkey derivation
let subkey = key.derive_subkey(b"unique_label");

// XOR combination
let combined_key = key1.xor_with(&key2);

// Security verification
if key.is_weak() {
    println!("Warning: weak key detected!");
}
```

## Serialization

```rust
// Serialize to JSON
let json = cipher.serialize_ciphertext(&ciphertext)?;

// Deserialize from JSON
let restored_ciphertext = cipher.deserialize_ciphertext(&json)?;

// Verify integrity
cipher.verify_ciphertext(&ciphertext)?;
```

## Security

### Algorithms Used

- **Encryption**: AES-256 in CBC mode
- **Hashing**: SHA-256 for key derivation
- **Padding**: PKCS#7
- **Random**: Cryptographically secure generator

### Security Considerations

1. **Key Management**: Keys are automatically cleared from memory
2. **Random IVs**: Each encryption uses a unique IV
3. **Random Padding**: Masks the real length of messages
4. **Timing Attack Resistance**: Constant-time comparisons

### Limitations

- Dual XOR encryption is not perfectly secure against all types of attacks
- Plausible deniability depends on the usage context
- Keys must be managed securely

## Use Cases

### Journalism and Activism

```rust
// Innocent public message
let cover_msg = b"Local weather report";

// Sensitive message
let real_msg = b"Information on human rights violations";

let ciphertext = cipher.encrypt_dual(cover_msg, real_msg, &public_key, &secret_key)?;

// In case of coercion, only the public key can be revealed
```

### Corporate Communications

```rust
// Official message
let official_msg = b"Standard quarterly report";

// Confidential information
let confidential_msg = b"Confidential acquisition strategy";

let ciphertext = cipher.encrypt_dual(official_msg, confidential_msg, &standard_key, &exec_key)?;
```

## Tests and Benchmarks

```bash
# Run tests
cargo test

# Run benchmarks
cargo bench

# Tests with detailed output
cargo test -- --nocapture
```

## Development

### Project Structure

```
src/
├── lib.rs          # Library entry point
├── main.rs         # CLI interface
├── cipher.rs       # Encryption implementation
├── key.rs          # Key management
├── error.rs        # Error types
└── utils.rs        # Utilities (padding, XOR, etc.)

benches/
└── anamorphic_bench.rs  # Performance benchmarks
```

### Contributing

1. Fork the project
2. Create a branch for your feature
3. Add tests for your code
4. Verify that all tests pass
5. Submit a pull request

## License

This project is licensed under MIT OR Apache-2.0. See the LICENSE-MIT and LICENSE-APACHE files for more details.

## Disclaimer

This library is provided for educational and research purposes. While it implements recognized cryptographic algorithms, it has not undergone a complete security audit. Use it with caution in production environments.

## Additional Resources

- [API Documentation](https://docs.rs/anamorphic)
- [Usage Examples](examples/)
- [Security Guide](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

**Note**: Anamorphic encryption is an active research field. This implementation represents a practical approach but may not cover all theoretical aspects of the domain.
