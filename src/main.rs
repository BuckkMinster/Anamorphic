//! Command-line interface for the anamorphic encryption library.

use anamorphic::{AnamorphicCipher, AnamorphicKey, AnamorphicError};
use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        print_usage();
        return;
    }

    let result = match args[1].as_str() {
        "generate-key" => generate_key_command(&args[2..]),
        "encrypt" => encrypt_command(&args[2..]),
        "decrypt" => decrypt_command(&args[2..]),
        "encrypt-dual" => encrypt_dual_command(&args[2..]),
        "help" | "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_usage();
            std::process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn print_usage() {
    println!("Anamorphic Encryption CLI");
    println!();
    println!("USAGE:");
    println!("    anamorphic-cli <COMMAND> [OPTIONS]");
    println!();
    println!("COMMANDS:");
    println!("    generate-key                Generate a new random key");
    println!("    encrypt <key> <input>       Encrypt a message with a single key");
    println!("    decrypt <key> <input>       Decrypt a ciphertext with a key");
    println!("    encrypt-dual <key1> <key2> <msg1> <msg2>  Encrypt two messages anamorphically");
    println!("    help                        Show this help message");
    println!();
    println!("EXAMPLES:");
    println!("    # Generate a new key");
    println!("    anamorphic-cli generate-key");
    println!();
    println!("    # Encrypt a message");
    println!("    anamorphic-cli encrypt mykey.hex \"Hello, World!\"");
    println!();
    println!("    # Decrypt a message");
    println!("    anamorphic-cli decrypt mykey.hex ciphertext.json");
    println!();
    println!("    # Encrypt two messages anamorphically");
    println!("    anamorphic-cli encrypt-dual key1.hex key2.hex \"Public message\" \"Secret message\"");
}

fn generate_key_command(args: &[String]) -> Result<(), AnamorphicError> {
    let key = AnamorphicKey::generate();
    let hex_key = key.to_hex();
    
    if args.is_empty() {
        // Print to stdout
        println!("{}", hex_key);
    } else {
        // Save to file
        let filename = &args[0];
        fs::write(filename, hex_key)
            .map_err(|e| AnamorphicError::IoError(e))?;
        println!("Key saved to: {}", filename);
    }
    
    Ok(())
}

fn encrypt_command(args: &[String]) -> Result<(), AnamorphicError> {
    if args.len() < 2 {
        return Err(AnamorphicError::invalid_input("Usage: encrypt <key> <input>"));
    }

    let key = load_key(&args[0])?;
    let message = load_input(&args[1])?;
    
    let cipher = AnamorphicCipher::new();
    let ciphertext = cipher.encrypt(&message, &key)?;
    let json = cipher.serialize_ciphertext(&ciphertext)?;
    
    // Output filename
    let output_file = if args.len() > 2 {
        args[2].clone()
    } else {
        "ciphertext.json".to_string()
    };
    
    fs::write(&output_file, json)
        .map_err(|e| AnamorphicError::IoError(e))?;
    
    println!("Encrypted message saved to: {}", output_file);
    Ok(())
}

fn decrypt_command(args: &[String]) -> Result<(), AnamorphicError> {
    if args.len() < 2 {
        return Err(AnamorphicError::invalid_input("Usage: decrypt <key> <ciphertext>"));
    }

    let key = load_key(&args[0])?;
    let ciphertext_json = fs::read_to_string(&args[1])
        .map_err(|e| AnamorphicError::IoError(e))?;
    
    let cipher = AnamorphicCipher::new();
    let ciphertext = cipher.deserialize_ciphertext(&ciphertext_json)?;
    let decrypted = cipher.decrypt(&ciphertext, &key)?;
    
    // Try to print as UTF-8, fallback to hex if not valid
    match String::from_utf8(decrypted.clone()) {
        Ok(text) => println!("Decrypted message: {}", text),
        Err(_) => {
            println!("Decrypted message (hex): {}", hex::encode(&decrypted));
        }
    }
    
    Ok(())
}

fn encrypt_dual_command(args: &[String]) -> Result<(), AnamorphicError> {
    if args.len() < 4 {
        return Err(AnamorphicError::invalid_input(
            "Usage: encrypt-dual <key1> <key2> <message1> <message2>"
        ));
    }

    let key1 = load_key(&args[0])?;
    let key2 = load_key(&args[1])?;
    let message1 = load_input(&args[2])?;
    let message2 = load_input(&args[3])?;
    
    let cipher = AnamorphicCipher::new();
    let ciphertext = cipher.encrypt_dual(&message1, &message2, &key1, &key2)?;
    let json = cipher.serialize_ciphertext(&ciphertext)?;
    
    // Output filename
    let output_file = if args.len() > 4 {
        args[4].clone()
    } else {
        "dual_ciphertext.json".to_string()
    };
    
    fs::write(&output_file, json)
        .map_err(|e| AnamorphicError::IoError(e))?;
    
    println!("Dual encrypted messages saved to: {}", output_file);
    println!("Use key1 to decrypt message1, key2 to decrypt message2");
    Ok(())
}

fn load_key(key_input: &str) -> Result<AnamorphicKey, AnamorphicError> {
    if Path::new(key_input).exists() {
        // Load from file
        let hex_key = fs::read_to_string(key_input)
            .map_err(|e| AnamorphicError::IoError(e))?;
        AnamorphicKey::from_hex(hex_key.trim())
    } else {
        // Treat as hex string directly
        AnamorphicKey::from_hex(key_input)
    }
}

fn load_input(input: &str) -> Result<Vec<u8>, AnamorphicError> {
    if Path::new(input).exists() {
        // Load from file
        fs::read(input).map_err(|e| AnamorphicError::IoError(e))
    } else {
        // Treat as string literal
        Ok(input.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn test_key_generation_and_loading() {
        let key = AnamorphicKey::generate();
        let hex = key.to_hex();
        
        // Test loading from hex string
        let loaded_key = load_key(&hex).unwrap();
        assert_eq!(key.as_bytes(), loaded_key.as_bytes());
    }

    #[test]
    fn test_input_loading() {
        // Test string input
        let input = load_input("hello").unwrap();
        assert_eq!(input, b"hello");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = AnamorphicKey::generate();
        let cipher = AnamorphicCipher::new();
        let message = b"Test message for CLI";
        
        let ciphertext = cipher.encrypt(message, &key).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &key).unwrap();
        
        assert_eq!(decrypted, message);
    }
}
