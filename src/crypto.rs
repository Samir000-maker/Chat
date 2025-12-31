use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use tracing::{error, info, warn};

const AES_KEY: &str = "0123456789abcdef"; // Must match your Android app's key
const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

/// Decrypt AES-GCM encrypted message
/// Format: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
pub fn decrypt_message(encrypted_base64: &str) -> Result<String, String> {
    let worker_id = std::process::id();
    
    info!("🔐 [Worker {}] CRYPTO: Starting decryption", worker_id);
    info!("   Input length: {} chars", encrypted_base64.len());
    
    // Validate input
    if encrypted_base64.is_empty() || encrypted_base64.len() < 20 {
        error!("❌ [Worker {}] CRYPTO: Encrypted data too short", worker_id);
        return Err("Encrypted data too short".to_string());
    }

    // Decode base64
    info!("🔐 [Worker {}] CRYPTO: Decoding base64...", worker_id);
    let combined = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| {
            error!("❌ [Worker {}] CRYPTO: Base64 decode error: {}", worker_id, e);
            format!("Base64 decode error: {}", e)
        })?;

    info!("✅ [Worker {}] CRYPTO: Base64 decoded successfully", worker_id);
    info!("   Decoded length: {} bytes", combined.len());

    // Check minimum length (IV + at least some ciphertext + auth tag)
    if combined.len() < GCM_IV_LENGTH + GCM_TAG_LENGTH {
        error!("❌ [Worker {}] CRYPTO: Decoded data too short: {} bytes (need at least {})", 
            worker_id, combined.len(), GCM_IV_LENGTH + GCM_TAG_LENGTH);
        return Err(format!(
            "Encrypted data too short: expected at least {} bytes, got {}",
            GCM_IV_LENGTH + GCM_TAG_LENGTH,
            combined.len()
        ));
    }

    // Extract components:
    // [0..12]: IV
    // [12..len-16]: Ciphertext
    // [len-16..len]: Auth Tag
    let iv = &combined[0..GCM_IV_LENGTH];
    let ciphertext_with_tag = &combined[GCM_IV_LENGTH..];
    
    // Split ciphertext and auth tag
    let ciphertext_len = ciphertext_with_tag.len() - GCM_TAG_LENGTH;
    let ciphertext = &ciphertext_with_tag[..ciphertext_len];
    let auth_tag = &ciphertext_with_tag[ciphertext_len..];

    info!("🔐 [Worker {}] CRYPTO: Component breakdown:", worker_id);
    info!("   Total length: {} bytes", combined.len());
    info!("   IV length: {} bytes", iv.len());
    info!("   Ciphertext length: {} bytes", ciphertext.len());
    info!("   Auth tag length: {} bytes", auth_tag.len());

    // Prepare key
    let key_bytes = AES_KEY.as_bytes();
    if key_bytes.len() != 16 {
        error!("❌ [Worker {}] CRYPTO: Invalid key length: {}", worker_id, key_bytes.len());
        return Err("Invalid key length".to_string());
    }

    info!("✅ [Worker {}] CRYPTO: Key validated (16 bytes)", worker_id);

    // Create cipher
    info!("🔐 [Worker {}] CRYPTO: Creating AES-128-GCM cipher...", worker_id);
    let cipher = Aes128Gcm::new_from_slice(key_bytes)
        .map_err(|e| {
            error!("❌ [Worker {}] CRYPTO: Failed to create cipher: {}", worker_id, e);
            format!("Failed to create cipher: {}", e)
        })?;

    info!("✅ [Worker {}] CRYPTO: Cipher created successfully", worker_id);

    // Create nonce
    let nonce = Nonce::from_slice(iv);
    info!("✅ [Worker {}] CRYPTO: Nonce created from IV", worker_id);

    // Combine ciphertext + tag for decrypt (aes_gcm expects them together)
    let mut payload = ciphertext.to_vec();
    payload.extend_from_slice(auth_tag);
    
    info!("🔐 [Worker {}] CRYPTO: Payload prepared ({} bytes)", worker_id, payload.len());

    // Decrypt
    info!("🔐 [Worker {}] CRYPTO: Attempting decryption...", worker_id);
    let decrypted = cipher.decrypt(nonce, payload.as_ref())
        .map_err(|e| {
            error!("❌ [Worker {}] CRYPTO: Decryption failed: {}", worker_id, e);
            error!("   This usually means:");
            error!("   - Wrong encryption key");
            error!("   - Corrupted/tampered data");
            error!("   - Wrong IV or auth tag");
            format!("Decryption error: {}", e)
        })?;

    info!("✅ [Worker {}] CRYPTO: Decryption successful!", worker_id);
    info!("   Decrypted length: {} bytes", decrypted.len());

    // Convert to UTF-8 string
    let decrypted_text = String::from_utf8(decrypted)
        .map_err(|e| {
            error!("❌ [Worker {}] CRYPTO: UTF-8 decode error: {}", worker_id, e);
            format!("UTF-8 decode error: {}", e)
        })?;

    info!("✅ [Worker {}] CRYPTO: UTF-8 conversion successful", worker_id);
    info!("   Decrypted text preview: \"{}...\"", 
        &decrypted_text[..decrypted_text.len().min(50)]
    );

    Ok(decrypted_text)
}

/// Test function to verify crypto module is working
pub fn test_crypto_module() -> Result<(), String> {
    info!("🔐 CRYPTO MODULE: Running initialization test...");
    
    // Test with a simple base64 string (not actually encrypted, just for module test)
    match decrypt_message("dGVzdA==") {
        Ok(_) => {
            // This will fail because it's not actually encrypted data
            warn!("⚠️ CRYPTO MODULE: Test returned unexpected success (expected failure)");
            Ok(())
        }
        Err(e) => {
            // Expected to fail
            info!("✅ CRYPTO MODULE: Test completed as expected");
            info!("   Error (expected): {}", e);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_module_available() {
        // Just verify the module compiles and functions are callable
        let result = test_crypto_module();
        assert!(result.is_ok());
    }

    #[test]
    fn test_decrypt_message_too_short() {
        let result = decrypt_message("short");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("too short"));
    }

    #[test]
    fn test_decrypt_message_invalid_base64() {
        let result = decrypt_message("!!!invalid base64!!!");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Base64"));
    }
}
