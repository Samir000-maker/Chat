use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use tracing::{error, info};

const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

/// Decrypt an AES-128-GCM encrypted message
/// 
/// Format: Base64(IV || Ciphertext || AuthTag)
/// - IV: 12 bytes
/// - Ciphertext: variable length
/// - AuthTag: 16 bytes (appended by Android's Cipher)
pub fn decrypt_message(encrypted_base64: &str) -> Result<String, Box<dyn std::error::Error>> {
    if encrypted_base64.is_empty() || encrypted_base64.len() < 20 {
        return Ok("New message".to_string());
    }

    // Decode base64
    let combined = general_purpose::STANDARD.decode(encrypted_base64)?;

    // Check minimum length
    if combined.len() < GCM_IV_LENGTH + GCM_TAG_LENGTH {
        error!("Encrypted data too short");
        return Ok("New message".to_string());
    }

    // Extract components
    let iv = &combined[..GCM_IV_LENGTH];
    let ciphertext_with_tag = &combined[GCM_IV_LENGTH..];

    // The auth tag is the LAST 16 bytes
    let auth_tag_start = ciphertext_with_tag.len() - GCM_TAG_LENGTH;
    let ciphertext = &ciphertext_with_tag[..auth_tag_start];
    let auth_tag = &ciphertext_with_tag[auth_tag_start..];

    info!(
        "Decryption debug:
  - Total length: {}
  - IV length: {}
  - Ciphertext length: {}
  - Auth tag length: {}",
        combined.len(),
        iv.len(),
        ciphertext.len(),
        auth_tag.len()
    );

    // Use the hardcoded AES key (must match Android app)
    let key = b"0123456789abcdef";

    // Create cipher
    let cipher = Aes128Gcm::new(key.into());

    // Combine ciphertext and auth tag for aes_gcm crate
    let mut ciphertext_with_tag_vec = ciphertext.to_vec();
    ciphertext_with_tag_vec.extend_from_slice(auth_tag);

    // Create nonce
    let nonce = Nonce::from_slice(iv);

    // Decrypt
    match cipher.decrypt(nonce, ciphertext_with_tag_vec.as_ref()) {
        Ok(plaintext) => {
            let decrypted = String::from_utf8(plaintext)?;
            info!(
                "✅ Decryption successful: \"{}...\"",
                &decrypted[..30.min(decrypted.len())]
            );
            Ok(decrypted)
        }
        Err(e) => {
            error!("❌ Decryption error: {}", e);
            Ok("New message".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_empty() {
        let result = decrypt_message("");
        assert_eq!(result.unwrap(), "New message");
    }

    #[test]
    fn test_decrypt_short() {
        let result = decrypt_message("abc");
        assert_eq!(result.unwrap(), "New message");
    }

    #[test]
    fn test_decrypt_invalid_base64() {
        let result = decrypt_message("not valid base64!");
        assert!(result.is_err());
    }
}
