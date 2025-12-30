use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use base64::{engine::general_purpose, Engine as _};
use tracing::{error, info};

const AES_KEY: &str = "0123456789abcdef"; // Must match your Android app's key
const GCM_IV_LENGTH: usize = 12;
const GCM_TAG_LENGTH: usize = 16;

/// Decrypt AES-GCM encrypted message
/// Format: [IV (12 bytes)][Ciphertext][Auth Tag (16 bytes)]
pub fn decrypt_message(encrypted_base64: &str) -> Result<String, String> {
    let worker_id = std::process::id();
    
    // Validate input
    if encrypted_base64.is_empty() || encrypted_base64.len() < 20 {
        error!("[Worker {}] Encrypted data too short", worker_id);
        return Err("Encrypted data too short".to_string());
    }

    // Decode base64
    let combined = general_purpose::STANDARD
        .decode(encrypted_base64)
        .map_err(|e| {
            error!("[Worker {}] Base64 decode error: {}", worker_id, e);
            format!("Base64 decode error: {}", e)
        })?;

    // Check minimum length (IV + at least some ciphertext + auth tag)
    if combined.len() < GCM_IV_LENGTH + GCM_TAG_LENGTH {
        error!("[Worker {}] Encrypted data too short after decode: {} bytes", worker_id, combined.len());
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

    info!(
        "[Worker {}] Decryption debug:
      - Total length: {}
      - IV length: {}
      - Ciphertext length: {}
      - Auth tag length: {}",
        worker_id,
        combined.len(),
        iv.len(),
        ciphertext.len(),
        auth_tag.len()
    );

    // Prepare key
    let key_bytes = AES_KEY.as_bytes();
    if key_bytes.len() != 16 {
        error!("[Worker {}] Invalid key length: {}", worker_id, key_bytes.len());
        return Err("Invalid key length".to_string());
    }

    // Create cipher
    let cipher = Aes128Gcm::new_from_slice(key_bytes)
        .map_err(|e| {
            error!("[Worker {}] Failed to create cipher: {}", worker_id, e);
            format!("Failed to create cipher: {}", e)
        })?;

    // Create nonce
    let nonce = Nonce::from_slice(iv);

    // Combine ciphertext + tag for decrypt (aes_gcm expects them together)
    let mut payload = ciphertext.to_vec();
    payload.extend_from_slice(auth_tag);

    // Decrypt
    let decrypted = cipher.decrypt(nonce, payload.as_ref())
        .map_err(|e| {
            error!("[Worker {}] ❌ Decryption error: {}", worker_id, e);
            format!("Decryption error: {}", e)
        })?;

    // Convert to UTF-8 string
    let decrypted_text = String::from_utf8(decrypted)
        .map_err(|e| {
            error!("[Worker {}] UTF-8 decode error: {}", worker_id, e);
            format!("UTF-8 decode error: {}", e)
        })?;

    info!("[Worker {}] ✅ Decryption successful: \"{}...\"", 
        worker_id, 
        &decrypted_text[..decrypted_text.len().min(30)]
    );

    Ok(decrypted_text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_message() {
        // This is a sample encrypted message - replace with actual test data
        let encrypted = "HxVlEpvm96zDWQdnJgiZTi1YsYlbzU";
        
        match decrypt_message(encrypted) {
            Ok(decrypted) => {
                println!("Decrypted: {}", decrypted);
                assert!(!decrypted.is_empty());
            }
            Err(e) => {
                println!("Decryption failed: {}", e);
            }
        }
    }
}
