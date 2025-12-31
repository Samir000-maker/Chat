use anyhow::{anyhow, Result};
use fcm_service::{FcmService as FcmClient, FcmMessage, FcmNotification, Target};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn, debug};

pub struct FcmService {
    client: FcmClient,
    project_id: String,
}

impl FcmService {
    pub fn new(service_account_path: &str) -> Result<Self> {
        info!("📱 FCM: Initializing with fcm-service...");
        info!("🕐 FCM: System time check: {:?}", SystemTime::now());
        
        // ✅ CRITICAL FIX: Check if path exists, otherwise read from env var
        let service_account_content = if std::path::Path::new(service_account_path).exists() {
            info!("📄 FCM: Reading service account from file: {}", service_account_path);
            std::fs::read_to_string(service_account_path)?
        } else {
            info!("📄 FCM: File not found, reading from FCM_SERVICE_ACCOUNT_JSON env var");
            std::env::var("FCM_SERVICE_ACCOUNT_JSON")
                .map_err(|_| anyhow!("FCM_SERVICE_ACCOUNT_JSON environment variable not set"))?
        };
        
        // Parse and validate service account JSON
        info!("🔍 FCM: Parsing service account JSON...");
        let service_account: serde_json::Value = serde_json::from_str(&service_account_content)
            .map_err(|e| anyhow!("Failed to parse service account JSON: {}", e))?;
        
        // ✅ CRITICAL: Validate all required fields
        info!("🔍 FCM: Validating service account fields...");
        let project_id = service_account["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'project_id' in service account"))?
            .to_string();
        
        let client_email = service_account["client_email"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'client_email' in service account"))?;
        
        let private_key = service_account["private_key"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'private_key' in service account"))?;
        
        let token_uri = service_account["token_uri"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'token_uri' in service account"))?;
        
        info!("✅ FCM: Service account validation passed");
        info!("   Project ID: {}", project_id);
        info!("   Client Email: {}", client_email);
        info!("   Token URI: {}", token_uri);
        info!("   Private Key Length: {} chars", private_key.len());
        
        // ✅ CRITICAL: Validate private key format
        if !private_key.starts_with("-----BEGIN PRIVATE KEY-----") {
            error!("❌ FCM: Invalid private key format - missing PEM header");
            return Err(anyhow!("Invalid private key format"));
        }
        if !private_key.ends_with("-----END PRIVATE KEY-----\n") && !private_key.ends_with("-----END PRIVATE KEY-----") {
            warn!("⚠️ FCM: Private key may be missing proper PEM footer");
        }
        
        // Count newlines in private key (should have multiple for proper formatting)
        let newline_count = private_key.matches('\n').count();
        info!("🔍 FCM: Private key has {} newlines", newline_count);
        if newline_count < 2 {
            warn!("⚠️ FCM: Private key may not be properly formatted (too few newlines)");
        }
        
        // ✅ CRITICAL FIX: Write to temp file for fcm-service crate
        let temp_path = "/tmp/fcm-service-account.json";
        std::fs::write(temp_path, &service_account_content)
            .map_err(|e| anyhow!("Failed to write temp service account file: {}", e))?;
        info!("📝 FCM: Wrote service account to temp file: {}", temp_path);
        
        // Verify file was written correctly
        let written_content = std::fs::read_to_string(temp_path)?;
        if written_content != service_account_content {
            error!("❌ FCM: Temp file content mismatch!");
            return Err(anyhow!("Failed to write service account correctly"));
        }
        info!("✅ FCM: Temp file verified");
        
        // Create FCM client with temp file path
        info!("🔧 FCM: Creating fcm-service client...");
        let client = FcmClient::new(temp_path);
        
        info!("✅ FCM: Initialized successfully");
        info!("   Project ID: {}", project_id);
        
        Ok(Self {
            client,
            project_id,
        })
    }
