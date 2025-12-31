use anyhow::{anyhow, Result};
use fcm_service::{FcmService as FcmClient, FcmMessage, FcmNotification, Target};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

pub struct FcmService {
    client: FcmClient,
    project_id: String,
}

impl FcmService {
    pub fn new(service_account_path: &str) -> Result<Self> {
        info!("📱 FCM: Initializing with fcm-service...");
        
        // ✅ CRITICAL: Check system time first
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time before UNIX epoch!");
        let timestamp_secs = now.as_secs();
        info!("🕐 FCM: System time check: {} seconds since epoch", timestamp_secs);
        
        // Warn if system time looks wrong (before 2020 or after 2030)
        if timestamp_secs < 1577836800 {
            error!("❌ FCM: System time appears to be BEFORE 2020! JWT signing will fail!");
            error!("   Current timestamp: {}", timestamp_secs);
        } else if timestamp_secs > 1893456000 {
            warn!("⚠️ FCM: System time appears to be AFTER 2030! Please verify.");
        } else {
            info!("✅ FCM: System time looks reasonable");
        }
        
        // ✅ CRITICAL FIX: Check if path exists, otherwise read from env var
        let service_account_content = if std::path::Path::new(service_account_path).exists() {
            info!("📄 FCM: Reading service account from file: {}", service_account_path);
            std::fs::read_to_string(service_account_path)?
        } else {
            info!("📄 FCM: File not found, reading from FCM_SERVICE_ACCOUNT_JSON env var");
            std::env::var("FCM_SERVICE_ACCOUNT_JSON")
                .map_err(|_| anyhow!("FCM_SERVICE_ACCOUNT_JSON environment variable not set"))?
        };
        
        info!("📊 FCM: Service account content length: {} bytes", service_account_content.len());
        
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
        
        let private_key_raw = service_account["private_key"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'private_key' in service account"))?;
        
        let token_uri = service_account["token_uri"]
            .as_str()
            .ok_or_else(|| anyhow!("Missing 'token_uri' in service account"))?;
        
        info!("✅ FCM: Service account validation passed");
        info!("   Project ID: {}", project_id);
        info!("   Client Email: {}", client_email);
        info!("   Token URI: {}", token_uri);
        
        // ✅ CRITICAL: Detailed private key validation
        info!("🔐 FCM: Validating private key format...");
        info!("   Private Key raw length: {} chars", private_key_raw.len());
        
        // Count different types of characters in the private key
        let newline_count = private_key_raw.matches('\n').count();
        let literal_backslash_n = private_key_raw.matches("\\n").count();
        let has_proper_header = private_key_raw.starts_with("-----BEGIN PRIVATE KEY-----");
        let has_proper_footer = private_key_raw.contains("-----END PRIVATE KEY-----");
        
        info!("🔍 FCM: Private key analysis:");
        info!("   Actual newlines (\\n): {}", newline_count);
        info!("   Literal '\\n' strings: {}", literal_backslash_n);
        info!("   Has proper header: {}", has_proper_header);
        info!("   Has proper footer: {}", has_proper_footer);
        info!("   First 50 chars: {}", &private_key_raw.chars().take(50).collect::<String>());
        info!("   Last 50 chars: {}", &private_key_raw.chars().rev().take(50).collect::<String>().chars().rev().collect::<String>());
        
        // ✅ CRITICAL FIX: Handle escaped \n characters
        let private_key = if literal_backslash_n > 0 {
            warn!("⚠️ FCM: Private key contains literal '\\n' strings - fixing...");
            let fixed = private_key_raw.replace("\\n", "\n");
            info!("✅ FCM: Replaced {} literal '\\n' with actual newlines", literal_backslash_n);
            info!("   New newline count: {}", fixed.matches('\n').count());
            fixed
        } else {
            private_key_raw.to_string()
        };
        
        // Validate PEM format
        if !private_key.starts_with("-----BEGIN PRIVATE KEY-----") {
            error!("❌ FCM: Invalid private key format - missing PEM header");
            error!("   Key starts with: {}", &private_key.chars().take(30).collect::<String>());
            return Err(anyhow!("Invalid private key format: missing PEM header"));
        }
        
        if !private_key.ends_with("-----END PRIVATE KEY-----\n") && !private_key.ends_with("-----END PRIVATE KEY-----") {
            warn!("⚠️ FCM: Private key may be missing proper PEM footer");
            warn!("   Key ends with: {}", &private_key.chars().rev().take(30).collect::<String>().chars().rev().collect::<String>());
        }
        
        // Check if key has reasonable structure
        let final_newline_count = private_key.matches('\n').count();
        if final_newline_count < 2 {
            error!("❌ FCM: Private key has too few newlines ({})", final_newline_count);
            error!("   This will cause JWT signature failures!");
            return Err(anyhow!("Invalid private key format: insufficient line breaks"));
        }
        
        info!("✅ FCM: Private key format validated");
        info!("   Final newline count: {}", final_newline_count);
        
        // ✅ CRITICAL: Create corrected service account JSON
        let corrected_service_account = serde_json::json!({
            "type": service_account["type"],
            "project_id": project_id,
            "private_key_id": service_account["private_key_id"],
            "private_key": private_key,
            "client_email": client_email,
            "client_id": service_account["client_id"],
            "auth_uri": service_account["auth_uri"],
            "token_uri": token_uri,
            "auth_provider_x509_cert_url": service_account["auth_provider_x509_cert_url"],
            "client_x509_cert_url": service_account["client_x509_cert_url"],
            "universe_domain": service_account.get("universe_domain").unwrap_or(&serde_json::json!("googleapis.com"))
        });
        
        let corrected_json = serde_json::to_string_pretty(&corrected_service_account)?;
        
        // ✅ Write corrected JSON to temp file
        let temp_path = "/tmp/fcm-service-account-corrected.json";
        std::fs::write(temp_path, &corrected_json)
            .map_err(|e| anyhow!("Failed to write temp service account file: {}", e))?;
        info!("📝 FCM: Wrote CORRECTED service account to: {}", temp_path);
        
        // Verify file was written correctly
        let written_content = std::fs::read_to_string(temp_path)?;
        if written_content.len() != corrected_json.len() {
            error!("❌ FCM: Temp file content length mismatch!");
            return Err(anyhow!("Failed to write service account correctly"));
        }
        info!("✅ FCM: Temp file verified ({} bytes)", written_content.len());
        
        // Create FCM client with corrected temp file
        info!("🔧 FCM: Creating fcm-service client with corrected credentials...");
        let client = FcmClient::new(temp_path);
        
        info!("✅ FCM: Client initialized successfully");
        info!("   Ready to send notifications");
        
        Ok(Self {
            client,
            project_id,
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub async fn send_notification(
        &self,
        device_token: &str,
        sender_name: &str,
        message_text: &str,
        chat_id: &str,
        sender_id: &str,
        timestamp: &str,
    ) -> Result<String> {
        info!("📤 FCM: Attempting to send notification");
        info!("   From: {}", sender_name);
        info!("   Message preview: {}...", &message_text.chars().take(30).collect::<String>());
        info!("   Token prefix: {}...", &device_token.chars().take(20).collect::<String>());

        // Create notification
        let mut notification = FcmNotification::new();
        notification.set_title(sender_name.to_string());
        notification.set_body(message_text.to_string());
        notification.set_image(None);

        // Create message
        let mut message = FcmMessage::new();
        message.set_notification(Some(notification));
        message.set_target(Target::Token(device_token.to_string()));

        // Add data payload
        let mut data = HashMap::new();
        data.insert("type".to_string(), "chat_message".to_string());
        data.insert("chatId".to_string(), chat_id.to_string());
        data.insert("senderId".to_string(), sender_id.to_string());
        data.insert("senderName".to_string(), sender_name.to_string());
        data.insert("messageText".to_string(), message_text.to_string());
        data.insert("timestamp".to_string(), timestamp.to_string());
        message.set_data(Some(data));

        info!("🔐 FCM: Signing JWT and requesting OAuth token...");
        
        // Send notification
        match self.client.send_notification(message).await {
            Ok(_) => {
                info!("✅ FCM: Notification sent successfully!");
                Ok("sent".to_string())
            }
            Err(e) => {
                error!("❌ FCM: Failed to send notification");
                error!("   Error: {}", e);
                error!("   This is likely due to:");
                error!("   1. Invalid JWT signature (check private key format)");
                error!("   2. System time mismatch (check server time)");
                error!("   3. Invalid service account credentials");
                Err(anyhow!("Failed to send FCM notification: {}", e))
            }
        }
    }
}
