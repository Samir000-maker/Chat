use anyhow::{anyhow, Result};
use fcm_service::{FcmService as FcmClient, FcmMessage, FcmNotification, Target};
use std::collections::HashMap;
use tracing::{error, info};

pub struct FcmService {
    client: FcmClient,
    project_id: String,
}

impl FcmService {
    pub fn new(service_account_path: &str) -> Result<Self> {
        info!("📱 FCM: Initializing with fcm-service...");
        
        // ✅ CRITICAL FIX: Check if path exists, otherwise read from env var
        let service_account_content = if std::path::Path::new(service_account_path).exists() {
            info!("📄 FCM: Reading service account from file: {}", service_account_path);
            std::fs::read_to_string(service_account_path)?
        } else {
            info!("📄 FCM: File not found, reading from FCM_SERVICE_ACCOUNT_JSON env var");
            std::env::var("FCM_SERVICE_ACCOUNT_JSON")
                .map_err(|_| anyhow!("FCM_SERVICE_ACCOUNT_JSON environment variable not set"))?
        };
        
        // Parse to get project_id
        let service_account: serde_json::Value = serde_json::from_str(&service_account_content)?;
        let project_id = service_account["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("No project_id in service account"))?
            .to_string();
        
        // ✅ CRITICAL FIX: Write to temp file for fcm-service crate
        // The fcm-service crate expects a file path, so we create a temp file
        let temp_path = "/tmp/fcm-service-account.json";
        std::fs::write(temp_path, &service_account_content)?;
        info!("📝 FCM: Wrote service account to temp file: {}", temp_path);
        
        // Create FCM client with temp file path
        let client = FcmClient::new(temp_path);
        
        info!("✅ FCM: Initialized successfully");
        info!("   Project ID: {}", project_id);
        
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
        info!("📤 FCM: Sending notification from: {}", sender_name);
        
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
        
        // Send notification
        self.client
            .send_notification(message)
            .await
            .map_err(|e| {
                error!("❌ FCM: Failed to send: {}", e);
                anyhow!("Failed to send FCM notification: {}", e)
            })?;
        
        info!("✅ FCM: Notification sent successfully!");
        Ok("sent".to_string())
    }
}
