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
        
        // Read project_id from service account
        let service_account_content = std::fs::read_to_string(service_account_path)?;
        let service_account: serde_json::Value = serde_json::from_str(&service_account_content)?;
        let project_id = service_account["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("No project_id in service account"))?
            .to_string();
        
        // Create FCM client - handles all OAuth automatically
        let client = FcmClient::new(service_account_path);
        
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
