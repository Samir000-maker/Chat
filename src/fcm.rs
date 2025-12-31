use anyhow::{anyhow, Result};
use oauth_fcm::{create_shared_token_manager, Message, Notification, Target};
use std::collections::HashMap;
use std::fs::File;
use std::sync::Arc;
use tracing::{error, info};

pub struct FcmService {
    token_manager: Arc<oauth_fcm::SharedTokenManager>,
    project_id: String,
}

impl FcmService {
    pub fn new(service_account_path: &str) -> Result<Self> {
        info!("📱 FCM: Initializing with oauth_fcm...");
        
        // Read service account to get project_id
        let service_account_content = std::fs::read_to_string(service_account_path)?;
        let service_account: serde_json::Value = serde_json::from_str(&service_account_content)?;
        let project_id = service_account["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("No project_id in service account"))?
            .to_string();
        
        // Create token manager - handles all JWT/OAuth automatically
        let file = File::open(service_account_path)
            .map_err(|e| anyhow!("Failed to open service account: {}", e))?;
        
        let token_manager = create_shared_token_manager(file)
            .map_err(|e| anyhow!("Failed to create token manager: {}", e))?;
        
        info!("✅ FCM: Initialized successfully");
        info!("   Project ID: {}", project_id);
        
        Ok(Self {
            token_manager,
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

        // Create data payload
        let mut data = HashMap::new();
        data.insert("type".to_string(), "chat_message".to_string());
        data.insert("chatId".to_string(), chat_id.to_string());
        data.insert("senderId".to_string(), sender_id.to_string());
        data.insert("senderName".to_string(), sender_name.to_string());
        data.insert("messageText".to_string(), message_text.to_string());
        data.insert("timestamp".to_string(), timestamp.to_string());

        // Create Android config
        let mut android_fields = HashMap::new();
        android_fields.insert("priority".to_string(), serde_json::json!("high"));
        
        let mut android_notification = HashMap::new();
        android_notification.insert("sound".to_string(), serde_json::json!("default"));
        android_notification.insert("channel_id".to_string(), serde_json::json!("chat_messages"));
        android_notification.insert("priority".to_string(), serde_json::json!("high"));
        android_notification.insert("icon".to_string(), serde_json::json!("ic_notification"));
        android_notification.insert("color".to_string(), serde_json::json!("#4CAF50"));
        android_notification.insert("default_vibrate_timings".to_string(), serde_json::json!(true));
        android_notification.insert("click_action".to_string(), serde_json::json!("OPEN_CHAT"));
        
        android_fields.insert("notification".to_string(), serde_json::json!(android_notification));

        // Build the message
        let message = Message::builder()
            .target(Target::Token(device_token.to_string()))
            .notification(
                Notification::builder()
                    .title(sender_name)
                    .body(message_text)
                    .build()
            )
            .data(data)
            .android(android_fields)
            .build()
            .map_err(|e| anyhow!("Failed to build message: {}", e))?;

        // Send the message - oauth_fcm handles everything!
        let response = self.token_manager
            .send_message(&self.project_id, message)
            .await
            .map_err(|e| {
                error!("❌ FCM: Failed to send: {}", e);
                anyhow!("Failed to send FCM message: {}", e)
            })?;

        info!("✅ FCM: Notification sent successfully!");

        // Extract message name from response
        Ok(response.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("sent")
            .to_string())
    }
}
