use anyhow::{anyhow, Result};
use gcp_auth::AuthenticationManager;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

const FCM_ENDPOINT: &str = "https://fcm.googleapis.com/v1/projects";
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

#[derive(Debug, Serialize)]
struct FcmMessage {
    message: Message,
}

#[derive(Debug, Serialize)]
struct Message {
    token: String,
    notification: Notification,
    data: MessageData,
    android: AndroidConfig,
}

#[derive(Debug, Serialize)]
struct Notification {
    title: String,
    body: String,
}

#[derive(Debug, Serialize)]
struct MessageData {
    #[serde(rename = "type")]
    msg_type: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "senderId")]
    sender_id: String,
    #[serde(rename = "senderName")]
    sender_name: String,
    #[serde(rename = "messageText")]
    message_text: String,
    timestamp: String,
}

#[derive(Debug, Serialize)]
struct AndroidConfig {
    priority: String,
    notification: AndroidNotification,
}

#[derive(Debug, Serialize)]
struct AndroidNotification {
    sound: String,
    #[serde(rename = "channel_id")]
    channel_id: String,
    priority: String,
    icon: String,
    color: String,
    #[serde(rename = "default_vibrate_timings")]
    default_vibrate_timings: bool,
    click_action: String,
}

#[derive(Debug, Deserialize)]
struct FcmResponse {
    name: String,
}

pub struct FcmService {
    auth_manager: AuthenticationManager,
    project_id: String,
}

impl FcmService {
    pub async fn new(service_account_path: &str) -> Result<Self> {
        info!("📱 FCM: Initializing with gcp_auth...");
        
        // ✅ gcp_auth automatically handles JWT creation, signing, and token exchange
        let auth_manager = AuthenticationManager::from_json_file(service_account_path).await?;
        
        // Get project ID from service account
        let service_account_info = std::fs::read_to_string(service_account_path)?;
        let parsed: serde_json::Value = serde_json::from_str(&service_account_info)?;
        let project_id = parsed["project_id"]
            .as_str()
            .ok_or_else(|| anyhow!("No project_id in service account"))?
            .to_string();
        
        info!("✅ FCM: Initialized successfully with project: {}", project_id);
        
        Ok(Self {
            auth_manager,
            project_id,
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    async fn get_access_token(&self) -> Result<String> {
        info!("🔑 FCM: Getting access token via gcp_auth...");
        
        // ✅ gcp_auth handles everything: JWT creation, signing, caching
        let token = self.auth_manager
            .get_token(&[FCM_SCOPE])
            .await?;
        
        info!("✅ FCM: Access token obtained");
        
        Ok(token.as_str().to_string())
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

        let access_token = self.get_access_token().await?;

        let fcm_message = FcmMessage {
            message: Message {
                token: device_token.to_string(),
                notification: Notification {
                    title: sender_name.to_string(),
                    body: message_text.to_string(),
                },
                data: MessageData {
                    msg_type: "chat_message".to_string(),
                    chat_id: chat_id.to_string(),
                    sender_id: sender_id.to_string(),
                    sender_name: sender_name.to_string(),
                    message_text: message_text.to_string(),
                    timestamp: timestamp.to_string(),
                },
                android: AndroidConfig {
                    priority: "high".to_string(),
                    notification: AndroidNotification {
                        sound: "default".to_string(),
                        channel_id: "chat_messages".to_string(),
                        priority: "high".to_string(),
                        icon: "ic_notification".to_string(),
                        color: "#4CAF50".to_string(),
                        default_vibrate_timings: true,
                        click_action: "OPEN_CHAT".to_string(),
                    },
                },
            },
        };

        let url = format!("{}/{}/messages:send", FCM_ENDPOINT, self.project_id);

        let client = reqwest::Client::new();
        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("Content-Type", "application/json")
            .json(&fcm_message)
            .send()
            .await?;

        let status = response.status();
        
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("❌ FCM: Request failed: {} - {}", status, body);
            return Err(anyhow!("FCM send failed: {} - {}", status, body));
        }

        let fcm_response: FcmResponse = response.json().await?;

        info!("✅ FCM: Notification sent! Message ID: {}", fcm_response.name);

        Ok(fcm_response.name)
    }
}
