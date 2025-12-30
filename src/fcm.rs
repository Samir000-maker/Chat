use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_ENDPOINT: &str = "https://fcm.googleapis.com/v1/projects";

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    project_id: String,
    private_key: String,
    client_email: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

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
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[allow(dead_code)]
    token_type: String,
}

#[derive(Debug, Deserialize)]
struct FcmResponse {
    name: String,
}

pub struct FcmService {
    project_id: String,
    private_key: String,
    client_email: String,
    access_token: parking_lot::RwLock<Option<String>>,
    token_expiry: parking_lot::RwLock<u64>,
}

impl FcmService {
    pub fn new(service_account_path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(service_account_path)
            .map_err(|e| anyhow!("Failed to read service account file: {}", e))?;

        let service_account: ServiceAccount = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse service account JSON: {}", e))?;

        Ok(Self {
            project_id: service_account.project_id,
            private_key: service_account.private_key,
            client_email: service_account.client_email,
            access_token: parking_lot::RwLock::new(None),
            token_expiry: parking_lot::RwLock::new(0),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    async fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let token = self.access_token.read();
            let expiry = *self.token_expiry.read();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if let Some(ref token_str) = *token {
                if now < expiry - 300 {
                    // Token valid for at least 5 more minutes
                    return Ok(token_str.clone());
                }
            }
        }

        // Generate new token
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let claims = Claims {
            iss: self.client_email.clone(),
            scope: FCM_SCOPE.to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: now + 3600,
            iat: now,
        };

        let header = Header::new(Algorithm::RS256);
        
        let key = EncodingKey::from_rsa_pem(self.private_key.as_bytes())
            .map_err(|e| anyhow!("Failed to parse private key: {}", e))?;

        let jwt = encode(&header, &claims, &key)
            .map_err(|e| anyhow!("Failed to encode JWT: {}", e))?;

        // Exchange JWT for access token
        let client = reqwest::Client::new();
        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ];

        let response = client
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to exchange JWT for token: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Token exchange failed: {} - {}", status, body));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse token response: {}", e))?;

        // Cache the token
        {
            *self.access_token.write() = Some(token_response.access_token.clone());
            *self.token_expiry.write() = now + token_response.expires_in;
        }

        info!("✅ Got new FCM access token");

        Ok(token_response.access_token)
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
            .await
            .map_err(|e| anyhow!("Failed to send FCM request: {}", e))?;

        let status = response.status();
        
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            error!("FCM request failed: {} - {}", status, body);
            
            // Check for invalid token errors
            if body.contains("INVALID_ARGUMENT") 
                || body.contains("UNREGISTERED")
                || body.contains("NOT_FOUND") {
                return Err(anyhow!("messaging/invalid-registration-token"));
            }
            
            return Err(anyhow!("FCM send failed: {} - {}", status, body));
        }

        let fcm_response: FcmResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse FCM response: {}", e))?;

        Ok(fcm_response.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fcm_service_initialization() {
        // This test requires a valid service account file
        match FcmService::new("./fcm-service-account.json") {
            Ok(service) => {
                println!("Project ID: {}", service.project_id());
            }
            Err(e) => {
                println!("Failed to initialize FCM: {}", e);
            }
        }
    }
}
