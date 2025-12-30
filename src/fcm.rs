use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone)]
pub struct FcmService {
    project_id: String,
    client_email: String,
    private_key: String,
    http: Client,
}

#[derive(Debug, Deserialize)]
struct ServiceAccount {
    project_id: String,
    client_email: String,
    private_key: String,
    token_uri: String,
}

#[derive(Debug, Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: usize,
    exp: usize,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    token_type: String,
}

impl FcmService {
    /// Initialize Firebase Cloud Messaging service
    pub fn new(service_account_path: &str) -> Result<Self> {
        let content = fs::read_to_string(service_account_path)
            .map_err(|e| anyhow!("Failed to read service account file: {}", e))?;

        let account: ServiceAccount =
            serde_json::from_str(&content).map_err(|e| anyhow!("Invalid JSON: {}", e))?;

        Ok(Self {
            project_id: account.project_id,
            client_email: account.client_email,
            private_key: account.private_key,
            http: Client::new(),
        })
    }

    /// Get Firebase project ID
    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    /// Send push notification via FCM HTTP v1 API
    pub async fn send_notification(
        &self,
        token: &str,
        title: &str,
        body: &str,
        chat_id: &str,
        sender_id: &str,
        timestamp: &str,
    ) -> Result<String> {
        let access_token = self.get_access_token().await?;

        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let payload = json!({
            "message": {
                "token": token,
                "notification": {
                    "title": title,
                    "body": body
                },
                "data": {
                    "chatId": chat_id,
                    "senderId": sender_id,
                    "timestamp": timestamp
                },
                "android": {
                    "priority": "high"
                }
            }
        });

        let res = self
            .http
            .post(&url)
            .bearer_auth(access_token)
            .json(&payload)
            .send()
            .await?;

        let status = res.status();
        let text = res.text().await?;

        if !status.is_success() {
            return Err(anyhow!(
                "FCM request failed [{}]: {}",
                status,
                text
            ));
        }

        let json: serde_json::Value = serde_json::from_str(&text)?;
        let name = json
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        Ok(name)
    }

    /// Generate OAuth2 access token using JWT
    async fn get_access_token(&self) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as usize;

        let claims = Claims {
            iss: self.client_email.clone(),
            scope: "https://www.googleapis.com/auth/firebase.messaging".to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            iat: now,
            exp: now + 3600,
        };

        let key = self
            .private_key
            .replace("\\n", "\n");

        let jwt = encode(
            &Header::new(Algorithm::RS256),
            &claims,
            &EncodingKey::from_rsa_pem(key.as_bytes())?,
        )?;

        let params = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &jwt),
        ];

        let res = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&params)
            .send()
            .await?;

        let status = res.status();
        let body = res.text().await?;

        if !status.is_success() {
            return Err(anyhow!(
                "Failed to get access token [{}]: {}",
                status,
                body
            ));
        }

        let token: TokenResponse = serde_json::from_str(&body)?;
        Ok(token.access_token)
    }
}
