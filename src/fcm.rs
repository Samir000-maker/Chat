use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
const FCM_ENDPOINT: &str = "https://fcm.googleapis.com/v1/projects";

// ✅ HARDCODED FALLBACK - Use these if service account file fails
const HARDCODED_PROJECT_ID: &str = "projectt3-8c55e";
const HARDCODED_CLIENT_EMAIL: &str = "firebase-adminsdk-fbsvc@projectt3-8c55e.iam.gserviceaccount.com";
const HARDCODED_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCyvilZpz9nElhT
aXW2D7PPKgLQEVr6ve//21rpe+GAj8v799/nDbXVWU7Nj3+P3KGkWPUIN5p0A6Wf
TOdXtipnVReOqvGpa4oUTisaU3zcT+bLCzbsGXmi+fCNWgV3CclURQjZP/7uVmDt
6hWyVb09MN088Szf9Kkps/AdqR1d9fv1+au9+Gj9sDerW8rM5EwAQ7AWcBPjcwqU
dsxR9+4ixtnIaCJO1/+1JoMe2x9d1fmw0x4CVXzasulw9oUgJ++MFFNsoJZMxB1y
i5w/yfJzKlzj2AYfKgnSU/FlsKaRuX1dj0lf++vmYrOFuaGbuaOMnBWC9wU23oHx
BQy5UhrLAgMBAAECggEADUA4u4tBEYiUILboQZN/boO8SqWGu6D6GlsuLbH/4TKH
2kmhgTUMfmENDQMu30DpgNARdkb8/c3JaPpgCioYkamGwg5dNQSia2fyHRUEZCbO
Qs41h6JJ2LGzyh7a2dzRXpxxj/2FDjE8JVcdvadKjK9DL4HnpEC0i8FpsyE26qCy
hJdwqxGXb00wnrUKJ3gBk6B4Zb26o4Eems34aAAkOCH9IfABy5yBo4ZQVpY603pN
pkOqoSx/huq4mWissNRbiAXHCVcg3eGDzS+WEngch86VC6UHAPRvdn6NFZAqyNU3
l+AX3tk2ui1neOZX4NuqbIgabL63S58dqDvBQe5SVQKBgQDiqKJuMfWeoOCCAaF6
Y+gtIEbPz1cQeRczd0tG89V/L3ZxCZZf+Mz1TEA9YhJ6DuQcC34Y37fx+cKP/Crp
EEbZEWg4ZBxG7JKQ6wQ5j9J9C37b75FR2gYJjM3V6mHjTZjlp6AJaum20UiqJzP1
YDpLonVFLzGtW/KFFc1nia1VTQKBgQDJ4Z2swEsOZHiq/5sg1FxpS1E0/nTOw8MV
NufauprfsfCTiNR13//AZ0TBQDEjC35H8lmVW/1FkWNz0kFKQj/cNYZ0ZCoXhcuA
vgs0hukZrIgGJT+wPXouicIXk5XFqd+1FMTSC+9E5UBPEEkW8p+MmG0bKBvcJRbd
F2vxE/NEdwKBgG3vUxFVpAdzilEkT1kYmiVBEXd73oO759frlZRtcfEFaVI8TzZv
a6HSgRoEtmeDT3qWzGtuHz77YDYMHhf68BIa0kz/qYNw/UnS47KzomlKKRat5PMp
Z2I8bB3EWAQyv+Ur34CR3ZfxfGgjKZ1rNfs3ad/LmzG1djS8tWrxqSPFAoGACI0d
+KtMgpeO5O9eys0z/OHL1srQd9Gi+csRlxpAZSlMX3N0TGnok2XMa8MkUa+y8ak6
UjFLUR8Pb2CAk3yq59D8mQGFJunr7NAf+WGdjhDY0inRwM1Z147OQeFmfrDrYOg4
Tg1jXS+4waCW9/ne+D2coYHZbEHF7ieH0vZdX5ECgYBaMy13ubgOhaus7mcN0zKd
bPU1++KBniw86LY4jNT77oIilnN34jVFy7mM0F9S1mnvCmESmr9RgmVFCrUZyS7T
n+TBpLjjfJMtE5QWNMGDFl1E8UEjqNVfR3bjUxFUYyP9iMdmQINNrPhJY88WMM36
nL8XavNrpnK8bNF3I7aMPw==
-----END PRIVATE KEY-----"#;

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
        info!("📱 FCM: Initializing service...");
        
        // Try to load from file first
        let (project_id, private_key, client_email) = 
            if std::path::Path::new(service_account_path).exists() {
                info!("✅ FCM: Service account file found, loading...");
                
                match std::fs::read_to_string(service_account_path) {
                    Ok(content) => {
                        match serde_json::from_str::<ServiceAccount>(&content) {
                            Ok(sa) => {
                                info!("✅ FCM: Service account loaded from file");
                                (sa.project_id, sa.private_key, sa.client_email)
                            }
                            Err(e) => {
                                error!("❌ FCM: Failed to parse service account: {}", e);
                                warn!("⚠️ FCM: Falling back to hardcoded credentials");
                                (
                                    HARDCODED_PROJECT_ID.to_string(),
                                    HARDCODED_PRIVATE_KEY.to_string(),
                                    HARDCODED_CLIENT_EMAIL.to_string(),
                                )
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ FCM: Failed to read file: {}", e);
                        warn!("⚠️ FCM: Falling back to hardcoded credentials");
                        (
                            HARDCODED_PROJECT_ID.to_string(),
                            HARDCODED_PRIVATE_KEY.to_string(),
                            HARDCODED_CLIENT_EMAIL.to_string(),
                        )
                    }
                }
            } else {
                warn!("⚠️ FCM: Service account file not found");
                warn!("⚠️ FCM: Using hardcoded credentials");
                (
                    HARDCODED_PROJECT_ID.to_string(),
                    HARDCODED_PRIVATE_KEY.to_string(),
                    HARDCODED_CLIENT_EMAIL.to_string(),
                )
            };

        info!("✅ FCM: Service initialized");
        info!("   Project ID: {}", project_id);
        info!("   Client Email: {}", client_email);
        info!("   Private Key length: {} chars", private_key.len());

        Ok(Self {
            project_id,
            private_key,
            client_email,
            access_token: parking_lot::RwLock::new(None),
            token_expiry: parking_lot::RwLock::new(0),
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    async fn get_access_token(&self) -> Result<String> {
        // Check cache
        {
            let token = self.access_token.read();
            let expiry = *self.token_expiry.read();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if let Some(ref token_str) = *token {
                if now < expiry - 300 {
                    return Ok(token_str.clone());
                }
            }
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        info!("🔑 FCM: Creating JWT...");
        let claims = Claims {
            iss: self.client_email.clone(),
            scope: FCM_SCOPE.to_string(),
            aud: "https://oauth2.googleapis.com/token".to_string(),
            exp: now + 3600,
            iat: now,
        };

        // ✅ CRITICAL FIX: Create header with typ explicitly set to "JWT"
        let mut header = Header::new(Algorithm::RS256);
        header.typ = Some("JWT".to_string());
        
        info!("✅ FCM: JWT header: alg=RS256, typ=JWT");

        // ✅ CRITICAL FIX: Properly handle newlines in private key
        let normalized_key = self.private_key
            .replace("\\n", "\n")
            .trim()
            .to_string();
        
        info!("🔑 FCM: Key first line: {}", 
            normalized_key.lines().next().unwrap_or(""));

        let key = EncodingKey::from_rsa_pem(normalized_key.as_bytes())
            .map_err(|e| {
                error!("❌ FCM: Failed to parse private key: {}", e);
                anyhow!("Failed to parse private key: {}", e)
            })?;

        let jwt = encode(&header, &claims, &key)
            .map_err(|e| {
                error!("❌ FCM: Failed to encode JWT: {}", e);
                anyhow!("Failed to encode JWT: {}", e)
            })?;

        info!("✅ FCM: JWT created (length: {} chars)", jwt.len());

        // Exchange JWT for access token
        info!("🔑 FCM: Exchanging JWT for access token...");
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
            .map_err(|e| anyhow!("Failed to exchange JWT: {}", e))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            error!("❌ FCM: Token exchange failed: {} - {}", status, body);
            error!("   JWT preview: {}...", &jwt[..100.min(jwt.len())]);
            return Err(anyhow!("Token exchange failed: {} - {}", status, body));
        }

        let token_response: TokenResponse = response
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse token response: {}", e))?;

        info!("✅ FCM: Access token obtained (expires in {} seconds)", 
            token_response.expires_in);

        // Cache the token
        {
            *self.access_token.write() = Some(token_response.access_token.clone());
            *self.token_expiry.write() = now + token_response.expires_in;
        }

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
        info!("📤 FCM: Sending notification");
        info!("   From: {}", sender_name);
        info!("   Message: {}...", &message_text[..message_text.len().min(30)]);

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
            error!("❌ FCM: Request failed: {} - {}", status, body);
            
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

        info!("✅ FCM: Notification sent!");
        info!("   Message ID: {}", fcm_response.name);

        Ok(fcm_response.name)
    }
}
