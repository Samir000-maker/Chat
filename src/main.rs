#![allow(dead_code)]

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use serde_json::json;
use socketioxide::{
    extract::{AckSender, Data, SocketRef, State as SocketState},
    SocketIo,
};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tracing::{error, info, warn};

mod crypto;
mod fcm;
mod rate_limit;

use crypto::decrypt_message;
use fcm::FcmService;
use rate_limit::RateLimiter;

// ==================== CONFIGURATION ====================

const RATE_LIMIT: u32 = 100;
const RATE_WINDOW_MS: u64 = 60000;
const MESSAGE_CACHE_TTL: u64 = 300;

// ==================== DATA STRUCTURES ====================

// ✅ CRITICAL FIX: Complete ChatMessage struct with ALL optional fields
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    #[serde(rename = "senderId")]
    sender_id: String,
    #[serde(rename = "receiverId")]
    receiver_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "messageId")]
    message_id: String,
    content: String,
    
    // ✅ CRITICAL FIX: Handle both string and u64 timestamps from Android
    #[serde(deserialize_with = "deserialize_timestamp")]
    timestamp: u64,
    
    // ✅ CRITICAL FIX: All optional fields that Android might send
    #[serde(default)]
    seen: bool,
    
    #[serde(rename = "senderUsername", skip_serializing_if = "Option::is_none")]
    sender_username: Option<String>,
    
    #[serde(rename = "senderProfilePicUrl", skip_serializing_if = "Option::is_none")]
    sender_profile_pic_url: Option<String>,
    
    #[serde(rename = "replyMessageId", skip_serializing_if = "Option::is_none")]
    reply_message_id: Option<String>,
    
    #[serde(rename = "replyMessage", skip_serializing_if = "Option::is_none")]
    reply_message: Option<String>,
    
    #[serde(rename = "attachmentType", skip_serializing_if = "Option::is_none")]
    attachment_type: Option<String>,
    
    #[serde(rename = "attachmentName", skip_serializing_if = "Option::is_none")]
    attachment_name: Option<String>,
    
    #[serde(rename = "attachmentSize", skip_serializing_if = "Option::is_none")]
    attachment_size: Option<u64>,
    
    #[serde(rename = "attachmentUrl", skip_serializing_if = "Option::is_none")]
    attachment_url: Option<String>,
    
    #[serde(rename = "attachmentData", skip_serializing_if = "Option::is_none")]
    attachment_data: Option<String>,
    
    #[serde(rename = "isSharedContent", skip_serializing_if = "Option::is_none")]
    is_shared_content: Option<bool>,
    
    #[serde(rename = "sharedPostId", skip_serializing_if = "Option::is_none")]
    shared_post_id: Option<String>,
    
    #[serde(rename = "sharedIsReel", skip_serializing_if = "Option::is_none")]
    shared_is_reel: Option<bool>,
    
    #[serde(rename = "sharedImageUrl", skip_serializing_if = "Option::is_none")]
    shared_image_url: Option<String>,
    
    #[serde(rename = "sharedCaption", skip_serializing_if = "Option::is_none")]
    shared_caption: Option<String>,
    
    #[serde(rename = "sharedUsername", skip_serializing_if = "Option::is_none")]
    shared_username: Option<String>,
    
    #[serde(rename = "sharedProfilePic", skip_serializing_if = "Option::is_none")]
    shared_profile_pic: Option<String>,
}

// ✅ CRITICAL FIX: Custom deserializer for timestamp that handles both string and number
fn deserialize_timestamp<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Deserialize};
    
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum TimestampValue {
        String(String),
        Number(u64),
    }
    
    match TimestampValue::deserialize(deserializer)? {
        TimestampValue::String(s) => s.parse::<u64>().map_err(de::Error::custom),
        TimestampValue::Number(n) => Ok(n),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageSeenEvent {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "messageId")]
    message_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypingEvent {
    #[serde(rename = "senderId")]
    sender_id: String,
    #[serde(rename = "receiverId")]
    receiver_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FcmTokenData {
    token: String,
    #[serde(rename = "deviceInfo")]
    device_info: Option<serde_json::Value>,
    #[serde(rename = "registeredAt")]
    registered_at: u64,
    #[serde(rename = "lastUpdated")]
    last_updated: u64,
}

#[derive(Debug, Deserialize)]
struct RegisterFcmRequest {
    #[serde(rename = "userId")]
    user_id: String,
    token: String,
    #[serde(rename = "deviceInfo")]
    device_info: Option<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct MessageAck {
    status: String,
    #[serde(rename = "messageId")]
    message_id: String,
    timestamp: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    #[serde(rename = "fcmEnabled")]
    fcm_enabled: bool,
    #[serde(rename = "registeredTokens")]
    registered_tokens: usize,
    #[serde(rename = "firebaseInitialized")]
    firebase_initialized: bool,
}

// ==================== APPLICATION STATE ====================

#[derive(Clone)]
struct AppState {
    redis: Option<ConnectionManager>,
    fcm_tokens: Arc<RwLock<HashMap<String, FcmTokenData>>>,
    fcm_service: Option<Arc<FcmService>>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    mongodb_api_url: String,
    pending_messages: Arc<RwLock<HashMap<String, Vec<ChatMessage>>>>,
    pending_seen_events: Arc<RwLock<HashMap<String, Vec<MessageSeenEvent>>>>,
    message_cache: Arc<RwLock<HashMap<String, ChatMessage>>>,
}

// ==================== MAIN ====================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ✅ CRITICAL FIX: Install default crypto provider FIRST
    rustls::crypto::CryptoProvider::install_default(
        rustls::crypto::aws_lc_rs::default_provider()
    )
    .expect("Failed to install rustls crypto provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    dotenv::dotenv().ok();

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()?;

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let mongodb_api_url = std::env::var("MONGODB_API_URL")
        .unwrap_or_else(|_| "https://server1-ki1x.onrender.com/api".to_string());

    let fcm_service_account_path = std::env::var("FCM_SERVICE_ACCOUNT_PATH")
        .unwrap_or_else(|_| "/opt/render/project/src/fcm-service-account.json".to_string());

    info!("🚀 Starting Chat Server on port {}", port);
    info!("📱 Looking for FCM service account at: {}", fcm_service_account_path);

    if std::path::Path::new(&fcm_service_account_path).exists() {
        info!("✅ FCM service account file found at: {}", fcm_service_account_path);
    } else {
        error!("❌ FCM service account file NOT FOUND at: {}", fcm_service_account_path);
        error!("   Push notifications will be DISABLED!");
    }

    info!("📡 Connecting to Redis at {}", redis_url);
    let redis_conn = match redis::Client::open(redis_url.clone()) {
        Ok(client) => match ConnectionManager::new(client).await {
            Ok(conn) => {
                info!("✅ Redis connection SUCCESSFUL");
                Some(conn)
            }
            Err(e) => {
                warn!("⚠️ Failed to connect to Redis: {}", e);
                warn!("💡 Using in-memory storage");
                None
            }
        },
        Err(e) => {
            warn!("⚠️ Invalid Redis URL: {}", e);
            warn!("💡 Using in-memory storage");
            None
        }
    };

info!("📱 Initializing Firebase Cloud Messaging...");

let fcm_service = match FcmService::new(&fcm_service_account_path) {
    Ok(service) => {
        info!("✅ FCM Service INITIALIZED successfully");
        info!("🧪 FCM: Running connection test...");
        
        // Test that we can at least create the client without immediate errors
        info!("✅ FCM: Service ready to send notifications");
        info!("   Project: {}", service.project_id());
        
        Some(Arc::new(service))
    }
    Err(e) => {
        error!("❌ FCM Service initialization FAILED");
        error!("   Error: {}", e);
        error!("   Possible causes:");
        error!("   1. Private key has literal '\\n' instead of actual newlines");
        error!("   2. System time is incorrect (JWT signing requires accurate time)");
        error!("   3. Service account JSON is malformed");
        error!("   4. Missing required fields in service account");
        error!("");
        error!("   Push notifications will be DISABLED");
        
        None
    }
};

    info!("🔐 Testing crypto module initialization...");
    match decrypt_message("dGVzdA==") {
        Ok(_) => info!("✅ Crypto module initialized successfully"),
        Err(e) => warn!("⚠️ Crypto module test failed (expected): {}", e),
    }

    let state = AppState {
        redis: redis_conn,
        fcm_tokens: Arc::new(RwLock::new(HashMap::new())),
        fcm_service: fcm_service.clone(),
        rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
            RATE_LIMIT,
            Duration::from_millis(RATE_WINDOW_MS),
        ))),
        mongodb_api_url,
        pending_messages: Arc::new(RwLock::new(HashMap::new())),
        pending_seen_events: Arc::new(RwLock::new(HashMap::new())),
        message_cache: Arc::new(RwLock::new(HashMap::new())),
    };

    info!("🔧 Configuring Socket.IO server...");
    
    let (socket_layer, io) = SocketIo::builder()
        .with_state(state.clone())
        .max_buffer_size(1024 * 1024)
        .ping_interval(Duration::from_secs(25))
        .ping_timeout(Duration::from_secs(60))
        .build_layer();

    info!("✅ Socket.IO configured");
    io.ns("/", handle_connection);
    info!("✅ Socket.IO namespace '/' registered");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/register-fcm-token", post(register_fcm_token))
        .route("/fcm-tokens/count", get(get_fcm_token_count))
        .route("/fcm-token/:user_id", delete(delete_fcm_token))
        .route("/recent-chats/:user_id", get(get_recent_chats))
        .layer(
            ServiceBuilder::new()
                .layer(CorsLayer::permissive())
                .layer(socket_layer),
        )
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    
    info!("🎉 ═══════════════════════════════════════════");
    info!("🎉 Server is LIVE and listening on {}", addr);
    info!("🎉 Ready to accept connections!");
    info!("🎉 ═══════════════════════════════════════════");

    axum::serve(listener, app).await?;

    Ok(())
}

// ==================== SOCKET.IO CONNECTION HANDLER ====================

fn handle_connection(socket: SocketRef) {
    let worker_id = std::process::id();
    info!("🔌 [Worker {}] NEW CLIENT CONNECTED: {}", worker_id, socket.id);

    socket.on(
        "register",
        |socket: SocketRef, Data(user_id): Data<String>, state: SocketState<AppState>| async move {
            let worker_id = std::process::id();
            info!("📝 [Worker {}] REGISTER event received", worker_id);
            info!("   User ID: {}", user_id);

            if user_id.is_empty() {
                error!("❌ Registration FAILED: Empty user_id");
                let _ = socket.emit("error", &json!({"message": "Invalid userId"}));
                return;
            }

            let _ = socket.leave_all();
            let _ = socket.join(user_id.clone());
            
            info!("✅ [Worker {}] User registered: {}", worker_id, user_id);

            if let Err(e) = replay_pending_messages(&socket, &user_id, &state.0).await {
                error!("❌ Failed to replay pending messages: {}", e);
            }

            if let Err(e) = replay_pending_seen_events(&socket, &user_id, &state.0).await {
                error!("❌ Failed to replay pending seen events: {}", e);
            }
        },
    );

    // ✅ CRITICAL FIX: Use serde_json::Value first to debug deserialization issues
    socket.on(
        "chat message",
        |socket: SocketRef, Data(value): Data<serde_json::Value>, ack: AckSender, state: SocketState<AppState>| async move {
            let worker_id = std::process::id();
            
            info!("💬 [Worker {}] ===== CHAT MESSAGE EVENT RECEIVED =====", worker_id);
            info!("📦 [Worker {}] Raw JSON: {}", worker_id, serde_json::to_string_pretty(&value).unwrap());
            
            // ✅ Try to deserialize
            match serde_json::from_value::<ChatMessage>(value.clone()) {
                Ok(message) => {
                    info!("✅ [Worker {}] Successfully deserialized message", worker_id);
                    info!("   Message ID: {}", message.message_id);
                    info!("   From: {} -> To: {}", message.sender_id, message.receiver_id);
                    info!("   Content length: {} bytes", message.content.len());
                    
                    handle_chat_message(socket, message, ack, state.0).await;
                }
                Err(e) => {
                    error!("❌ [Worker {}] DESERIALIZATION ERROR: {}", worker_id, e);
                    error!("❌ Raw JSON that failed: {}", serde_json::to_string_pretty(&value).unwrap());
                    
                    let error_response = ErrorResponse {
                        status: "error".to_string(),
                        message: format!("Failed to parse message: {}", e),
                    };
                    let _ = ack.send(&error_response);
                }
            }
        },
    );

    socket.on(
        "message_seen",
        |socket: SocketRef, Data(data): Data<MessageSeenEvent>, state: SocketState<AppState>| async move {
            let worker_id = std::process::id();
            info!("👁️ [Worker {}] MESSAGE_SEEN event received", worker_id);
            handle_message_seen(socket, data, state.0).await;
        },
    );

    socket.on(
        "typing",
        |socket: SocketRef, Data(data): Data<TypingEvent>| async move {
            let worker_id = std::process::id();
            info!("⌨️ [Worker {}] TYPING event received", worker_id);
            
            if !data.receiver_id.is_empty() {
                let _ = socket.to(data.receiver_id.clone()).emit("typing", &data);
            }
        },
    );

    socket.on_disconnect(|socket: SocketRef| async move {
        let worker_id = std::process::id();
        info!("🔌 [Worker {}] CLIENT DISCONNECTED: {}", worker_id, socket.id);
    });

    info!("✅ [Worker {}] Event handlers registered for socket: {}", worker_id, socket.id);
}

// ==================== HTTP HANDLERS (same as before) ====================

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let token_count = state.fcm_tokens.read().await.len();
    
    Json(HealthResponse {
        status: "ok".to_string(),
        fcm_enabled: state.fcm_service.is_some(),
        registered_tokens: token_count,
        firebase_initialized: state.fcm_service.is_some(),
    })
}

async fn register_fcm_token(
    State(state): State<AppState>,
    Json(req): Json<RegisterFcmRequest>,
) -> impl IntoResponse {
    info!("📱 FCM token registration request for: {}", req.user_id);

    if req.user_id.is_empty() || req.token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"success": false, "error": "userId and token required"})),
        );
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let token_data = FcmTokenData {
        token: req.token.clone(),
        device_info: req.device_info,
        registered_at: now,
        last_updated: now,
    };

    state.fcm_tokens.write().await.insert(req.user_id.clone(), token_data);

    info!("✅ FCM token registered for: {}", req.user_id);
    info!("   Total tokens: {}", state.fcm_tokens.read().await.len());

    (StatusCode::OK, Json(json!({"success": true})))
}

async fn get_fcm_token_count(State(state): State<AppState>) -> impl IntoResponse {
    let tokens = state.fcm_tokens.read().await;
    Json(json!({"count": tokens.len(), "users": tokens.keys().collect::<Vec<_>>()}))
}

async fn delete_fcm_token(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let mut tokens = state.fcm_tokens.write().await;
    
    if tokens.remove(&user_id).is_some() {
        (StatusCode::OK, Json(json!({"success": true})))
    } else {
        (StatusCode::NOT_FOUND, Json(json!({"success": false})))
    }
}

async fn get_recent_chats(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let url = format!("{}/recent-chats/{}", state.mongodb_api_url, user_id);
    
    match reqwest::get(&url).await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(data) => (StatusCode::OK, Json(data.get("chats").cloned().unwrap_or(json!([])))),
            Err(e) => {
                error!("Failed to parse: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Parse failed"})))
            }
        },
        Err(e) => {
            error!("Failed to fetch: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "Fetch failed"})))
        }
    }
}

// ==================== MESSAGE HANDLERS (continue in next file) ====================

async fn handle_chat_message(
    socket: SocketRef,
    message: ChatMessage,
    ack: AckSender,
    state: AppState,
) {
    let worker_id = std::process::id();
    info!("📨 [Worker {}] Processing message {}", worker_id, message.message_id);
    
    // Validate
    if message.sender_id.is_empty() || message.receiver_id.is_empty() {
        error!("Invalid message structure");
        let _ = ack.send(&ErrorResponse {
            status: "error".to_string(),
            message: "Invalid message".to_string(),
        });
        return;
    }

    // Rate limit
    {
        let mut limiter = state.rate_limiter.write().await;
        if !limiter.check(&message.sender_id) {
            warn!("Rate limit exceeded");
            let _ = ack.send(&ErrorResponse {
                status: "error".to_string(),
                message: "Rate limit exceeded".to_string(),
            });
            return;
        }
    }

    // Cache message
    if let Some(redis) = &state.redis {
        let msg_key = format!("msg:{}", message.message_id);
        let msg_json = serde_json::to_string(&message).unwrap();
        let mut redis_conn = redis.clone();
        let _: Result<(), redis::RedisError> = redis::cmd("SETEX")
            .arg(&msg_key)
            .arg(MESSAGE_CACHE_TTL)
            .arg(&msg_json)
            .query_async(&mut redis_conn)
            .await;
    } else {
        state.message_cache.write().await.insert(message.message_id.clone(), message.clone());
    }

    // Update MongoDB
    let mongodb_url = state.mongodb_api_url.clone();
    let msg_clone = message.clone();
    tokio::spawn(async move {
        let _ = update_recent_chats_in_mongodb(&mongodb_url, &msg_clone).await;
    });

    // Check receiver online
    let receiver_sockets = socket.within(message.receiver_id.clone()).sockets().unwrap_or_default();
    let is_receiver_online = !receiver_sockets.is_empty();

    info!("🔍 [Worker {}] Receiver {} online: {}", worker_id, message.receiver_id, is_receiver_online);

    if is_receiver_online {
        let _ = socket.within(message.receiver_id.clone()).emit("chat message", &message);
        info!("✅ [Worker {}] Delivered to ONLINE user", worker_id);
    } else {
        // Buffer message
        if let Some(redis) = &state.redis {
            let pending_key = format!("pending:{}", message.receiver_id);
            let msg_json = serde_json::to_string(&message).unwrap();
            let mut redis_conn = redis.clone();
            
            let _: Result<(), redis::RedisError> = redis::cmd("RPUSH")
                .arg(&pending_key)
                .arg(&msg_json)
                .query_async(&mut redis_conn)
                .await;

            let _: Result<(), redis::RedisError> = redis::cmd("EXPIRE")
                .arg(&pending_key)
                .arg(MESSAGE_CACHE_TTL)
                .query_async(&mut redis_conn)
                .await;
        } else {
            state.pending_messages.write().await
                .entry(message.receiver_id.clone())
                .or_insert_with(Vec::new)
                .push(message.clone());
        }

        info!("📦 [Worker {}] Buffered for OFFLINE user", worker_id);
        
        // Send push notification
        let tokens = state.fcm_tokens.read().await;
        if let Some(token_data) = tokens.get(&message.receiver_id) {
            if let Some(fcm_service) = &state.fcm_service {
                let sender_name = message.sender_username.clone().unwrap_or_else(|| "Someone".to_string());
                let content = message.content.clone();
                
                info!("📲 [Worker {}] Sending push notification", worker_id);
                
                let fcm_service_clone = fcm_service.clone();
                let receiver_id = message.receiver_id.clone();
                let chat_id = message.chat_id.clone();
                let sender_id = message.sender_id.clone();
                let token = token_data.token.clone();
                
                tokio::spawn(async move {
                    match send_push_notification(
                        &fcm_service_clone,
                        &receiver_id,
                        &sender_name,
                        &content,
                        &chat_id,
                        &sender_id,
                        &token,
                    ).await {
                        Ok(msg_id) => info!("✅ Push sent: {}", msg_id),
                        Err(e) => warn!("⚠️ Push failed: {}", e),
                    }
                });
            }
        }
    }

    // Send acknowledgment
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let _ = ack.send(&MessageAck {
        status: "delivered".to_string(),
        message_id: message.message_id.clone(),
        timestamp: now,
    });
    
    info!("✅ [Worker {}] Ack sent for {}", worker_id, message.message_id);
}

async fn handle_message_seen(socket: SocketRef, data: MessageSeenEvent, state: AppState) {
    let worker_id = std::process::id();
    info!("👁️ [Worker {}] Processing seen event", worker_id);

    let sender_id = if let Some(redis) = &state.redis {
        let msg_key = format!("msg:{}", data.message_id);
        let mut redis_conn = redis.clone();
        let msg_str: Result<Option<String>, redis::RedisError> = redis::cmd("GET")
            .arg(&msg_key)
            .query_async(&mut redis_conn)
            .await;

        match msg_str {
            Ok(Some(s)) => match serde_json::from_str::<ChatMessage>(&s) {
                Ok(msg) => msg.sender_id,
                Err(_) => return,
            },
            _ => return,
        }
    } else {
        let cache = state.message_cache.read().await;
        match cache.get(&data.message_id) {
            Some(msg) => msg.sender_id.clone(),
            None => return,
        }
    };

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let evt = MessageSeenEvent {
        user_id: data.user_id,
        message_id: data.message_id,
        chat_id: data.chat_id,
        timestamp: now,
    };

    let sender_sockets = socket.within(sender_id.clone()).sockets().unwrap_or_default();
    
    if !sender_sockets.is_empty() {
        let _ = socket.within(sender_id).emit("message_seen", &evt);
    } else {
        if let Some(redis) = &state.redis {
            let pending_key = format!("pending_seen:{}", sender_id);
            let evt_json = serde_json::to_string(&evt).unwrap();
            let mut redis_conn = redis.clone();
            let _: Result<(), redis::RedisError> = redis::cmd("RPUSH")
                .arg(&pending_key)
                .arg(&evt_json)
                .query_async(&mut redis_conn)
                .await;
        }
    }
}

async fn replay_pending_messages(socket: &SocketRef, user_id: &str, state: &AppState) -> anyhow::Result<()> {
    let messages = if let Some(redis) = &state.redis {
        let pending_key = format!("pending:{}", user_id);
        let mut redis_conn = redis.clone();
        let messages: Vec<String> = redis::cmd("LRANGE")
            .arg(&pending_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut redis_conn)
            .await?;

        if !messages.is_empty() {
            let _: () = redis::cmd("DEL").arg(&pending_key).query_async(&mut redis_conn).await?;
        }

        messages.iter().filter_map(|s| serde_json::from_str::<ChatMessage>(s).ok()).collect()
    } else {
        state.pending_messages.write().await.remove(user_id).unwrap_or_default()
    };

    for msg in &messages {
        let _ = socket.emit("chat message", msg);
    }

    if !messages.is_empty() {
        info!("📬 Replayed {} messages for {}", messages.len(), user_id);
    }

    Ok(())
}

async fn replay_pending_seen_events(socket: &SocketRef, user_id: &str, state: &AppState) -> anyhow::Result<()> {
    let events = if let Some(redis) = &state.redis {
        let pending_key = format!("pending_seen:{}", user_id);
        let mut redis_conn = redis.clone();
        let events: Vec<String> = redis::cmd("LRANGE")
            .arg(&pending_key)
            .arg(0)
            .arg(-1)
            .query_async(&mut redis_conn)
            .await?;

        if !events.is_empty() {
            let _: () = redis::cmd("DEL").arg(&pending_key).query_async(&mut redis_conn).await?;
        }

        events.iter().filter_map(|s| serde_json::from_str::<MessageSeenEvent>(s).ok()).collect()
    } else {
        state.pending_seen_events.write().await.remove(user_id).unwrap_or_default()
    };

    for evt in &events {
        let _ = socket.emit("message_seen", evt);
    }

    Ok(())
}

async fn update_recent_chats_in_mongodb(mongodb_url: &str, message: &ChatMessage) -> anyhow::Result<()> {
    let url = format!("{}/recent-chats/update", mongodb_url);
    
    let payload = json!({
        "senderId": message.sender_id,
        "receiverId": message.receiver_id,
        "chatId": message.chat_id,
        "lastMessage": message.content,
        "timestamp": message.timestamp,
        "senderUsername": message.sender_username,
        "senderProfilePicUrl": message.sender_profile_pic_url
    });

    let client = reqwest::Client::new();
    let _ = client.post(&url).json(&payload).timeout(Duration::from_secs(3)).send().await?;
    Ok(())
}

async fn send_push_notification(
    fcm_service: &FcmService,
    _receiver_user_id: &str,
    sender_name: &str,
    message_text: &str,
    chat_id: &str,
    sender_id: &str,
    token: &str,
) -> anyhow::Result<String> {
    let mut notification_text = message_text.to_string();

    let is_encrypted = message_text.len() > 40
        && message_text.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !message_text.contains(' ');

    if is_encrypted {
        match decrypt_message(message_text) {
            Ok(decrypted) if !decrypted.is_empty() => {
                notification_text = decrypted;
            }
            _ => {
                notification_text = "New message".to_string();
            }
        }
    }

    if notification_text.len() > 100 {
        notification_text = format!("{}...", &notification_text[..97]);
    }

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis().to_string();

    fcm_service.send_notification(token, sender_name, &notification_text, chat_id, sender_id, &now).await
}
