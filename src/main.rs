use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use redis::aio::ConnectionManager;
use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef, State as SocketState},
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

const AES_KEY: &str = "0123456789abcdef";
const RATE_LIMIT: u32 = 100;
const RATE_WINDOW_MS: u64 = 60000;
const MESSAGE_CACHE_TTL: u64 = 300;

// ==================== DATA STRUCTURES ====================

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
    timestamp: u64,
    #[serde(rename = "senderUsername")]
    sender_username: Option<String>,
    #[serde(rename = "senderProfilePicUrl")]
    sender_profile_pic_url: Option<String>,
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
    redis: ConnectionManager,
    fcm_tokens: Arc<RwLock<HashMap<String, FcmTokenData>>>,
    fcm_service: Arc<FcmService>,
    rate_limiter: Arc<RwLock<RateLimiter>>,
    mongodb_api_url: String,
}

// ==================== MAIN ====================

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // Load environment variables
    dotenv::dotenv().ok();

    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()?;

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://localhost:6379".to_string());

    let mongodb_api_url = std::env::var("MONGODB_API_URL")
        .unwrap_or_else(|_| "https://server1-ki1x.onrender.com/api".to_string());

    let fcm_service_account_path = std::env::var("FCM_SERVICE_ACCOUNT_PATH")
        .unwrap_or_else(|_| "fcm-service-account.json".to_string());

    info!("🚀 Starting Chat Server on port {}", port);

    // Initialize Redis
    info!("📡 Connecting to Redis at {}", redis_url);
    let redis_client = redis::Client::open(redis_url)?;
    let redis_conn = ConnectionManager::new(redis_client).await?;
    info!("✅ Connected to Redis");

    // Initialize FCM
    info!("📱 Initializing Firebase Cloud Messaging");
    let fcm_service = Arc::new(FcmService::new(&fcm_service_account_path)?);
    info!("✅ Firebase Admin initialized - Project: {}", fcm_service.project_id());

    // Initialize shared state
    let state = AppState {
        redis: redis_conn.clone(),
        fcm_tokens: Arc::new(RwLock::new(HashMap::new())),
        fcm_service,
        rate_limiter: Arc::new(RwLock::new(RateLimiter::new(
            RATE_LIMIT,
            Duration::from_millis(RATE_WINDOW_MS),
        ))),
        mongodb_api_url,
    };

    // Create Socket.IO layer
    let (socket_layer, io) = SocketIo::builder()
        .with_state(state.clone())
        .build_layer();

    // Configure Socket.IO event handlers
    io.ns("/", |socket: SocketRef, state: SocketState<AppState>| {
        info!("🔌 Client connected: {}", socket.id);

        // Register event
        socket.on(
            "register",
            |socket: SocketRef, Data::<String>(user_id), state: SocketState<AppState>| async move {
                if user_id.is_empty() {
                    socket.emit("error", &json!({"message": "Invalid userId"})).ok();
                    return;
                }

                socket.leave_all().ok();
                socket.join(user_id).ok();
                
                info!("✅ User registered: {} (socket: {})", user_id, socket.id);

                // Replay pending messages
                if let Err(e) = replay_pending_messages(&socket, &user_id, &state.redis).await {
                    error!("Failed to replay pending messages for {}: {}", user_id, e);
                }

                // Replay pending seen events
                if let Err(e) = replay_pending_seen_events(&socket, &user_id, &state.redis).await {
                    error!("Failed to replay pending seen events for {}: {}", user_id, e);
                }
            },
        );

        // Chat message event
        socket.on(
            "chat message",
            |socket: SocketRef, Data::<ChatMessage>(message), state: SocketState<AppState>| async move {
                handle_chat_message(socket, message, state).await;
            },
        );

        // Message seen event
        socket.on(
            "message_seen",
            |socket: SocketRef, Data::<MessageSeenEvent>(data), state: SocketState<AppState>| async move {
                handle_message_seen(socket, data, state).await;
            },
        );

        // Typing event
        socket.on(
            "typing",
            |socket: SocketRef, Data::<TypingEvent>(data)| async move {
                if !data.receiver_id.is_empty() {
                    socket.to(data.receiver_id.as_str()).emit("typing", &data).ok();
                }
            },
        );

        socket.on_disconnect(|socket: SocketRef| async move {
            info!("🔌 Client disconnected: {}", socket.id);
        });
    });

    // Build HTTP router
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

    // Start server
    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("🎉 Server listening on {}", addr);

    axum::serve(listener, app).await?;

    Ok(())
}

// ==================== HTTP HANDLERS ====================

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let token_count = state.fcm_tokens.read().await.len();
    
    Json(HealthResponse {
        status: "ok".to_string(),
        fcm_enabled: true,
        registered_tokens: token_count,
        firebase_initialized: true,
    })
}

async fn register_fcm_token(
    State(state): State<AppState>,
    Json(req): Json<RegisterFcmRequest>,
) -> impl IntoResponse {
    if req.user_id.is_empty() || req.token.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "userId and token are required"
            })),
        );
    }

    if req.token.len() < 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "success": false,
                "error": "Invalid FCM token format"
            })),
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

    state
        .fcm_tokens
        .write()
        .await
        .insert(req.user_id.clone(), token_data);

    info!(
        "✅ FCM token registered for user: {} (token: {}...)",
        req.user_id,
        &req.token[..20.min(req.token.len())]
    );

    (
        StatusCode::OK,
        Json(json!({
            "success": true,
            "message": "FCM token registered successfully"
        })),
    )
}

async fn get_fcm_token_count(State(state): State<AppState>) -> impl IntoResponse {
    let tokens = state.fcm_tokens.read().await;
    let users: Vec<String> = tokens.keys().cloned().collect();

    Json(json!({
        "count": tokens.len(),
        "users": users
    }))
}

async fn delete_fcm_token(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    let mut tokens = state.fcm_tokens.write().await;
    
    if tokens.remove(&user_id).is_some() {
        info!("🗑️ Token deleted for user: {}", user_id);
        (
            StatusCode::OK,
            Json(json!({
                "success": true,
                "message": "Token deleted"
            })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({
                "success": false,
                "error": "Token not found"
            })),
        )
    }
}

async fn get_recent_chats(
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> impl IntoResponse {
    info!("📥 Proxying recent chats request for {}", user_id);

    let url = format!("{}/recent-chats/{}", state.mongodb_api_url, user_id);
    
    match reqwest::get(&url).await {
        Ok(response) => match response.json::<serde_json::Value>().await {
            Ok(data) => {
                let chats = data.get("chats").cloned().unwrap_or(json!([]));
                (StatusCode::OK, Json(chats))
            }
            Err(e) => {
                error!("Failed to parse recent chats response: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": "Failed to parse response" })),
                )
            }
        },
        Err(e) => {
            error!("Failed to fetch recent chats: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "Failed to fetch recent chats" })),
            )
        }
    }
}

// ==================== SOCKET.IO MESSAGE HANDLERS ====================

async fn handle_chat_message(
    socket: SocketRef,
    message: ChatMessage,
    state: SocketState<AppState>,
) {
    // Validation
    if message.sender_id.is_empty()
        || message.receiver_id.is_empty()
        || message.chat_id.is_empty()
        || message.message_id.is_empty()
    {
        error!("Invalid message structure");
        socket
            .emit(
                "ack",
                ErrorResponse {
                    status: "error".to_string(),
                    message: "Invalid message structure".to_string(),
                },
            )
            .ok();
        return;
    }

    // Rate limiting
    {
        let mut limiter = state.rate_limiter.write().await;
        if !limiter.check(&message.sender_id) {
            warn!("Rate limit exceeded for {}", message.sender_id);
            socket
                .emit(
                    "ack",
                    ErrorResponse {
                        status: "error".to_string(),
                        message: "Rate limit exceeded".to_string(),
                    },
                )
                .ok();
            return;
        }
    }

    info!(
        "💬 Message {}: {} -> {}",
        message.message_id, message.sender_id, message.receiver_id
    );

    // Store message in Redis
    let msg_key = format!("msg:{}", message.message_id);
    let msg_json = serde_json::to_string(&message).unwrap();

    if let Err(e) = redis::cmd("SETEX")
        .arg(&msg_key)
        .arg(MESSAGE_CACHE_TTL)
        .arg(&msg_json)
        .query_async::<_, ()>(&mut state.redis.clone())
        .await
    {
        error!("Failed to store message in Redis: {}", e);
    }

    // Update recent chats in MongoDB (fire and forget)
    let mongodb_url = state.mongodb_api_url.clone();
    let msg_clone = message.clone();
    tokio::spawn(async move {
        if let Err(e) = update_recent_chats_in_mongodb(&mongodb_url, &msg_clone).await {
            error!("Failed to update recent chats: {}", e);
        }
    });

    // Check if receiver is online
    let receiver_sockets = socket.within(&message.receiver_id).sockets().unwrap_or_default();
    let is_receiver_online = !receiver_sockets.is_empty();

    if is_receiver_online {
        // Deliver to online user
        socket
            .within(&message.receiver_id)
            .emit("chat message", &message)
            .ok();
        info!("✅ Message delivered to ONLINE user {}", message.receiver_id);
    } else {
        // Buffer for offline user
        let pending_key = format!("pending:{}", message.receiver_id);
        
        if let Err(e) = redis::cmd("RPUSH")
            .arg(&pending_key)
            .arg(&msg_json)
            .query_async::<_, ()>(&mut state.redis.clone())
            .await
        {
            error!("Failed to buffer message: {}", e);
        }

        if let Err(e) = redis::cmd("EXPIRE")
            .arg(&pending_key)
            .arg(MESSAGE_CACHE_TTL)
            .query_async::<_, ()>(&mut state.redis.clone())
            .await
        {
            error!("Failed to set expiry on pending messages: {}", e);
        }

        info!("📦 Buffered message for OFFLINE user {}", message.receiver_id);

        // Send push notification
        info!("📲 Sending push notification to {}...", message.receiver_id);
        
        let tokens = state.fcm_tokens.read().await;
        if let Some(token_data) = tokens.get(&message.receiver_id) {
            let sender_name = message.sender_username.clone().unwrap_or_else(|| "Someone".to_string());
            let content = message.content.clone();
            
            let fcm_service = state.fcm_service.clone();
            let receiver_id = message.receiver_id.clone();
            let chat_id = message.chat_id.clone();
            let sender_id = message.sender_id.clone();
            let token = token_data.token.clone();
            
            tokio::spawn(async move {
                match send_push_notification(
                    &fcm_service,
                    &receiver_id,
                    &sender_name,
                    &content,
                    &chat_id,
                    &sender_id,
                    &token,
                )
                .await
                {
                    Ok(message_id) => {
                        info!("✅ Push notification sent - FCM ID: {}", message_id);
                    }
                    Err(e) => {
                        warn!("⚠️ Push notification failed: {}", e);
                    }
                }
            });
        } else {
            warn!("⚠️ No FCM token found for user: {}", message.receiver_id);
        }
    }

    // Send acknowledgment
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    socket
        .emit(
            "ack",
            MessageAck {
                status: "delivered".to_string(),
                message_id: message.message_id.clone(),
                timestamp: now,
            },
        )
        .ok();
}

async fn handle_message_seen(
    socket: SocketRef,
    data: MessageSeenEvent,
    state: SocketState<AppState>,
) {
    if data.user_id.is_empty() || data.message_id.is_empty() {
        error!("Invalid seen event data");
        return;
    }

    info!("👁️ Message seen: {} by {}", data.message_id, data.user_id);

    // Get original message to find sender
    let msg_key = format!("msg:{}", data.message_id);
    let msg_str: Option<String> = redis::cmd("GET")
        .arg(&msg_key)
        .query_async(&mut state.redis.clone())
        .await
        .ok()
        .flatten();

    let sender_id = match msg_str {
        Some(s) => match serde_json::from_str::<ChatMessage>(&s) {
            Ok(msg) => msg.sender_id,
            Err(e) => {
                error!("Failed to parse cached message: {}", e);
                return;
            }
        },
        None => {
            warn!("Message {} not found in cache", data.message_id);
            return;
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    let evt = MessageSeenEvent {
        user_id: data.user_id.clone(),
        message_id: data.message_id.clone(),
        chat_id: data.chat_id.clone(),
        timestamp: now,
    };

    // Check if sender is online
    let sender_sockets = socket.within(&sender_id).sockets().unwrap_or_default();
    let is_sender_online = !sender_sockets.is_empty();

    if is_sender_online {
        socket.within(&sender_id).emit("message_seen", &evt).ok();
    } else {
        // Buffer for offline sender
        let pending_key = format!("pending_seen:{}", sender_id);
        let evt_json = serde_json::to_string(&evt).unwrap();

        if let Err(e) = redis::cmd("RPUSH")
            .arg(&pending_key)
            .arg(&evt_json)
            .query_async::<_, ()>(&mut state.redis.clone())
            .await
        {
            error!("Failed to buffer seen event: {}", e);
        }

        if let Err(e) = redis::cmd("EXPIRE")
            .arg(&pending_key)
            .arg(MESSAGE_CACHE_TTL)
            .query_async::<_, ()>(&mut state.redis.clone())
            .await
        {
            error!("Failed to set expiry on pending seen events: {}", e);
        }
    }
}

// ==================== HELPER FUNCTIONS ====================

async fn replay_pending_messages(
    socket: &SocketRef,
    user_id: &str,
    redis: &ConnectionManager,
) -> anyhow::Result<()> {
    let pending_key = format!("pending:{}", user_id);
    
    let messages: Vec<String> = redis::cmd("LRANGE")
        .arg(&pending_key)
        .arg(0)
        .arg(-1)
        .query_async(&mut redis.clone())
        .await?;

    for msg_str in &messages {
        if let Ok(msg) = serde_json::from_str::<ChatMessage>(msg_str) {
            socket.emit("chat message", msg).ok();
        }
    }

    if !messages.is_empty() {
        redis::cmd("DEL")
            .arg(&pending_key)
            .query_async::<()>(&mut redis.clone())
            .await?;
        
        info!("📬 Replayed {} pending messages for {}", messages.len(), user_id);
    }

    Ok(())
}

async fn replay_pending_seen_events(
    socket: &SocketRef,
    user_id: &str,
    redis: &ConnectionManager,
) -> anyhow::Result<()> {
    let pending_key = format!("pending_seen:{}", user_id);
    
    let events: Vec<String> = redis::cmd("LRANGE")
        .arg(&pending_key)
        .arg(0)
        .arg(-1)
        .query_async(&mut redis.clone())
        .await?;

    for evt_str in &events {
        if let Ok(evt) = serde_json::from_str::<MessageSeenEvent>(evt_str) {
            socket.emit("message_seen", evt).ok();
        }
    }

    if !events.is_empty() {
        redis::cmd("DEL")
            .arg(&pending_key)
            .query_async::<()>(&mut redis.clone())
            .await?;
        
        info!("👁️ Replayed {} pending seen events for {}", events.len(), user_id);
    }

    Ok(())
}

async fn update_recent_chats_in_mongodb(
    mongodb_url: &str,
    message: &ChatMessage,
) -> anyhow::Result<()> {
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
    let response = client
        .post(&url)
        .json(&payload)
        .timeout(Duration::from_secs(3))
        .send()
        .await?;

    if response.status().is_success() {
        info!("✅ Recent chats updated in MongoDB for chat {}", message.chat_id);
    } else {
        warn!("⚠️ Failed to update recent chats: status {}", response.status());
    }

    Ok(())
}

async fn send_push_notification(
    fcm_service: &FcmService,
    receiver_user_id: &str,
    sender_name: &str,
    message_text: &str,
    chat_id: &str,
    sender_id: &str,
    token: &str,
) -> anyhow::Result<String> {
    info!("Original message text length: {}", message_text.len());
    info!("First 30 chars: {}", &message_text[..30.min(message_text.len())]);

    let mut notification_text = message_text.to_string();

    // Check if message appears encrypted
    let is_encrypted = message_text.len() > 40
        && message_text.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        && !message_text.contains(' ');

    if is_encrypted {
        info!("Message appears encrypted, attempting decryption...");
        match decrypt_message(message_text) {
            Ok(decrypted) if decrypted != "New message" => {
                notification_text = decrypted;
                info!("✅ Successfully decrypted: \"{}\"", notification_text);
            }
            _ => {
                info!("⚠️ Decryption failed, using fallback");
                notification_text = "New message".to_string();
            }
        }
    } else {
        info!("Message does not appear encrypted");
    }

    // Truncate long messages
    if notification_text.len() > 100 {
        notification_text = format!("{}...", &notification_text[..97]);
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
        .to_string();

    let message_id = fcm_service
        .send_notification(
            token,
            sender_name,
            &notification_text,
            chat_id,
            sender_id,
            &now,
        )
        .await?;

    info!("✅ Push notification sent to {}", receiver_user_id);
    info!("   From: {}", sender_name);
    info!(
        "   Message preview: \"{}{}\"",
        &notification_text[..50.min(notification_text.len())],
        if notification_text.len() > 50 { "..." } else { "" }
    );

    Ok(message_id)
}

#[macro_export]
macro_rules! json {
    ($($json:tt)+) => {
        serde_json::json!($($json)+)
    };
}
