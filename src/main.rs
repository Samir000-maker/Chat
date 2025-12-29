use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use parking_lot::RwLock;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client as RedisClient, RedisError};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use serde::{Deserialize, Serialize};
use socketioxide::{
    extract::{Data, SocketRef, State as SocketState},
    SocketIo,
};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::interval;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer,
};
use tracing::{debug, error, info, warn};
use base64::{Engine as _, engine::general_purpose};

// ==================== CONSTANTS & CONFIGURATION ====================
const MAX_CONNECTIONS: usize = 400_000;
const GLOBAL_RATE_LIMIT: u64 = 1_000_000;
const USER_RATE_LIMIT: u64 = 100;
const RATE_WINDOW_SECS: u64 = 60;
const PENDING_MESSAGE_TTL: i64 = 300;
const REDIS_POOL_SIZE: usize = 32;

// AES-128-GCM Encryption
const AES_KEY: &[u8] = b"0123456789abcdef";

// ==================== TYPES & STRUCTURES ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    #[serde(rename = "messageId")]
    message_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "senderId")]
    sender_id: String,
    #[serde(rename = "receiverId")]
    receiver_id: String,
    content: String,
    timestamp: String,
    seen: bool,
    #[serde(rename = "replyMessageId", skip_serializing_if = "Option::is_none")]
    reply_message_id: Option<String>,
    #[serde(rename = "replyMessage", skip_serializing_if = "Option::is_none")]
    reply_message: Option<String>,
    #[serde(rename = "senderUsername", skip_serializing_if = "Option::is_none")]
    sender_username: Option<String>,
    #[serde(rename = "senderProfilePicUrl", skip_serializing_if = "Option::is_none")]
    sender_profile_pic_url: Option<String>,
    #[serde(rename = "attachmentType", skip_serializing_if = "Option::is_none")]
    attachment_type: Option<String>,
    #[serde(rename = "attachmentName", skip_serializing_if = "Option::is_none")]
    attachment_name: Option<String>,
    #[serde(rename = "attachmentSize", skip_serializing_if = "Option::is_none")]
    attachment_size: Option<i64>,
    #[serde(rename = "attachmentUrl", skip_serializing_if = "Option::is_none")]
    attachment_url: Option<String>,
    #[serde(rename = "attachmentData", skip_serializing_if = "Option::is_none")]
    attachment_data: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageSeen {
    #[serde(rename = "messageId")]
    message_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "userId")]
    user_id: String,
    timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypingIndicator {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "receiverId")]
    receiver_id: String,
    #[serde(rename = "chatId")]
    chat_id: String,
    #[serde(rename = "isTyping")]
    is_typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FcmTokenRequest {
    #[serde(rename = "userId")]
    user_id: String,
    token: String,
    #[serde(rename = "deviceInfo", skip_serializing_if = "Option::is_none")]
    device_info: Option<HashMap<String, String>>,
}

struct RateLimiter {
    user_limits: Arc<DashMap<String, (u64, u64)>>,
    global_counter: Arc<AtomicU64>,
    global_reset: Arc<AtomicU64>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            user_limits: Arc::new(DashMap::new()),
            global_counter: Arc::new(AtomicU64::new(0)),
            global_reset: Arc::new(AtomicU64::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + RATE_WINDOW_SECS,
            )),
        }
    }

    fn check_global(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let reset_time = self.global_reset.load(Ordering::Relaxed);

        if now > reset_time {
            self.global_counter.store(0, Ordering::Relaxed);
            self.global_reset
                .store(now + RATE_WINDOW_SECS, Ordering::Relaxed);
        }

        let count = self.global_counter.fetch_add(1, Ordering::Relaxed);
        count < GLOBAL_RATE_LIMIT
    }

    fn check_user(&self, user_id: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut entry = self
            .user_limits
            .entry(user_id.to_string())
            .or_insert((0, now + RATE_WINDOW_SECS));

        if now > entry.1 {
            *entry = (1, now + RATE_WINDOW_SECS);
            true
        } else if entry.0 < USER_RATE_LIMIT {
            entry.0 += 1;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct AppState {
    redis_pool: Arc<RwLock<Vec<ConnectionManager>>>,
    fcm_tokens: Arc<DashMap<String, String>>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<Metrics>,
    user_sockets: Arc<DashMap<String, String>>, // user_id -> socket_id mapping
}

struct Metrics {
    total_connections: AtomicUsize,
    total_messages: AtomicU64,
    active_users: AtomicUsize,
    failed_messages: AtomicU64,
    rate_limited: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            total_connections: AtomicUsize::new(0),
            total_messages: AtomicU64::new(0),
            active_users: AtomicUsize::new(0),
            failed_messages: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
        }
    }
}

// ==================== ENCRYPTION ====================

fn decrypt_message(encrypted_b64: &str) -> Result<String, Box<dyn std::error::Error>> {
    let combined = general_purpose::STANDARD.decode(encrypted_b64)?;

    if combined.len() < 12 + 16 {
        return Ok("New message".to_string());
    }

    let iv = &combined[0..12];
    let ciphertext_with_tag = &combined[12..];

    let unbound_key = UnboundKey::new(&AES_128_GCM, AES_KEY)
        .map_err(|_| "Failed to create key")?;
    let key = LessSafeKey::new(unbound_key);
    
    let nonce = Nonce::try_assume_unique_for_key(iv)
        .map_err(|_| "Invalid nonce")?;

    let mut in_out = ciphertext_with_tag.to_vec();
    let decrypted = key
        .open_in_place(nonce, Aad::empty(), &mut in_out)
        .map_err(|_| "Decryption failed")?;

    Ok(String::from_utf8(decrypted.to_vec())?)
}

// ==================== REDIS CONNECTION POOL ====================

async fn create_redis_pool(redis_url: &str) -> Result<Vec<ConnectionManager>, RedisError> {
    let mut pool = Vec::with_capacity(REDIS_POOL_SIZE);
    let client = RedisClient::open(redis_url)?;

    for i in 0..REDIS_POOL_SIZE {
        match ConnectionManager::new(client.clone()).await {
            Ok(conn) => {
                pool.push(conn);
                if i == 0 {
                    info!("✅ Redis connection established");
                }
            }
            Err(e) => {
                warn!("⚠️ Redis connection {} failed: {}", i, e);
                if i == 0 {
                    break;
                }
            }
        }
    }

    if pool.is_empty() {
        warn!("⚠️ No Redis connections available - running without persistence");
    } else {
        info!("📦 Redis pool created with {} connections", pool.len());
    }

    Ok(pool)
}

fn get_redis_conn(state: &AppState) -> Option<ConnectionManager> {
    let pool = state.redis_pool.read();
    if pool.is_empty() {
        return None;
    }
    let idx = rand::random::<usize>() % pool.len();
    Some(pool[idx].clone())
}

// ==================== SOCKET.IO HANDLERS ====================

async fn on_connect(socket: SocketRef, SocketState(state): SocketState<AppState>) {
    info!("🟢 Socket connected: {}", socket.id);
    
    state.metrics.total_connections.fetch_add(1, Ordering::Relaxed);
    
    // Register handler
    socket.on(
        "register",
        |socket: SocketRef, Data::<String>(user_id), SocketState(state): SocketState<AppState>| async move {
            info!("📝 User registered: {} -> {}", user_id, socket.id);
            
            // Store user_id -> socket_id mapping
            state.user_sockets.insert(user_id.clone(), socket.id.to_string());
            state.metrics.active_users.fetch_add(1, Ordering::Relaxed);
            
            // Replay pending messages from Redis
            if let Some(mut redis) = get_redis_conn(&state) {
                let key = format!("pending:{}", user_id);
                if let Ok(messages) = redis.lrange::<_, Vec<String>>(&key, 0, -1).await {
                    for msg_str in messages {
                        if let Ok(msg) = serde_json::from_str::<ChatMessage>(&msg_str) {
                            let _ = socket.emit("chat message", msg);
                        }
                    }
                    let _: Result<(), RedisError> = redis.del(&key).await;
                    info!("📬 Replayed pending messages for user: {}", user_id);
                }
            }
        },
    );
    
    // Chat message handler
    socket.on(
        "chat message",
        |socket: SocketRef, Data::<ChatMessage>(msg), SocketState(state): SocketState<AppState>| async move {
            info!("📨 Message received: {} from {} to {}", msg.message_id, msg.sender_id, msg.receiver_id);
            
            // Rate limiting
            if !state.rate_limiter.check_global() {
                state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                let _ = socket.emit("error", serde_json::json!({"error": "Global rate limit exceeded"}));
                return Ok(());
            }
            
            if !state.rate_limiter.check_user(&msg.sender_id) {
                state.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
                let _ = socket.emit("error", serde_json::json!({"error": "User rate limit exceeded"}));
                return Ok(());
            }
            
            state.metrics.total_messages.fetch_add(1, Ordering::Relaxed);
            
            // Check if receiver is online
            if let Some(receiver_socket_id) = state.user_sockets.get(&msg.receiver_id) {
                // Send to receiver's socket
                if let Some(receiver_socket) = socket.get_socket(receiver_socket_id.value()) {
                    let _ = receiver_socket.emit("chat message", msg.clone());
                    debug!("✅ Message delivered to online user: {}", msg.receiver_id);
                } else {
                    // Socket not found, store in Redis
                    store_pending_message(&state, &msg).await;
                }
            } else {
                // User offline, store in Redis
                store_pending_message(&state, &msg).await;
                
                // Send push notification
                send_push_notification(&state, &msg).await;
            }
            
            // Send acknowledgment to sender
            socket.emit("chat message", serde_json::json!({
                "status": "delivered",
                "messageId": msg.message_id
            }))
        },
    );
    
    // Message seen handler
    socket.on(
        "message_seen",
        |socket: SocketRef, Data::<MessageSeen>(seen), SocketState(state): SocketState<AppState>| async move {
            debug!("👁️ Message seen: {} by {}", seen.message_id, seen.user_id);
            
            // Find sender's socket and notify
            // Note: You need to track who sent which message to route this correctly
            // For simplicity, we'll broadcast to the chat
            if let Some(sender_socket_id) = state.user_sockets.get(&seen.user_id) {
                if let Some(sender_socket) = socket.get_socket(sender_socket_id.value()) {
                    let _ = sender_socket.emit("message_seen", seen);
                }
            }
            
            Ok(())
        },
    );
    
    // Typing indicator handler
    socket.on(
        "typing",
        |socket: SocketRef, Data::<TypingIndicator>(typing), SocketState(state): SocketState<AppState>| async move {
            debug!("⌨️ Typing: {} -> {}", typing.user_id, typing.receiver_id);
            
            // Send to receiver
            if let Some(receiver_socket_id) = state.user_sockets.get(&typing.receiver_id) {
                if let Some(receiver_socket) = socket.get_socket(receiver_socket_id.value()) {
                    let _ = receiver_socket.emit("typing", typing);
                }
            }
            
            Ok(())
        },
    );
}

async fn on_disconnect(socket: SocketRef, SocketState(state): SocketState<AppState>) {
    info!("🔴 Socket disconnected: {}", socket.id);
    
    // Remove from user_sockets mapping
    state.user_sockets.retain(|_, v| v != &socket.id.to_string());
    state.metrics.active_users.fetch_sub(1, Ordering::Relaxed);
    
    info!(
        "📊 Remaining connections: {}",
        state.metrics.active_users.load(Ordering::Relaxed)
    );
}

async fn store_pending_message(state: &AppState, msg: &ChatMessage) {
    if let Some(mut redis) = get_redis_conn(state) {
        let key = format!("pending:{}", msg.receiver_id);
        let value = serde_json::to_string(&msg).unwrap_or_default();
        
        let _: Result<(), RedisError> = redis.rpush(&key, &value).await;
        let _: Result<(), RedisError> = redis.expire(&key, PENDING_MESSAGE_TTL).await;
        
        debug!("📦 Message buffered for offline user: {}", msg.receiver_id);
    }
}

async fn send_push_notification(state: &AppState, msg: &ChatMessage) {
    if let Some(fcm_token) = state.fcm_tokens.get(&msg.receiver_id) {
        let decrypted = decrypt_message(&msg.content)
            .unwrap_or_else(|_| "New message".to_string());

        let truncated = if decrypted.len() > 100 {
            format!("{}...", &decrypted[..97])
        } else {
            decrypted
        };

        info!(
            "📲 FCM push would be sent to {} - Token: {}... Message: {}",
            msg.receiver_id,
            &fcm_token.value()[..20.min(fcm_token.value().len())],
            truncated
        );
    }
}

// ==================== HTTP HANDLERS ====================

async fn register_fcm_token(
    State(state): State<AppState>,
    Json(req): Json<FcmTokenRequest>,
) -> impl IntoResponse {
    if req.token.len() < 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "success": false,
                "error": "Invalid FCM token format"
            })),
        );
    }

    state.fcm_tokens.insert(req.user_id.clone(), req.token.clone());
    info!("📱 FCM token registered for user: {}", req.user_id);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "success": true,
            "message": "FCM token registered successfully"
        })),
    )
}

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "active_connections": state.metrics.active_users.load(Ordering::Relaxed),
        "total_messages": state.metrics.total_messages.load(Ordering::Relaxed),
        "failed_messages": state.metrics.failed_messages.load(Ordering::Relaxed),
        "rate_limited": state.metrics.rate_limited.load(Ordering::Relaxed),
        "fcm_tokens": state.fcm_tokens.len(),
    }))
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = format!(
        "# HELP chat_active_connections Number of active Socket.IO connections\n\
         # TYPE chat_active_connections gauge\n\
         chat_active_connections {}\n\
         # HELP chat_total_messages Total messages processed\n\
         # TYPE chat_total_messages counter\n\
         chat_total_messages {}\n\
         # HELP chat_failed_messages Total failed messages\n\
         # TYPE chat_failed_messages counter\n\
         chat_failed_messages {}\n\
         # HELP chat_rate_limited Total rate limited requests\n\
         # TYPE chat_rate_limited counter\n\
         chat_rate_limited {}\n",
        state.metrics.active_users.load(Ordering::Relaxed),
        state.metrics.total_messages.load(Ordering::Relaxed),
        state.metrics.failed_messages.load(Ordering::Relaxed),
        state.metrics.rate_limited.load(Ordering::Relaxed),
    );

    (StatusCode::OK, metrics)
}

async fn root_handler() -> &'static str {
    "Ultra Chat Server with Socket.IO - Running 🚀"
}

// ==================== MAIN APPLICATION ====================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .compact()
        .init();

    info!("🚀 Ultra Chat Server with Socket.IO Starting...");

    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    info!("📡 Configured port: {}", port);

    let redis_pool = match create_redis_pool(&redis_url).await {
        Ok(pool) => pool,
        Err(e) => {
            warn!("⚠️ Redis connection failed: {} - continuing without Redis", e);
            Vec::new()
        }
    };

    let state = AppState {
        redis_pool: Arc::new(RwLock::new(redis_pool)),
        fcm_tokens: Arc::new(DashMap::with_capacity(100_000)),
        rate_limiter: Arc::new(RateLimiter::new()),
        metrics: Arc::new(Metrics::new()),
        user_sockets: Arc::new(DashMap::with_capacity(MAX_CONNECTIONS)),
    };

    // Create Socket.IO layer
    let (layer, io) = SocketIo::builder()
        .with_state(state.clone())
        .build_layer();

    // Register Socket.IO event handlers
    io.ns("/", |socket: SocketRef, SocketState(state): SocketState<AppState>| async move {
        on_connect(socket.clone(), SocketState(state.clone())).await;
    });

    io.ns("/", |socket: SocketRef, SocketState(state): SocketState<AppState>| async move {
        socket.on_disconnect(move || async move {
            on_disconnect(socket, SocketState(state)).await;
        });
    });

    // Build router with Socket.IO
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .route("/register-fcm-token", post(register_fcm_token))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(
                    CorsLayer::new()
                        .allow_origin(tower_http::cors::Any)
                        .allow_methods(tower_http::cors::Any)
                        .allow_headers(tower_http::cors::Any)
                ),
        )
        .layer(layer)
        .with_state(state.clone());

    // Stats reporting task
    tokio::spawn({
        let state = state.clone();
        async move {
            let mut interval = interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                info!(
                    "📊 Stats - Connections: {} | Messages: {} | Rate Limited: {}",
                    state.metrics.active_users.load(Ordering::Relaxed),
                    state.metrics.total_messages.load(Ordering::Relaxed),
                    state.metrics.rate_limited.load(Ordering::Relaxed),
                );
            }
        }
    });

    // Bind to address
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    
    info!("🎯 Attempting to bind to address: {}", addr);
    
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            info!("✅ Successfully bound to: {}", local_addr);
            info!("🌐 Server is now accessible on port {}", port);
            listener
        }
        Err(e) => {
            error!("❌ Failed to bind to {}: {}", addr, e);
            info!("💡 Trying fallback IPv4-only binding...");
            
            let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = tokio::net::TcpListener::bind(addr_v4).await?;
            let local_addr = listener.local_addr()?;
            info!("✅ Successfully bound to IPv4: {}", local_addr);
            listener
        }
    };

    info!("📡 Max connections: {}", MAX_CONNECTIONS);
    info!("⚡ Ready to handle Socket.IO connections!");
    info!("🔗 Socket.IO endpoint: http://0.0.0.0:{}/socket.io/", port);
    info!("💚 Health check: http://0.0.0.0:{}/health", port);

    axum::serve(listener, app).await?;

    Ok(())
}
