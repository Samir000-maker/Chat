use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        Path, State,
    },
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use dashmap::DashMap;
use flume::{bounded, Receiver, Sender};
use futures::{SinkExt, StreamExt};
use parking_lot::RwLock;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Client as RedisClient, RedisError};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::Semaphore,
    time::interval,
};
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer,
};
use tracing::{debug, error, info, warn};
use base64::{Engine as _, engine::general_purpose};

// ==================== CONSTANTS & CONFIGURATION ====================
const MAX_CONNECTIONS_PER_WORKER: usize = 50_000;
const WORKER_COUNT: usize = 8;
const MESSAGE_BUFFER_SIZE: usize = 10_000;
const GLOBAL_RATE_LIMIT: u64 = 1_000_000;
const USER_RATE_LIMIT: u64 = 100;
const RATE_WINDOW_SECS: u64 = 60;
const PENDING_MESSAGE_TTL: i64 = 300;
const REDIS_POOL_SIZE: usize = 32;
const HEARTBEAT_INTERVAL_SECS: u64 = 30;
const CLIENT_TIMEOUT_SECS: u64 = 90;

// AES-128-GCM Encryption
const AES_KEY: &[u8] = b"0123456789abcdef";

// ==================== TYPES & STRUCTURES ====================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChatMessage {
    message_id: String,
    chat_id: String,
    sender_id: String,
    receiver_id: String,
    content: String,
    timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sender_profile_pic_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MessageSeen {
    message_id: String,
    chat_id: String,
    user_id: String,
    timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TypingIndicator {
    sender_id: String,
    receiver_id: String,
    is_typing: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FcmTokenRequest {
    user_id: String,
    token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    device_info: Option<HashMap<String, String>>,
}

#[derive(Debug)]
struct UserConnection {
    user_id: String,
    tx: Sender<WsMessage>,
    last_activity: Arc<AtomicU64>,
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
    connections: Arc<DashMap<String, UserConnection>>,
    redis_pool: Arc<RwLock<Vec<ConnectionManager>>>,
    fcm_tokens: Arc<DashMap<String, String>>,
    rate_limiter: Arc<RateLimiter>,
    metrics: Arc<Metrics>,
    connection_semaphore: Arc<Semaphore>,
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
                    // If first connection fails, try fewer connections
                    break;
                }
            }
        }
    }

    if pool.is_empty() {
        warn!("⚠️ No Redis connections available - running without persistence");
        // Return empty pool instead of error - server can work without Redis
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

// ==================== MESSAGE PROCESSING ====================

async fn process_chat_message(state: &AppState, msg: ChatMessage) {
    state
        .metrics
        .total_messages
        .fetch_add(1, Ordering::Relaxed);

    // Check if receiver is online
    if let Some(receiver_conn) = state.connections.get(&msg.receiver_id) {
        let json = serde_json::to_string(&msg).unwrap_or_default();
        let ws_msg = WsMessage::Text(json);

        if receiver_conn.tx.send_async(ws_msg).await.is_err() {
            warn!("Failed to send message to online user: {}", msg.receiver_id);
        } else {
            debug!("✅ Message delivered to online user: {}", msg.receiver_id);
        }
    } else {
        // User is offline - store in Redis if available
        if let Some(mut redis) = get_redis_conn(state) {
            let key = format!("pending:{}", msg.receiver_id);
            let value = serde_json::to_string(&msg).unwrap_or_default();

            let _: Result<(), RedisError> = redis.rpush(&key, &value).await;
            let _: Result<(), RedisError> = redis.expire(&key, PENDING_MESSAGE_TTL).await;

            debug!("📦 Message buffered for offline user: {}", msg.receiver_id);
        }

        // Send push notification
        tokio::spawn({
            let state = state.clone();
            let msg = msg.clone();
            async move {
                send_push_notification(&state, &msg).await;
            }
        });
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

// ==================== WEBSOCKET HANDLER ====================

async fn handle_websocket(ws: WebSocket, state: AppState, user_id: String) {
    let (mut ws_tx, mut ws_rx) = ws.split();
    let (tx, rx) = bounded::<WsMessage>(MESSAGE_BUFFER_SIZE);

    let last_activity = Arc::new(AtomicU64::new(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    ));

    let user_conn = UserConnection {
        user_id: user_id.clone(),
        tx: tx.clone(),
        last_activity: last_activity.clone(),
    };

    state.connections.insert(user_id.clone(), user_conn);
    state
        .metrics
        .total_connections
        .fetch_add(1, Ordering::Relaxed);
    state.metrics.active_users.fetch_add(1, Ordering::Relaxed);

    info!(
        "🟢 User connected: {} (Total: {})",
        user_id,
        state.metrics.active_users.load(Ordering::Relaxed)
    );

    // Replay pending messages if Redis is available
    tokio::spawn({
        let state = state.clone();
        let user_id = user_id.clone();
        let tx = tx.clone();
        async move {
            if let Some(mut redis) = get_redis_conn(&state) {
                let key = format!("pending:{}", user_id);

                if let Ok(messages) = redis.lrange::<_, Vec<String>>(&key, 0, -1).await {
                    for msg_str in messages {
                        if let Ok(msg) = serde_json::from_str::<ChatMessage>(&msg_str) {
                            let json = serde_json::to_string(&msg).unwrap_or_default();
                            let _ = tx.send_async(WsMessage::Text(json)).await;
                        }
                    }
                    let _: Result<(), RedisError> = redis.del(&key).await;
                    info!("📬 Replayed pending messages for user: {}", user_id);
                }
            }
        }
    });

    // Outgoing message task
    let outgoing_task = tokio::spawn({
        let user_id = user_id.clone();
        async move {
            while let Ok(msg) = rx.recv_async().await {
                if ws_tx.send(msg).await.is_err() {
                    break;
                }
            }
            debug!("Outgoing task ended for user: {}", user_id);
        }
    });

    // Heartbeat task
    let heartbeat_task = tokio::spawn({
        let last_activity = last_activity.clone();
        let user_id = user_id.clone();
        let tx = tx.clone();
        async move {
            let mut interval = interval(Duration::from_secs(HEARTBEAT_INTERVAL_SECS));
            loop {
                interval.tick().await;

                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let last = last_activity.load(Ordering::Relaxed);

                if now - last > CLIENT_TIMEOUT_SECS {
                    warn!("⏱️ Client timeout for user: {}", user_id);
                    break;
                }

                if tx.send_async(WsMessage::Ping(vec![])).await.is_err() {
                    break;
                }
            }
        }
    });

    // Incoming message handling
    while let Some(result) = ws_rx.next().await {
        match result {
            Ok(WsMessage::Text(text)) => {
                last_activity.store(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    Ordering::Relaxed,
                );

                // Rate limiting
                if !state.rate_limiter.check_global() {
                    state
                        .metrics
                        .rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = tx
                        .send_async(WsMessage::Text(
                            r#"{"error":"Global rate limit exceeded"}"#.to_string(),
                        ))
                        .await;
                    continue;
                }

                if !state.rate_limiter.check_user(&user_id) {
                    state
                        .metrics
                        .rate_limited
                        .fetch_add(1, Ordering::Relaxed);
                    let _ = tx
                        .send_async(WsMessage::Text(
                            r#"{"error":"User rate limit exceeded"}"#.to_string(),
                        ))
                        .await;
                    continue;
                }

                // Parse and route message
                if let Ok(msg) = serde_json::from_str::<ChatMessage>(&text) {
                    tokio::spawn({
                        let state = state.clone();
                        async move {
                            process_chat_message(&state, msg).await;
                        }
                    });
                } else if let Ok(seen) = serde_json::from_str::<MessageSeen>(&text) {
                    if let Some(receiver) = state.connections.get(&seen.user_id) {
                        let json = serde_json::to_string(&seen).unwrap_or_default();
                        let _ = receiver.tx.send_async(WsMessage::Text(json)).await;
                    }
                } else if let Ok(typing) = serde_json::from_str::<TypingIndicator>(&text) {
                    if let Some(receiver) = state.connections.get(&typing.receiver_id) {
                        let json = serde_json::to_string(&typing).unwrap_or_default();
                        let _ = receiver.tx.send_async(WsMessage::Text(json)).await;
                    }
                }
            }
            Ok(WsMessage::Pong(_)) => {
                last_activity.store(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    Ordering::Relaxed,
                );
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    // Cleanup
    state.connections.remove(&user_id);
    state.metrics.active_users.fetch_sub(1, Ordering::Relaxed);
    outgoing_task.abort();
    heartbeat_task.abort();

    info!(
        "🔴 User disconnected: {} (Remaining: {})",
        user_id,
        state.metrics.active_users.load(Ordering::Relaxed)
    );
}

// ==================== HTTP HANDLERS ====================

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path(user_id): Path<String>,
) -> Response {
    if state.connection_semaphore.try_acquire().is_err() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Too many connections").into_response();
    }

    ws.on_upgrade(move |socket| handle_websocket(socket, state, user_id))
}

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

    state
        .fcm_tokens
        .insert(req.user_id.clone(), req.token.clone());
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
        "# HELP chat_active_connections Number of active WebSocket connections\n\
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
    "Ultra Chat Server - Running 🚀"
}

// ==================== MAIN APPLICATION ====================

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .compact()
        .init();

    info!("🚀 Ultra Chat Server Starting...");

    // Get configuration from environment
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    info!("📡 Configured port: {}", port);

    // Create Redis pool (non-blocking)
    let redis_pool = match create_redis_pool(&redis_url).await {
        Ok(pool) => pool,
        Err(e) => {
            warn!("⚠️ Redis connection failed: {} - continuing without Redis", e);
            Vec::new()
        }
    };

    let max_connections = MAX_CONNECTIONS_PER_WORKER * WORKER_COUNT;

    let state = AppState {
        connections: Arc::new(DashMap::with_capacity(max_connections)),
        redis_pool: Arc::new(RwLock::new(redis_pool)),
        fcm_tokens: Arc::new(DashMap::with_capacity(100_000)),
        rate_limiter: Arc::new(RateLimiter::new()),
        metrics: Arc::new(Metrics::new()),
        connection_semaphore: Arc::new(Semaphore::new(max_connections)),
    };

    // Build router
    let app = Router::new()
        .route("/", get(root_handler))
        .route("/ws/:user_id", get(ws_handler))
        .route("/health", get(health_check))
        .route("/metrics", get(metrics_handler))
        .route("/register-fcm-token", post(register_fcm_token))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive()),
        )
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

    // Bind to address - support both IPv4 and IPv6
    let addr = SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port));
    
    info!("🎯 Attempting to bind to address: {}", addr);
    
    // Create TCP listener
    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => {
            let local_addr = listener.local_addr()?;
            info!("✅ Successfully bound to: {}", local_addr);
            info!("🌐 Server is now accessible on port {}", port);
            listener
        }
        Err(e) => {
            error!("❌ Failed to bind to {}: {}", addr, e);
            error!("💡 Trying fallback IPv4-only binding...");
            
            // Fallback to IPv4 only
            let addr_v4 = SocketAddr::from(([0, 0, 0, 0], port));
            let listener = tokio::net::TcpListener::bind(addr_v4).await?;
            let local_addr = listener.local_addr()?;
            info!("✅ Successfully bound to IPv4: {}", local_addr);
            listener
        }
    };

    info!("📡 Max connections: {}", max_connections);
    info!("⚡ Ready to handle messages!");
    info!("🔗 WebSocket endpoint: ws://0.0.0.0:{}/ws/:user_id", port);
    info!("💚 Health check: http://0.0.0.0:{}/health", port);

    // Start server
    axum::serve(listener, app).await?;

    Ok(())
}
