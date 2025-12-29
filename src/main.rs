// main.rs - Ultra Chat Server with 2025 Best Practices

use axum::{
    extract::{
        ws::{Message as WsMessage, WebSocket, WebSocketUpgrade},
        ConnectInfo, State,
    },
    response::IntoResponse,
    routing::get,
    Router,
};
use dashmap::DashMap;

use futures_util::{
    sink::SinkExt,
    stream::{SplitSink, SplitStream, StreamExt},
};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::{broadcast, RwLock},
    time::interval,
};
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// ============================================================
// CONSTANTS (2025 Production Standards)
// ============================================================
const MAX_CONNECTIONS_PER_USER: usize = 3;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(60);
const MESSAGE_RATE_LIMIT: u64 = 100; // messages per minute
const BROADCAST_CHANNEL_SIZE: usize = 10000;

// ============================================================
// MESSAGE TYPES (Type-Safe Serde-based)
// ============================================================
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ClientMessage {
    Chat {
        recipient_id: String,
        content: String,
        timestamp: u64,
    },
    Typing {
        recipient_id: String,
    },
    Seen {
        recipient_id: String,
        message_id: String,
    },
    Ping,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum ServerMessage {
    Chat {
        sender_id: String,
        content: String,
        message_id: String,
        timestamp: u64,
    },
    Typing {
        sender_id: String,
    },
    Seen {
        sender_id: String,
        message_id: String,
    },
    Pong,
    Error {
        code: String,
        message: String,
    },
    Connected {
        user_id: String,
        timestamp: u64,
    },
}

// ============================================================
// CONNECTION TRACKING (Thread-Safe with DashMap)
// ============================================================
#[derive(Clone)]
struct UserConnection {
    user_id: String,
    tx: broadcast::Sender<ServerMessage>,
    last_activity: Arc<RwLock<u64>>,
    message_count: Arc<RwLock<u64>>,
}

impl UserConnection {
    fn new(user_id: String, tx: broadcast::Sender<ServerMessage>) -> Self {
        Self {
            user_id,
            tx,
            last_activity: Arc::new(RwLock::new(now())),
            message_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn update_activity(&self) {
        *self.last_activity.write().await = now();
    }

    async fn increment_message_count(&self) -> u64 {
        let mut count = self.message_count.write().await;
        *count += 1;
        *count
    }

    async fn is_rate_limited(&self) -> bool {
        let count = *self.message_count.read().await;
        count > MESSAGE_RATE_LIMIT
    }
}

// ============================================================
// APPLICATION STATE (2025 Architecture)
// ============================================================
#[derive(Clone)]
struct AppState {
    connections: Arc<DashMap<String, Vec<UserConnection>>>,
    redis_pool: RedisPool,
    broadcast_tx: broadcast::Sender<ServerMessage>,
}

impl AppState {
    async fn new(redis_url: &str) -> anyhow::Result<Self> {
        // ✅ 2025 Best Practice: Use fred with connection pooling
        let config = RedisConfig::from_url(redis_url)?;
        let policy = ReconnectPolicy::new_exponential(0, 100, 30_000, 2);
        
        let redis_pool = RedisPool::new(config, None, Some(policy), None, 6)?;
        redis_pool.connect();
        redis_pool.wait_for_connect().await?;

        info!("✅ Redis pool connected with 6 connections");

        let (broadcast_tx, _) = broadcast::channel(BROADCAST_CHANNEL_SIZE);

        Ok(Self {
            connections: Arc::new(DashMap::new()),
            redis_pool,
            broadcast_tx,
        })
    }

    fn add_connection(&self, user_id: String, conn: UserConnection) -> Result<(), String> {
        let mut entry = self.connections.entry(user_id.clone()).or_insert_with(Vec::new);
        
        if entry.len() >= MAX_CONNECTIONS_PER_USER {
            return Err(format!("Max connections ({}) reached for user", MAX_CONNECTIONS_PER_USER));
        }
        
        entry.push(conn);
        info!("👤 User {} connected (total connections: {})", user_id, entry.len());
        Ok(())
    }

    fn remove_connection(&self, user_id: &str, tx: &broadcast::Sender<ServerMessage>) {
        if let Some(mut entry) = self.connections.get_mut(user_id) {
            entry.retain(|conn| !Arc::ptr_eq(&conn.tx, tx));
            let remaining = entry.len();
            
            if remaining == 0 {
                drop(entry);
                self.connections.remove(user_id);
                info!("👋 User {} fully disconnected", user_id);
            } else {
                info!("🔌 User {} connection closed ({} remaining)", user_id, remaining);
            }
        }
    }

    async fn send_to_user(&self, user_id: &str, message: ServerMessage) {
        if let Some(connections) = self.connections.get(user_id) {
            let mut failed = 0;
            for conn in connections.iter() {
                if conn.tx.send(message.clone()).is_err() {
                    failed += 1;
                }
            }
            if failed > 0 {
                warn!("⚠️ Failed to send to {}/{} connections for user {}", failed, connections.len(), user_id);
            }
        }
    }
}

// ============================================================
// WEBSOCKET HANDLER (2025 Split Architecture)
// ============================================================
async fn ws_handler(
    ws: WebSocketUpgrade,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    State(state): State<AppState>,
) -> impl IntoResponse {
    info!("🔗 New WebSocket connection from {}", addr);
    
    ws.on_upgrade(move |socket| handle_socket(socket, addr, state))
}

async fn handle_socket(socket: WebSocket, addr: SocketAddr, state: AppState) {
    let (sender, receiver) = socket.split();
    
    // Create per-connection broadcast channel
    let (tx, rx) = broadcast::channel(100);
    
    // Spawn sender task
    let sender_handle = tokio::spawn(handle_sender(sender, rx, addr));
    
    // Handle receiver (this is the main task)
    let user_id = match handle_receiver(receiver, tx.clone(), state.clone(), addr).await {
        Ok(uid) => uid,
        Err(e) => {
            error!("❌ Receiver error for {}: {}", addr, e);
            sender_handle.abort();
            return;
        }
    };
    
    // Cleanup
    state.remove_connection(&user_id, &tx);
    sender_handle.abort();
    info!("🧹 Cleaned up connection for user {} from {}", user_id, addr);
}

// ✅ 2025 Best Practice: Separate sender/receiver tasks
async fn handle_sender(
    mut sender: SplitSink<WebSocket, WsMessage>,
    mut rx: broadcast::Receiver<ServerMessage>,
    addr: SocketAddr,
) {
    // Heartbeat timer
    let mut heartbeat = interval(HEARTBEAT_INTERVAL);
    
    loop {
        tokio::select! {
            Ok(msg) = rx.recv() => {
                let json = match serde_json::to_string(&msg) {
                    Ok(j) => j,
                    Err(e) => {
                        error!("❌ Serialization error: {}", e);
                        continue;
                    }
                };
                
                if sender.send(WsMessage::Text(json)).await.is_err() {
                    warn!("⚠️ Failed to send to {}", addr);
                    break;
                }
            }
            _ = heartbeat.tick() => {
                if sender.send(WsMessage::Ping(vec![])).await.is_err() {
                    warn!("⚠️ Heartbeat failed for {}", addr);
                    break;
                }
            }
        }
    }
}

async fn handle_receiver(
    mut receiver: SplitStream<WebSocket>,
    tx: broadcast::Sender<ServerMessage>,
    state: AppState,
    addr: SocketAddr,
) -> anyhow::Result<String> {
    // First message must be authentication
    let user_id = match receiver.next().await {
        Some(Ok(WsMessage::Text(text))) => {
            let auth: serde_json::Value = serde_json::from_str(&text)?;
            auth["user_id"].as_str()
                .ok_or_else(|| anyhow::anyhow!("Missing user_id"))?
                .to_string()
        }
        _ => anyhow::bail!("First message must be auth"),
    };

    info!("🔐 User {} authenticated from {}", user_id, addr);
    
    // Register connection
    let conn = UserConnection::new(user_id.clone(), tx.clone());
    state.add_connection(user_id.clone(), conn.clone())
        .map_err(|e| anyhow::anyhow!(e))?;
    
    // Send connected confirmation
    let _ = tx.send(ServerMessage::Connected {
        user_id: user_id.clone(),
        timestamp: now(),
    });
    
    // Message handling loop
    while let Some(result) = receiver.next().await {
        match result {
            Ok(WsMessage::Text(text)) => {
                conn.update_activity().await;
                
                // Rate limiting
                if conn.is_rate_limited().await {
                    let _ = tx.send(ServerMessage::Error {
                        code: "RATE_LIMIT".to_string(),
                        message: "Too many messages".to_string(),
                    });
                    continue;
                }
                
                conn.increment_message_count().await;
                
                // Parse and handle message
                match serde_json::from_str::<ClientMessage>(&text) {
                    Ok(msg) => handle_client_message(msg, &user_id, &state).await,
                    Err(e) => {
                        warn!("⚠️ Invalid message from {}: {}", user_id, e);
                        let _ = tx.send(ServerMessage::Error {
                            code: "INVALID_MESSAGE".to_string(),
                            message: e.to_string(),
                        });
                    }
                }
            }
            Ok(WsMessage::Ping(_)) => {
                // Pings are handled automatically by Axum
            }
            Ok(WsMessage::Pong(_)) => {
                conn.update_activity().await;
            }
            Ok(WsMessage::Close(_)) => {
                info!("👋 User {} closed connection", user_id);
                break;
            }
            Err(e) => {
                error!("❌ WebSocket error for {}: {}", user_id, e);
                break;
            }
            _ => {}
        }
    }
    
    Ok(user_id)
}

async fn handle_client_message(msg: ClientMessage, sender_id: &str, state: &AppState) {
    match msg {
        ClientMessage::Chat { recipient_id, content, timestamp } => {
            let message_id = generate_message_id();
            
            // Save to Redis
            let _ = save_message_to_redis(
                &state.redis_pool,
                &message_id,
                sender_id,
                &recipient_id,
                &content,
                timestamp,
            ).await;
            
            // Send to recipient
            state.send_to_user(&recipient_id, ServerMessage::Chat {
                sender_id: sender_id.to_string(),
                content,
                message_id,
                timestamp,
            }).await;
        }
        ClientMessage::Typing { recipient_id } => {
            state.send_to_user(&recipient_id, ServerMessage::Typing {
                sender_id: sender_id.to_string(),
            }).await;
        }
        ClientMessage::Seen { recipient_id, message_id } => {
            state.send_to_user(&recipient_id, ServerMessage::Seen {
                sender_id: sender_id.to_string(),
                message_id,
            }).await;
        }
        ClientMessage::Ping => {
            // Handled by heartbeat
        }
    }
}

// ============================================================
// REDIS OPERATIONS (2025 Best Practice with fred)
// ============================================================
async fn save_message_to_redis(
    pool: &RedisPool,
    message_id: &str,
    sender_id: &str,
    recipient_id: &str,
    content: &str,
    timestamp: u64,
) -> anyhow::Result<()> {
    let client = pool.next();
    let key = format!("message:{}", message_id);
    
    let data = serde_json::json!({
        "sender_id": sender_id,
        "recipient_id": recipient_id,
        "content": content,
        "timestamp": timestamp,
    });
    
    client.set(
        key,
        serde_json::to_string(&data)?,
        Some(fred::types::Expiration::EX(86400)), // 24 hours
        None,
        false,
    ).await?;
    
    Ok(())
}

// ============================================================
// UTILITY FUNCTIONS
// ============================================================
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_message_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("msg_{}_{}", now(), rng.gen::<u32>())
}

// ============================================================
// HEALTH CHECK ENDPOINT
// ============================================================
async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let conn_count: usize = state.connections.iter().map(|entry| entry.value().len()).sum();
    let user_count = state.connections.len();
    
    let health = serde_json::json!({
        "status": "healthy",
        "timestamp": now(),
        "connections": conn_count,
        "users": user_count,
        "redis": "connected",
    });
    
    axum::Json(health)
}

// ============================================================
// MAIN (2025 Production Setup)
// ============================================================
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ✅ Initialize tracing (2025 standard)
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ultra_chat_server=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 Ultra Chat Server Starting...");

    // ✅ Get PORT from environment (Render requirement)
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "10000".to_string())
        .parse::<u16>()?;
    
    let redis_url = std::env::var("REDIS_URL")
        .unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

    // Initialize state
    let state = AppState::new(&redis_url).await?;

    // ✅ 2025 CORS Configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        .route("/ws", get(ws_handler))
        .route("/health", get(health_check))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // ✅ Bind to 0.0.0.0 (Render requirement)
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    
    info!("🎧 Listening on {}", addr);

    // ✅ 2025 Axum serve syntax
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
