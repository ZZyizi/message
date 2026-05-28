//! 分布式 IM Relay 服务器
//!
//! 职责：
//! - WebSocket 连接管理
//! - 在线状态追踪（内存）
//! - 消息转发（接收者在线时直发，离线时缓存）
//! - Ping/Pong 心跳（30s）

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    extract::{
        ws::{Message as AxumMessage, WebSocket, WebSocketUpgrade},
        State,
    },
    response::{Response, IntoResponse},
    routing::get,
    Json,
    Router,
};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{info, warn, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

/// WebSocket 消息类型（与客户端协议对齐）
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// 聊天消息
    ChatMessage {
        event_id: String,
        from: String,
        to: String,
        payload: String,
        media_id: Option<String>,
        timestamp: i64,
        signature: String,
    },
    /// 消息已收到确认
    MessageAck {
        event_id: String,
        from: String,
        timestamp: i64,
    },
    /// 消息撤回
    MessageRecall {
        ref_event_id: String,
        from: String,
        timestamp: i64,
    },
    /// 心跳
    Ping,
    /// 心跳响应
    Pong,
    /// 错误
    Error { code: i32, message: String },
}

/// 在线客户端会话
struct ClientSession {
    /// 客户端公钥
    pubkey: String,
    /// WebSocket 发送通道
    tx: broadcast::Sender<WsMessage>,
}

/// 应用状态（内存存储）
struct AppState {
    // 在线客户端：pubkey -> Session
    clients: RwLock<HashMap<String, Arc<ClientSession>>>,

    // 消息缓存：event_id -> (msg, expire_at_ms)，TTL 7 天，过期自动清理
    cache: RwLock<HashMap<String, (WsMessage, i64)>>,
}

impl AppState {
    fn new() -> Self {
        Self {
            clients: RwLock::new(HashMap::new()),
            cache: RwLock::new(HashMap::new()),
        }
    }
}

/// 初始化日志系统
fn setup_logging() {
    let log_dir = std::env::var("LOG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::data_local_dir()
                .unwrap_or_else(|| std::path::PathBuf::from("."))
                .join("decentralized-im-relay")
                .join("logs")
        });

    std::fs::create_dir_all(&log_dir).ok();

    let file_appender = RollingFileAppender::new(Rotation::DAILY, log_dir, "relay.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    Box::leak(Box::new(_guard));
}

/// WebSocket 升级处理
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    axum::extract::Path(pubkey): axum::extract::Path<String>,
) -> Response {
    info!("WebSocket upgrade request: {}", pubkey);
    ws.on_upgrade(move |socket| handle_socket(socket, state, pubkey))
}

/// 处理单个 WebSocket 连接
async fn handle_socket(socket: WebSocket, state: Arc<AppState>, pubkey: String) {
    info!("Client connected: {}", pubkey);

    // 创建广播 channel，容量 100
    let (tx, mut rx) = broadcast::channel::<WsMessage>(100);

    // 注册客户端（如果已有连接则替换）
    {
        let mut clients = state.clients.write();
        clients.insert(pubkey.clone(), Arc::new(ClientSession { pubkey: pubkey.clone(), tx }));
    }

    let (mut sender, mut receiver) = socket.split();

    // 发送任务：从广播 channel 读取消息，转发给 WebSocket 客户端
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            let text = match serde_json::to_string(&msg) {
                Ok(t) => t,
                Err(e) => {
                    error!("Serialize error: {}", e);
                    continue;
                }
            };
            if sender.send(AxumMessage::Text(text.into())).await.is_err() {
                break;
            }
        }
    });

    // 接收任务：读取客户端消息，处理后删除本地客户端
    let state_clone = state.clone();
    let pubkey_clone = pubkey.clone();
    let recv_task = tokio::spawn(async move {
        while let Some(msg_result) = receiver.next().await {
            match msg_result {
                Ok(AxumMessage::Text(text)) => {
                    let text_str = text.to_string();
                    if let Err(e) = handle_client_message(&text_str, &state_clone, &pubkey_clone).await {
                        error!("Handle message error: {}", e);
                    }
                }
                Ok(AxumMessage::Close(_)) => {
                    info!("Client disconnected: {}", pubkey_clone);
                    break;
                }
                Err(e) => {
                    warn!("WebSocket error: {}", e);
                    break;
                }
                _ => {}
            }
        }
    });

    // 等待任一任务结束
    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }

    // 清理：移除客户端
    state.clients.write().remove(&pubkey);
    info!("Client session ended: {}", pubkey);
}

/// 处理客户端发来的消息
async fn handle_client_message(
    text: &str,
    state: &Arc<AppState>,
    from_pubkey: &str,
) -> Result<(), String> {
    let msg: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("Parse error: {}", e))?;

    let msg_type = msg
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    match msg_type {
        "chat_message" => handle_chat_message(state, &msg).await?,
        "message_ack" => handle_ack(state, &msg).await?,
        "message_recall" => handle_recall(state, &msg).await?,
        "ping" => {
            // 回复 Pong
            let pong = WsMessage::Pong;
            if let Some(session) = state.clients.read().get(from_pubkey) {
                let _ = session.tx.send(pong);
            }
        }
        _ => {
            warn!("Unknown message type: {}", msg_type);
        }
    }

    Ok(())
}

/// 处理聊天消息：缓存 + 转发给接收者
async fn handle_chat_message(state: &Arc<AppState>, msg: &serde_json::Value) -> Result<(), String> {
    let to = msg.get("to").and_then(|v| v.as_str()).unwrap_or("");
    let from = msg.get("from").and_then(|v| v.as_str()).unwrap_or("");
    let event_id = msg.get("event_id").and_then(|v| v.as_str()).unwrap_or("");

    info!(
        "Chat message: {} -> {} (event_id: {})",
        from, to, event_id
    );

    // 缓存消息（TTL 7 天）
    if !event_id.is_empty() {
        let mut cache = state.cache.write();
        let expire_at = Utc::now().timestamp_millis() + 7 * 24 * 60 * 60 * 1000;
        cache.insert(
            event_id.to_string(),
            (serde_json::from_value(msg.clone()).unwrap(), expire_at),
        );
    }

    // 接收者在线：直接转发（不回显给发送者，发送者已在本地存储）
    let clients = state.clients.read();
    if let Some(session) = clients.get(to) {
        let ws_msg: WsMessage =
            serde_json::from_value(msg.clone()).map_err(|e| e.to_string())?;
        if session.tx.send(ws_msg).is_err() {
            warn!("Failed to forward to {}", to);
        } else {
            info!("Message forwarded: {} -> {} (event_id: {})", from, to, event_id);
        }
    } else {
        info!("Recipient {} offline, message cached only (event_id: {})", to, event_id);
    }

    Ok(())
}

/// 处理消息 ACK：从缓存删除，告知发送者
async fn handle_ack(state: &Arc<AppState>, msg: &serde_json::Value) -> Result<(), String> {
    let ref_event_id = msg
        .get("ref_event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let from = msg.get("from").and_then(|v| v.as_str()).unwrap_or("");

    info!("Message ack: {} for event {}", from, ref_event_id);

    // 从缓存删除
    state.cache.write().remove(ref_event_id);

    // TODO: 可以向消息发送者确认（需要存储 event_id -> from 映射）
    let _ = from;

    Ok(())
}

/// 处理消息撤回：广播给所有在线客户端
async fn handle_recall(state: &Arc<AppState>, msg: &serde_json::Value) -> Result<(), String> {
    let ref_event_id = msg
        .get("ref_event_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let from = msg.get("from").and_then(|v| v.as_str()).unwrap_or("");

    info!("Message recall: {} recall event {}", from, ref_event_id);

    let recall_msg = WsMessage::MessageRecall {
        ref_event_id: ref_event_id.to_string(),
        from: from.to_string(),
        timestamp: Utc::now().timestamp_millis(),
    };

    // 广播给所有在线客户端
    let clients = state.clients.read();
    for (_, session) in clients.iter() {
        let _ = session.tx.send(recall_msg.clone());
    }

    Ok(())
}

/// 获取当前在线用户列表
async fn get_online_users(
    State(state): State<Arc<AppState>>,
) -> Response {
    let clients = state.clients.read();
    let users: Vec<String> = clients.keys().cloned().collect();
    Json(serde_json::json!({ "users": users }))
        .into_response()
}

/// 后台任务：清理过期缓存 + 广播 Ping
async fn run_keeper(state: Arc<AppState>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));

    loop {
        interval.tick().await;
        let now = Utc::now().timestamp_millis();

        // 清理过期缓存
        {
            let mut cache = state.cache.write();
            cache.retain(|_, (_, expire_at)| *expire_at > now);
        }

        // 广播 Ping 给所有客户端
        let ping = WsMessage::Ping;
        let clients = state.clients.read();
        for (_, session) in clients.iter() {
            let _ = session.tx.send(ping.clone());
        }
    }
}

#[tokio::main]
async fn main() {
    setup_logging();

    info!("启动弱中心化即时通讯中继服务器");

    let state = Arc::new(AppState::new());
    let state_clone = state.clone();

    // 启动后台 keeper 任务
    tokio::spawn(async move {
        run_keeper(state_clone).await;
    });

    // 构建路由
    let app = Router::new()
        .route("/ws/{pubkey}", get(ws_handler))
        .route("/health", get(|| async { "ok" }))
        .route("/users", get(get_online_users))
        .with_state(state);

    let addr: SocketAddr = std::env::var("RELAY_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .expect("Invalid RELAY_ADDR");

    info!("Relay 服务器在 {}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Failed to bind TCP listener");
    axum::serve(listener, app).await.expect("Server error");
}