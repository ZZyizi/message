//! 中继服务器连接模块
//!
//! 负责与 Relay 服务器的 WebSocket 连接管理、消息收发。
//! 支持聊天消息、消息确认（ACK）和消息撤回（Recall）三种消息类型。

use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tracing::{info, warn, error, debug};
use base64::Engine;
use urlencoding::encode;
use tauri::{Manager, Emitter};

use crate::crypto;
use crate::db::Message as DbMessage;
use crate::Error;
///
/// 定义与 Relay 服务器通信的所有消息格式。
/// - `ChatMessage`: 常规聊天消息，包含完整的事件信息
/// - `MessageAck`: 消息确认，告知对方已收到并处理
/// - `MessageRecall`: 消息撤回，请求删除指定消息
/// - `Ping/Pong`: 心跳保活消息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WsMessage {
    ChatMessage {
        event_id: String,
        from: String,
        to: String,
        payload: String,
        media_id: Option<String>,
        timestamp: i64,
        signature: String,
    },
    MessageAck {
        event_id: String,
        from: String,
        timestamp: i64,
    },
    MessageRecall {
        ref_event_id: String,
        from: String,
        timestamp: i64,
    },
    Ping,
    Pong,
    Error { code: i32, message: String },
}

/// 连接状态
///
/// 标识 Relay 连接的生命周期状态。
/// 状态转换: Disconnected -> Connecting -> Connected -> Disconnected
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Connected,
}

/// Relay 状态信息
///
/// 用于前端 UI 展示当前连接状态和最后心跳时间
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayStatus {
    pub state: String,
    pub relay_url: Option<String>,
    pub last_ping: Option<i64>,
}

/// 全局连接状态（进程级别共享）
/// 注意：多线程环境下通过原子操作和 RwLock 保证线程安全
static CONNECTED: AtomicBool = AtomicBool::new(false);
static RELAY_URL: RwLock<Option<String>> = RwLock::new(None);
static LAST_PING: RwLock<Option<i64>> = RwLock::new(None);
static CLIENT_STATE: RwLock<ConnectionState> = RwLock::new(ConnectionState::Disconnected);
/// 消息广播 channel，发送端广播消息，多个接收端可订阅
static MESSAGE_TX: RwLock<Option<broadcast::Sender<WsMessage>>> = RwLock::new(None);

/// 连接到 Relay 服务器
///
/// 若已存在连接则先断开，然后建立新的 WebSocket 连接。
/// 连接成功后会将 relay_url 持久化到数据库设置中。
#[tauri::command]
pub async fn connect(
    relay_url: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    info!("Connecting to relay: {}", relay_url);

    if CONNECTED.load(Ordering::SeqCst) {
        warn!("Already connected, disconnecting first");
        disconnect().await?;
    }

    *RELAY_URL.write() = Some(relay_url.clone());
    *CLIENT_STATE.write() = ConnectionState::Connecting;

    // 初始化消息广播 channel，缓冲区容量 100
    let (tx, _) = broadcast::channel(100);
    *MESSAGE_TX.write() = Some(tx.clone());

    let pubkey_str = {
        let identity = state.identity.read();
        identity.get_public_key()
            .ok_or_else(|| Error::Identity("No identity found".to_string()))?
            .to_string()
    };

    // 自动补充 ws:// / wss:// 前缀，并添加 /ws/{pubkey} 路径
    let path = if relay_url.starts_with("ws://") || relay_url.starts_with("wss://") {
        format!("{}/ws/{}", relay_url.trim_end_matches('/'), encode(&pubkey_str))
    } else {
        format!("ws://{}/ws/{}", relay_url.trim_end_matches('/'), encode(&pubkey_str))
    };

    info!("Connecting to WebSocket: {}", path);

    // 异步启动 WebSocket 客户端，不阻塞当前调用
    let app_handle = state.app_handle.clone();
    tokio::spawn(async move {
        if let Err(e) = run_websocket_client(path, tx, app_handle).await {
            error!("WebSocket error: {}", e);
        }
    });

    // 等待连接建立（500ms 等待握手完成）
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    *CLIENT_STATE.write() = ConnectionState::Connected;
    CONNECTED.store(true, Ordering::SeqCst);
    *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());

    {
        let db = state.db.lock().unwrap();
        db.set_setting("relay_url", &relay_url)?;
    }

    info!("Connected to relay successfully");
    Ok(())
}

/// WebSocket 客户端主循环
///
/// 负责：
/// 1. 维护 WebSocket 连接
/// 2. 每 30 秒发送一次 Ping 心跳
/// 3. 接收并广播收到的新消息（存入数据库并通知前端）
/// 4. 检测 120 秒无响应视为连接断开
async fn run_websocket_client(relay_url: String, tx: broadcast::Sender<WsMessage>, app_handle: tauri::AppHandle) -> Result<(), Error> {
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    use futures_util::{StreamExt, SinkExt};

    info!("Connecting to WebSocket: {}", relay_url);

    let (ws_stream, _) = connect_async(&relay_url)
        .await
        .map_err(|e| Error::Relay(format!("WebSocket connect failed: {}", e)))?;

    info!("WebSocket connected");

    *CLIENT_STATE.write() = ConnectionState::Connected;
    CONNECTED.store(true, Ordering::SeqCst);

    let (mut write, mut read) = ws_stream.split();

    // 心跳任务：每 30 秒发送一次 Ping
    let tx_clone = tx.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            if tx_clone.receiver_count() == 0 {
                break;
            }
            let ping = WsMessage::Ping;
            if let Ok(json) = serde_json::to_string(&ping) {
                let msg = Message::Text(json.into());
                if let Err(e) = write.send(msg).await {
                    warn!("Failed to send ping: {}", e);
                    break;
                }
            }
            *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());
        }
    });

    // 消息接收主循环
    loop {
        tokio::select! {
            msg = read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Received: {}", text);
                        if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                            // 收到 Pong 更新最后心跳时间
                            if let WsMessage::Pong = &ws_msg {
                                *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());
                            }
                            // 收到聊天消息：存入数据库并通知前端
                            if let WsMessage::ChatMessage { event_id, from, to, payload, media_id, timestamp, signature } = &ws_msg {
                                info!("New chat message: {} -> {} (event_id: {})", from, to, event_id);
                                let app_state = app_handle.state::<crate::AppState>();
                                let db = app_state.db.lock().unwrap();
                                let msg = DbMessage {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    event_id: event_id.clone(),
                                    msg_type: "text".to_string(),
                                    from_pubkey: from.clone(),
                                    to_recipient: to.clone(),
                                    payload: payload.clone(),
                                    media_id: media_id.clone(),
                                    timestamp: *timestamp,
                                    seq_id: 0,
                                    signature: signature.clone(),
                                    delivered: true,
                                    recalled: false,
                                };
                                if let Err(e) = db.insert_message(&msg) {
                                    error!("Failed to store message: {}", e);
                                }
                                // 通知前端收到新消息
                                let _ = app_handle.emit("new_message", &msg);
                            }
                            // 收到消息撤回
                            if let WsMessage::MessageRecall { ref_event_id, .. } = &ws_msg {
                                let app_state = app_handle.state::<crate::AppState>();
                                let db = app_state.db.lock().unwrap();
                                if let Err(e) = db.mark_message_recalled(ref_event_id) {
                                    error!("Failed to recall message: {}", e);
                                }
                                let _ = app_handle.emit("message_recalled", ref_event_id);
                            }
                            // 广播消息给所有订阅者
                            if tx.receiver_count() > 0 {
                                if let Err(e) = tx.send(ws_msg) {
                                    warn!("Failed to broadcast: {}", e);
                                }
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        info!("WebSocket closed");
                        break;
                    }
                    Some(Err(e)) => {
                        error!("WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
            // 每 60 秒检查一次心跳超时（120 秒无响应视为断开）
            _ = tokio::time::sleep(tokio::time::Duration::from_secs(60)) => {
                let last = *LAST_PING.read();
                if let Some(ts) = last {
                    if chrono::Utc::now().timestamp_millis() - ts > 120000 {
                        warn!("Connection seems dead (no pong for 120s)");
                    }
                }
            }
        }
    }

    // 清理连接状态
    *CLIENT_STATE.write() = ConnectionState::Disconnected;
    CONNECTED.store(false, Ordering::SeqCst);
    *MESSAGE_TX.write() = None;
    info!("WebSocket client stopped");

    Ok(())
}

/// 断开与 Relay 服务器的连接
///
/// 重置所有连接状态，清空消息广播 channel
#[tauri::command]
pub async fn disconnect() -> Result<(), Error> {
    info!("Disconnecting from relay");

    *CLIENT_STATE.write() = ConnectionState::Disconnected;
    CONNECTED.store(false, Ordering::SeqCst);
    *MESSAGE_TX.write() = None;
    *RELAY_URL.write() = None;

    info!("Disconnected from relay");
    Ok(())
}

/// 获取当前 Relay 连接状态
///
/// 返回连接状态、服务器地址和最后心跳时间
#[tauri::command]
pub async fn get_status() -> Result<RelayStatus, Error> {
    let state = *CLIENT_STATE.read();
    Ok(RelayStatus {
        state: format!("{:?}", state).to_lowercase(),
        relay_url: RELAY_URL.read().clone(),
        last_ping: LAST_PING.read().clone(),
    })
}

/// 发送聊天消息
///
/// 1. 生成唯一 event_id 和序列号 seq_id
/// 2. 使用发送者私钥对消息内容签名
/// 3. 构造 WebSocket 消息并广播
/// 4. 将消息存入 pending_messages 表，等待对方确认
///
/// 返回生成的 event_id 用于追踪消息状态
#[tauri::command]
pub async fn send_chat_message(
    to: String,
    payload: String,
    media_id: Option<String>,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    if *CLIENT_STATE.read() != ConnectionState::Connected {
        return Err(Error::Relay("Not connected to relay".to_string()));
    }

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

    let event_id = uuid::Uuid::new_v4().to_string();
    let timestamp = chrono::Utc::now().timestamp_millis();
    let seq_id = {
        let db = state.db.lock().unwrap();
        db.get_next_seq_id(&to)?
    };

    // 签名数据：event_id + from + payload + seq_id
    let signature_data = format!("{}{}{}{}", event_id, from_pubkey, payload, seq_id);
    let privkey = identity.decrypt_private_key(&[0u8; 32])?;
    let signature = crypto::sign_data(signature_data.as_bytes(), &privkey)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    let ws_msg = WsMessage::ChatMessage {
        event_id: event_id.clone(),
        from: from_pubkey.to_string(),
        to: to.clone(),
        payload: payload.clone(),
        media_id: media_id.clone(),
        timestamp,
        signature: signature_b64.clone(),
    };

    let json = serde_json::to_string(&ws_msg)
        .map_err(|e| Error::Relay(e.to_string()))?;

    // 存入 messages 表和 pending 表
    let db_msg = DbMessage {
        id: uuid::Uuid::new_v4().to_string(),
        event_id: event_id.clone(),
        msg_type: "text".to_string(),
        from_pubkey: from_pubkey.to_string(),
        to_recipient: to.clone(),
        payload: payload.clone(),
        media_id: media_id.clone(),
        timestamp,
        seq_id,
        signature: signature_b64.clone(),
        delivered: false,
        recalled: false,
    };
    {
        let db = state.db.lock().unwrap();
        db.insert_message(&db_msg)?;
        let pending = crate::db::PendingMessage {
            id: uuid::Uuid::new_v4().to_string(),
            event_id: event_id.clone(),
            to_recipient: to,
            payload: json.clone(),
            created_at: timestamp,
            retry_count: 0,
        };
        db.insert_pending(&pending)?;
    }

    // 广播消息到 Relay
    if let Some(tx) = MESSAGE_TX.read().as_ref() {
        if let Err(e) = tx.send(ws_msg) {
            error!("Failed to send message: {}", e);
        }
    }

    debug!("Message queued: {}", json);
    Ok(event_id)
}

/// 发送消息确认（ACK）
///
/// 当收到对方发送的 ChatMessage 后，回复 MessageAck 确认已收到。
/// 确认成功后从 pending_messages 表删除对应条目。
#[tauri::command]
pub async fn send_ack(
    event_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    if *CLIENT_STATE.read() != ConnectionState::Connected {
        return Err(Error::Relay("Not connected to relay".to_string()));
    }

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

    let ack = WsMessage::MessageAck {
        event_id,
        from: from_pubkey.to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
    };

    let event_id_clone = if let WsMessage::MessageAck { event_id, .. } = &ack {
        event_id.clone()
    } else {
        return Err(Error::Relay("Invalid message type".to_string()));
    };

    // 广播 ACK 给订阅者
    if let Some(tx) = MESSAGE_TX.read().as_ref() {
        let _ = tx.send(ack);
    }

    // 确认成功后从 pending 表删除（消息已确认，无需重试）
    {
        let db = state.db.lock().unwrap();
        db.delete_pending(&event_id_clone)?;
    }

    Ok(())
}

/// 发送消息撤回（Recall）
///
/// 请求 Relay 删除指定 event_id 的消息。
/// 只会撤回自己发送的消息（from 字段匹配当前身份）。
/// 撤回成功后标记数据库中对应消息为已撤回状态。
#[tauri::command]
pub async fn send_recall(
    event_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    if *CLIENT_STATE.read() != ConnectionState::Connected {
        return Err(Error::Relay("Not connected to relay".to_string()));
    }

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

    let recall = WsMessage::MessageRecall {
        ref_event_id: event_id,
        from: from_pubkey.to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
    };

    let ref_event_id_clone = if let WsMessage::MessageRecall { ref_event_id, .. } = &recall {
        ref_event_id.clone()
    } else {
        return Err(Error::Relay("Invalid message type".to_string()));
    };

    // 广播 Recall 给订阅者
    if let Some(tx) = MESSAGE_TX.read().as_ref() {
        let _ = tx.send(recall.clone());
    }

    // 标记数据库中消息为已撤回
    {
        let db = state.db.lock().unwrap();
        db.mark_message_recalled(&ref_event_id_clone)?;
    }

    Ok(())
}

/// 订阅消息广播
///
/// 前端调用此命令建立消息订阅，之后收到的消息会通过广播 channel 推送。
/// 注意：当前实现仅做连接状态校验，实际订阅机制依赖 broadcast channel
#[tauri::command]
pub fn subscribe_messages() -> Result<(), Error> {
    if *CLIENT_STATE.read() != ConnectionState::Connected {
        return Err(Error::Relay("Not connected to relay".to_string()));
    }
    Ok(())
}

/// 获取在线用户列表
///
/// 连接 relay 服务器后，通过 HTTP 请求获取当前在线的所有用户公钥列表。
#[tauri::command]
pub async fn get_online_users(_state: tauri::State<'_, crate::AppState>) -> Result<Vec<String>, Error> {
    let relay_url = RELAY_URL.read().clone()
        .ok_or_else(|| Error::Relay("Not connected to relay".to_string()))?;

    // 将 ws:// 或 wss:// 替换为 http:// 或 https://
    let url = relay_url
        .trim_end_matches('/')
        .replace("ws://", "http://")
        .replace("wss://", "https://")
        .replace("http://", "http://")
        .replace("https://", "https://");

    let url = format!("{}/users", url);

    info!("Fetching online users from: {}", url);

    let resp = reqwest::get(&url)
        .await
        .map_err(|e| Error::Relay(format!("Failed to fetch users: {}", e)))?;

    let body: serde_json::Value = resp.json()
        .await
        .map_err(|e| Error::Relay(format!("Failed to parse response: {}", e)))?;

    let users = body.get("users")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();

    Ok(users)
}