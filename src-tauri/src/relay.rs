//! 中继服务器连接模块
//!
//! 负责与 Relay 服务器的 WebSocket 连接管理、消息收发。
//! 支持聊天消息、消息确认（ACK）、消息撤回（Recall）、
//! 密钥交换（KeyExchange）和密钥确认（KeyConfirm）五种消息类型。

use std::sync::atomic::{AtomicBool, Ordering};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    ChatMessage {
        event_id: String,
        from: String,
        to: String,
        payload: String,
        media_id: Option<String>,
        timestamp: i64,
        signature: String,
        seq_id: i64,
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
    KeyExchange {
        from: String,
        to: String,
        ephemeral_pubkey: String,
        signature: String,
        nonce: String,
        timestamp: i64,
    },
    KeyConfirm {
        from: String,
        to: String,
        encrypted_confirm: String,
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
/// 出站消息 channel，用于将消息发送到 Relay WebSocket
static OUTBOUND_TX: RwLock<Option<mpsc::Sender<WsMessage>>> = RwLock::new(None);

/// 连接到 Relay 服务器
///
/// 若已存在连接则先断开，然后建立新的 WebSocket 连接。
/// 使用 oneshot channel 等待 WebSocket 实际连接成功后再返回。
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

    // 使用 oneshot channel 等待 WebSocket 连接结果
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<Result<(), String>>();
    let app_handle = state.app_handle.clone();

    tokio::spawn(async move {
        run_websocket_client(path, app_handle, ready_tx).await;
    });

    // 等待 WebSocket 连接结果（最多 10 秒）
    match tokio::time::timeout(tokio::time::Duration::from_secs(10), ready_rx).await {
        Ok(Ok(Ok(()))) => {
            info!("Connected to relay successfully");
        }
        Ok(Ok(Err(e))) => {
            *CLIENT_STATE.write() = ConnectionState::Disconnected;
            return Err(Error::Relay(format!("WebSocket connect failed: {}", e)));
        }
        Ok(Err(_)) => {
            *CLIENT_STATE.write() = ConnectionState::Disconnected;
            return Err(Error::Relay("WebSocket task panicked".to_string()));
        }
        Err(_) => {
            *CLIENT_STATE.write() = ConnectionState::Disconnected;
            return Err(Error::Relay("WebSocket connect timed out".to_string()));
        }
    }

    *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());

    {
        let db = state.db.lock().unwrap();
        db.set_setting("relay_url", &relay_url)?;
    }

    Ok(())
}

/// WebSocket 客户端主循环
///
/// 负责：
/// 1. 维护 WebSocket 连接
/// 2. 每 30 秒发送一次 Ping 心跳
/// 3. 接收并广播收到的新消息（存入数据库并通知前端）
/// 4. 检测 120 秒无响应视为连接断开
///
/// 使用 mpsc channel 管理出站消息：send_chat_message 通过 OUTBOUND_TX 发送，
/// 写任务从 mpsc 接收并写入 WebSocket。
async fn run_websocket_client(
    relay_url: String,
    app_handle: tauri::AppHandle,
    ready_tx: tokio::sync::oneshot::Sender<Result<(), String>>,
) {
    use tokio_tungstenite::{connect_async, tungstenite::Message};
    use futures_util::{StreamExt, SinkExt};

    info!("Connecting to WebSocket: {}", relay_url);

    let ws_result = connect_async(&relay_url).await;
    let (ws_stream, _) = match ws_result {
        Ok(pair) => pair,
        Err(e) => {
            let msg = format!("WebSocket connect failed: {}", e);
            error!("{}", msg);
            let _ = ready_tx.send(Err(msg));
            return;
        }
    };

    info!("WebSocket connected");

    // 创建出站消息 mpsc channel
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<WsMessage>(100);

    // 存储出站 channel 到全局状态（供 send_chat_message 等使用）
    *OUTBOUND_TX.write() = Some(outbound_tx);

    // 通知 connect() 函数连接已成功
    let _ = ready_tx.send(Ok(()));

    *CLIENT_STATE.write() = ConnectionState::Connected;
    CONNECTED.store(true, Ordering::SeqCst);

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // 写任务：从 mpsc channel 读取消息，写入 WebSocket（包括 pings 和用户消息）
    tokio::spawn(async move {
        loop {
            tokio::select! {
                // 优先处理出站消息
                msg = outbound_rx.recv() => {
                    match msg {
                        Some(ws_msg) => {
                            if let Ok(json) = serde_json::to_string(&ws_msg) {
                                if ws_write.send(Message::Text(json.into())).await.is_err() {
                                    warn!("Failed to write message to WebSocket");
                                    break;
                                }
                            }
                        }
                        None => {
                            // Channel closed, stop writer
                            break;
                        }
                    }
                }
                // 每 30 秒发送一次 Ping 心跳
                _ = tokio::time::sleep(tokio::time::Duration::from_secs(30)) => {
                    let ping = WsMessage::Ping;
                    if let Ok(json) = serde_json::to_string(&ping) {
                        if ws_write.send(Message::Text(json.into())).await.is_err() {
                            warn!("Failed to send ping");
                            break;
                        }
                    }
                    *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());
                }
            }
        }
    });

    // 消息接收主循环
    loop {
        tokio::select! {
            msg = ws_read.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        debug!("Received: {}", text);
                        if let Ok(ws_msg) = serde_json::from_str::<WsMessage>(&text) {
                            // 收到 Pong 更新最后心跳时间
                            if let WsMessage::Pong = &ws_msg {
                                *LAST_PING.write() = Some(chrono::Utc::now().timestamp_millis());
                            }
                            // 处理收到的聊天消息
                            if let WsMessage::ChatMessage { event_id, from, to, payload, media_id, timestamp, signature, seq_id } = &ws_msg {
                                let app_state = app_handle.state::<crate::AppState>();
                                let my_pubkey = {
                                    let identity = app_state.identity.read();
                                    identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
                                };
                                // 忽略发送给其他人后的回显（from=me 且 to!=me）
                                // 但自己发给自己的消息需要处理（from=me 且 to=me）
                                if from == &my_pubkey && *to != my_pubkey {
                                    debug!("Ignoring echo of own message: {}", event_id);
                                    continue;
                                }

                                // 验证签名
                                let signature_data = format!("{}{}{}{}", event_id, from, payload, seq_id);
                                if let Ok(from_pubkey_bytes) = base64::engine::general_purpose::STANDARD.decode(from) {
                                    if let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature) {
                                        let valid = crypto::verify_signature(signature_data.as_bytes(), &sig_bytes, &from_pubkey_bytes)
                                            .unwrap_or(false);
                                        if !valid {
                                            warn!("Invalid message signature from {}", from);
                                            continue;
                                        }
                                    }
                                }

                                // 尝试解密（有会话密钥时才解密，自己发给自己的消息无密钥）
                                let (decrypted_for_display, stored_payload) = if let Some(session) = app_state.sessions.get(from) {
                                    let s = session.read();
                                    if s.status == crate::session::SessionStatus::Active && s.session_key.is_some() {
                                        if let Ok(cipher_bytes) = base64::engine::general_purpose::STANDARD.decode(payload) {
                                            match s.decrypt(&cipher_bytes) {
                                                Ok(plaintext) => {
                                                    let display = String::from_utf8_lossy(&plaintext).to_string();
                                                    (display, payload.clone())
                                                }
                                                Err(e) => {
                                                    warn!("Decryption failed from {}: {}", from, e);
                                                    ("[解密失败]".to_string(), payload.clone())
                                                }
                                            }
                                        } else {
                                            (payload.clone(), payload.clone())
                                        }
                                    } else {
                                        (payload.clone(), payload.clone())
                                    }
                                } else {
                                    (payload.clone(), payload.clone())
                                };

                                info!("New chat message: {} -> {} (event_id: {})", from, to, event_id);
                                let db = app_state.db.lock().unwrap();
                                let msg = DbMessage {
                                    id: uuid::Uuid::new_v4().to_string(),
                                    event_id: event_id.clone(),
                                    msg_type: "text".to_string(),
                                    from_pubkey: from.clone(),
                                    to_recipient: to.clone(),
                                    payload: stored_payload,
                                    media_id: media_id.clone(),
                                    timestamp: *timestamp,
                                    seq_id: *seq_id,
                                    signature: signature.clone(),
                                    delivered: true,
                                    recalled: false,
                                };
                                if let Err(e) = db.insert_message(&msg) {
                                    error!("Failed to store message: {}", e);
                                }
                                // 通知前端收到新消息（使用解密后的明文）
                                let mut display_msg = msg.clone();
                                display_msg.payload = decrypted_for_display;
                                let _ = app_handle.emit("new_message", &display_msg);
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

                            // 处理密钥交换消息
                            if let WsMessage::KeyExchange { from, to, ephemeral_pubkey, signature, nonce, timestamp } = &ws_msg {
                                let app_state = app_handle.state::<crate::AppState>();
                                let my_pubkey = {
                                    let identity = app_state.identity.read();
                                    identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
                                };

                                if *to != my_pubkey {
                                    continue;
                                }

                                // 忽略自己发给自己的回显
                                if *from == my_pubkey {
                                    debug!("Ignoring echo of own KeyExchange");
                                    continue;
                                }

                                info!("Received KeyExchange from: {}", from);

                                // 解码临时公钥
                                let ephemeral_pub_bytes = match base64::engine::general_purpose::STANDARD.decode(ephemeral_pubkey) {
                                    Ok(bytes) if bytes.len() == 32 => {
                                        let mut arr = [0u8; 32];
                                        arr.copy_from_slice(&bytes);
                                        arr
                                    }
                                    _ => {
                                        warn!("Invalid ephemeral pubkey from {}", from);
                                        continue;
                                    }
                                };

                                // 验证时间戳（5分钟内）
                                let now = chrono::Utc::now().timestamp();
                                if (now - timestamp).abs() > 300 {
                                    warn!("KeyExchange timestamp too old from {}", from);
                                    continue;
                                }

                                // 验证签名
                                let nonce_bytes = match base64::engine::general_purpose::STANDARD.decode(nonce) {
                                    Ok(bytes) if bytes.len() == 32 => bytes,
                                    _ => {
                                        warn!("Invalid nonce from {}", from);
                                        continue;
                                    }
                                };

                                let mut signed_data = Vec::new();
                                signed_data.extend_from_slice(&ephemeral_pub_bytes);
                                signed_data.extend_from_slice(from.as_bytes());
                                signed_data.extend_from_slice(&nonce_bytes);
                                signed_data.extend_from_slice(&timestamp.to_le_bytes());

                                let from_pubkey_bytes = match base64::engine::general_purpose::STANDARD.decode(from) {
                                    Ok(bytes) if bytes.len() == 32 => bytes,
                                    _ => {
                                        warn!("Invalid from pubkey from {}", from);
                                        continue;
                                    }
                                };

                                let sig_bytes = match base64::engine::general_purpose::STANDARD.decode(signature) {
                                    Ok(bytes) => bytes,
                                    _ => {
                                        warn!("Invalid signature from {}", from);
                                        continue;
                                    }
                                };

                                let valid = crypto::verify_signature(&signed_data, &sig_bytes, &from_pubkey_bytes)
                                    .unwrap_or(false);

                                if !valid {
                                    warn!("Invalid KeyExchange signature from {}", from);
                                    continue;
                                }

                                // 获取或创建会话
                                let session = app_state.sessions.get_or_create(&from);

                                // 检查是否需要先回复 KeyExchange（双向协商）
                                {
                                    let mut s = session.write();
                                    if s.status == crate::session::SessionStatus::None {
                                        let (my_ephemeral_pub, my_ephemeral_priv) = crypto::generate_x25519_keypair();
                                        let my_ephemeral_pub_b64 = base64::engine::general_purpose::STANDARD.encode(&my_ephemeral_pub);

                                        let mut nonce_bytes = [0u8; 32];
                                        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
                                        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);
                                        let timestamp = chrono::Utc::now().timestamp();

                                        let mut signed_data = Vec::new();
                                        signed_data.extend_from_slice(&my_ephemeral_pub);
                                        signed_data.extend_from_slice(my_pubkey.as_bytes());
                                        signed_data.extend_from_slice(&nonce_bytes);
                                        signed_data.extend_from_slice(&timestamp.to_le_bytes());

                                        let my_privkey = {
                                            let identity = app_state.identity.read();
                                            match identity.decrypt_private_key(&[0u8; 32]) {
                                                Ok(key) => key,
                                                Err(e) => {
                                                    warn!("Failed to decrypt private key: {}", e);
                                                    continue;
                                                }
                                            }
                                        };
                                        let my_signature = match crypto::sign_data(&signed_data, &my_privkey) {
                                            Ok(sig) => sig,
                                            Err(e) => {
                                                warn!("Failed to sign key exchange: {}", e);
                                                continue;
                                            }
                                        };
                                        let my_signature_b64 = base64::engine::general_purpose::STANDARD.encode(&my_signature);

                                        let mut privkey_arr = [0u8; 32];
                                        privkey_arr.copy_from_slice(&my_ephemeral_priv);
                                        s.my_ephemeral_privkey = privkey_arr;
                                        s.status = crate::session::SessionStatus::WaitingForPeer;

                                        drop(s);

                                        let key_exchange = WsMessage::KeyExchange {
                                            from: my_pubkey.clone(),
                                            to: from.clone(),
                                            ephemeral_pubkey: my_ephemeral_pub_b64,
                                            signature: my_signature_b64,
                                            nonce: nonce_b64,
                                            timestamp,
                                        };
                                        if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                                            let _ = tx.try_send(key_exchange);
                                        }
                                    }
                                }

                                // 处理对方的密钥交换
                                {
                                    let mut s = session.write();
                                    if let Err(e) = s.handle_key_exchange(ephemeral_pub_bytes) {
                                        warn!("Failed to handle key exchange: {}", e);
                                        continue;
                                    }
                                }

                                // 发送 KeyConfirm
                                {
                                    let key = { session.read().session_key };
                                    if let Some(key) = key {
                                        let confirm_plaintext = b"confirm";
                                        match crypto::encrypt_message(confirm_plaintext, &key, None) {
                                            Ok(enc) => {
                                                let enc_b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
                                                let confirm = WsMessage::KeyConfirm {
                                                    from: my_pubkey.clone(),
                                                    to: from.clone(),
                                                    encrypted_confirm: enc_b64,
                                                    timestamp: chrono::Utc::now().timestamp(),
                                                };
                                                if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                                                    let _ = tx.try_send(confirm);
                                                }

                                                let mut s = session.write();
                                                s.status = crate::session::SessionStatus::Active;
                                                info!("Session activated with peer: {}", from);

                                                // 刷新待发明文消息队列
                                                let pending = s.flush_pending_plaintext();
                                                drop(s);
                                                for p in pending {
                                                    let s = session.read();
                                                    if let Ok(enc) = s.encrypt(p.payload.as_bytes()) {
                                                        let enc_b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
                                                        drop(s);

                                                        let signature_data = format!("{}{}{}{}", p.event_id, my_pubkey, enc_b64, p.seq_id);
                                                        let identity = app_state.identity.read();
                                                        if let Ok(privkey) = identity.decrypt_private_key(&[0u8; 32]) {
                                                            drop(identity);
                                                            if let Ok(sig) = crypto::sign_data(signature_data.as_bytes(), &privkey) {
                                                                let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

                                                                let ws_msg = WsMessage::ChatMessage {
                                                                    event_id: p.event_id.clone(),
                                                                    from: my_pubkey.clone(),
                                                                    to: p.to_recipient.clone(),
                                                                    payload: enc_b64.clone(),
                                                                    media_id: None,
                                                                    timestamp: p.created_at,
                                                                    signature: sig_b64.clone(),
                                                                    seq_id: p.seq_id,
                                                                };
                                                                if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                                                                    let _ = tx.try_send(ws_msg);
                                                                }

                                                                let db = app_state.db.lock().unwrap();
                                                                let _ = db.update_message_payload_and_signature(&p.event_id, &enc_b64, &sig_b64);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                warn!("Failed to encrypt key confirm: {}", e);
                                            }
                                        }
                                    }
                                }
                            }

                            // 处理密钥确认消息
                            if let WsMessage::KeyConfirm { from, to, encrypted_confirm, .. } = &ws_msg {
                                let app_state = app_handle.state::<crate::AppState>();
                                let my_pubkey = {
                                    let identity = app_state.identity.read();
                                    identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
                                };

                                if *to != my_pubkey {
                                    continue;
                                }

                                info!("Received KeyConfirm from: {}", from);

                                if let Some(session) = app_state.sessions.get(from) {
                                    let enc_bytes = match base64::engine::general_purpose::STANDARD.decode(encrypted_confirm) {
                                        Ok(bytes) => bytes,
                                        _ => {
                                            warn!("Invalid encrypted confirm from {}", from);
                                            continue;
                                        }
                                    };

                                    let mut s = session.write();
                                    match s.decrypt(&enc_bytes) {
                                        Ok(plaintext) if plaintext == b"confirm" => {
                                            s.status = crate::session::SessionStatus::Active;
                                            info!("Session confirmed with peer: {}", from);

                                            let pending = s.flush_pending_plaintext();
                                            drop(s);
                                            for p in pending {
                                                let s = session.read();
                                                if let Ok(enc) = s.encrypt(p.payload.as_bytes()) {
                                                    let enc_b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
                                                    drop(s);

                                                    let signature_data = format!("{}{}{}{}", p.event_id, my_pubkey, enc_b64, p.seq_id);
                                                    let identity = app_state.identity.read();
                                                    if let Ok(privkey) = identity.decrypt_private_key(&[0u8; 32]) {
                                                        drop(identity);
                                                        if let Ok(sig) = crypto::sign_data(signature_data.as_bytes(), &privkey) {
                                                            let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);
                                                            let ws_msg = WsMessage::ChatMessage {
                                                                event_id: p.event_id.clone(),
                                                                from: my_pubkey.clone(),
                                                                to: p.to_recipient.clone(),
                                                                payload: enc_b64.clone(),
                                                                media_id: None,
                                                                timestamp: p.created_at,
                                                                signature: sig_b64.clone(),
                                                                seq_id: p.seq_id,
                                                            };
                                                            if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                                                                let _ = tx.try_send(ws_msg);
                                                            }
                                                            let db = app_state.db.lock().unwrap();
                                                            let _ = db.update_message_payload_and_signature(&p.event_id, &enc_b64, &sig_b64);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(_) => {
                                            warn!("KeyConfirm content mismatch from {}", from);
                                            s.status = crate::session::SessionStatus::None;
                                        }
                                        Err(e) => {
                                            warn!("Failed to decrypt KeyConfirm from {}: {}", from, e);
                                            s.status = crate::session::SessionStatus::None;
                                        }
                                    }
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
    *OUTBOUND_TX.write() = None;
    info!("WebSocket client stopped");
}

/// 断开与 Relay 服务器的连接
///
/// 重置所有连接状态，清空消息广播 channel
#[tauri::command]
pub async fn disconnect() -> Result<(), Error> {
    info!("Disconnecting from relay");

    *CLIENT_STATE.write() = ConnectionState::Disconnected;
    CONNECTED.store(false, Ordering::SeqCst);
    *OUTBOUND_TX.write() = None;
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

    // 检查会话状态，决定是否加密
    let session = state.sessions.get_or_create(&to);
    let (encrypted_payload, should_send_now) = {
        let s = session.read();
        if s.status == crate::session::SessionStatus::Active && s.session_key.is_some() {
            // 有会话密钥，加密发送
            match s.encrypt(payload.as_bytes()) {
                Ok(enc) => (base64::engine::general_purpose::STANDARD.encode(&enc), true),
                Err(e) => {
                    warn!("Encryption failed: {}", e);
                    return Err(Error::Crypto(e));
                }
            }
        } else if s.status == crate::session::SessionStatus::Active {
            // 会话已激活但无密钥（给自己发消息），明文发送
            (payload.clone(), true)
        } else {
            warn!("Session not active, queueing message");
            (payload.clone(), false)
        }
    };

    // 签名数据：event_id + from + 加密后的payload + seq_id
    let signature_data = format!("{}{}{}{}", event_id, from_pubkey, encrypted_payload, seq_id);
    let privkey = identity.decrypt_private_key(&[0u8; 32])?;
    let signature = crypto::sign_data(signature_data.as_bytes(), &privkey)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    // 存入 messages 表（使用加密后的 payload）
    let db_msg = DbMessage {
        id: uuid::Uuid::new_v4().to_string(),
        event_id: event_id.clone(),
        msg_type: "text".to_string(),
        from_pubkey: from_pubkey.to_string(),
        to_recipient: to.clone(),
        payload: encrypted_payload.clone(),
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
    }

    if should_send_now {
        // 会话已建立，直接发送加密消息
        let ws_msg = WsMessage::ChatMessage {
            event_id: event_id.clone(),
            from: from_pubkey.to_string(),
            to: to.clone(),
            payload: encrypted_payload.clone(),
            media_id: media_id.clone(),
            timestamp,
            signature: signature_b64.clone(),
            seq_id,
        };

        if let Some(tx) = OUTBOUND_TX.read().as_ref() {
            if let Err(e) = tx.try_send(ws_msg) {
                error!("Failed to send message: {}", e);
            }
        } else {
            error!("No outbound channel available");
        }
    } else {
        // 会话未建立，加入明文队列等待密钥协商完成后发送
        let mut s = session.write();
        let pending = crate::session::PendingPlaintext {
            event_id: event_id.clone(),
            to_recipient: to.clone(),
            payload: payload.clone(),
            seq_id,
            created_at: timestamp,
        };
        if let Err(e) = s.enqueue_plaintext(pending) {
            warn!("Failed to queue message: {}", e);
            return Err(Error::Relay(e));
        }
    }

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

    // 发送 ACK 到 Relay
    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
        let _ = tx.try_send(ack);
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

    // 发送 Recall 到 Relay
    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
        let _ = tx.try_send(recall.clone());
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

/// 获取在线用户列表（内部实现，可被其他模块调用）
///
/// 连接 relay 服务器后，通过 HTTP 请求获取当前在线的所有用户公钥列表。
pub async fn fetch_online_users() -> Result<Vec<String>, Error> {
    let relay_url = RELAY_URL.read().clone()
        .ok_or_else(|| Error::Relay("Not connected to relay".to_string()))?;

    // 将 ws:// 或 wss:// 替换为 http:// 或 https://
    let url = relay_url
        .trim_end_matches('/')
        .replace("ws://", "http://")
        .replace("wss://", "https://");

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

/// 获取在线用户列表（Tauri 命令）
#[tauri::command]
pub async fn get_online_users() -> Result<Vec<String>, Error> {
    fetch_online_users().await
}

/// 发起密钥协商
///
/// 生成临时密钥对，用 Ed25519 私钥对复合值签名后通过 Relay 发送给对方
#[tauri::command]
pub async fn initiate_key_exchange(
    peer_pubkey: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    info!("initiate_key_exchange called for peer: {}", peer_pubkey);

    if *CLIENT_STATE.read() != ConnectionState::Connected {
        warn!("initiate_key_exchange: not connected to relay");
        return Err(Error::Relay("Not connected to relay".to_string()));
    }

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| {
            warn!("initiate_key_exchange: no identity found");
            Error::Identity("No identity found".to_string())
        })?
        .to_string();
    info!("initiate_key_exchange: from_pubkey = {}", from_pubkey);

    // 给自己发消息：跳过密钥协商，直接激活会话（无需 E2EE）
    if from_pubkey == peer_pubkey {
        info!("Self-message detected, activating session directly");
        let session = state.sessions.get_or_create(&peer_pubkey);
        let mut s = session.write();
        s.status = crate::session::SessionStatus::Active;
        return Ok(());
    }

    // 获取或创建会话并生成临时密钥
    let session = state.sessions.get_or_create(&peer_pubkey);
    let my_ephemeral_pubkey = {
        let mut s = session.write();
        info!("initiate_key_exchange: session status before = {:?}", s.status);
        let result = s.initiate_key_exchange()
            .map_err(|e| {
                warn!("initiate_key_exchange: initiate_key_exchange failed: {}", e);
                Error::Relay(e)
            })?;
        info!("initiate_key_exchange: session status after = {:?}", s.status);
        result
    };

    // 生成随机 nonce
    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);

    let timestamp = chrono::Utc::now().timestamp();

    // 签名复合值: ephemeral_pubkey || from || nonce || timestamp
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&my_ephemeral_pubkey);
    signed_data.extend_from_slice(from_pubkey.as_bytes());
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_le_bytes());

    let privkey = identity.decrypt_private_key(&[0u8; 32])?;
    let signature = crypto::sign_data(&signed_data, &privkey)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    let ephemeral_pub_b64 = base64::engine::general_purpose::STANDARD.encode(&my_ephemeral_pubkey);

    // 发送 KeyExchange
    let key_exchange = WsMessage::KeyExchange {
        from: from_pubkey,
        to: peer_pubkey.clone(),
        ephemeral_pubkey: ephemeral_pub_b64,
        signature: signature_b64,
        nonce: nonce_b64,
        timestamp,
    };

    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
        if let Err(e) = tx.try_send(key_exchange) {
            warn!("initiate_key_exchange: failed to send KeyExchange: {}", e);
        } else {
            info!("initiate_key_exchange: KeyExchange sent successfully");
        }
    } else {
        warn!("initiate_key_exchange: no outbound channel");
        return Err(Error::Relay("No outbound channel".to_string()));
    }

    // 启动超时定时器（30秒）
    let app_handle_clone = state.app_handle.clone();
    let peer_clone = peer_pubkey.clone();
    let session_clone = session.clone();

    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
        let mut s = session_clone.write();
        if s.status == crate::session::SessionStatus::WaitingForPeer {
            warn!("KeyExchange timeout for peer: {}", peer_clone);
            s.status = crate::session::SessionStatus::None;
            let _ = app_handle_clone.emit("session_timeout", &peer_clone);
        }
    });

    info!("KeyExchange sent to peer");
    Ok(())
}

/// 获取会话状态
#[tauri::command]
pub async fn get_session_status(
    peer_pubkey: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    match state.sessions.get(&peer_pubkey) {
        Some(session) => {
            let s = session.read();
            Ok(format!("{:?}", s.status))
        }
        None => Ok("None".to_string()),
    }
}