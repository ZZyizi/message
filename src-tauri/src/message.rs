//! 消息收发模块
//!
//! 提供消息的发送、接收、撤回等功能。
//! 发送时使用 Ed25519 对消息签名，接收时验证签名；
//! 未确认的消息存入 pending 队列待重试（重试机制尚未实现）。

use base64::Engine;
use uuid::Uuid;

use crate::crypto;
use crate::db::{Message, PendingMessage};
use crate::Error;

/// 发送消息请求结构
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SendMessageRequest {
    pub to: String,           // 接收者公钥或群组 ID
    pub msg_type: String,     // 消息类型（如 "text", "image"）
    pub payload: String,      // 消息内容（已加密）
    pub media_id: Option<String>, // 媒体附件 ID（如有）
}

/// 发送消息响应结构
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct MessageResponse {
    pub event_id: String,  // 全局唯一事件 ID
    pub seq_id: i64,        // 序列号（用于消息排序）
}

/// 发送消息
///
/// 执行流程：
/// 1. 生成唯一 event_id（UUID）
/// 2. 获取当前身份公钥作为发送者
/// 3. 计算目标接收者的下一个序列号
/// 4. 对消息内容签名（防止篡改）
/// 5. 存入数据库
/// 6. 加入 pending 队列（待 relay 确认送达后删除）
///
/// 返回生成的 event_id 和 seq_id 供前端追踪。
#[tauri::command]
pub async fn send_message(
    request: SendMessageRequest,
    state: tauri::State<'_, crate::AppState>,
) -> Result<MessageResponse, Error> {
    let event_id = Uuid::new_v4().to_string();

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

    let db = state.db.lock().unwrap();
    let seq_id = db.get_next_seq_id(&request.to)?;

    // 签名数据：event_id + from_pubkey + payload + seq_id
    let signature_data = format!("{}{}{}{}", event_id, from_pubkey, request.payload, seq_id);
    let privkey = identity.decrypt_private_key(&[0u8; 32])?;
    let signature = crypto::sign_data(signature_data.as_bytes(), &privkey)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    let timestamp = chrono::Utc::now().timestamp_millis();

    let msg = Message {
        id: Uuid::new_v4().to_string(),
        event_id: event_id.clone(),
        msg_type: request.msg_type,
        from_pubkey: from_pubkey.to_string(),
        to_recipient: request.to,
        payload: request.payload,
        media_id: request.media_id,
        timestamp,
        seq_id,
        signature: signature_b64,
        delivered: false,
        recalled: false,
    };

    db.insert_message(&msg)?;

    // 加入 pending 队列，等待 relay 确认送达后删除
    let pending = PendingMessage {
        id: Uuid::new_v4().to_string(),
        event_id: event_id.clone(),
        to_recipient: msg.to_recipient.clone(),
        payload: msg.payload.clone(),
        created_at: timestamp,
        retry_count: 0,
    };
    db.insert_pending(&pending)?;

    Ok(MessageResponse { event_id, seq_id })
}

/// 获取消息列表
///
/// - `recipient`: 接收者公钥或群组 ID
/// - `since_seq`: 从指定序列号之后开始（可选，用于增量同步）
/// - `limit`: 返回条数上限（默认 100）
///
/// 自动过滤已撤回的消息。
#[tauri::command]
pub async fn get_messages(
    recipient: String,
    since_seq: Option<i64>,
    limit: Option<i64>,
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<Message>, Error> {
    let db = state.db.lock().unwrap();
    let messages = db.get_messages(&recipient, since_seq, limit.unwrap_or(100))?;
    Ok(messages)
}

/// 获取与指定联系人的聊天记录（双向）
///
/// 同时查询发送给我的消息和我发送给对方的消息，按时间排序。
#[tauri::command]
pub async fn get_chat_messages(
    peer_pubkey: String,
    limit: Option<i64>,
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<Message>, Error> {
    let identity = state.identity.read();
    let my_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?;
    let my_pubkey = my_pubkey.to_string();
    drop(identity);

    let db = state.db.lock().unwrap();
    let limit = limit.unwrap_or(100);

    // 自己发给自己时只查一次，避免重复
    if my_pubkey == peer_pubkey {
        let messages = db.get_messages(&my_pubkey, None, limit)?;
        return Ok(messages);
    }

    // 查询我发送给对方的消息
    let sent = db.get_messages(&peer_pubkey, None, limit)?;
    // 查询对方发送给我的消息（我作为接收者）
    let received = db.get_messages(&my_pubkey, None, limit)?;

    // 合并并按时间排序
    let mut all: Vec<Message> = sent.into_iter().chain(received.into_iter()).collect();
    all.sort_by_key(|m| m.timestamp);

    Ok(all)
}

/// 撤回消息（逻辑删除）
///
/// 标记消息为 recalled=1，前端不再显示。
/// 实际数据仍保留在数据库中，可用于审计。
#[tauri::command]
pub async fn recall_message(
    event_id: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    let db = state.db.lock().unwrap();
    db.mark_message_recalled(&event_id)?;
    Ok(())
}

/// 获取 pending 队列消息数量（用于调试）
///
/// 注意：pending 重试机制尚未实现，此函数仅供调试使用。
#[allow(dead_code)]
#[tauri::command]
pub async fn get_pending_count(
    state: tauri::State<'_, crate::AppState>,
) -> Result<i64, Error> {
    let db = state.db.lock().unwrap();
    let pending = db.get_pending_messages(1000)?;
    Ok(pending.len() as i64)
}

/// 清理过期的 pending 消息（用于维护）
///
/// - `max_age_days`: 最大存活天数
///
/// 注意：pending 重试机制尚未实现，此函数仅供维护使用。
#[allow(dead_code)]
#[tauri::command]
pub async fn cleanup_expired_pending(
    max_age_days: i64,
    state: tauri::State<'_, crate::AppState>,
) -> Result<i64, Error> {
    let db = state.db.lock().unwrap();
    let deleted = db.cleanup_expired_pending(max_age_days * 24 * 60 * 60)?;
    Ok(deleted)
}