//! 会话状态管理模块
//!
//! 管理一对一聊天的 E2EE 会话状态，包括密钥协商、会话密钥存储和明文消息队列。

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::info;
use zeroize::Zeroize;

use crate::crypto;

/// HKDF info 参数，双方必须一致
const E2EE_INFO: &[u8] = b"decentralized-im-e2ee-1to1";

/// 会话超时时间（秒），用于后续 Task 5.5 的超时定时器
#[allow(dead_code)]
const SESSION_TIMEOUT_SECS: u64 = 30;

/// 等待密钥的最大明文消息队列长度
const MAX_PENDING_PLAINTEXT: usize = 100;

/// 会话状态枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionStatus {
    /// 未开始协商
    None,
    /// 已发送 KeyExchange，等待对方
    WaitingForPeer,
    /// 已收到对方 KeyExchange，已派生密钥
    KeyExchanged,
    /// 已发送 KeyConfirm，等待确认
    WaitingForConfirm,
    /// 会话已建立，可通信
    Active,
    /// 正在重新协商密钥
    Rekeying,
}

/// 等待密钥就绪的明文消息
#[derive(Debug, Clone)]
pub struct PendingPlaintext {
    pub event_id: String,
    pub to_recipient: String,
    pub payload: String,
    pub seq_id: i64,
    pub created_at: i64,
}

/// 会话状态
pub struct SessionState {
    pub status: SessionStatus,
    pub peer_static_pubkey: String,
    pub my_ephemeral_privkey: [u8; 32],
    pub peer_ephemeral_pubkey: Option<[u8; 32]>,
    pub session_key: Option<[u8; 32]>,
    pub pending_plaintext: Vec<PendingPlaintext>,
}

impl Drop for SessionState {
    fn drop(&mut self) {
        self.my_ephemeral_privkey.zeroize();
        if let Some(ref mut key) = self.session_key {
            key.zeroize();
        }
        if let Some(ref mut key) = self.peer_ephemeral_pubkey {
            key.zeroize();
        }
    }
}

impl SessionState {
    /// 创建新会话（不生成密钥，密钥在 initiate_key_exchange 时生成）
    pub fn new(peer_pubkey: String) -> Self {
        info!("Created new session for peer: {}", peer_pubkey);

        SessionState {
            status: SessionStatus::None,
            peer_static_pubkey: peer_pubkey,
            my_ephemeral_privkey: [0u8; 32],
            peer_ephemeral_pubkey: None,
            session_key: None,
            pending_plaintext: Vec::new(),
        }
    }

    /// 发起密钥协商（生成临时密钥对，状态转为 WaitingForPeer）
    pub fn initiate_key_exchange(&mut self) -> Result<[u8; 32], String> {
        if self.status == SessionStatus::WaitingForPeer
            || self.status == SessionStatus::WaitingForConfirm
        {
            return Err("Key exchange already in progress".to_string());
        }

        let (ephemeral_pub, ephemeral_priv) = crypto::generate_x25519_keypair();
        let mut privkey = [0u8; 32];
        privkey.copy_from_slice(&ephemeral_priv);
        self.my_ephemeral_privkey = privkey;
        self.status = SessionStatus::WaitingForPeer;

        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&ephemeral_pub);
        Ok(pubkey)
    }

    /// 获取我方临时公钥
    pub fn my_ephemeral_pubkey(&self) -> [u8; 32] {
        let mut pubkey = [0u8; 32];
        // 从私钥推导公钥
        let secret = x25519_dalek::StaticSecret::from(self.my_ephemeral_privkey);
        let public = x25519_dalek::PublicKey::from(&secret);
        pubkey.copy_from_slice(public.as_bytes());
        pubkey
    }

    /// 处理收到的对方 KeyExchange
    pub fn handle_key_exchange(
        &mut self,
        peer_ephemeral_pubkey: [u8; 32],
    ) -> Result<(), String> {
        // 守卫：如果临时私钥全为零，说明尚未发起协商
        if self.my_ephemeral_privkey == [0u8; 32] {
            return Err("No ephemeral key generated yet".to_string());
        }

        if self.status == SessionStatus::Active {
            // 已建立会话，进入 Rekeying
            info!("Rekeying session with peer: {}", self.peer_static_pubkey);
            self.status = SessionStatus::Rekeying;
        }

        self.peer_ephemeral_pubkey = Some(peer_ephemeral_pubkey);

        // 派生会话密钥
        let session_key = crypto::derive_session_key(
            &self.my_ephemeral_privkey,
            &peer_ephemeral_pubkey,
            E2EE_INFO,
        )
        .map_err(|e| format!("Failed to derive session key: {}", e))?;

        let mut key = [0u8; 32];
        key.copy_from_slice(&session_key);
        self.session_key = Some(key);

        self.status = SessionStatus::KeyExchanged;
        info!("Session key derived for peer: {}", self.peer_static_pubkey);

        Ok(())
    }

    /// 确认会话密钥（收到 KeyConfirm 后调用）
    pub fn confirm_session(&mut self) -> Result<(), String> {
        if self.status != SessionStatus::WaitingForConfirm {
            return Err(format!("Unexpected confirm in status: {:?}", self.status));
        }

        self.status = SessionStatus::Active;
        info!("Session activated with peer: {}", self.peer_static_pubkey);

        Ok(())
    }

    /// 加入等待密钥的明文消息队列
    ///
    /// 仅在 WaitingForPeer 或 KeyExchanged 状态下允许入队
    pub fn enqueue_plaintext(&mut self, msg: PendingPlaintext) -> Result<(), String> {
        if self.status != SessionStatus::WaitingForPeer && self.status != SessionStatus::KeyExchanged {
            return Err(format!("Cannot enqueue in status: {:?}", self.status));
        }
        if self.pending_plaintext.len() >= MAX_PENDING_PLAINTEXT {
            return Err("Pending plaintext queue full".to_string());
        }
        self.pending_plaintext.push(msg);
        Ok(())
    }

    /// 刷新队列（密钥就绪后返回所有待发消息，由调用方加密发送）
    pub fn flush_pending_plaintext(&mut self) -> Vec<PendingPlaintext> {
        std::mem::take(&mut self.pending_plaintext)
    }

    /// 加密消息
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.session_key.ok_or("No session key")?;
        crypto::encrypt_message(plaintext, &key, None)
            .map_err(|e| format!("Encryption failed: {}", e))
    }

    /// 解密消息
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let key = self.session_key.ok_or("No session key")?;
        crypto::decrypt_message(ciphertext, &key, None)
            .map_err(|e| format!("Decryption failed: {}", e))
    }
}

/// 会话管理器
pub struct SessionManager {
    sessions: RwLock<HashMap<String, Arc<RwLock<SessionState>>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        SessionManager {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    /// 获取或创建会话
    pub fn get_or_create(&self, peer_pubkey: &str) -> Arc<RwLock<SessionState>> {
        let mut sessions = self.sessions.write();
        sessions
            .entry(peer_pubkey.to_string())
            .or_insert_with(|| Arc::new(RwLock::new(SessionState::new(peer_pubkey.to_string()))))
            .clone()
    }

    /// 获取会话（不创建）
    pub fn get(&self, peer_pubkey: &str) -> Option<Arc<RwLock<SessionState>>> {
        self.sessions.read().get(peer_pubkey).cloned()
    }

    /// 移除会话
    pub fn remove(&self, peer_pubkey: &str) {
        self.sessions.write().remove(peer_pubkey);
    }
}
