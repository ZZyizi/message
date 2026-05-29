# 一对一聊天端到端加密 (E2EE) 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为一对一聊天实现端到端加密，保护消息在传输和存储过程中不被窃听。

**Architecture:** 基于 X25519 ECDH 密钥协商 + AES-256-GCM 对称加密，每次会话使用临时密钥对提供前向保密。复用已有的 `derive_session_key`、`encrypt_message`、`decrypt_message` 函数。

**Tech Stack:** Rust (tokio, x25519-dalek, ed25519-dalek, aes-gcm), Svelte 5, Tauri v2

**Spec:** `docs/superpowers/specs/2026-05-29-e2ee-1to1-design.md`

---

## File Structure

| 文件 | 职责 |
|---|---|
| `src-tauri/src/session.rs` | 新建：会话状态机、SessionState 结构体、密钥协商逻辑 |
| `src-tauri/src/crypto.rs` | 重命名 `generate_device_keypair` → `generate_x25519_keypair` |
| `src-tauri/src/relay.rs` | 新增 `KeyExchange`/`KeyConfirm` 消息变体和处理逻辑 |
| `src-tauri/src/message.rs` | 发送路径接入加密，接收路径接入解密 |
| `src-tauri/src/lib.rs` | AppState 新增 `sessions` 字段，注册新 Tauri 命令 |
| `src-tauri/Cargo.toml` | 新增 `zeroize` 依赖 |
| `src/routes/+page.svelte` | 打开聊天时触发协商，SessionKey 就绪前禁用输入 |

> **注意：** `message.rs` 中的 `send_message` 命令不在此计划中修改。当前 UI 使用 `relay.rs::send_chat_message` 作为主要发送路径。`message.rs::send_message` 保留为离线消息发送的备选路径，后续可单独接入加密。

---

### Task 1: 添加 zeroize 依赖并重命名函数

**Files:**
- Modify: `src-tauri/Cargo.toml`
- Modify: `src-tauri/src/crypto.rs`

- [ ] **Step 1: 添加 zeroize 依赖**

在 `Cargo.toml` 的 `[dependencies]` 中添加：

```toml
zeroize = "1"
```

- [ ] **Step 2: 重命名 generate_device_keypair**

在 `crypto.rs` 中将函数名改为 `generate_x25519_keypair`，同时更新所有调用方。

```rust
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.as_bytes().to_vec())
}
```

更新 `cmd_generate_device_keypair` 为 `cmd_generate_x25519_keypair`：

```rust
#[tauri::command]
pub fn cmd_generate_x25519_keypair() -> Result<(String, String), Error> {
    let (pubkey, privkey) = generate_x25519_keypair();
    Ok((
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pubkey),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &privkey),
    ))
}
```

- [ ] **Step 3: 更新 lib.rs 中的命令注册**

将 `crypto::cmd_generate_device_keypair` 改为 `crypto::cmd_generate_x25519_keypair`。

- [ ] **Step 4: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过，无错误

- [ ] **Step 5: 提交**

```bash
git add src-tauri/Cargo.toml src-tauri/src/crypto.rs src-tauri/src/lib.rs
git commit -m "chore: add zeroize dep and rename generate_device_keypair to generate_x25519_keypair"
```

---

### Task 2: 创建 session.rs 模块 — 会话状态机

**Files:**
- Create: `src-tauri/src/session.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: 创建 session.rs 基础结构**

```rust
//! 会话状态管理模块
//!
//! 管理一对一聊天的 E2EE 会话状态，包括密钥协商、会话密钥存储和明文消息队列。

use std::collections::HashMap;
use std::sync::Arc;
use parking_lot::RwLock;
use tracing::{info, warn};
use zeroize::Zeroize;

use crate::crypto;

/// HKDF info 参数，双方必须一致
const E2EE_INFO: &[u8] = b"decentralized-im-e2ee-1to1";

/// 会话超时时间（秒）
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
    pub fn enqueue_plaintext(&mut self, msg: PendingPlaintext) -> Result<(), String> {
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
```

- [ ] **Step 2: 在 lib.rs 中声明模块并添加到 AppState**

在 `lib.rs` 顶部添加 `mod session;`。

在 `AppState` 中添加 `sessions` 字段：

```rust
pub struct AppState {
    pub db: Arc<Mutex<db::Database>>,
    pub identity_db: Arc<Mutex<db::Database>>,
    pub identity: Arc<RwLock<identity::IdentityManager>>,
    pub sessions: session::SessionManager,
    pub app_handle: tauri::AppHandle,
}
```

在 `setup` 闭包中初始化：

```rust
let state = AppState {
    db: Arc::new(Mutex::new(db)),
    identity_db: Arc::new(Mutex::new(identity_db)),
    identity: Arc::new(RwLock::new(identity)),
    sessions: session::SessionManager::new(),
    app_handle: app.handle().clone(),
};
```

- [ ] **Step 3: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 4: 提交**

```bash
git add src-tauri/src/session.rs src-tauri/src/lib.rs
git commit -m "feat(e2ee): add session module with state machine and key management"
```

---

### Task 3: 扩展 WsMessage 协议 — 添加 KeyExchange/KeyConfirm

**Files:**
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 在 WsMessage 枚举中添加新变体，并修改 ChatMessage**

在 `relay.rs` 的 `WsMessage` 枚举中：

1. 给现有的 `ChatMessage` 添加 `seq_id: i64` 字段：

```rust
ChatMessage {
    event_id: String,
    from: String,
    to: String,
    payload: String,
    media_id: Option<String>,
    timestamp: i64,
    signature: String,
    seq_id: i64,  // 新增：用于接收方验证签名
},
```

2. 添加新的变体：

```rust
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
},
```

- [ ] **Step 2: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 3: 提交**

```bash
git add src-tauri/src/relay.rs
git commit -m "feat(e2ee): add KeyExchange and KeyConfirm message types to WsMessage"
```

---

### Task 4: 实现密钥协商 Tauri 命令

**Files:**
- Modify: `src-tauri/src/relay.rs`
- Modify: `src-tauri/src/lib.rs`

- [ ] **Step 1: 实现 initiate_key_exchange 命令**

在 `relay.rs` 中添加：

```rust
/// 发起密钥协商
///
/// 生成临时密钥对，签名后通过 Relay 发送给对方
#[tauri::command]
pub async fn initiate_key_exchange(
    peer_pubkey: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    if *CLIENT_STATE.read() != ConnectionState::Connected {
        return Err(Error::Relay("Not connected to relay".to_string()));
    }

    let identity = state.identity.read();
    let from_pubkey = identity.get_public_key()
        .ok_or_else(|| Error::Identity("No identity found".to_string()))?
        .to_string();

    // 获取或创建会话
    let session = state.sessions.get_or_create(&peer_pubkey);

    // 检查当前会话状态
    {
        let s = session.read();
        if s.status == crate::session::SessionStatus::Active {
            // 已建立会话，需要 Rekeying
            info!("Session already active, initiating rekeying");
        } else if s.status == crate::session::SessionStatus::WaitingForPeer
            || s.status == crate::session::SessionStatus::WaitingForConfirm
        {
            // 正在协商中，拒绝重复发起
            return Err(Error::Relay("Key exchange already in progress".to_string()));
        }
    }

    // 生成临时密钥对
    let (ephemeral_pub, ephemeral_priv) = crypto::generate_x25519_keypair();
    let ephemeral_pub_b64 = base64::engine::general_purpose::STANDARD.encode(&ephemeral_pub);

    // 生成随机 nonce
    let mut nonce_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce_bytes);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(&nonce_bytes);

    let timestamp = chrono::Utc::now().timestamp();

    // 签名复合值: ephemeral_pubkey || from || nonce || timestamp
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(&ephemeral_pub);
    signed_data.extend_from_slice(from_pubkey.as_bytes());
    signed_data.extend_from_slice(&nonce_bytes);
    signed_data.extend_from_slice(&timestamp.to_le_bytes());

    let privkey = identity.decrypt_private_key(&[0u8; 32])?;
    let signature = crypto::sign_data(&signed_data, &privkey)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(&signature);

    // 更新会话状态
    {
        let mut s = session.write();
        s.my_ephemeral_privkey = ephemeral_priv;
        s.status = crate::session::SessionStatus::WaitingForPeer;
    }

    // 发送 KeyExchange
    let key_exchange = WsMessage::KeyExchange {
        from: from_pubkey,
        to: peer_pubkey,
        ephemeral_pubkey: ephemeral_pub_b64,
        signature: signature_b64,
        nonce: nonce_b64,
        timestamp,
    };

    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
        let _ = tx.try_send(key_exchange);
    } else {
        return Err(Error::Relay("No outbound channel".to_string()));
    }

    info!("KeyExchange sent to peer");
    Ok(())
}
```

- [ ] **Step 2: 实现 get_session_status 命令**

```rust
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
```

- [ ] **Step 3: 在 lib.rs 中注册新命令**

在 `invoke_handler` 中添加：

```rust
relay::initiate_key_exchange,
relay::get_session_status,
```

- [ ] **Step 4: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 5: 提交**

```bash
git add src-tauri/src/relay.rs src-tauri/src/lib.rs
git commit -m "feat(e2ee): add initiate_key_exchange and get_session_status Tauri commands"
```

---

### Task 5: 实现 KeyExchange/KeyConfirm 消息处理

**Files:**
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 在 run_websocket_client 中处理 KeyExchange**

在 `relay.rs` 的 `run_websocket_client` 函数的消息接收循环中，在 `WsMessage::ChatMessage` 处理之后添加 KeyExchange 处理：

```rust
// 处理密钥交换消息
if let WsMessage::KeyExchange { from, to, ephemeral_pubkey, signature, nonce, timestamp } = &ws_msg {
    let app_state = app_handle.state::<crate::AppState>();
    let my_pubkey = {
        let identity = app_state.identity.read();
        identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
    };

    // 只处理发给我的消息
    if *to != my_pubkey {
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
    // 必须在 handle_key_exchange 之前，因为 handle_key_exchange 会改变状态
    {
        let mut s = session.write();
        if s.status == crate::session::SessionStatus::None {
            // 我方尚未发送 KeyExchange，需要先生成密钥并发送
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
                identity.decrypt_private_key(&[0u8; 32])
                    .map_err(|e| Error::Identity(e.to_string()))?
            };
            let my_signature = crypto::sign_data(&signed_data, &my_privkey)
                .map_err(|e| Error::Crypto(e.to_string()))?;
            let my_signature_b64 = base64::engine::general_purpose::STANDARD.encode(&my_signature);

            s.my_ephemeral_privkey = my_ephemeral_priv;
            s.status = crate::session::SessionStatus::WaitingForPeer;

            drop(s);

            // 发送 KeyExchange 回复
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

    // 处理对方的密钥交换（此时我方密钥已就绪）
    {
        let mut s = session.write();
        if let Err(e) = s.handle_key_exchange(ephemeral_pub_bytes) {
            warn!("Failed to handle key exchange: {}", e);
            continue;
        }
    }

    // 发送 KeyConfirm
    {
        let s = session.read();
        if let Some(key) = s.session_key {
            drop(s);
            let confirm_plaintext = b"confirm";
            let encrypted = crypto::encrypt_message(confirm_plaintext, &key, None)
                .map_err(|e| Error::Crypto(e.to_string()));
            match encrypted {
                Ok(enc) => {
                    let enc_b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
                    let confirm = WsMessage::KeyConfirm {
                        from: my_pubkey,
                        to: from.clone(),
                        encrypted_confirm: enc_b64,
                    };
                    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                        let _ = tx.try_send(confirm);
                    }

                    // 更新状态为 Active
                    let mut s = session.write();
                    s.status = crate::session::SessionStatus::Active;
                    info!("Session activated with peer: {}", from);

                    // 刷新待发明文消息队列
                    let pending = s.flush_pending_plaintext();
                    drop(s);
                    for p in pending {
                        // 加密并发送每条待发消息
                        let s = session.read();
                        if let Ok(enc) = s.encrypt(p.payload.as_bytes()) {
                            let enc_b64 = base64::engine::general_purpose::STANDARD.encode(&enc);
                            drop(s);

                            // 签名
                            let signature_data = format!("{}{}{}{}", p.event_id, my_pubkey, enc_b64, p.seq_id);
                            let identity = app_state.identity.read();
                            if let Ok(privkey) = identity.decrypt_private_key(&[0u8; 32]) {
                                drop(identity);
                                if let Ok(sig) = crypto::sign_data(signature_data.as_bytes(), &privkey) {
                                    let sig_b64 = base64::engine::general_purpose::STANDARD.encode(&sig);

                                    // 发送
                                    let ws_msg = WsMessage::ChatMessage {
                                        event_id: p.event_id.clone(),
                                        from: my_pubkey.clone(),
                                        to: p.to_recipient.clone(),
                                        payload: enc_b64.clone(),
                                        media_id: None,
                                        timestamp: p.created_at,
                                        signature: sig_b64,
                                        seq_id: p.seq_id,
                                    };
                                    if let Some(tx) = OUTBOUND_TX.read().as_ref() {
                                        let _ = tx.try_send(ws_msg);
                                    }

                                    // 更新数据库：将明文替换为密文并更新签名
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
```

- [ ] **Step 2: 处理 KeyConfirm 消息**

```rust
// 处理密钥确认消息
if let WsMessage::KeyConfirm { from, to, encrypted_confirm } = &ws_msg {
    let app_state = app_handle.state::<crate::AppState>();
    let my_pubkey = {
        let identity = app_state.identity.read();
        identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
    };

    // 只处理发给我的消息
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
                                    signature: sig_b64,
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
```

- [ ] **Step 3: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 4: 提交**

```bash
git add src-tauri/src/relay.rs
git commit -m "feat(e2ee): implement KeyExchange and KeyConfirm message handling"
```

---

### Task 5.5: 实现会话超时机制

**Files:**
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 在 initiate_key_exchange 中添加超时定时器**

在 `initiate_key_exchange` 函数的末尾，发送 KeyExchange 后，启动超时定时器：

```rust
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
```

- [ ] **Step 2: 在 KeyConfirm 处理中添加超时定时器**

在 Task 5 的 KeyConfirm 处理代码中，发送 KeyConfirm 后启动超时定时器：

```rust
// 启动 KeyConfirm 超时定时器（30秒）
let app_handle_clone = app_handle.clone();
let peer_clone = from.clone();
let session_clone = session.clone();

tokio::spawn(async move {
    tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
    let mut s = session_clone.write();
    if s.status == crate::session::SessionStatus::WaitingForConfirm {
        warn!("KeyConfirm timeout for peer: {}", peer_clone);
        s.status = crate::session::SessionStatus::None;
        let _ = app_handle_clone.emit("session_timeout", &peer_clone);
    }
});
```

- [ ] **Step 3: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 4: 提交**

```bash
git add src-tauri/src/relay.rs
git commit -m "feat(e2ee): add session timeout mechanism for key exchange"
```

---

### Task 5.6: 添加数据库更新方法和修改 send_chat_message

**Files:**
- Modify: `src-tauri/src/db.rs`
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 在 db.rs 中添加 update_message_payload_and_signature 方法**

在 `Database` 实现中添加：

```rust
/// 更新消息的 payload 和 signature（用于将明文替换为密文并更新签名）
pub fn update_message_payload_and_signature(
    &self,
    event_id: &str,
    new_payload: &str,
    new_signature: &str,
) -> Result<(), Error> {
    self.conn.execute(
        "UPDATE messages SET payload = ?1, signature = ?2 WHERE event_id = ?3",
        rusqlite::params![new_payload, new_signature, event_id],
    )?;
    Ok(())
}
```

- [ ] **Step 2: 修改 send_chat_message 中的 WsMessage 构造**

在 `relay.rs` 的 `send_chat_message` 中，给 `WsMessage::ChatMessage` 添加 `seq_id` 字段：

```rust
let ws_msg = WsMessage::ChatMessage {
    event_id: event_id.clone(),
    from: from_pubkey.to_string(),
    to: to.clone(),
    payload: encrypted_payload.clone(),
    media_id: media_id.clone(),
    timestamp,
    signature: signature_b64.clone(),
    seq_id,  // 新增
};
```

- [ ] **Step 3: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 4: 提交**

```bash
git add src-tauri/src/db.rs src-tauri/src/relay.rs
git commit -m "feat(e2ee): add update_message_payload and include seq_id in ChatMessage"
```

---

### Task 6: 修改消息发送路径 — 接入加密

**Files:**
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 修改 send_chat_message 函数**

在 `relay.rs` 的 `send_chat_message` 函数中，在签名之前添加加密步骤：

```rust
// 检查会话状态（如果不存在则创建）
let session = state.sessions.get_or_create(&to);
let (encrypted_payload, should_send_now) = {
    let s = session.read();
    if s.status == crate::session::SessionStatus::Active {
        // 会话已建立，加密消息
        match s.encrypt(payload.as_bytes()) {
            Ok(enc) => (base64::engine::general_purpose::STANDARD.encode(&enc), true),
            Err(e) => {
                warn!("Encryption failed: {}", e);
                return Err(Error::Crypto(e));
            }
        }
    } else {
        // 会话未建立，加入明文队列
        warn!("Session not active, queueing message");
        (payload.clone(), false)
    }
};

// 如果未就绪，加入明文队列
if !should_send_now {
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
        // 消息已加入队列，不立即发送
        // 存入数据库（标记为未发送）
        let db_msg = DbMessage {
            // ...
            payload: payload.clone(),  // 存明文以便后续加密
            // ...
        };
        // ... 插入数据库
        return Ok(event_id);
    }
}

// 使用加密后的 payload 进行签名
let signature_data = format!("{}{}{}{}", event_id, from_pubkey, encrypted_payload, seq_id);
```

同时将 `WsMessage::ChatMessage` 中的 `payload` 改为 `encrypted_payload`：

```rust
let ws_msg = WsMessage::ChatMessage {
    event_id: event_id.clone(),
    from: from_pubkey.to_string(),
    to: to.clone(),
    payload: encrypted_payload.clone(),
    media_id: media_id.clone(),
    timestamp,
    signature: signature_b64.clone(),
};
```

数据库中也存储加密后的 payload：

```rust
let db_msg = DbMessage {
    // ...
    payload: encrypted_payload.clone(),
    // ...
};
```

- [ ] **Step 2: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 3: 提交**

```bash
git add src-tauri/src/relay.rs
git commit -m "feat(e2ee): encrypt outgoing messages when session is active"
```

---

### Task 7: 修改消息接收路径 — 接入解密

**Files:**
- Modify: `src-tauri/src/relay.rs`

- [ ] **Step 1: 修改 ChatMessage 接收处理**

在 `run_websocket_client` 中处理 `ChatMessage` 时，接收后尝试解密：

```rust
if let WsMessage::ChatMessage { event_id, from, to, payload, media_id, timestamp, signature, seq_id } = &ws_msg {
    let app_state = app_handle.state::<crate::AppState>();
    let my_pubkey = {
        let identity = app_state.identity.read();
        identity.get_public_key().map(|s| s.to_string()).unwrap_or_default()
    };

    // 忽略回显
    if from == &my_pubkey && *to != my_pubkey {
        continue;
    }

    // 验证签名（使用消息中携带的 seq_id）
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

    // 尝试解密
    let (decrypted_for_display, stored_payload) = if let Some(session) = app_state.sessions.get(from) {
        let s = session.read();
        if s.status == crate::session::SessionStatus::Active {
            if let Ok(cipher_bytes) = base64::engine::general_purpose::STANDARD.decode(payload) {
                match s.decrypt(&cipher_bytes) {
                    Ok(plaintext) => {
                        let display = String::from_utf8_lossy(&plaintext).to_string();
                        (display, payload.clone())  // 数据库存密文
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
        payload: stored_payload,  // 数据库存储密文
        media_id: media_id.clone(),
        timestamp: *timestamp,
        seq_id,
        signature: signature.clone(),
        delivered: true,
        recalled: false,
    };

    if let Err(e) = db.insert_message(&msg) {
        error!("Failed to store message: {}", e);
    }

    // 通知前端时使用解密后的明文
    let mut display_msg = msg.clone();
    display_msg.payload = decrypted_for_display;
    let _ = app_handle.emit("new_message", &display_msg);
}
```

- [ ] **Step 2: 编译验证**

Run: `cd src-tauri && cargo check`
Expected: 编译通过

- [ ] **Step 3: 提交**

```bash
git add src-tauri/src/relay.rs
git commit -m "feat(e2ee): decrypt incoming messages when session is active"
```

---

### Task 8: 前端集成 — 密钥协商触发和 UI 状态

**Files:**
- Modify: `src/routes/+page.svelte`

- [ ] **Step 1: 添加会话状态变量**

在 `<script>` 中添加：

```javascript
let sessionStatus = $state('None');
```

- [ ] **Step 2: 修改 selectContact 函数**

```javascript
async function selectContact(contact) {
  currentContact = contact;
  sessionStatus = 'None';
  await loadChat(contact.pubkey);

  // 发起密钥协商
  try {
    await invoke('initiate_key_exchange', { peerPubkey: contact.pubkey });
    // 轮询会话状态
    const pollInterval = setInterval(async () => {
      try {
        const status = await invoke('get_session_status', { peerPubkey: contact.pubkey });
        sessionStatus = status;
        if (status === 'Active') {
          clearInterval(pollInterval);
        }
      } catch (e) {
        console.error('Failed to get session status:', e);
      }
    }, 1000);

    // 30秒超时
    setTimeout(() => {
      clearInterval(pollInterval);
      if (sessionStatus !== 'Active') {
        sessionStatus = 'Timeout';
      }
    }, 30000);
  } catch (e) {
    console.error('Failed to initiate key exchange:', e);
  }
}
```

- [ ] **Step 3: 修改 sendMessage 函数**

```javascript
async function sendMessage() {
  if (!inputMessage.trim() || !currentContact) return;

  // 检查会话状态
  if (sessionStatus !== 'Active') {
    showToast('安全通道尚未建立，请稍候...');
    return;
  }

  try {
    const result = await invoke('send_chat_message', {
      to: currentContact.pubkey,
      payload: inputMessage,
      mediaId: null,
    });

    // ... 其余代码不变
  } catch (e) {
    // ...
  }
}
```

- [ ] **Step 4: 修改聊天输入区域 UI**

在 `chat-input-area` 部分，根据 `sessionStatus` 禁用输入：

```svelte
<div class="chat-input-area">
  {#if sessionStatus !== 'Active'}
    <div class="session-status-bar">
      {#if sessionStatus === 'None' || sessionStatus === 'WaitingForPeer'}
        正在建立安全通道...
      {:else if sessionStatus === 'Timeout'}
        密钥协商失败
        <button onclick={() => selectContact(currentContact)}>重试</button>
      {:else}
        正在确认密钥...
      {/if}
    </div>
  {/if}

  <textarea
    bind:value={inputMessage}
    onkeydown={handleKeydown}
    placeholder={sessionStatus === 'Active' ? 'Type a message...' : 'Waiting for secure channel...'}
    class="chat-input"
    rows="1"
    disabled={sessionStatus !== 'Active'}
  ></textarea>
  <button class="btn-send" onclick={sendMessage} disabled={!inputMessage.trim() || sessionStatus !== 'Active'}>
    Send
  </button>
</div>
```

- [ ] **Step 5: 添加会话状态栏样式**

在 `<style>` 中添加：

```css
.session-status-bar {
  padding: 0.5rem 1rem;
  background: #1c2128;
  border-bottom: 1px solid #30363d;
  font-size: 0.85rem;
  color: #d29922;
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.session-status-bar button {
  padding: 0.2rem 0.5rem;
  border: 1px solid #30363d;
  border-radius: 4px;
  background: #21262d;
  color: #e6edf3;
  cursor: pointer;
  font-size: 0.8rem;
}
```

- [ ] **Step 6: 编译验证**

Run: `npm run build`
Expected: 编译通过

- [ ] **Step 7: 提交**

```bash
git add src/routes/+page.svelte
git commit -m "feat(e2ee): add key exchange UI flow and session status display"
```

---

### Task 8.5: 监听会话超时事件

**Files:**
- Modify: `src/routes/+page.svelte`

- [ ] **Step 1: 添加超时事件监听**

在 `onMount` 中添加对 `session_timeout` 事件的监听：

```javascript
// 订阅会话超时事件
const unlistenTimeout = await listen('session_timeout', (event) => {
  const peerPubkey = event.payload;
  if (currentContact && currentContact.pubkey === peerPubkey) {
    sessionStatus = 'Timeout';
    showToast('密钥协商超时，请重试');
  }
});

return () => {
  unlistenNewMsg();
  unlistenRecall();
  unlistenTimeout();
  clearInterval(refreshInterval);
};
```

- [ ] **Step 2: 提交**

```bash
git add src/routes/+page.svelte
git commit -m "feat(e2ee): listen for session timeout events"
```

---

### Task 9: 端到端测试

- [ ] **Step 1: 启动两个客户端实例**

使用两个不同的数据目录启动应用，模拟 Alice 和 Bob。

- [ ] **Step 2: 测试密钥协商**

1. Alice 和 Bob 分别连接 Relay
2. Alice 选择 Bob 作为聊天对象
3. 观察控制台日志，确认 KeyExchange 消息发送和接收
4. 确认双方状态变为 Active

- [ ] **Step 3: 测试加密消息发送**

1. Alice 发送消息 "Hello Bob"
2. 确认消息在 Relay 中为密文
3. Bob 收到消息并解密显示 "Hello Bob"

- [ ] **Step 4: 测试解密失败场景**

1. 手动篡改消息密文
2. 确认接收方显示 "[解密失败]"

- [ ] **Step 5: 测试会话超时**

1. 只有一方发起 KeyExchange
2. 等待 30 秒
3. 确认状态超时并提示用户

- [ ] **Step 6: 最终提交**

```bash
git add -A
git commit -m "feat(e2ee): complete 1:1 chat end-to-end encryption implementation"
```
