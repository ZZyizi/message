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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_session_status() {
        let s = SessionState::new("peer1".to_string());
        assert_eq!(s.status, SessionStatus::None);
        assert_eq!(s.peer_static_pubkey, "peer1");
        assert!(s.session_key.is_none());
        assert!(s.pending_plaintext.is_empty());
    }

    #[test]
    fn test_initiate_key_exchange() {
        let mut s = SessionState::new("peer1".to_string());
        let pubkey = s.initiate_key_exchange().unwrap();
        assert_eq!(s.status, SessionStatus::WaitingForPeer);
        // 临时公钥不应全为零
        assert_ne!(pubkey, [0u8; 32]);
        // 临时私钥也不应全为零
        assert_ne!(s.my_ephemeral_privkey, [0u8; 32]);
    }

    #[test]
    fn test_initiate_key_exchange_prevents_duplicate() {
        let mut s = SessionState::new("peer1".to_string());
        s.initiate_key_exchange().unwrap();
        // 重复发起应报错
        assert!(s.initiate_key_exchange().is_err());
    }

    #[test]
    fn test_handle_key_exchange_derives_session_key() {
        // 模拟 Alice 和 Bob 的密钥交换
        let (alice_pub, alice_priv) = crypto::generate_x25519_keypair();
        let (bob_pub, bob_priv) = crypto::generate_x25519_keypair();

        let mut alice_session = SessionState::new("bob".to_string());
        alice_session.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&alice_priv);
            arr
        };
        alice_session.status = SessionStatus::WaitingForPeer;

        let mut bob_session = SessionState::new("alice".to_string());
        bob_session.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bob_priv);
            arr
        };
        bob_session.status = SessionStatus::WaitingForPeer;

        // Alice 收到 Bob 的临时公钥
        let mut bob_pub_arr = [0u8; 32];
        bob_pub_arr.copy_from_slice(&bob_pub);
        alice_session.handle_key_exchange(bob_pub_arr).unwrap();
        assert_eq!(alice_session.status, SessionStatus::KeyExchanged);
        assert!(alice_session.session_key.is_some());

        // Bob 收到 Alice 的临时公钥
        let mut alice_pub_arr = [0u8; 32];
        alice_pub_arr.copy_from_slice(&alice_pub);
        bob_session.handle_key_exchange(alice_pub_arr).unwrap();
        assert_eq!(bob_session.status, SessionStatus::KeyExchanged);
        assert!(bob_session.session_key.is_some());

        // 双方派生的会话密钥应相同
        assert_eq!(alice_session.session_key, bob_session.session_key);
    }

    #[test]
    fn test_handle_key_exchange_without_ephemeral_key_fails() {
        let mut s = SessionState::new("peer1".to_string());
        // 没有先调用 initiate_key_exchange，临时私钥全为零
        let peer_pub = [1u8; 32];
        assert!(s.handle_key_exchange(peer_pub).is_err());
    }

    #[test]
    fn test_handle_key_exchange_triggers_rekeying() {
        let mut s = SessionState::new("peer1".to_string());
        s.initiate_key_exchange().unwrap();
        let peer_pub1 = [1u8; 32];
        s.handle_key_exchange(peer_pub1).unwrap();
        assert_eq!(s.status, SessionStatus::KeyExchanged);

        // 模拟已有 Active 会话，再次收到 KeyExchange 进入 Rekeying
        s.status = SessionStatus::Active;
        let peer_pub2 = [2u8; 32];
        s.handle_key_exchange(peer_pub2).unwrap();
        assert_eq!(s.status, SessionStatus::KeyExchanged);
    }

    #[test]
    fn test_confirm_session() {
        let mut s = SessionState::new("peer1".to_string());
        s.status = SessionStatus::WaitingForConfirm;
        s.confirm_session().unwrap();
        assert_eq!(s.status, SessionStatus::Active);
    }

    #[test]
    fn test_confirm_session_wrong_status_fails() {
        let mut s = SessionState::new("peer1".to_string());
        s.status = SessionStatus::None;
        assert!(s.confirm_session().is_err());
    }

    #[test]
    fn test_enqueue_and_flush_pending_plaintext() {
        let mut s = SessionState::new("peer1".to_string());
        s.initiate_key_exchange().unwrap();

        let msg = PendingPlaintext {
            event_id: "evt1".to_string(),
            to_recipient: "peer1".to_string(),
            payload: "hello".to_string(),
            seq_id: 1,
            created_at: 1000,
        };
        s.enqueue_plaintext(msg).unwrap();
        assert_eq!(s.pending_plaintext.len(), 1);

        let flushed = s.flush_pending_plaintext();
        assert_eq!(flushed.len(), 1);
        assert_eq!(flushed[0].event_id, "evt1");
        assert!(s.pending_plaintext.is_empty());
    }

    #[test]
    fn test_enqueue_rejects_wrong_status() {
        let mut s = SessionState::new("peer1".to_string());
        s.status = SessionStatus::Active;
        let msg = PendingPlaintext {
            event_id: "evt1".to_string(),
            to_recipient: "peer1".to_string(),
            payload: "hello".to_string(),
            seq_id: 1,
            created_at: 1000,
        };
        assert!(s.enqueue_plaintext(msg).is_err());
    }

    #[test]
    fn test_enqueue_rejects_full_queue() {
        let mut s = SessionState::new("peer1".to_string());
        s.initiate_key_exchange().unwrap();
        for i in 0..MAX_PENDING_PLAINTEXT {
            let msg = PendingPlaintext {
                event_id: format!("evt{}", i),
                to_recipient: "peer1".to_string(),
                payload: "hello".to_string(),
                seq_id: i as i64,
                created_at: 1000,
            };
            s.enqueue_plaintext(msg).unwrap();
        }
        let extra = PendingPlaintext {
            event_id: "overflow".to_string(),
            to_recipient: "peer1".to_string(),
            payload: "hello".to_string(),
            seq_id: 999,
            created_at: 1000,
        };
        assert!(s.enqueue_plaintext(extra).is_err());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let (alice_pub, alice_priv) = crypto::generate_x25519_keypair();
        let (bob_pub, _bob_priv) = crypto::generate_x25519_keypair();

        let mut alice = SessionState::new("bob".to_string());
        alice.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&alice_priv);
            arr
        };
        alice.status = SessionStatus::WaitingForPeer;

        let mut bob = SessionState::new("alice".to_string());
        bob.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&_bob_priv);
            arr
        };
        bob.status = SessionStatus::WaitingForPeer;

        // 完成密钥交换
        let mut bob_pub_arr = [0u8; 32];
        bob_pub_arr.copy_from_slice(&bob_pub);
        alice.handle_key_exchange(bob_pub_arr).unwrap();

        let mut alice_pub_arr = [0u8; 32];
        alice_pub_arr.copy_from_slice(&alice_pub);
        bob.handle_key_exchange(alice_pub_arr).unwrap();

        // Alice 加密消息
        let plaintext = b"Hello Bob!";
        let ciphertext = alice.encrypt(plaintext).unwrap();
        assert_ne!(ciphertext, plaintext);

        // Bob 解密消息
        let decrypted = bob.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let (_, alice_priv) = crypto::generate_x25519_keypair();
        let (_, bob_priv) = crypto::generate_x25519_keypair();

        let mut alice = SessionState::new("bob".to_string());
        alice.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&alice_priv);
            arr
        };
        alice.status = SessionStatus::WaitingForPeer;

        let mut bob_wrong = SessionState::new("alice".to_string());
        bob_wrong.my_ephemeral_privkey = {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bob_priv);
            arr
        };
        bob_wrong.status = SessionStatus::WaitingForPeer;

        // Alice 用自己的密钥加密
        let fake_peer_pub = [99u8; 32];
        alice.handle_key_exchange(fake_peer_pub).unwrap();
        let ciphertext = alice.encrypt(b"secret").unwrap();

        // Bob 用不同的密钥解密应失败
        let different_peer_pub = [88u8; 32];
        bob_wrong.handle_key_exchange(different_peer_pub).unwrap();
        assert!(bob_wrong.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_encrypt_without_key_fails() {
        let s = SessionState::new("peer1".to_string());
        assert!(s.encrypt(b"hello").is_err());
    }

    #[test]
    fn test_session_manager_get_or_create() {
        let mgr = SessionManager::new();
        let s1 = mgr.get_or_create("peer1");
        let s2 = mgr.get_or_create("peer1");
        // 同一 peer 应返回同一个 Arc
        assert!(std::sync::Arc::ptr_eq(&s1, &s2));

        let s3 = mgr.get_or_create("peer2");
        // 不同 peer 应返回不同的 Arc
        assert!(!std::sync::Arc::ptr_eq(&s1, &s3));
    }

    #[test]
    fn test_session_manager_get_none() {
        let mgr = SessionManager::new();
        assert!(mgr.get("nonexistent").is_none());
    }

    #[test]
    fn test_session_manager_remove() {
        let mgr = SessionManager::new();
        mgr.get_or_create("peer1");
        assert!(mgr.get("peer1").is_some());
        mgr.remove("peer1");
        assert!(mgr.get("peer1").is_none());
    }

    #[test]
    fn test_my_ephemeral_pubkey_derivation() {
        let mut s = SessionState::new("peer1".to_string());
        s.initiate_key_exchange().unwrap();
        let pubkey = s.my_ephemeral_pubkey();
        // 从私钥推导的公钥不应全为零
        assert_ne!(pubkey, [0u8; 32]);
    }

    /// 模拟两个不同用户的完整 E2EE 通信流程
    ///
    /// 测试场景：
    /// - Alice (pubkey: "alice") 和 Bob (pubkey: "bob") 是两个不同用户
    /// - Alice 发起密钥协商
    /// - Bob 收到 KeyExchange 后响应
    /// - 双方完成密钥协商，会话激活
    /// - Alice 加密发送消息，Bob 解密接收
    /// - Bob 加密回复，Alice 解密接收
    /// - Eve（窃听者）无法解密任何消息
    #[test]
    fn test_cross_user_e2ee_communication() {
        // ===== 模拟两个用户的 SessionManager =====
        let alice_sessions = SessionManager::new();
        let bob_sessions = SessionManager::new();

        // ===== Step 1: Alice 发起密钥协商 =====
        let alice_session = alice_sessions.get_or_create("bob");
        let alice_ephemeral_pub = {
            let mut s = alice_session.write();
            s.initiate_key_exchange().unwrap()
        };
        assert_eq!(alice_session.read().status, SessionStatus::WaitingForPeer);

        // ===== Step 2: Bob 收到 Alice 的 KeyExchange =====
        let bob_session = bob_sessions.get_or_create("alice");
        {
            let mut s = bob_session.write();
            // Bob 也发起自己的密钥协商（双向）
            let _bob_ephemeral_pub = s.initiate_key_exchange().unwrap();
        }
        // Bob 处理 Alice 的 KeyExchange -> 派生会话密钥
        {
            let mut s = bob_session.write();
            s.handle_key_exchange(alice_ephemeral_pub).unwrap();
        }
        assert_eq!(bob_session.read().status, SessionStatus::KeyExchanged);
        assert!(bob_session.read().session_key.is_some());

        // ===== Step 3: Alice 收到 Bob 的 KeyExchange =====
        let bob_ephemeral_pub = bob_session.read().my_ephemeral_pubkey();
        {
            let mut s = alice_session.write();
            s.handle_key_exchange(bob_ephemeral_pub).unwrap();
        }
        assert_eq!(alice_session.read().status, SessionStatus::KeyExchanged);

        // ===== Step 4: 模拟 KeyConfirm 交换后激活会话 =====
        // 在真实协议中：Bob 发送 KeyConfirm -> Alice 收到后 confirm_session()
        // Alice 发送 KeyConfirm -> Bob 收到后 confirm_session()
        // 这里模拟双方都收到 KeyConfirm 后的状态转换
        {
            let mut s = alice_session.write();
            s.status = SessionStatus::WaitingForConfirm;
            s.confirm_session().unwrap();
        }
        assert_eq!(alice_session.read().status, SessionStatus::Active);

        {
            let mut s = bob_session.write();
            s.status = SessionStatus::WaitingForConfirm;
            s.confirm_session().unwrap();
        }
        assert_eq!(bob_session.read().status, SessionStatus::Active);

        // ===== Step 5: 验证双方会话密钥相同 =====
        let alice_key = alice_session.read().session_key;
        let bob_key = bob_session.read().session_key;
        assert_eq!(alice_key, bob_key, "双方会话密钥必须一致");

        // ===== Step 6: Alice 加密消息 -> Bob 解密 =====
        let plaintext1 = b"Hello Bob, this is a secret message from Alice!";
        let ciphertext1 = {
            let s = alice_session.read();
            s.encrypt(plaintext1).unwrap()
        };
        // 密文不应等于明文
        assert_ne!(ciphertext1, plaintext1);

        let decrypted1 = {
            let s = bob_session.read();
            s.decrypt(&ciphertext1).unwrap()
        };
        assert_eq!(decrypted1, plaintext1, "Bob 应能解密 Alice 的消息");

        // ===== Step 7: Bob 加密回复 -> Alice 解密 =====
        let plaintext2 = b"Hi Alice, got your message. This is Bob's secret reply!";
        let ciphertext2 = {
            let s = bob_session.read();
            s.encrypt(plaintext2).unwrap()
        };
        assert_ne!(ciphertext2, plaintext2);

        let decrypted2 = {
            let s = alice_session.read();
            s.decrypt(&ciphertext2).unwrap()
        };
        assert_eq!(decrypted2, plaintext2, "Alice 应能解密 Bob 的回复");

        // ===== Step 8: 多条消息连续收发 =====
        for i in 0..10 {
            let msg = format!("Message {} from Alice", i);
            let ct = {
                let s = alice_session.read();
                s.encrypt(msg.as_bytes()).unwrap()
            };
            let pt = {
                let s = bob_session.read();
                s.decrypt(&ct).unwrap()
            };
            assert_eq!(String::from_utf8(pt).unwrap(), msg);
        }

        // ===== Step 9: Eve（窃听者）无法解密 =====
        let eve_session = SessionManager::new();
        let eve_peer = eve_session.get_or_create("alice");
        // Eve 没有参与密钥协商，没有会话密钥
        assert!(eve_peer.read().session_key.is_none());
        assert!(eve_peer.read().decrypt(&ciphertext1).is_err());
        assert!(eve_peer.read().decrypt(&ciphertext2).is_err());

        // 即使 Eve 生成了自己的密钥对，也无法解密
        {
            let mut s = eve_peer.write();
            let _ = s.initiate_key_exchange();
            // Eve 用自己的临时密钥派生了一个密钥（与 Alice/Bob 的不同）
            let fake_peer_pub = [42u8; 32];
            let _ = s.handle_key_exchange(fake_peer_pub);
        }
        // Eve 的会话密钥与 Alice/Bob 的不同，解密失败
        assert_ne!(
            eve_peer.read().session_key,
            alice_session.read().session_key
        );
        assert!(eve_peer.read().decrypt(&ciphertext1).is_err());

        // ===== Step 10: 明文队列测试 =====
        // 模拟密钥协商前发送的消息，密钥就绪后刷新并加密
        let alice_session2 = alice_sessions.get_or_create("charlie");
        {
            let mut s = alice_session2.write();
            s.initiate_key_exchange().unwrap();
            // 在 WaitingForPeer 状态下入队消息
            for i in 0..5 {
                let pending = PendingPlaintext {
                    event_id: format!("evt{}", i),
                    to_recipient: "charlie".to_string(),
                    payload: format!("Queued message {}", i),
                    seq_id: i,
                    created_at: 1000 + i,
                };
                s.enqueue_plaintext(pending).unwrap();
            }
            assert_eq!(s.pending_plaintext.len(), 5);
            // 刷新队列
            let flushed = s.flush_pending_plaintext();
            assert_eq!(flushed.len(), 5);
            assert_eq!(flushed[0].payload, "Queued message 0");
            assert_eq!(flushed[4].payload, "Queued message 4");
            assert!(s.pending_plaintext.is_empty());
        }
    }
}
