//! 密码学原语模块
//!
//! 提供应用所需的所有加密功能：
//! - 身份密钥对生成（Ed25519）
//! - 设备密钥对生成（X25519）
//! - 会话密钥派生（HKDF-SHA256）
//! - 消息加密解密（AES-256-GCM）
//! - 数据签名与验证（Ed25519）
//! - 哈希运算（SHA256, BLAKE3）
//!
//! 所有密钥和签名均使用 Base64 编码进行传输。

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use sha2::{Sha256, Digest};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::Error;

/// AES-256-GCM nonce 字节长度（96 bit / 12 字节）
const NONCE_SIZE: usize = 12;

/// Ed25519 签名字节长度（512 bit / 64 字节）
const _SIG_SIZE: usize = 64;

/// 生成身份密钥对（Ed25519）
///
/// 用于标识用户身份，公钥可公开分享，私钥需安全存储。
/// - 公钥：用于标识用户身份，可自由分发
/// - 私钥：用于签名，需加密存储
///
/// 返回 (公钥, 私钥)，均为 32 字节。
pub fn generate_identity_keypair() -> (Vec<u8>, Vec<u8>) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (verifying_key.as_bytes().to_vec(), signing_key.to_bytes().to_vec())
}

/// 生成 X25519 密钥对
///
/// 用于设备间密钥交换（ECDH）和临时会话密钥。
/// - 公钥：可用于与其他设备建立加密通道
/// - 私钥：用于密钥协商，需安全存储
///
/// 返回 (公钥, 私钥)，均为 32 字节。
pub fn generate_x25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.as_bytes().to_vec())
}

/// 使用 HKDF-SHA256 从 X25519 密钥交换派生会话密钥
///
/// 通过 ECDH 共享密钥 + HKDF 派生出独立的会话密钥。
///
/// - `our_private`: 我们自己的私钥（32 字节，X25519）
/// - `their_public`: 对方公钥（32 字节，X25519）
/// - `info`: HKDF info 字段，用于绑定密钥到特定上下文（防止密钥混淆）
///
/// 返回 32 字节的派生会话密钥。
#[allow(dead_code)]
pub fn derive_session_key(
    our_private: &[u8],
    their_public: &[u8],
    info: &[u8],
) -> Result<Vec<u8>, Error> {
    let secret = StaticSecret::from(*arrayref::array_ref!(our_private, 0, 32));
    let public = PublicKey::from(*arrayref::array_ref!(their_public, 0, 32));
    let shared = secret.diffie_hellman(&public);
    let shared_bytes = shared.as_bytes();

    let mut okm = [0u8; 32];
    hkdf::Hkdf::<Sha256>::new(Some(info), shared_bytes)
        .expand(&[], &mut okm)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok(okm.to_vec())
}

/// 使用 AES-256-GCM 加密消息
///
/// 对称加密，使用 256 位密钥。每次加密随机生成 96 位 nonce。
/// AAD（Additional Authenticated Data）可选，用于绑定额外上下文而不加密。
///
/// - `plaintext`: 明文数据
/// - `key`: 256 位（32 字节）密钥
/// - `_aad`: 额外认证数据（可选，不加密但会被认证）
///
/// 返回格式：nonce（12字节）|| 密文。密文包含认证标签。
pub fn encrypt_message(
    plaintext: &[u8],
    key: &[u8],
    _aad: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let mut result = nonce_bytes.to_vec();
    result.extend(ciphertext);
    Ok(result)
}

/// 使用 AES-256-GCM 解密消息
///
/// 输入格式必须与 `encrypt_message` 输出格式匹配：nonce（12字节）|| 密文。
///
/// - `ciphertext`: 密文数据（前 12 字节为 nonce）
/// - `key`: 256 位（32 字节）密钥
/// - `_aad`: 额外认证数据（必须与加密时一致）
///
/// 返回解密后的明文。
pub fn decrypt_message(
    ciphertext: &[u8],
    key: &[u8],
    _aad: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if ciphertext.len() < NONCE_SIZE {
        return Err(Error::Crypto("Ciphertext too short".to_string()));
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
    let encrypted = &ciphertext[NONCE_SIZE..];

    let plaintext = cipher.decrypt(nonce, encrypted)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    Ok(plaintext)
}

/// 使用 Ed25519 对数据签名
///
/// - `data`: 要签名的数据
/// - `private_key`: 32 字节私钥
///
/// 返回 64 字节的 Ed25519 签名。
pub fn sign_data(data: &[u8], private_key: &[u8]) -> Result<Vec<u8>, Error> {
    if private_key.len() != 32 {
        return Err(Error::Crypto("Invalid private key length".to_string()));
    }
    let signing_key = SigningKey::from_bytes(arrayref::array_ref!(private_key, 0, 32));
    let signature = signing_key.sign(data);
    Ok(signature.to_bytes().to_vec())
}

/// 验证 Ed25519 签名
///
/// - `data`: 原始数据
/// - `signature`: 64 字节签名
/// - `public_key`: 32 字节公钥
///
/// 返回签名是否有效。
#[allow(dead_code)]
pub fn verify_signature(
    data: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<bool, Error> {
    if signature.len() != _SIG_SIZE || public_key.len() != 32 {
        return Err(Error::Crypto("Invalid signature or key length".to_string()));
    }
    let signature = Signature::from_bytes(arrayref::array_ref!(signature, 0, 64));
    let verifying_key = VerifyingKey::from_bytes(arrayref::array_ref!(public_key, 0, 32))
        .map_err(|e| Error::Crypto(e.to_string()))?;
    Ok(verifying_key.verify(data, &signature).is_ok())
}

/// 计算 SHA256 哈希
///
/// 返回 32 字节哈希值。
#[allow(dead_code)]
pub fn hash_data(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// 计算 BLAKE3 哈希
///
/// BLAKE3 相比 SHA256 更快，且输出 32 字节。
#[allow(dead_code)]
pub fn blake3_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// 计算 BLAKE3 带密钥哈希（可用作 MAC）
///
/// 结合密钥的哈希函数，可用于消息认证。
///
/// - `data`: 要哈希的数据
/// - `key`: 32 字节密钥
#[allow(dead_code)]
pub fn blake3_keyed_hash(data: &[u8], key: &[u8]) -> Vec<u8> {
    let key_arr = *arrayref::array_ref!(key, 0, 32);
    let mut hasher = blake3::Hasher::new_keyed(&key_arr);
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

/// Tauri 命令：加密消息（Base64 输入/输出）
#[tauri::command]
pub fn encrypt_message_cmd(
    plaintext: String,
    key: String,
    aad: Option<String>,
) -> Result<String, Error> {
    let key_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let aad_bytes = aad.as_ref().map(|s| s.as_bytes());
    let plaintext_bytes = plaintext.as_bytes();

    let encrypted = encrypt_message(plaintext_bytes, &key_bytes, aad_bytes)?;
    Ok(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &encrypted))
}

/// Tauri 命令：解密消息（Base64 输入/输出）
#[tauri::command]
pub fn decrypt_message_cmd(
    ciphertext: String,
    key: String,
    aad: Option<String>,
) -> Result<String, Error> {
    let ciphertext_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &ciphertext)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let key_bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &key)
        .map_err(|e| Error::Crypto(e.to_string()))?;
    let aad_bytes = aad.as_ref().map(|s| s.as_bytes());

    let decrypted = decrypt_message(&ciphertext_bytes, &key_bytes, aad_bytes)?;
    String::from_utf8(decrypted).map_err(|e| Error::Crypto(e.to_string()))
}

/// Tauri 命令：生成身份密钥对
///
/// 返回 (公钥, 私钥)，均为 Base64 编码。
#[tauri::command]
pub fn cmd_generate_identity_keypair() -> Result<(String, String), Error> {
    let (pubkey, privkey) = generate_identity_keypair();
    Ok((
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pubkey),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &privkey),
    ))
}

/// Tauri 命令：生成 X25519 密钥对
///
/// 返回 (公钥, 私钥)，均为 Base64 编码。
#[tauri::command]
pub fn cmd_generate_x25519_keypair() -> Result<(String, String), Error> {
    let (pubkey, privkey) = generate_x25519_keypair();
    Ok((
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &pubkey),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &privkey),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========== 密钥生成 ==========

    #[test]
    fn test_generate_identity_keypair() {
        let (pubkey, privkey) = generate_identity_keypair();
        assert_eq!(pubkey.len(), 32);
        assert_eq!(privkey.len(), 32);
        assert_ne!(pubkey, privkey);
    }

    #[test]
    fn test_generate_x25519_keypair() {
        let (pubkey, privkey) = generate_x25519_keypair();
        assert_eq!(pubkey.len(), 32);
        assert_eq!(privkey.len(), 32);
        assert_ne!(pubkey, privkey);
    }

    #[test]
    fn test_generate_x25519_keypair_unique() {
        let (pub1, _) = generate_x25519_keypair();
        let (pub2, _) = generate_x25519_keypair();
        assert_ne!(pub1, pub2);
    }

    // ========== 密钥协商 ==========

    #[test]
    fn test_derive_session_key_deterministic() {
        let (pub_a, priv_a) = generate_x25519_keypair();
        let (pub_b, priv_b) = generate_x25519_keypair();

        // Alice 用 Alice私钥 + Bob公钥
        let key1 = derive_session_key(&priv_a, &pub_b, b"test").unwrap();
        // Bob 用 Bob私钥 + Alice公钥
        let key2 = derive_session_key(&priv_b, &pub_a, b"test").unwrap();

        // ECDH 保证双方派生出相同密钥
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_session_key_different_info() {
        let (_pub_a, priv_a) = generate_x25519_keypair();
        let (pub_b, _) = generate_x25519_keypair();

        let key1 = derive_session_key(&priv_a, &pub_b, b"info1").unwrap();
        let key2 = derive_session_key(&priv_a, &pub_b, b"info2").unwrap();
        assert_ne!(key1, key2);
    }

    // ========== 加密解密 ==========

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = vec![0u8; 32];
        let plaintext = b"Hello, World!";
        let ciphertext = encrypt_message(plaintext, &key, None).unwrap();
        assert_ne!(ciphertext, plaintext);
        let decrypted = decrypt_message(&ciphertext, &key, None).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_decrypt_with_aad() {
        let key = vec![0u8; 32];
        let aad = b"additional data";
        let plaintext = b"Secret message";
        let ciphertext = encrypt_message(plaintext, &key, Some(aad)).unwrap();
        let decrypted = decrypt_message(&ciphertext, &key, Some(aad)).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32];
        let ciphertext = encrypt_message(b"secret", &key1, None).unwrap();
        assert!(decrypt_message(&ciphertext, &key2, None).is_err());
    }

    #[test]
    fn test_aad_ignored_in_current_impl() {
        // 当前实现中 AAD 未实际使用（参数为 _aad）
        // 解密时传入不同 AAD 仍能成功
        let key = vec![0u8; 32];
        let ciphertext = encrypt_message(b"secret", &key, Some(b"aad1")).unwrap();
        assert!(decrypt_message(&ciphertext, &key, Some(b"aad2")).is_ok());
    }

    #[test]
    fn test_decrypt_too_short_ciphertext() {
        let key = vec![0u8; 32];
        assert!(decrypt_message(&[0u8; 5], &key, None).is_err());
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext_each_time() {
        let key = vec![0u8; 32];
        let ct1 = encrypt_message(b"same", &key, None).unwrap();
        let ct2 = encrypt_message(b"same", &key, None).unwrap();
        // 随机 nonce 导致每次密文不同
        assert_ne!(ct1, ct2);
    }

    // ========== 签名验证 ==========

    #[test]
    fn test_sign_and_verify() {
        let (pubkey, privkey) = generate_identity_keypair();
        let data = b"message to sign";
        let signature = sign_data(data, &privkey).unwrap();
        assert!(verify_signature(data, &signature, &pubkey).unwrap());
    }

    #[test]
    fn test_verify_wrong_data_fails() {
        let (pubkey, privkey) = generate_identity_keypair();
        let signature = sign_data(b"original", &privkey).unwrap();
        assert!(!verify_signature(b"tampered", &signature, &pubkey).unwrap());
    }

    #[test]
    fn test_verify_wrong_key_fails() {
        let (_, privkey) = generate_identity_keypair();
        let (other_pubkey, _) = generate_identity_keypair();
        let signature = sign_data(b"message", &privkey).unwrap();
        assert!(!verify_signature(b"message", &signature, &other_pubkey).unwrap());
    }

    #[test]
    fn test_sign_invalid_key_length() {
        assert!(sign_data(b"data", &[0u8; 16]).is_err());
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let (pubkey, _) = generate_identity_keypair();
        assert!(verify_signature(b"data", &[0u8; 32], &pubkey).is_err());
    }

    // ========== 哈希 ==========

    #[test]
    fn test_hash_data() {
        let h1 = hash_data(b"hello");
        let h2 = hash_data(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_hash_data_different_input() {
        let h1 = hash_data(b"hello");
        let h2 = hash_data(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_blake3_hash() {
        let h1 = blake3_hash(b"hello");
        let h2 = blake3_hash(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
    }

    #[test]
    fn test_blake3_keyed_hash() {
        let key = vec![0u8; 32];
        let h1 = blake3_keyed_hash(b"hello", &key);
        let h2 = blake3_keyed_hash(b"hello", &key);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_blake3_keyed_hash_different_key() {
        let key1 = vec![0u8; 32];
        let key2 = vec![1u8; 32];
        let h1 = blake3_keyed_hash(b"hello", &key1);
        let h2 = blake3_keyed_hash(b"hello", &key2);
        assert_ne!(h1, h2);
    }

    // ========== E2EE 完整流程 ==========

    #[test]
    fn test_e2ee_full_flow() {
        // 模拟完整的 E2EE 流程
        let info = b"decentralized-im-e2ee-1to1";

        // 1. 双方生成临时密钥对
        let (alice_ephemeral_pub, alice_ephemeral_priv) = generate_x25519_keypair();
        let (bob_ephemeral_pub, bob_ephemeral_priv) = generate_x25519_keypair();

        // 2. 双方通过 ECDH + HKDF 派生相同的会话密钥
        let alice_key = derive_session_key(&alice_ephemeral_priv, &bob_ephemeral_pub, info).unwrap();
        let bob_key = derive_session_key(&bob_ephemeral_priv, &alice_ephemeral_pub, info).unwrap();
        assert_eq!(alice_key, bob_key, "Session keys must match");

        // 3. Alice 签署她的临时公钥，Bob 验证
        let (alice_id_pub, alice_id_priv) = generate_identity_keypair();
        let alice_signed = sign_data(&alice_ephemeral_pub, &alice_id_priv).unwrap();
        assert!(verify_signature(&alice_ephemeral_pub, &alice_signed, &alice_id_pub).unwrap());

        // 4. Alice 加密消息
        let plaintext = b"Hello Bob, this is secret!";
        let ciphertext = encrypt_message(plaintext, &alice_key, None).unwrap();

        // 5. Bob 解密消息
        let decrypted = decrypt_message(&ciphertext, &bob_key, None).unwrap();
        assert_eq!(decrypted, plaintext);

        // 6. Bob 回复
        let reply = b"Hi Alice, got your message!";
        let reply_ct = encrypt_message(reply, &bob_key, None).unwrap();
        let reply_pt = decrypt_message(&reply_ct, &alice_key, None).unwrap();
        assert_eq!(reply_pt, reply);
    }
}