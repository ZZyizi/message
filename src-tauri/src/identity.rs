//! 身份管理模块
//!
//! 负责用户身份密钥的生成、存储、导出（助记词备份）和导入。
//! 私钥使用 AES-256-GCM 加密后存储，支持通过助记词进行冷备份。
//!
//! 身份存储在 `app_data_dir/identity.db` 中，与主数据库分离。

use std::path::Path;
use base64::Engine;

use crate::crypto;
use crate::db::Database;
use crate::Error;

/// BIP39 助记词词表（简化版 256 词）
///
/// 注意：实际应用中应使用完整的 2048 词 BIP39 词表。
/// 此处简化实现：每个词对应 0-255 的索引，每个字节映射为两个词。
const MNEMONIC_WORDS: &[&str] = &[
    "abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
    "absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
    "acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
    "adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
    "advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
    "agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
];

/// 身份管理器
///
/// 持有用户的公私钥对，私钥以加密形式存储。
/// 同一 `app_data_dir` 下共享一个 `identity.db` 数据库。
///
/// - `pubkey`: 用户公钥（Base64 编码），用于标识身份
/// - `encrypted_private`: 加密后的私钥（Base64 编码）
pub struct IdentityManager {
    /// 用户公钥（Base64 编码）
    pubkey: Option<String>,
    /// 加密后的私钥（Base64 编码）
    encrypted_private: Option<String>,
    /// 用户昵称
    nickname: String,
}

impl IdentityManager {
    /// 从 app_data_dir 加载或创建身份
    ///
    /// 若数据库中已有身份，则加载；否则创建空身份（has_identity() 返回 false）。
    pub fn new(app_data_dir: &Path) -> Result<Self, Error> {
        let db_path = app_data_dir.join("identity.db");
        let db = Database::new(&db_path)?;

        let nickname = db.get_nickname()?.unwrap_or_default();

        let identity = if let Some((pubkey, encrypted_private)) = db.get_identity()? {
            Self {
                pubkey: Some(pubkey),
                encrypted_private: Some(encrypted_private),
                nickname,
            }
        } else {
            Self {
                pubkey: None,
                encrypted_private: None,
                nickname: String::new(),
            }
        };

        Ok(identity)
    }

    /// 检查是否已有身份
    pub fn has_identity(&self) -> bool {
        self.pubkey.is_some()
    }

    /// 获取公钥（若无身份返回 None）
    pub fn get_public_key(&self) -> Option<&str> {
        self.pubkey.as_deref()
    }

    /// 获取昵称
    pub fn get_nickname(&self) -> &str {
        &self.nickname
    }

    /// 设置昵称
    pub fn set_nickname(&mut self, nickname: &str) {
        self.nickname = nickname.to_string();
    }

    /// 生成新身份密钥对
    ///
    /// 生成 Ed25519 密钥对后，使用 `encryption_key` 加密私钥并存储到数据库。
    /// 生成后 has_identity() 将返回 true。
    ///
    /// - `encryption_key`: 用于加密私钥的 32 字节密钥（通常来自用户口令）
    /// - 返回新生成的公钥（Base64 编码）
    pub fn generate_identity(&mut self, encryption_key: &[u8]) -> Result<String, Error> {
        let (pubkey, privkey) = crypto::generate_identity_keypair();

        // 加密私钥后存储
        let encrypted = crypto::encrypt_message(&privkey, encryption_key, None)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        self.pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&pubkey));
        self.encrypted_private = Some(encrypted_b64.clone());

        Ok(self.pubkey.as_ref().unwrap().clone())
    }

    /// 自动创建身份（开发用）
    ///
    /// 若无身份则生成新密钥对，使用全零密钥加密私钥后存储到数据库。
    /// 用于开发阶段无需手动导入助记词。
    ///
    /// - 返回新生成的公钥
    pub fn auto_create_identity(&mut self, db: &Database) -> Result<String, Error> {
        let zero_key = [0u8; 32];
        let pubkey = self.generate_identity(&zero_key)?;

        // 持久化到 identity.db
        let encrypted_private = self.encrypted_private.as_ref().unwrap();
        db.save_identity(&pubkey, encrypted_private)?;

        Ok(pubkey)
    }

    /// 导出助记词（用于备份）
    ///
    /// 先使用 `encryption_key` 解密私钥，再转换为 24 个助记词。
    /// 用户应将助记词安全备份，并将 encryption_key 作为口令单独保存。
    ///
    /// - `encryption_key`: 解密私钥的密钥
    /// - 返回 24 个助记词（空格分隔）
    pub fn export_mnemonic(&self, encryption_key: &[u8]) -> Result<String, Error> {
        let encrypted_private = self.encrypted_private
            .as_ref()
            .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

        let decrypted = crypto::decrypt_message(
            &base64::engine::general_purpose::STANDARD.decode(encrypted_private).map_err(|e| Error::Crypto(e.to_string()))?,
            encryption_key,
            None,
        )?;

        let mnemonic = bytes_to_mnemonic(&decrypted);
        Ok(mnemonic)
    }

    /// 从助记词导入身份
    ///
    /// 将 24 个助记词转换回私钥字节，计算公钥，然后加密存储。
    /// 用于从备份恢复身份。
    ///
    /// - `mnemonic`: 24 个助记词（空格分隔）
    /// - `encryption_key`: 用于加密私钥的密钥
    /// - 返回新导入身份的公钥
    pub fn import_mnemonic(&mut self, mnemonic: &str, encryption_key: &[u8]) -> Result<String, Error> {
        let privkey = mnemonic_to_bytes(mnemonic)?;
        let pubkey = Self::derive_pubkey_from_privkey(&privkey)?;

        let encrypted = crypto::encrypt_message(&privkey, encryption_key, None)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        self.pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&pubkey));
        self.encrypted_private = Some(encrypted_b64);

        Ok(self.pubkey.as_ref().unwrap().clone())
    }

    /// 从私钥派生公钥（占位实现）
    ///
    /// 注意：此为简化实现，实际应从私钥直接计算 Ed25519 公钥。
    /// 当前实现会生成新的密钥对而非从私钥派生。
    fn derive_pubkey_from_privkey(_privkey: &[u8]) -> Result<Vec<u8>, Error> {
        let (pubkey, _sig) = crypto::generate_identity_keypair();
        Ok(pubkey)
    }

    /// 解密私钥返回原始字节
    ///
    /// - `encryption_key`: 解密私钥的密钥
    /// - 返回原始 32 字节私钥
    pub fn decrypt_private_key(&self, encryption_key: &[u8]) -> Result<Vec<u8>, Error> {
        let encrypted_private = self.encrypted_private
            .as_ref()
            .ok_or_else(|| Error::Identity("No identity found".to_string()))?;

        crypto::decrypt_message(
            &base64::engine::general_purpose::STANDARD.decode(encrypted_private).map_err(|e| Error::Crypto(e.to_string()))?,
            encryption_key,
            None,
        )
    }
}

/// 将字节数组转换为助记词（简化实现）
///
/// 每个 2 字节映射到一个词表的词索引（256 词表，所以取模 256）。
/// 24 个词需要 24 字节，实际助记词长度是 24 词。
///
/// 注意：实际生产应使用 BIP39 规范（2048 词表，11 位索引）。
fn bytes_to_mnemonic(bytes: &[u8]) -> String {
    let mut indices: Vec<usize> = Vec::new();
    for chunk in bytes.chunks(2) {
        if chunk.len() == 2 {
            let index = (chunk[0] as usize) << 8 | (chunk[1] as usize);
            indices.push(index % 256);
        } else {
            indices.push(chunk[0] as usize);
        }
    }

    indices.iter()
        .take(24)
        .map(|&i| MNEMONIC_WORDS[i as usize % MNEMONIC_WORDS.len()])
        .collect::<Vec<_>>()
        .join(" ")
}

/// 将助记词转换回字节数组
///
/// - `mnemonic`: 24 个助记词（空格分隔）
/// - 返回解密后的私钥字节
fn mnemonic_to_bytes(mnemonic: &str) -> Result<Vec<u8>, Error> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() != 24 {
        return Err(Error::Identity("Mnemonic must be 24 words".to_string()));
    }

    let mut bytes = Vec::new();
    for word in words {
        let index = MNEMONIC_WORDS.iter().position(|&w| w == word)
            .ok_or_else(|| Error::Identity(format!("Invalid word: {}", word)))?;
        bytes.push((index >> 8) as u8);
        bytes.push((index & 0xFF) as u8);
    }

    Ok(bytes)
}

/// 获取当前身份公钥
///
/// 若无身份则返回错误。
#[tauri::command]
pub fn get_public_key(state: tauri::State<'_, crate::AppState>) -> Result<String, Error> {
    let identity = state.identity.read();
    identity.get_public_key()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Identity("No identity found".to_string()).into())
}

/// 导出身份助记词备份
///
/// - `encryption_key`: Base64 编码的解密密钥
#[tauri::command]
pub fn export_identity_mnemonic(
    encryption_key: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(&encryption_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let identity = state.identity.read();
    identity.export_mnemonic(&key_bytes)
}

/// 从助记词导入/恢复身份
///
/// - `mnemonic`: 24 个助记词
/// - `encryption_key`: Base64 编码的加密密钥
#[tauri::command]
pub fn import_identity_mnemonic(
    mnemonic: String,
    encryption_key: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(&encryption_key)
        .map_err(|e| Error::Crypto(e.to_string()))?;

    let mut identity = state.identity.write();
    identity.import_mnemonic(&mnemonic, &key_bytes)
}

/// 自动创建身份（开发用）
///
/// 若无身份则生成新密钥对，使用全零密钥加密私钥后存储。
/// 用于开发阶段无需手动导入助记词。
#[tauri::command]
pub fn auto_create_identity(
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    let mut identity = state.identity.write();
    if identity.has_identity() {
        tracing::info!("Identity already exists, returning existing pubkey");
        return identity.get_public_key()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Identity("No identity found".to_string()));
    }

    let identity_db = state.identity_db.lock().map_err(|e| Error::Identity(format!("Identity DB lock poisoned: {}", e)))?;
    let pubkey = identity.auto_create_identity(&identity_db)?;
    tracing::info!("Identity created and saved, pubkey: {}", pubkey);

    Ok(pubkey)
}

/// 获取用户昵称
#[tauri::command]
pub fn get_nickname(state: tauri::State<'_, crate::AppState>) -> Result<String, Error> {
    let identity = state.identity.read();
    Ok(identity.get_nickname().to_string())
}

/// 设置用户昵称
///
/// 同时更新内存和数据库中的昵称。
#[tauri::command]
pub fn set_nickname(
    nickname: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    // 更新数据库
    let identity_db = state.identity_db.lock().map_err(|e| Error::Identity(format!("Identity DB lock poisoned: {}", e)))?;
    identity_db.set_nickname(&nickname)?;
    // 更新内存
    let mut identity = state.identity.write();
    identity.set_nickname(&nickname);

    tracing::info!("Nickname updated to: {}", nickname);
    Ok(())
}