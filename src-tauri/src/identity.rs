//! 身份管理模块
//!
//! 负责用户身份密钥的生成、存储、导出（助记词备份）和导入。
//! 私钥使用 AES-256-GCM 加密后存储，支持通过助记词进行冷备份。
//!
//! 身份存储在 `app_data_dir/identity.db` 中，与主数据库分离。

use std::path::Path;
use base64::Engine;
use zeroize::Zeroize;

use crate::crypto;
use crate::db::Database;
use crate::Error;

/// Mnemonic word list: 256 4-char hex words, each encodes 1 byte.
///
/// Simplified BIP39: 2048 words + 11-bit index would be used in production.
/// Here 256 hex strings encode 32 bytes -> 32 words.
const MNEMONIC_WORDS: &[&str] = &[
        "0000",     "0001",     "0002",     "0003",
        "0004",     "0005",     "0006",     "0007",
        "0008",     "0009",     "000a",     "000b",
        "000c",     "000d",     "000e",     "000f",
        "0010",     "0011",     "0012",     "0013",
        "0014",     "0015",     "0016",     "0017",
        "0018",     "0019",     "001a",     "001b",
        "001c",     "001d",     "001e",     "001f",
        "0020",     "0021",     "0022",     "0023",
        "0024",     "0025",     "0026",     "0027",
        "0028",     "0029",     "002a",     "002b",
        "002c",     "002d",     "002e",     "002f",
        "0030",     "0031",     "0032",     "0033",
        "0034",     "0035",     "0036",     "0037",
        "0038",     "0039",     "003a",     "003b",
        "003c",     "003d",     "003e",     "003f",
        "0040",     "0041",     "0042",     "0043",
        "0044",     "0045",     "0046",     "0047",
        "0048",     "0049",     "004a",     "004b",
        "004c",     "004d",     "004e",     "004f",
        "0050",     "0051",     "0052",     "0053",
        "0054",     "0055",     "0056",     "0057",
        "0058",     "0059",     "005a",     "005b",
        "005c",     "005d",     "005e",     "005f",
        "0060",     "0061",     "0062",     "0063",
        "0064",     "0065",     "0066",     "0067",
        "0068",     "0069",     "006a",     "006b",
        "006c",     "006d",     "006e",     "006f",
        "0070",     "0071",     "0072",     "0073",
        "0074",     "0075",     "0076",     "0077",
        "0078",     "0079",     "007a",     "007b",
        "007c",     "007d",     "007e",     "007f",
        "0080",     "0081",     "0082",     "0083",
        "0084",     "0085",     "0086",     "0087",
        "0088",     "0089",     "008a",     "008b",
        "008c",     "008d",     "008e",     "008f",
        "0090",     "0091",     "0092",     "0093",
        "0094",     "0095",     "0096",     "0097",
        "0098",     "0099",     "009a",     "009b",
        "009c",     "009d",     "009e",     "009f",
        "00a0",     "00a1",     "00a2",     "00a3",
        "00a4",     "00a5",     "00a6",     "00a7",
        "00a8",     "00a9",     "00aa",     "00ab",
        "00ac",     "00ad",     "00ae",     "00af",
        "00b0",     "00b1",     "00b2",     "00b3",
        "00b4",     "00b5",     "00b6",     "00b7",
        "00b8",     "00b9",     "00ba",     "00bb",
        "00bc",     "00bd",     "00be",     "00bf",
        "00c0",     "00c1",     "00c2",     "00c3",
        "00c4",     "00c5",     "00c6",     "00c7",
        "00c8",     "00c9",     "00ca",     "00cb",
        "00cc",     "00cd",     "00ce",     "00cf",
        "00d0",     "00d1",     "00d2",     "00d3",
        "00d4",     "00d5",     "00d6",     "00d7",
        "00d8",     "00d9",     "00da",     "00db",
        "00dc",     "00dd",     "00de",     "00df",
        "00e0",     "00e1",     "00e2",     "00e3",
        "00e4",     "00e5",     "00e6",     "00e7",
        "00e8",     "00e9",     "00ea",     "00eb",
        "00ec",     "00ed",     "00ee",     "00ef",
        "00f0",     "00f1",     "00f2",     "00f3",
        "00f4",     "00f5",     "00f6",     "00f7",
        "00f8",     "00f9",     "00fa",     "00fb",
        "00fc",     "00fd",     "00fe",     "00ff",
];

/// 身份管理器
///
/// 持有用户的公私钥对，私钥以加密形式存储。
/// 同一 `app_data_dir` 下共享一个 `identity.db` 数据库。
///
/// - `pubkey`: 用户公钥（Base64 编码），用于标识身份
/// - `encrypted_private`: 加密后的私钥（Base64 编码）
/// - `salt`: Argon2 派生口令密钥时使用的盐（PHC b64 格式）
pub struct IdentityManager {
    /// 用户公钥（Base64 编码）
    pubkey: Option<String>,
    /// 加密后的私钥（Base64 编码）
    encrypted_private: Option<String>,
    /// Argon2 盐（PHC b64 格式）
    salt: Option<String>,
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

        let identity = if let Some((pubkey, encrypted_private, salt)) = db.get_identity()? {
            Self {
                pubkey: Some(pubkey),
                encrypted_private: Some(encrypted_private),
                salt: Some(salt),
                nickname,
            }
        } else {
            Self {
                pubkey: None,
                encrypted_private: None,
                salt: None,
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
    /// 生成 Ed25519 密钥对后，使用 `encryption_key` 加密私钥并存储。
    /// 同时生成一个 Argon2 salt 与密文一同保存。
    /// 生成后 has_identity() 将返回 true。
    ///
    /// - `encryption_key`: 用于加密私钥的 32 字节密钥（来自口令的 Argon2 派生值）
    /// - 返回新生成的公钥（Base64 编码）
    pub fn generate_identity(&mut self, encryption_key: &[u8]) -> Result<String, Error> {
        let (pubkey, privkey) = crypto::generate_identity_keypair();

        // 生成 salt
        let salt = crypto::generate_salt()?;

        // 加密私钥后存储
        let encrypted = crypto::encrypt_message(&privkey, encryption_key, None)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        self.pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&pubkey));
        self.encrypted_private = Some(encrypted_b64);
        self.salt = Some(salt);

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
        let salt = self.salt.as_ref().unwrap();
        db.save_identity(&pubkey, encrypted_private, salt)?;

        Ok(pubkey)
    }

    /// 导出助记词（用于备份）
    ///
    /// 先使用 `encryption_key` 解密私钥，再转换为 32 个助记词。
    /// 用户应将助记词安全备份，并将 encryption_key 作为口令单独保存。
    ///
    /// - `encryption_key`: 解密私钥的密钥
    /// - 返回 32 个助记词（空格分隔）
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
    /// 将 32 个助记词转换回私钥字节，计算公钥，然后加密存储。
    /// 用于从备份恢复身份。
    ///
    /// - `mnemonic`: 32 个助记词（空格分隔）
    /// - `encryption_key`: 用于加密私钥的密钥
    /// - 返回新导入身份的公钥
    pub fn import_mnemonic(&mut self, mnemonic: &str, encryption_key: &[u8]) -> Result<String, Error> {
        let privkey = mnemonic_to_bytes(mnemonic)?;
        let pubkey = Self::derive_pubkey_from_privkey(&privkey)?;

        // 派生新的 salt（每个身份使用独立 salt）
        let salt = crypto::generate_salt()?;
        let encrypted = crypto::encrypt_message(&privkey, encryption_key, None)?;
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);

        self.pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&pubkey));
        self.encrypted_private = Some(encrypted_b64);
        self.salt = Some(salt);

        Ok(self.pubkey.as_ref().unwrap().clone())
    }

    /// 从私钥派生 Ed25519 公钥
    ///
    /// 私钥是 32 字节的 Ed25519 signing key seed，Ed25519 公钥可从私钥直接计算得出。
    /// 这是 Ed25519 的标准行为：公钥 = SHA-512(seed)[:32] 经曲线运算后的结果。
    fn derive_pubkey_from_privkey(privkey: &[u8]) -> Result<Vec<u8>, Error> {
        use ed25519_dalek::SigningKey;
        if privkey.len() != 32 {
            return Err(Error::Identity("Private key must be 32 bytes".to_string()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(privkey);
        let signing_key = SigningKey::from_bytes(&seed);
        Ok(signing_key.verifying_key().as_bytes().to_vec())
    }

    /// 使用口令解锁身份（持久化的 salt 用于派生密钥）
    ///
    /// 返回 `Some([u8; 32])` 表示成功，调用方应缓存该 key 用于后续签名/解密。
    /// 返回 `Err` 表示口令错误或身份不存在。
    pub fn unlock(&self, passphrase: &str) -> Result<[u8; 32], Error> {
        let salt = self.salt.as_ref()
            .ok_or_else(|| Error::Identity("No identity to unlock".to_string()))?;
        let key = crypto::derive_key_from_passphrase(passphrase, salt)?;

        // 验证派生 key 是否能正确解密（避免错误口令留下无效缓存）
        let _privkey = self.decrypt_private_key(&key)
            .map_err(|_| Error::Identity("Wrong passphrase".to_string()))?;

        Ok(key)
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
/// 每个字节映射为词表中的一个 4 字符 hex 词。
/// 32 字节的 Ed25519 私钥 → 32 个助记词。
///
/// 注意：实际生产应使用 BIP39 规范（2048 词表，11 位索引）。
fn bytes_to_mnemonic(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(32)
        .map(|&b| MNEMONIC_WORDS[b as usize])
        .collect::<Vec<_>>()
        .join(" ")
}

/// 将助记词转换回字节数组
///
/// 接受 32 个 4 字符 hex 助记词（每个对应 1 字节）。
///
/// - `mnemonic`: 空格分隔的助记词
/// - 返回解密后的私钥字节（32 字节）
fn mnemonic_to_bytes(mnemonic: &str) -> Result<Vec<u8>, Error> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    if words.len() != 32 {
        return Err(Error::Identity("Mnemonic must be 32 words".to_string()));
    }

    let mut bytes = Vec::with_capacity(32);
    for word in &words {
        let index = MNEMONIC_WORDS.iter().position(|&w| w == *word)
            .ok_or_else(|| Error::Identity(format!("Invalid word: {}", word)))?;
        bytes.push(index as u8);
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
/// - `mnemonic`: 32 个助记词
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

/// 当前是否为开发构建（编译期常量）
///
/// 编译期求值，release 构建返回 false，debug 构建返回 true。
/// 用于在 `auto_create_identity` 中拒绝 dev 零密钥的"自动解锁"行为。
#[inline]
pub fn is_dev_mode() -> bool {
    cfg!(debug_assertions)
}

/// 自动创建身份（仅开发构建可用）
///
/// **dev-only**：使用 dev 全零密钥加密私钥并自动解锁。
/// 适合开发阶段无需手动输入口令。前端应在每次启动时调用此命令，
/// 以恢复应用重启后丢失的内存密钥。
///
/// **release 构建直接返回错误** —— 生产环境必须用 `setup_identity(passphrase)`
/// 创建身份、`unlock_identity(passphrase)` 解锁身份。
#[tauri::command]
pub fn auto_create_identity(
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    if !is_dev_mode() {
        return Err(Error::Identity(
            "auto_create_identity is disabled in release builds. \
             Use setup_identity(passphrase) for first-time setup, \
             then unlock_identity(passphrase) on subsequent launches."
                .to_string(),
        ));
    }

    let dev_key = [0u8; 32];

    let pubkey = {
        let mut identity = state.identity.write();
        if identity.has_identity() {
            let pk = identity.get_public_key()
                .ok_or_else(|| Error::Identity("No identity found".to_string()))?
                .to_string();
            tracing::info!("Identity already exists, ensuring dev unlock: {}", pk);
            pk
        } else {
            let identity_db = state.identity_db.lock()
                .map_err(|e| Error::Identity(format!("Identity DB lock poisoned: {}", e)))?;
            let pk = identity.auto_create_identity(&identity_db)?;
            tracing::info!("Identity created and saved, pubkey: {}", pk);
            pk
        }
    };

    // 把 dev 零密钥缓存到 AppState（替换旧值并 zeroize 旧 key）。
    {
        let mut slot = state.encryption_key.write();
        if let Some(mut old) = slot.take() {
            old.zeroize();
        }
        *slot = Some(dev_key);
    }

    Ok(pubkey)
}

/// 首次设置身份（仅生产构建可用，必须输入口令）
///
/// **prod-only**：用 Argon2id 从口令派生 32 字节密钥，加密私钥并保存。
/// 同时生成新 salt 与密文一同落盘。成功后自动解锁身份。
///
/// **debug 构建直接返回错误** —— 开发模式应使用 `auto_create_identity`。
///
/// - `passphrase`: 用户口令（必须非空）
/// - 返回新身份的公钥
#[tauri::command]
pub fn setup_identity(
    passphrase: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    if is_dev_mode() {
        return Err(Error::Identity(
            "setup_identity is disabled in dev builds. Use auto_create_identity() instead."
                .to_string(),
        ));
    }
    if passphrase.is_empty() {
        return Err(Error::Identity("Passphrase cannot be empty".to_string()));
    }

    // 已有身份则拒绝覆盖（避免误操作丢私钥）
    {
        let identity = state.identity.read();
        if identity.has_identity() {
            return Err(Error::Identity(
                "Identity already exists. Use unlock_identity(passphrase) to unlock."
                    .to_string(),
            ));
        }
    }

    // 派生 Argon2 密钥
    let salt = crypto::generate_salt()?;
    let key = crypto::derive_key_from_passphrase(&passphrase, &salt)?;

    // 生成新身份并用派生 key 加密
    let mut identity = state.identity.write();
    let pubkey = identity.generate_identity(&key)?;

    // 持久化到 identity.db
    let identity_db = state.identity_db.lock()
        .map_err(|e| Error::Identity(format!("Identity DB lock poisoned: {}", e)))?;
    let encrypted_private = identity
        .encrypted_private
        .as_ref()
        .ok_or_else(|| Error::Identity("Internal: missing encrypted private".to_string()))?;
    identity_db.save_identity(&pubkey, encrypted_private, &salt)?;
    drop(identity_db);
    drop(identity);

    // 缓存派生 key
    {
        let mut slot = state.encryption_key.write();
        if let Some(mut old) = slot.take() {
            old.zeroize();
        }
        *slot = Some(key);
    }

    tracing::info!("Identity created with passphrase, pubkey: {}", pubkey);
    Ok(pubkey)
}

/// 解锁身份（使用口令派生加密密钥并缓存到 AppState）
///
/// 前端在启动时调用，成功后所有需要私钥的操作（签名/解密/导出助记词）
/// 都可以直接通过 `AppState::current_encryption_key()` 获取密钥。
///
/// - 开发构建：空口令也接受（用 dev 零密钥），方便本地调试
/// - 生产构建：拒绝空口令，强制用户输入真实口令
#[tauri::command]
pub fn unlock_identity(
    passphrase: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<String, Error> {
    if !is_dev_mode() && passphrase.is_empty() {
        return Err(Error::Identity(
            "Passphrase required in release build. Empty passphrase is not allowed."
                .to_string(),
        ));
    }

    let identity = state.identity.read();
    if !identity.has_identity() {
        let hint = if is_dev_mode() {
            "No identity to unlock. Call auto_create_identity() first."
        } else {
            "No identity to unlock. Call setup_identity(passphrase) first."
        };
        return Err(Error::Identity(hint.to_string()));
    }
    let key = identity.unlock(&passphrase)?;
    drop(identity);

    // 缓存到 AppState（替换旧值并 zeroize 旧 key）
    {
        let mut slot = state.encryption_key.write();
        if let Some(mut old) = slot.take() {
            old.zeroize();
        }
        *slot = Some(key);
    }

    tracing::info!("Identity unlocked");
    Ok(state.identity.read().get_public_key()
        .map(|s| s.to_string())
        .unwrap_or_default())
}

/// 锁定身份（清除内存中的加密密钥）
#[tauri::command]
pub fn lock_identity(
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    state.lock();
    tracing::info!("Identity locked");
    Ok(())
}

/// 检查身份是否已解锁
#[tauri::command]
pub fn is_unlocked(
    state: tauri::State<'_, crate::AppState>,
) -> Result<bool, Error> {
    Ok(state.encryption_key.read().is_some())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 助记词双向编码应该是无损的（32 字节 → 32 hex 词 → 32 字节，原值不变）
    #[test]
    fn test_mnemonic_encoding_roundtrip() {
        let original: Vec<u8> = (0..32).collect();
        let mnemonic = bytes_to_mnemonic(&original);
        assert_eq!(mnemonic.split_whitespace().count(), 32);
        let recovered = mnemonic_to_bytes(&mnemonic).unwrap();
        assert_eq!(recovered, original, "助记词应可逆编码");
    }

    #[test]
    fn test_mnemonic_encoding_random_bytes() {
        for _ in 0..10 {
            let mut bytes = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
            let mnemonic = bytes_to_mnemonic(&bytes);
            let recovered = mnemonic_to_bytes(&mnemonic).unwrap();
            assert_eq!(recovered.to_vec(), bytes.to_vec());
        }
    }

    /// 验证 derive_pubkey_from_privkey 真正从私钥派生公钥（不是随机生成）
    #[test]
    fn test_derive_pubkey_deterministic() {
        let (real_pub, priv_bytes) = crypto::generate_identity_keypair();
        let derived_pub = IdentityManager::derive_pubkey_from_privkey(&priv_bytes).unwrap();
        assert_eq!(derived_pub, real_pub, "派生公钥必须等于原公钥");
    }

    #[test]
    fn test_derive_pubkey_wrong_length_fails() {
        assert!(IdentityManager::derive_pubkey_from_privkey(&[0u8; 16]).is_err());
        assert!(IdentityManager::derive_pubkey_from_privkey(&[]).is_err());
    }

    /// 完整流程：生成身份 → 用正确口令解锁（私钥可解密）
    #[test]
    fn test_generate_unlock_with_passphrase() {
        let dir = std::env::temp_dir().join("decentralized-im-test-1");
        std::fs::create_dir_all(&dir).unwrap();
        let mut mgr = IdentityManager::new(&dir).unwrap();

        // 用一个固定的"伪口令派生 key"作为 encryption_key（模拟用户输入口令后的派生结果）
        // 然后生成身份（内部会重新生成 salt）
        let original_key = [7u8; 32];
        mgr.generate_identity(&original_key).unwrap();

        // 用相同 salt + 相同口令重新派生，应能解密私钥
        // 注意：generate_identity 内部用的是 original_key 本身（不派生），
        // 所以 unlock 时必须直接用 original_key（不重新派生），因为没有"口令"输入
        let privkey = mgr.decrypt_private_key(&original_key).unwrap();
        assert_eq!(privkey.len(), 32);

        // 用不同 key 解密应失败（AEAD 错误）
        let wrong_key = [9u8; 32];
        assert!(mgr.decrypt_private_key(&wrong_key).is_err());

        // 验证 unlock 方法：需要先准备一个口令派生的真实场景
        // 我们手动重新生成一个身份，这次用真实的口令派生
        let passphrase = "test-passphrase";
        let salt_for_unlock = crate::crypto::generate_salt().unwrap();
        let derived_key = crate::crypto::derive_key_from_passphrase(passphrase, &salt_for_unlock).unwrap();

        // 手动构造 IdentityManager 状态以测试 unlock 流程
        let (pub_bytes, priv_bytes) = crypto::generate_identity_keypair();
        let encrypted = crypto::encrypt_message(&priv_bytes, &derived_key, None).unwrap();
        let encrypted_b64 = base64::engine::general_purpose::STANDARD.encode(&encrypted);
        mgr.pubkey = Some(base64::engine::general_purpose::STANDARD.encode(&pub_bytes));
        mgr.encrypted_private = Some(encrypted_b64);
        mgr.salt = Some(salt_for_unlock);

        // 用错误口令应失败
        assert!(mgr.unlock("wrong-passphrase").is_err());
        // 用正确口令应成功并能解密出原私钥
        let unlocked_key = mgr.unlock(passphrase).unwrap();
        let recovered = mgr.decrypt_private_key(&unlocked_key).unwrap();
        assert_eq!(recovered, priv_bytes);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// 助记词导出→导入应能恢复同一身份（公钥一致）
    #[test]
    fn test_mnemonic_export_import_roundtrip() {
        let dir = std::env::temp_dir().join("decentralized-im-test-2");
        std::fs::create_dir_all(&dir).unwrap();

        // 用零 key 生成身份（开发模式）
        let zero_key = [0u8; 32];
        let mut mgr = IdentityManager::new(&dir).unwrap();
        let original_pubkey = mgr.generate_identity(&zero_key).unwrap();

        // 导出助记词（32 字节 → 32 个 hex 词）
        let mnemonic = mgr.export_mnemonic(&zero_key).unwrap();
        assert_eq!(mnemonic.split_whitespace().count(), 32);

        // 导入到新实例
        let dir2 = std::env::temp_dir().join("decentralized-im-test-3");
        std::fs::create_dir_all(&dir2).unwrap();
        let mut mgr2 = IdentityManager::new(&dir2).unwrap();
        let imported_pubkey = mgr2.import_mnemonic(&mnemonic, &zero_key).unwrap();

        assert_eq!(original_pubkey, imported_pubkey, "助记词恢复应得到相同公钥");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&dir2).ok();
    }
}