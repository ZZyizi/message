//! 联系人管理模块
//!
//! 负责联系人的增删查、在线状态同步。
//! 联系人昵称使用 AES-256-GCM 加密存储。

use base64::Engine;
use serde::Serialize;

use crate::crypto;
use crate::Error;

/// 前端展示用的联系人信息
#[derive(Debug, Clone, Serialize)]
pub struct ContactInfo {
    pub pubkey: String,
    pub nickname: String,
    pub is_online: bool,
    pub last_seen: i64,
}

/// 加密昵称并存储联系人
#[tauri::command]
pub fn save_contact(
    pubkey: String,
    nickname: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    let encrypted = if nickname.is_empty() {
        None
    } else {
        let encrypted_bytes = crypto::encrypt_message(nickname.as_bytes(), &[0u8; 32], None)?;
        Some(base64::engine::general_purpose::STANDARD.encode(&encrypted_bytes))
    };

    let db = state.identity_db.lock().unwrap();
    db.upsert_contact(&pubkey, encrypted.as_deref())?;
    Ok(())
}

/// 获取所有联系人（解密昵称）
#[tauri::command]
pub fn get_contacts(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<ContactInfo>, Error> {
    let db = state.identity_db.lock().unwrap();
    let contacts = db.get_contacts()?;
    let my_pubkey = {
        let identity = state.identity.read();
        identity.get_public_key().unwrap_or("").to_string()
    };

    let mut result = Vec::new();
    for c in contacts {
        if c.pubkey == my_pubkey {
            continue; // 跳过自己
        }
        let nickname = decrypt_nickname(c.encrypted_nickname.as_deref());
        result.push(ContactInfo {
            pubkey: c.pubkey,
            nickname,
            is_online: false, // 由 sync_online_contacts 更新
            last_seen: c.last_seen,
        });
    }
    Ok(result)
}

/// 删除联系人
#[tauri::command]
pub fn delete_contact(
    pubkey: String,
    state: tauri::State<'_, crate::AppState>,
) -> Result<(), Error> {
    let db = state.identity_db.lock().unwrap();
    db.delete_contact(&pubkey)?;
    Ok(())
}

/// 同步在线联系人
///
/// 从 relay 获取在线用户列表，更新 last_seen，合并存储的联系人，
/// 返回带在线状态的完整联系人列表。
#[tauri::command]
pub async fn sync_online_contacts(
    state: tauri::State<'_, crate::AppState>,
) -> Result<Vec<ContactInfo>, Error> {
    let now = chrono::Utc::now().timestamp_millis();

    // 获取在线用户列表
    let online_pubkeys = match crate::relay::fetch_online_users().await {
        Ok(users) => users,
        Err(_) => Vec::new(),
    };

    let online_set: std::collections::HashSet<String> = online_pubkeys.iter().cloned().collect();

    // 更新在线用户的 last_seen
    {
        let db = state.identity_db.lock().unwrap();
        for pubkey in &online_pubkeys {
            // 如果联系人不存在则自动添加
            if db.get_contact_by_pubkey(pubkey)?.is_none() {
                db.upsert_contact(pubkey, None)?;
            }
            db.update_contact_last_seen(pubkey, now)?;
        }
    }

    // 读取所有联系人并解密昵称
    let db = state.identity_db.lock().unwrap();
    let contacts = db.get_contacts()?;
    let mut result = Vec::new();

    for contact in contacts {
        let nickname = decrypt_nickname(contact.encrypted_nickname.as_deref());
        let is_online = online_set.contains(&contact.pubkey);

        result.push(ContactInfo {
            pubkey: contact.pubkey,
            nickname,
            is_online,
            last_seen: contact.last_seen,
        });
    }

    // 把在线但不在联系人表中的用户也加入结果
    for pubkey in &online_pubkeys {
        if !result.iter().any(|c| &c.pubkey == pubkey) {
            result.push(ContactInfo {
                pubkey: pubkey.clone(),
                nickname: String::new(),
                is_online: true,
                last_seen: now,
            });
        }
    }

    // 在线的排前面
    result.sort_by(|a, b| {
        b.is_online.cmp(&a.is_online)
            .then(b.last_seen.cmp(&a.last_seen))
    });

    Ok(result)
}

/// 解密昵称（Base64 → AES-256-GCM 解密 → UTF-8）
fn decrypt_nickname(encrypted: Option<&str>) -> String {
    let Some(data) = encrypted else {
        return String::new();
    };
    let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data) else {
        return String::new();
    };
    let Ok(decrypted) = crypto::decrypt_message(&bytes, &[0u8; 32], None) else {
        return String::new();
    };
    String::from_utf8(decrypted).unwrap_or_default()
}
