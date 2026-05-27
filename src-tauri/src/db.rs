//! SQLite 数据库层
//!
//! 负责所有持久化存储：
//! - messages：存储所有消息记录
//! - groups / group_members：群组结构
//! - devices：设备公钥绑定（多设备功能尚未实现）
//! - pending_messages：未确认消息的暂存队列
//! - group_keys：群组加密密钥
//! - identities：加密存储的身份密钥
//! - settings：键值配置存储

use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::Error;

/// 消息记录结构
///
/// 存储在 messages 表中，每条消息都有唯一的 event_id 和 seq_id。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: String,              // 本地唯一 ID（UUID）
    pub event_id: String,        // 全局唯一事件 ID（用于去重和追踪）
    pub msg_type: String,        // 消息类型（如 "text", "image"）
    pub from_pubkey: String,     // 发送者公钥
    pub to_recipient: String,    // 接收者公钥或群组 ID
    pub payload: String,         // 消息内容（已加密）
    pub media_id: Option<String>, // 媒体附件 ID（如有）
    pub timestamp: i64,          // 时间戳（毫秒，Unix epoch）
    pub seq_id: i64,             // 序列号（用于消息排序，每个接收者独立递增）
    pub signature: String,       // Ed25519 签名（防止篡改）
    pub delivered: bool,         // 是否已送达对方
    pub recalled: bool,          // 是否已撤回（逻辑删除）
}

/// 群组结构
///
/// 存储在 groups 表中，群主（owner）拥有管理权限。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub name: String,
    pub owner_pubkey: String,    // 群主公钥
    pub created_at: i64,
    pub group_key_id: String,    // 群密钥 ID（在 relay 端存储）
}

/// 设备记录结构（多设备功能尚未实现）
///
/// 存储在 devices 表中，每个设备有独立的公钥绑定到用户身份。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct Device {
    pub id: String,
    pub pubkey: String,          // 设备公钥
    pub identity_pubkey: String,  // 绑定的身份公钥
    pub permissions: String,      // 权限 JSON（owner/admin/device）
    pub expires_at: Option<i64>, // 过期时间（可选）
    pub revoked: bool,           // 是否已撤销
    pub created_at: i64,
}

/// 未确认消息（暂存队列）
///
/// 存储在 pending_messages 表中，用于消息发送失败时的重试。
/// 消息发送后加入 pending，收到对方 ACK 后删除。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingMessage {
    pub id: String,
    pub event_id: String,        // 关联的消息 event_id
    pub to_recipient: String,    // 接收者
    pub payload: String,         // 消息内容（JSON 格式）
    pub created_at: i64,          // 创建时间（毫秒）
    pub retry_count: i32,        // 重试次数
}

/// 联系人记录结构
///
/// 存储在 contacts 表中，昵称使用 AES-256-GCM 加密后存储。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub pubkey: String,
    pub encrypted_nickname: Option<String>,
    pub last_seen: i64,
    pub created_at: i64,
}

/// 数据库连接包装器
///
/// 封装 rusqlite Connection，提供类型安全的数据库操作。
pub struct Database {
    conn: Connection,
}

impl Database {
    /// 打开或创建数据库文件
    ///
    /// 若文件不存在则创建，并初始化表结构。
    pub fn new(path: &Path) -> Result<Self, Error> {
        let conn = Connection::open(path)?;
        let db = Self { conn };
        db.init_tables()?;
        Ok(db)
    }

    /// 初始化数据库表结构
    ///
    /// 创建所有必要的表和索引。若表已存在则跳过（CREATE TABLE IF NOT EXISTS）。
    fn init_tables(&self) -> Result<(), Error> {
        self.conn.execute_batch(
            r#"
            -- 消息表：存储所有聊天消息
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                event_id TEXT UNIQUE NOT NULL,
                msg_type TEXT NOT NULL,
                from_pubkey TEXT NOT NULL,
                to_recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                media_id TEXT,
                timestamp INTEGER NOT NULL,
                seq_id INTEGER NOT NULL,
                signature TEXT NOT NULL,
                delivered INTEGER DEFAULT 0,
                recalled INTEGER DEFAULT 0
            );

            -- 群组表：存储群组基本信息
            CREATE TABLE IF NOT EXISTS groups (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                owner_pubkey TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                group_key_id TEXT NOT NULL
            );

            -- 群组成员表：存储群组成员和角色
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                pubkey TEXT NOT NULL,
                role TEXT NOT NULL,
                joined_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, pubkey)
            );

            -- 设备表：存储多设备绑定（尚未完全实现）
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                identity_pubkey TEXT NOT NULL,
                permissions TEXT NOT NULL,
                expires_at INTEGER,
                revoked INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            -- 未确认消息表：存储待确认消息实现重试
            CREATE TABLE IF NOT EXISTS pending_messages (
                id TEXT PRIMARY KEY,
                event_id TEXT NOT NULL,
                to_recipient TEXT NOT NULL,
                payload TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                retry_count INTEGER DEFAULT 0
            );

            -- 群密钥表：存储群组加密密钥（在 relay 端存储）
            CREATE TABLE IF NOT EXISTS group_keys (
                group_id TEXT NOT NULL,
                key_id TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (group_id, key_id)
            );

            -- 身份表：存储加密后的身份密钥
            CREATE TABLE IF NOT EXISTS identities (
                id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL,
                encrypted_private TEXT NOT NULL,
                nickname TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            );

            -- 联系人表：存储联系人信息（昵称加密存储）
            CREATE TABLE IF NOT EXISTS contacts (
                id TEXT PRIMARY KEY,
                pubkey TEXT NOT NULL UNIQUE,
                encrypted_nickname TEXT,
                last_seen INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            );

            -- 设置表：存储键值配置（如 relay_url）
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            -- 索引：加速常见查询
            CREATE INDEX IF NOT EXISTS idx_messages_from ON messages(from_pubkey);
            CREATE INDEX IF NOT EXISTS idx_messages_to ON messages(to_recipient);
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp);
            CREATE INDEX IF NOT EXISTS idx_pending_created ON pending_messages(created_at);
            "#,
        )?;

        // 迁移：为已有的 identities 表添加 nickname 列（若已存在则忽略）
        let _ = self.conn.execute(
            "ALTER TABLE identities ADD COLUMN nickname TEXT NOT NULL DEFAULT ''",
            [],
        );

        Ok(())
    }

    /// 插入消息记录
    ///
    /// 新消息默认 delivered=0, recalled=0。
    pub fn insert_message(&self, msg: &Message) -> Result<(), Error> {
        self.conn.execute(
            r#"INSERT INTO messages (id, event_id, msg_type, from_pubkey, to_recipient, payload, media_id, timestamp, seq_id, signature, delivered, recalled)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            params![
                msg.id,
                msg.event_id,
                msg.msg_type,
                msg.from_pubkey,
                msg.to_recipient,
                msg.payload,
                msg.media_id,
                msg.timestamp,
                msg.seq_id,
                msg.signature,
                msg.delivered as i32,
                msg.recalled as i32,
            ],
        )?;
        Ok(())
    }

    /// 获取消息列表
    ///
    /// - `recipient`: 接收者公钥或群组 ID
    /// - `since_seq`: 从指定序列号之后开始查询（可选，用于增量同步）
    /// - `limit`: 返回条数上限
    ///
    /// 自动过滤已撤回的消息（recalled = 0），按 seq_id 升序排列。
    pub fn get_messages(
        &self,
        recipient: &str,
        since_seq: Option<i64>,
        limit: i64,
    ) -> Result<Vec<Message>, Error> {
        let sql = if since_seq.is_some() {
            "SELECT id, event_id, msg_type, from_pubkey, to_recipient, payload, media_id, timestamp, seq_id, signature, delivered, recalled FROM messages WHERE to_recipient = ?1 AND seq_id > ?2 AND recalled = 0 ORDER BY seq_id ASC LIMIT ?3"
        } else {
            "SELECT id, event_id, msg_type, from_pubkey, to_recipient, payload, media_id, timestamp, seq_id, signature, delivered, recalled FROM messages WHERE to_recipient = ?1 AND recalled = 0 ORDER BY seq_id ASC LIMIT ?2"
        };

        let mut messages = Vec::new();

        if let Some(seq) = since_seq {
            let mut stmt = self.conn.prepare(sql)?;
            let mut rows = stmt.query(params![recipient, seq, limit])?;
            while let Some(row) = rows.next()? {
                messages.push(Message {
                    id: row.get(0)?,
                    event_id: row.get(1)?,
                    msg_type: row.get(2)?,
                    from_pubkey: row.get(3)?,
                    to_recipient: row.get(4)?,
                    payload: row.get(5)?,
                    media_id: row.get(6)?,
                    timestamp: row.get(7)?,
                    seq_id: row.get(8)?,
                    signature: row.get(9)?,
                    delivered: row.get::<_, i32>(10)? != 0,
                    recalled: row.get::<_, i32>(11)? != 0,
                });
            }
        } else {
            let mut stmt = self.conn.prepare(sql)?;
            let mut rows = stmt.query(params![recipient, limit])?;
            while let Some(row) = rows.next()? {
                messages.push(Message {
                    id: row.get(0)?,
                    event_id: row.get(1)?,
                    msg_type: row.get(2)?,
                    from_pubkey: row.get(3)?,
                    to_recipient: row.get(4)?,
                    payload: row.get(5)?,
                    media_id: row.get(6)?,
                    timestamp: row.get(7)?,
                    seq_id: row.get(8)?,
                    signature: row.get(9)?,
                    delivered: row.get::<_, i32>(10)? != 0,
                    recalled: row.get::<_, i32>(11)? != 0,
                });
            }
        }

        Ok(messages)
    }

    /// 标记消息已送达
    pub fn mark_message_delivered(&self, event_id: &str) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE messages SET delivered = 1 WHERE event_id = ?1",
            params![event_id],
        )?;
        Ok(())
    }

    /// 标记消息已撤回（逻辑删除）
    ///
    /// 实际数据仍保留，仅将 recalled 设为 1，前端不再显示。
    pub fn mark_message_recalled(&self, event_id: &str) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE messages SET recalled = 1 WHERE event_id = ?1",
            params![event_id],
        )?;
        Ok(())
    }

    /// 获取下一个序列号
    ///
    /// 查询当前已存储的最大 seq_id，加 1 后返回。
    /// 若无消息则返回 1。
    pub fn get_next_seq_id(&self, recipient: &str) -> Result<i64, Error> {
        let result: Option<Option<i64>> = self
            .conn
            .query_row(
                "SELECT MAX(seq_id) FROM messages WHERE to_recipient = ?1",
                params![recipient],
                |row| row.get(0),
            )
            .optional()?;
        Ok(result.flatten().unwrap_or(0) + 1)
    }

    /// 插入未确认消息到 pending 队列
    pub fn insert_pending(&self, pending: &PendingMessage) -> Result<(), Error> {
        self.conn.execute(
            r#"INSERT INTO pending_messages (id, event_id, to_recipient, payload, created_at, retry_count)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                pending.id,
                pending.event_id,
                pending.to_recipient,
                pending.payload,
                pending.created_at,
                pending.retry_count,
            ],
        )?;
        Ok(())
    }

    /// 获取未确认消息列表
    ///
    /// 按创建时间升序返回，用于消息重试。
    pub fn get_pending_messages(&self, limit: i64) -> Result<Vec<PendingMessage>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_id, to_recipient, payload, created_at, retry_count FROM pending_messages ORDER BY created_at ASC LIMIT ?1"
        )?;
        let mut messages = Vec::new();
        let mut rows = stmt.query(params![limit])?;
        while let Some(row) = rows.next()? {
            messages.push(PendingMessage {
                id: row.get(0)?,
                event_id: row.get(1)?,
                to_recipient: row.get(2)?,
                payload: row.get(3)?,
                created_at: row.get(4)?,
                retry_count: row.get(5)?,
            });
        }
        Ok(messages)
    }

    /// 从 pending 队列删除消息（收到 ACK 后调用）
    pub fn delete_pending(&self, event_id: &str) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM pending_messages WHERE event_id = ?1",
            params![event_id],
        )?;
        Ok(())
    }

    /// 清理过期的 pending 消息
    ///
    /// - `max_age_secs`: 最大存活时间（秒）
    /// - 返回删除的消息数量
    pub fn cleanup_expired_pending(&self, max_age_secs: i64) -> Result<i64, Error> {
        let cutoff = Utc::now().timestamp() - max_age_secs;
        let deleted = self.conn.execute(
            "DELETE FROM pending_messages WHERE created_at < ?1",
            params![cutoff],
        )?;
        Ok(deleted as i64)
    }

    /// 插入群组记录
    pub fn insert_group(&self, group: &Group) -> Result<(), Error> {
        self.conn.execute(
            r#"INSERT INTO groups (id, name, owner_pubkey, created_at, group_key_id)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![
                group.id,
                group.name,
                group.owner_pubkey,
                group.created_at,
                group.group_key_id,
            ],
        )?;
        Ok(())
    }

    /// 获取群组信息
    pub fn get_group(&self, group_id: &str) -> Result<Option<Group>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, name, owner_pubkey, created_at, group_key_id FROM groups WHERE id = ?1"
        )?;
        let group = stmt
            .query_row(params![group_id], |row| {
                Ok(Group {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    owner_pubkey: row.get(2)?,
                    created_at: row.get(3)?,
                    group_key_id: row.get(4)?,
                })
            })
            .optional()?;
        Ok(group)
    }

    /// 获取群组成员列表
    ///
    /// 返回 (pubkey, role) 元组列表。
    pub fn get_group_members(&self, group_id: &str) -> Result<Vec<(String, String)>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT pubkey, role FROM group_members WHERE group_id = ?1"
        )?;
        let mut members = Vec::new();
        let mut rows = stmt.query(params![group_id])?;
        while let Some(row) = rows.next()? {
            members.push((row.get(0)?, row.get(1)?));
        }
        Ok(members)
    }

    /// 添加群组成员
    ///
    /// - `group_id`: 群组 ID
    /// - `pubkey`: 成员公钥
    /// - `role`: 角色（"owner"/"admin"/"member"）
    pub fn add_group_member(&self, group_id: &str, pubkey: &str, role: &str) -> Result<(), Error> {
        self.conn.execute(
            r#"INSERT OR REPLACE INTO group_members (group_id, pubkey, role, joined_at)
               VALUES (?1, ?2, ?3, ?4)"#,
            params![group_id, pubkey, role, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// 移除群组成员
    pub fn remove_group_member(&self, group_id: &str, pubkey: &str) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM group_members WHERE group_id = ?1 AND pubkey = ?2",
            params![group_id, pubkey],
        )?;
        Ok(())
    }

    /// 保存身份到数据库
    ///
    /// 使用 INSERT OR REPLACE，相同 id 的记录会被更新。
    pub fn save_identity(&self, pubkey: &str, encrypted_private: &str) -> Result<(), Error> {
        self.conn.execute(
            r#"INSERT OR REPLACE INTO identities (id, pubkey, encrypted_private, nickname, created_at)
               VALUES ('default', ?1, ?2, '', ?3)"#,
            params![pubkey, encrypted_private, Utc::now().timestamp()],
        )?;
        Ok(())
    }

    /// 从数据库加载身份
    pub fn get_identity(&self) -> Result<Option<(String, String)>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT pubkey, encrypted_private FROM identities WHERE id = 'default'"
        )?;
        let identity = stmt
            .query_row([], |row| Ok((row.get(0)?, row.get(1)?)))
            .optional()?;
        Ok(identity)
    }

    /// 保存昵称
    pub fn set_nickname(&self, nickname: &str) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE identities SET nickname = ?1 WHERE id = 'default'",
            params![nickname],
        )?;
        Ok(())
    }

    /// 获取昵称
    pub fn get_nickname(&self) -> Result<Option<String>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT nickname FROM identities WHERE id = 'default'"
        )?;
        let nickname = stmt
            .query_row([], |row| row.get(0))
            .optional()?;
        Ok(nickname)
    }

    // ========== 联系人操作 ==========

    /// 添加或更新联系人
    ///
    /// 若 pubkey 已存在则更新昵称，否则插入新记录。
    pub fn upsert_contact(&self, pubkey: &str, encrypted_nickname: Option<&str>) -> Result<(), Error> {
        let now = Utc::now().timestamp();
        self.conn.execute(
            r#"INSERT INTO contacts (id, pubkey, encrypted_nickname, last_seen, created_at)
               VALUES (?1, ?2, ?3, 0, ?4)
               ON CONFLICT(pubkey) DO UPDATE SET encrypted_nickname = ?3"#,
            params![uuid::Uuid::new_v4().to_string(), pubkey, encrypted_nickname, now],
        )?;
        Ok(())
    }

    /// 获取所有联系人
    pub fn get_contacts(&self) -> Result<Vec<Contact>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pubkey, encrypted_nickname, last_seen, created_at FROM contacts ORDER BY last_seen DESC"
        )?;
        let mut contacts = Vec::new();
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            contacts.push(Contact {
                id: row.get(0)?,
                pubkey: row.get(1)?,
                encrypted_nickname: row.get(2)?,
                last_seen: row.get(3)?,
                created_at: row.get(4)?,
            });
        }
        Ok(contacts)
    }

    /// 根据公钥获取联系人
    pub fn get_contact_by_pubkey(&self, pubkey: &str) -> Result<Option<Contact>, Error> {
        let mut stmt = self.conn.prepare(
            "SELECT id, pubkey, encrypted_nickname, last_seen, created_at FROM contacts WHERE pubkey = ?1"
        )?;
        let contact = stmt
            .query_row(params![pubkey], |row| {
                Ok(Contact {
                    id: row.get(0)?,
                    pubkey: row.get(1)?,
                    encrypted_nickname: row.get(2)?,
                    last_seen: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .optional()?;
        Ok(contact)
    }

    /// 更新联系人最后在线时间
    pub fn update_contact_last_seen(&self, pubkey: &str, timestamp: i64) -> Result<(), Error> {
        self.conn.execute(
            "UPDATE contacts SET last_seen = ?1 WHERE pubkey = ?2",
            params![timestamp, pubkey],
        )?;
        Ok(())
    }

    /// 删除联系人
    pub fn delete_contact(&self, pubkey: &str) -> Result<(), Error> {
        self.conn.execute(
            "DELETE FROM contacts WHERE pubkey = ?1",
            params![pubkey],
        )?;
        Ok(())
    }

    /// 保存设置键值对
    ///
    /// 使用 INSERT OR REPLACE，相同 key 的值会被更新。
    pub fn set_setting(&self, key: &str, value: &str) -> Result<(), Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
            params![key, value],
        )?;
        Ok(())
    }

    /// 获取设置值
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, Error> {
        let mut stmt = self.conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let value = stmt
            .query_row(params![key], |row| row.get(0))
            .optional()?;
        Ok(value)
    }
}