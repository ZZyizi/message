//! 统一错误类型定义
//!
//! 定义应用中所有可能的错误类型，实现 `std::error::Error` 和 `serde::Serialize`。
//! 所有错误通过网络返回给前端，因此必须支持序列化。

use thiserror::Error;

/// 应用错误枚举
///
/// 包含以下变体：
/// - `Database`: 数据库操作错误（SQLite 相关）
/// - `Serialization`: JSON 序列化/反序列化错误
/// - `Crypto`: 密码学操作错误（加密、解密、签名失败等）
/// - `Identity`: 身份管理错误（无身份、密钥不匹配等）
/// - `Relay`: 中继服务器错误（连接失败、消息发送失败等）
/// - `Io`: 文件/网络 IO 错误
/// - `NotFound`: 资源未找到错误
#[derive(Error, Debug)]
pub enum Error {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Identity error: {0}")]
    Identity(String),

    #[error("Relay error: {0}")]
    Relay(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Not found: {0}")]
    NotFound(String),
}

/// 实现 serde::Serialize，确保错误可以通过 Tauri 返回给前端
///
/// 将错误格式化为字符串（使用 thiserror 的 Display 实现）
impl serde::Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}