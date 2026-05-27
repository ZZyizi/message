//! 分布式端到端加密即时通讯系统 - 核心库
//!
//! 本模块是应用的入口点，负责：
//! - 初始化日志系统（写入文件 + 控制台）
//! - 创建应用状态（数据库 + 身份管理器）
//! - 注册所有 Tauri 命令处理器

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod contact;    // 联系人管理模块
mod crypto;    // 加密原语模块
mod db;         // SQLite 数据库层
mod error;      // 统一错误类型
mod identity;  // 身份密钥管理
mod message;    // 消息收发
mod relay;     // 中继服务器连接

use std::sync::Arc;
use std::sync::Mutex;
use parking_lot::RwLock;
use tauri::Manager;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
use tracing_appender::rolling::{RollingFileAppender, Rotation};

pub use error::Error;

/// 应用全局状态，供所有 Tauri 命令访问
///
/// - `db`: SQLite 数据库连接（线程安全）
/// - `identity`: 身份管理器（存储用户的公私钥对）
/// - `app_handle`: Tauri 应用句柄，用于发送事件到前端
pub struct AppState {
    /// 数据库连接，使用 Mutex 保证线程安全
    pub db: Arc<Mutex<db::Database>>,
    /// 身份数据库连接
    pub identity_db: Arc<Mutex<db::Database>>,
    /// 身份管理器，使用 RwLock 支持并发读
    pub identity: Arc<RwLock<identity::IdentityManager>>,
    /// Tauri 应用句柄
    pub app_handle: tauri::AppHandle,
}

/// 初始化日志系统
///
/// 日志同时写入两个目标：
/// 1. 本地日志文件（按天轮转，存放在 `decentralized-im/logs/`）
/// 2. 控制台 stderr（开发时可见）
///
/// 使用 `Box::leak` 将 guard 泄漏到堆上，确保程序运行期间日志一直有效
fn setup_logging() {
    // 获取系统本地数据目录，fallback 到当前目录
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("decentralized-im")
        .join("logs");

    std::fs::create_dir_all(&log_dir).ok();

    // 创建按天轮转的文件写入器
    let file_appender = RollingFileAppender::new(Rotation::DAILY, log_dir, "app.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

    // 默认日志级别为 info，可通过 RUST_LOG 环境变量配置
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info"));

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_writer(non_blocking))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .init();

    // 泄漏 guard 使其在程序生命周期内持续有效
    Box::leak(Box::new(_guard));
}

/// 应用主入口
///
/// 执行流程：
/// 1. 初始化日志系统
/// 2. 创建 Tauri 应用
/// 3. 在 `setup` 阶段初始化数据库和身份管理器
/// 4. 注册命令处理器
/// 5. 运行应用
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    setup_logging();

    tracing::info!("Starting Decentralized IM application");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .setup(|app| {
            tracing::info!("Initializing application state");

            // 获取应用数据目录（跨平台兼容）
            let app_data_dir = app.path().app_data_dir()
                .expect("Failed to get app data dir");
            std::fs::create_dir_all(&app_data_dir)?;

            // 初始化数据库
            let db_path = app_data_dir.join("data.db");
            let db = db::Database::new(&db_path)
                .expect("Failed to initialize database");

            // 初始化身份数据库
            let identity_db_path = app_data_dir.join("identity.db");
            let identity_db = db::Database::new(&identity_db_path)
                .expect("Failed to initialize identity database");

            // 初始化身份管理器
            let identity = identity::IdentityManager::new(&app_data_dir)
                .expect("Failed to initialize identity manager");

            // 构建并注册全局状态
            let state = AppState {
                db: Arc::new(Mutex::new(db)),
                identity_db: Arc::new(Mutex::new(identity_db)),
                identity: Arc::new(RwLock::new(identity)),
                app_handle: app.handle().clone(),
            };

            app.manage(state);

            tracing::info!("Application initialized successfully");
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            // 加密相关命令
            crypto::encrypt_message_cmd,
            crypto::decrypt_message_cmd,
            crypto::cmd_generate_identity_keypair,
            crypto::cmd_generate_device_keypair,
            // 身份管理命令
            identity::get_public_key,
            identity::export_identity_mnemonic,
            identity::import_identity_mnemonic,
            identity::auto_create_identity,
            identity::get_nickname,
            identity::set_nickname,
            // 联系人命令
            contact::save_contact,
            contact::get_contacts,
            contact::delete_contact,
            contact::sync_online_contacts,
            // 消息命令
            message::send_message,
            message::get_messages,
            message::get_chat_messages,
            message::recall_message,
            // 中继命令
            relay::connect,
            relay::disconnect,
            relay::get_status,
            relay::send_chat_message,
            relay::send_ack,
            relay::send_recall,
            relay::subscribe_messages,
            relay::get_online_users,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}