# 弱中心化加密即时通讯系统

基于 **Tauri v2 + Rust Core + Svelte 5** 构建的弱中心化端到端加密即时通讯系统。

> 弱中心化 + 端到端加密 + 设备为核心身份的即时通讯协议与应用系统

## 核心特性

- **端到端加密 (E2EE)**：X25519 临时密钥交换 → HKDF 派生会话密钥 → AES-256-GCM 消息加密，支持 Rekeying
- **去中心化身份**：Ed25519 公私钥体系，助记词备份/导入，Argon2id 口令派生加密密钥，无需手机号或邮箱
- **联系人管理**：AES-256-GCM 加密昵称存储，Relay 在线状态同步，自动过滤自身公钥
- **消息系统**：Ed25519 签名 + Pending 队列 + ACK 确认 + 消息撤回，双向聊天记录查询
- **群聊系统**（数据库层就绪）：群组管理、成员角色、群密钥轮转设计
- **Relay 服务器**：axum + WebSocket，消息缓存（TTL 7 天），在线状态，E2EE 协商消息暂存投递
- **多设备支持**（已设计）：设备授权绑定流程、设备撤销机制
- **媒体存储**（已设计）：用户自持 OSS/R2 桶分布式存储，媒体不经 Relay 中转

## 技术栈

| 层级 | 技术 | 用途 |
|------|------|------|
| 桌面框架 | Tauri v2 | 内存占用 20-80MB，原生性能 |
| 前端 | SvelteKit + Svelte 5 runes | 响应式 UI（$state/$props） |
| 后端 | Rust + tokio | 异步运行时，密码学运算 |
| 数据库 | SQLite (rusqlite, bundled) | 本地消息/身份/联系人存储 |
| 密码学 | X25519, Ed25519, AES-256-GCM, BLAKE3, HKDF, Argon2id | 完整密码学套件 |
| Relay | axum + WebSocket + reqwest | 消息转发、在线状态、缓存 |

## 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                         客户端                                │
│  ┌──────────┐  ┌───────────────┐  ┌────────────────────┐   │
│  │ Svelte 5 │  │   Rust Core   │  │  pending 重试后台   │   │
│  │    UI    │  │ crypto/sync   │  │  (tokio::spawn)    │   │
│  └──────────┘  └───────────────┘  └────────────────────┘   │
│        │               │                     │               │
│        └───────────────┴─────────────────────┘               │
│                        │                                     │
│             ┌──────────┴──────────┐                          │
│             │  SQLite 数据库 ×2   │                          │
│             │  data.db + identity │                          │
│             │  .db                │                          │
│             └─────────────────────┘                          │
│                        │                                     │
│            WebSocket / HTTP                                  │
└────────────────────────┼─────────────────────────────────────┘
                         │
                         ▼
┌──────────────────────────────────────────────────────────────┐
│                     Relay 服务器 (axum)                       │
│  - WebSocket 连接管理 (/ws/{pubkey})                         │
│  - 在线状态（内存 HashMap）                                   │
│  - 加密消息缓存（TTL 7 天）                                   │
│  - E2EE 协商消息暂存（TTL 5 分钟，上线投递）                  │
│  - Ping/Pong 心跳                                            │
│  - /users 端点查询在线用户                                    │
│  - /health 健康检查                                           │
└──────────────────────────────────────────────────────────────┘
```

### Rust 后端模块 (`src-tauri/src/`)

| 文件 | 说明 |
|------|------|
| `lib.rs` | 应用入口，AppState 管理（db + identity_db + identity + sessions + encryption_key），日志初始化，命令注册 |
| `main.rs` | Windows 子系统入口 |
| `crypto.rs` | 密码学原语：Ed25519/X25519 密钥生成、HKDF 会话密钥派生、AES-256-GCM 加解密、Ed25519 签名/验签、BLAKE3/SHA256 哈希、Argon2id 口令派生 |
| `db.rs` | SQLite 层：messages、pending_messages、groups、group_members、devices、identities、contacts、settings 表，含完整 CRUD 和单元测试 |
| `identity.rs` | 身份密钥管理：生成/导入/导出助记词、Argon2id 口令解锁/锁定、昵称管理 |
| `message.rs` | 消息发送（签名 + 本地存储 + pending 队列）、消息获取、双向聊天记录、消息撤回、pending 清理 |
| `session.rs` | E2EE 会话状态管理：密钥协商状态机（None→WaitingForPeer→KeyExchanged→Active）、待发明文队列、会话超时、Rekeying 支持 |
| `contact.rs` | 联系人管理：加密昵称存储/解密、在线状态同步、自动过滤自身公钥 |
| `relay.rs` | WebSocket 客户端：连接/断开、消息收发、ACK、撤回广播、在线用户拉取、E2EE 协商转发、pending 重试后台循环 |
| `error.rs` | 统一错误枚举（Database/Crypto/Identity/Relay/Io/NotFound），支持 serde 序列化 |
| `mnemonic_words_const.rs` | 助记词 BIP39 词表常量 |

### Relay 服务器 (`relay/`)

| 文件 | 说明 |
|------|------|
| `relay/src/main.rs` | axum WebSocket 服务器：客户端会话管理、消息缓存/转发、E2EE 协商暂存投递、ACK 处理、撤回广播、在线用户查询 |

### 前端 (`src/`)

| 文件 | 说明 |
|------|------|
| `routes/+page.svelte` | 主聊天界面：联系人列表、消息列表、在线状态、Relay 连接、E2EE 会话状态、消息收发 |
| `routes/+layout.svelte` | 根布局，全局样式 |
| `routes/profile/+page.svelte` | 个人资料/身份设置页 |
| `lib/toast.svelte` | Toast 通知组件 |

## 数据流

1. **身份初始化**：生成 Ed25519 密钥对 → Argon2id 口令派生加密密钥 → AES-256-GCM 加密私钥 → 存入 SQLite
2. **E2EE 会话建立**：发起方生成 X25519 临时密钥对 → Ed25519 签名 → Relay 转发 KeyExchange → 对方派生会话密钥 → KeyConfirm 确认 → 会话激活
3. **消息发送**：Svelte UI → `invoke('send_message')` → Ed25519 签名 → 存入本地 SQLite → 加入 pending 队列 → Relay 转发 → 收到 ACK 后清理 pending
4. **消息接收**：Relay WebSocket 推送 → 存入本地 SQLite → Tauri 事件广播 → Svelte 前端更新
5. **联系人同步**：`sync_online_contacts` → HTTP 拉取 Relay `/users` → 更新本地 last_seen → 合并返回

## 项目状态

当前处于 **阶段二/阶段三** 交界，核心模块已实现，E2EE 消息流已打通。

### 已实现

- [x] Ed25519 身份密钥生成、助记词导入/导出
- [x] Argon2id 口令派生 + AES-256-GCM 私钥加密存储
- [x] X25519 临时密钥交换 + HKDF 会话密钥派生
- [x] AES-256-GCM 消息加解密、Ed25519 签名/验签
- [x] SQLite 消息/身份/联系人/群组/设备/pending 全表 CRUD
- [x] 联系人管理（加密昵称 + 在线状态同步）
- [x] Pending 队列 + 后台重试循环
- [x] WebSocket Relay 客户端（连接/心跳/消息收发/ACK/撤回）
- [x] axum Relay 服务器（消息缓存/转发/E2EE 协商投递/在线用户）
- [x] 消息撤回（本地 + Relay 广播）
- [x] E2EE 会话状态机 + 待发明文队列 + 超时处理
- [x] 双向聊天记录查询
- [x] Svelte 5 前端（聊天界面 + 身份设置 + Toast 通知）

### 待开发

- [ ] 群组管理、群密钥轮转、群消息加解密
- [ ] 多设备绑定流程、设备撤销
- [ ] 媒体上传/下载（OSS/R2）
- [ ] 后台守护进程 + 离线消息同步
- [ ] 完整 UI（群组界面、通讯录、设置）
- [ ] 集成测试

详细任务分解请查看 [TODO.md](TODO.md)。

## 快速开始

### 环境要求

- Node.js 18+
- Rust 1.70+
- Tauri CLI v2

### 开发

```bash
# 安装前端依赖
npm install

# 启动 Relay 服务器（开发模式，默认 0.0.0.0:8080）
npm run relay:dev

# 前端开发（SvelteKit 服务于 port 1420）
npm run dev

# Tauri 开发（带原生窗口，连接 Relay 后可使用完整功能）
npm run tauri dev

# 仅构建前端
npm run build

# 预览构建后的前端
npm run preview

# Rust 类型检查
npm run review

# 构建 Relay 服务器（release）
npm run relay:build

# E2E 测试
npm run test:e2e
```

## 安全说明

- Relay 无法解密消息（仅转发加密数据，不持有任何私钥）
- 消息使用 Ed25519 签名保证完整性与不可否认性
- 身份由用户控制的助记词备份保护（32 词 BIP39 词表）
- 私钥使用 Argon2id 口令派生密钥加密存储，开发模式支持零密钥快速迭代
- 临时密钥在 Drop 时自动 zeroize，会话密钥内存安全

## 协议文档

- [技术方案设计文档](doc/技术方案设计文档.md) - 详细系统设计
- [初版需求](doc/初版需求.txt) - 产品需求文档
- [TODO 清单](TODO.md) - 任务分解与里程碑
