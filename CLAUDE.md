# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Decentralized IM** is a decentralized end-to-end encrypted instant messaging system built with Tauri + Rust Core + Svelte 5. The project is in early development stage (Phase 1) per the TODO.md roadmap.

Key technologies:
- **Desktop Framework**: Tauri v2 (20-80MB memory footprint)
- **Frontend**: SvelteKit with static adapter, Svelte 5 runes ($state, $props)
- **Backend**: Rust with async runtime (tokio)
- **Database**: SQLite via rusqlite (bundled)
- **Crypto**: X25519, Ed25519, AES-256-GCM, BLAKE3, HKDF

## Development Commands

```bash
# Frontend development (SvelteKit dev server on port 1420)
npm run dev

# Build frontend only
npm run build

# Preview built frontend
npm run preview

# Tauri commands (build, dev, etc.)
npm run tauri dev
npm run tauri build
```

## Architecture

### Rust Backend (`src-tauri/`)

The Rust core exposes Tauri commands invoked from the Svelte frontend via `invoke()`.

**Module structure:**
- `lib.rs` — App entry, state management (AppState with db + identity), logging setup
- `main.rs` — Windows subsystem entry point
- `crypto.rs` — Cryptographic primitives (identity/device key generation, session key derivation via HKDF, AES-256-GCM encrypt/decrypt, Ed25519 sign/verify, BLAKE3/SHA256 hash)
- `db.rs` — SQLite database layer with tables: messages, groups, group_members, devices, pending_messages, group_keys, identities, settings
- `identity.rs` — Identity key management with mnemonic word-list backup/export
- `message.rs` — Message send/get/recall operations with pending queue
- `relay.rs` — WebSocket relay connection state (currently stub with in-memory state)
- `error.rs` — Custom Error enum with serialization support

**AppState** (thread-safe):
```rust
pub struct AppState {
    pub db: Arc<Mutex<db::Database>>,
    pub identity: Arc<RwLock<identity::IdentityManager>>,
}
```

### Svelte Frontend (`src/`)

- `src/routes/+page.svelte` — Main chat UI with sidebar navigation (Chats, Groups, Devices, Settings)
- `src/routes/+layout.svelte` — Root layout with global styles

### Data Flow

1. **Message sending**: Svelte UI → `invoke('send_message')` → Rust `message.rs` → SQLite + pending queue
2. **Identity**: Generated/imported via mnemonic → stored encrypted in SQLite
3. **Relay**: Connection state managed in `relay.rs` (not yet connected to real server)

### Database Schema (SQLite)

Key tables:
- `messages` — event_id, type, from/to pubkeys, payload, timestamp, seq_id, signature, delivered, recalled
- `pending_messages` — unconfirmed messages for retry
- `groups` / `group_members` — group structure with owner and role-based members
- `devices` — device pubkeys bound to identity
- `identities` — encrypted identity key storage

## Key Constraints

- **Encryption key derivation**: Currently hardcoded zero-key `[0u8; 32]` for identity decryption — this is a placeholder
- **Relay client**: `relay.rs` has connection state but no actual WebSocket implementation yet
- **Multi-device**: Device binding flow is designed but not implemented
- **Group keys**: Stored in Redis on relay side, not yet implemented in client

## TODO.md Phases

The project follows a 10-phase development roadmap:
- Phase 1: Infrastructure (T1.1-T1.3)
- Phase 2: Identity & Encryption (T2.1-T2.2)
- Phase 3: Messaging (T3.1-T3.4)
- Phase 4: Groups (T4.1-T4.3)
- Phase 5: Multi-device (T5.1-T5.2)
- Phase 6: Media (T6.1-T6.2)
- Phase 7: Sync & Daemon (T7.1-T7.2)
- Phase 8: UI (T8.1)
- Phase 9: Relay server (T9.1)
- Phase 10: Testing (T10.1)
