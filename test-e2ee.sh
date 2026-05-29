#!/bin/bash
# E2EE 一对一聊天端到端加密测试脚本
# 用法: bash test-e2ee.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass=0
fail=0

run_test() {
    local name="$1"
    shift
    echo -n "  TEST: $name ... "
    if "$@" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS${NC}"
        ((pass++))
    else
        echo -e "${RED}FAIL${NC}"
        ((fail++))
    fi
}

echo "========================================"
echo " E2EE 一对一聊天测试"
echo "========================================"
echo ""

# ------ 1. 编译检查 ------
echo -e "${YELLOW}[1/4] 编译检查${NC}"
run_test "cargo check" cargo check --manifest-path src-tauri/Cargo.toml
echo ""

# ------ 2. 单元测试 ------
echo -e "${YELLOW}[2/4] 单元测试${NC}"

echo "  --- crypto.rs ---"
run_test "keypair generation" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_generate_x25519_keypair
run_test "keypair uniqueness" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_generate_x25519_keypair_unique
run_test "session key derivation" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_derive_session_key_deterministic
run_test "session key different info" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_derive_session_key_different_info
run_test "encrypt/decrypt roundtrip" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_encrypt_decrypt_roundtrip
run_test "encrypt/decrypt with AAD" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_encrypt_decrypt_with_aad
run_test "decrypt wrong key fails" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_decrypt_with_wrong_key_fails
run_test "decrypt wrong AAD fails" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_decrypt_with_wrong_aad_fails
run_test "decrypt too short" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_decrypt_too_short_ciphertext
run_test "encrypt nonce random" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_encrypt_produces_different_ciphertext_each_time
run_test "sign and verify" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_sign_and_verify
run_test "verify wrong data" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_verify_wrong_data_fails
run_test "verify wrong key" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_verify_wrong_key_fails
run_test "e2ee full flow" cargo test --manifest-path src-tauri/Cargo.toml -- crypto::tests::test_e2ee_full_flow

echo ""
echo "  --- session.rs ---"
run_test "new session status" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_new_session_status
run_test "initiate key exchange" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_initiate_key_exchange
run_test "prevent duplicate exchange" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_initiate_key_exchange_prevents_duplicate
run_test "handle key exchange" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_handle_key_exchange_derives_session_key
run_test "handle exchange no key" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_handle_key_exchange_without_ephemeral_key_fails
run_test "handle exchange rekeying" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_handle_key_exchange_triggers_rekeying
run_test "confirm session" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_confirm_session
run_test "confirm wrong status" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_confirm_session_wrong_status_fails
run_test "enqueue and flush" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_enqueue_and_flush_pending_plaintext
run_test "enqueue wrong status" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_enqueue_rejects_wrong_status
run_test "enqueue full queue" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_enqueue_rejects_full_queue
run_test "session encrypt/decrypt" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_encrypt_decrypt_roundtrip
run_test "session decrypt wrong key" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_decrypt_with_wrong_key_fails
run_test "session encrypt no key" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_encrypt_without_key_fails
run_test "manager get or create" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_session_manager_get_or_create
run_test "manager get none" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_session_manager_get_none
run_test "manager remove" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_session_manager_remove
run_test "ephemeral pubkey derivation" cargo test --manifest-path src-tauri/Cargo.toml -- session::tests::test_my_ephemeral_pubkey_derivation

echo ""
echo "  --- db.rs ---"
run_test "insert and get message" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_insert_and_get_message
run_test "update payload and signature" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_update_message_payload_and_signature
run_test "update nonexistent message" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_update_nonexistent_message
run_test "mark delivered" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_mark_delivered
run_test "mark recalled" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_mark_recalled
run_test "get next seq id" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_get_next_seq_id
run_test "pending messages" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_pending_messages
run_test "settings" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_settings
run_test "contacts" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_contacts
run_test "identity" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_identity
run_test "group operations" cargo test --manifest-path src-tauri/Cargo.toml -- db::tests::test_group_operations

echo ""

# ------ 3. 运行全部测试 ------
echo -e "${YELLOW}[3/4] 运行全部测试 (cargo test)${NC}"
cargo test --manifest-path src-tauri/Cargo.toml 2>&1 | tail -5
echo ""

# ------ 4. 前端构建 ------
echo -e "${YELLOW}[4/4] 前端构建检查${NC}"
run_test "npm run build" npm run build
echo ""

# ------ 结果汇总 ------
echo "========================================"
echo -e " 结果: ${GREEN}${pass} passed${NC}, ${RED}${fail} failed${NC}"
echo "========================================"

if [ $fail -gt 0 ]; then
    exit 1
fi
