/**
 * 端到端聊天测试脚本
 *
 * 测试两个用户之间的 WebSocket 消息收发：
 * 1. 启动两个独立的 WebSocket 连接（模拟两个客户端）
 * 2. 建立 relay 连接
 * 3. 双向发送消息并验证接收
 *
 * 用法：node test/e2e-chat.mjs
 */

import { WebSocket } from 'ws';
import crypto from 'crypto';

// 工具函数
function delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function uuid() {
    return crypto.randomUUID();
}

function base64Encode(buffer) {
    return Buffer.from(buffer).toString('base64');
}

// 构造 ChatMessage
function buildChatMessage({ event_id, from, to, payload, timestamp, signature }) {
    return {
        type: 'chat_message',
        event_id,
        from,
        to,
        payload,
        media_id: null,
        timestamp,
        signature,
    };
}

// 生成临时 Ed25519 密钥对（仅用于测试，不涉及真实身份）
function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
        publicKeyEncoding: { type: 'spki', format: 'der' },
        privateKeyEncoding: { type: 'pkcs8', format: 'der' },
    });
    // x25519 公钥转换为 Curve25519
    const publicKeyBase64 = base64Encode(publicKey);
    const privateKeyBase64 = base64Encode(privateKey);
    return { publicKey: publicKeyBase64, privateKey: privateKeyBase64 };
}

class TestClient {
    constructor(pubkey) {
        this.pubkey = pubkey;
        this.ws = null;
        this.relayUrl = null;
        this.receivedMessages = [];
        this.onMessage = null;
    }

    async connect(relayUrl) {
        this.relayUrl = relayUrl.startsWith('ws') ? relayUrl : `ws://${relayUrl}`;
        const wsUrl = `${this.relayUrl}/ws/${encodeURIComponent(this.pubkey)}`;

        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(wsUrl);

            this.ws.on('open', () => {
                console.log(`  [${this.pubkey.slice(0, 8)}...] WebSocket connected`);
                resolve();
            });

            this.ws.on('error', (err) => {
                console.error(`  [${this.pubkey.slice(0, 8)}...] WebSocket error:`, err.message);
                reject(err);
            });

            this.ws.on('message', (data) => {
                try {
                    const msg = JSON.parse(data.toString());
                    this._handleMessage(msg);
                } catch (e) {
                    console.error(`  [${this.pubkey.slice(0, 8)}...] Failed to parse message:`, e.message);
                }
            });

            this.ws.on('close', () => {
                console.log(`  [${this.pubkey.slice(0, 8)}...] WebSocket closed`);
            });
        });
    }

    _handleMessage(msg) {
        if (msg.type === 'pong') {
            console.log(`  [${this.pubkey.slice(0, 8)}...] Received Pong`);
            return;
        }
        if (msg.type === 'chat_message') {
            console.log(`  [${this.pubkey.slice(0, 8)}...] Received: "${msg.payload}" from ${msg.from.slice(0, 8)}...`);
            this.receivedMessages.push(msg);
            if (this.onMessage) {
                this.onMessage(msg);
            }
        }
        if (msg.type === 'message_recall') {
            console.log(`  [${this.pubkey.slice(0, 8)}...] Received Recall for ${msg.ref_event_id}`);
        }
    }

    send(payload, to) {
        const event_id = uuid();
        const timestamp = Date.now();
        const msg = buildChatMessage({
            event_id,
            from: this.pubkey,
            to,
            payload,
            timestamp,
            signature: 'test-signature',
        });

        this.ws.send(JSON.stringify(msg));
        console.log(`  [${this.pubkey.slice(0, 8)}...] Sent: "${payload}" to ${to.slice(0, 8)}...`);
        return event_id;
    }

    async disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

async function main() {
    const relayUrl = process.argv[2] || 'localhost:8080';
    const fullRelayUrl = relayUrl.startsWith('ws') ? relayUrl : `ws://${relayUrl}`;

    console.log('=== 端到端聊天测试 ===');
    console.log(`Relay: ${fullRelayUrl}\n`);

    // 生成两个测试身份
    const alice = generateKeyPair();
    const bob = generateKeyPair();
    console.log(`Alice: ${alice.publicKey.slice(0, 16)}...`);
    console.log(`Bob:   ${bob.publicKey.slice(0, 16)}...\n`);

    // 连接
    console.log('--- 建立连接 ---');
    const aliceClient = new TestClient(alice.publicKey);
    const bobClient = new TestClient(bob.publicKey);

    try {
        await Promise.all([
            aliceClient.connect(fullRelayUrl),
            bobClient.connect(fullRelayUrl),
        ]);
    } catch (e) {
        console.error('连接失败:', e.message);
        process.exit(1);
    }

    // 等待连接稳定
    await delay(500);

    // 测试1: Alice 发给 Bob
    console.log('\n--- 测试1: Alice -> Bob ---');
    aliceClient.send('Hello Bob!', bob.publicKey);
    await delay(300);

    // 测试2: Bob 发给 Alice
    console.log('\n--- 测试2: Bob -> Alice ---');
    bobClient.send('Hi Alice!', alice.publicKey);
    await delay(300);

    // 测试3: Bob 发给 Bob 自己（自聊）
    console.log('\n--- 测试3: Bob -> Bob (自聊) ---');
    bobClient.send('Talking to myself...', bob.publicKey);
    await delay(300);

    // 等待所有消息到达
    await delay(1000);

    // 验证结果
    console.log('\n--- 验证结果 ---');
    let passed = true;

    // Bob 应该收到 Alice 的消息
    const bobFromAlice = bobClient.receivedMessages.filter(m => m.from === alice.publicKey);
    if (bobFromAlice.length === 0) {
        console.error('FAIL: Bob 没有收到 Alice 的消息');
        passed = false;
    } else {
        console.log(`PASS: Bob 收到 Alice 的消息 (${bobFromAlice.length} 条)`);
    }

    // Alice 应该收到 Bob 的消息
    const aliceFromBob = aliceClient.receivedMessages.filter(m => m.from === bob.publicKey);
    if (aliceFromBob.length === 0) {
        console.error('FAIL: Alice 没有收到 Bob 的消息');
        passed = false;
    } else {
        console.log(`PASS: Alice 收到 Bob 的消息 (${aliceFromBob.length} 条)`);
    }

    // Bob 收好自己发自己的消息（relay 不回显，自己发给自己 relay 会转发）
    const bobFromBob = bobClient.receivedMessages.filter(m => m.from === bob.publicKey);
    if (bobFromBob.length === 0) {
        console.error('FAIL: Bob 没有收到自己发给自己的消息');
        passed = false;
    } else {
        console.log(`PASS: Bob 收到自己发给自己的消息 (${bobFromBob.length} 条)`);
    }

    // 清理
    console.log('\n--- 断开连接 ---');
    await Promise.all([
        aliceClient.disconnect(),
        bobClient.disconnect(),
    ]);

    await delay(300);

    if (passed) {
        console.log('\n=== 全部测试通过 ===');
        process.exit(0);
    } else {
        console.error('\n=== 存在测试失败 ===');
        process.exit(1);
    }
}

main().catch(e => {
    console.error('测试异常:', e);
    process.exit(1);
});