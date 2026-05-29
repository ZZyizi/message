<script>
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { listen } from '@tauri-apps/api/event';
  import { showToast } from '$lib/toast.svelte.js';

  let status = $state('disconnected');
  let relayUrl = $state('ws://localhost:8080');
  let messages = $state([]);
  let inputMessage = $state('');
  let currentContact = $state(null);
  let contacts = $state([]);
  let isConnected = $state(false);
  let myPubkey = $state('');
  let myNickname = $state('');
  let sessionStatus = $state('None');

  onMount(async () => {
    // 获取我的公钥和昵称
    try {
      myPubkey = await invoke('get_public_key');
      myNickname = await invoke('get_nickname') || '';
    } catch (e) {
      console.error('Failed to get pubkey:', e);
    }

    // 同步后端连接状态（页面重新挂载时恢复 UI）
    try {
      const relayStatus = await invoke('get_status');
      if (relayStatus.state === 'connected') {
        status = 'connected';
        isConnected = true;
        relayUrl = relayStatus.relay_url || relayUrl;
        await loadContacts();
      }
    } catch (e) {
      console.error('Failed to get relay status:', e);
    }

    // 订阅新消息事件（只处理来自对方的消息，忽略自己的回显）
    const unlistenNewMsg = await listen('new_message', (event) => {
      const msg = event.payload;
      // 忽略自己发送的消息（relay 会回显给发送者）
      if (msg.from_pubkey === myPubkey) return;
      // 只处理与当前聊天对象相关的消息
      if (currentContact && msg.from_pubkey === currentContact.pubkey) {
        // 避免重复：检查是否已存在相同 event_id
        if (!messages.some(m => m.event_id === msg.event_id)) {
          messages = [...messages, msg];
        }
      }
    });

    // 订阅消息撤回事件
    const unlistenRecall = await listen('message_recalled', (event) => {
      const eventId = event.payload;
      messages = messages.map(m => m.event_id === eventId ? { ...m, recalled: true } : m);
    });

    // 定时刷新联系人列表（每 15 秒）
    const refreshInterval = setInterval(async () => {
      if (isConnected) {
        await loadContacts();
      }
    }, 15000);

    // 订阅会话超时事件
    const unlistenTimeout = await listen('session_timeout', (event) => {
      const peerPubkey = event.payload;
      if (currentContact && currentContact.pubkey === peerPubkey) {
        sessionStatus = 'Timeout';
        showToast('密钥协商超时，请重试');
      }
    });

    return () => {
      unlistenNewMsg();
      unlistenRecall();
      unlistenTimeout();
      clearInterval(refreshInterval);
    };
  });

  async function connect() {
    try {
      status = 'connecting';
      const result = await invoke('connect', { relayUrl });
      status = 'connected';
      isConnected = true;
      await loadContacts();
    } catch (e) {
      console.error('Failed to connect:', e);
      showToast('连接失败: ' + (e?.message || e));
      status = 'error';
    }
  }

  async function loadContacts() {
    if (!isConnected) return;
    try {
      const result = await invoke('sync_online_contacts');
      contacts = (result || []).map((c, index) => {
        const isMe = c.pubkey === myPubkey;
        const displayName = isMe
          ? (myNickname ? myNickname + ' (我)' : '我')
          : (c.nickname || (c.pubkey.substring(0, 8) + '...'));
        return {
          id: `contact_${index}`,
          name: displayName,
          pubkey: c.pubkey,
          is_online: c.is_online,
          is_me: isMe,
          last_seen: c.last_seen,
          lastMessage: '',
          lastTime: '',
        };
      });
    } catch (e) {
      console.error('Failed to load contacts:', e);
    }
  }

  async function disconnect() {
    try {
      await invoke('disconnect');
      status = 'disconnected';
      isConnected = false;
    } catch (e) {
      console.error('Failed to disconnect:', e);
      showToast('断开连接失败: ' + (e?.message || e));
    }
  }

  async function sendMessage() {
    if (!inputMessage.trim() || !currentContact) return;

    // 检查会话状态
    if (sessionStatus !== 'Active') {
      showToast('安全通道尚未建立，请稍候...');
      return;
    }

    try {
      const result = await invoke('send_chat_message', {
        to: currentContact.pubkey,
        payload: inputMessage,
        mediaId: null,
      });

      // 立即显示发送的消息
      const sentMsg = {
        id: result,
        event_id: result,
        from_pubkey: myPubkey,
        to_recipient: currentContact.pubkey,
        payload: inputMessage,
        timestamp: Date.now(),
        delivered: false,
        recalled: false,
      };
      messages = [...messages, sentMsg];
      inputMessage = '';
    } catch (e) {
      console.error('Failed to send:', e);
      showToast('发送消息失败: ' + (e?.message || e));
    }
  }

  async function selectContact(contact) {
    currentContact = contact;
    sessionStatus = 'None';
    await loadChat(contact.pubkey);

    // 发起密钥协商
    try {
      console.log('Initiating key exchange with:', contact.pubkey);
      await invoke('initiate_key_exchange', { peerPubkey: contact.pubkey });
      console.log('Key exchange initiated successfully');
      // 轮询会话状态
      const pollInterval = setInterval(async () => {
        try {
          const status = await invoke('get_session_status', { peerPubkey: contact.pubkey });
          console.log('Session status:', status);
          sessionStatus = status;
          if (status === 'Active') {
            clearInterval(pollInterval);
          }
        } catch (e) {
          console.error('Failed to get session status:', e);
        }
      }, 1000);

      // 30秒超时
      setTimeout(() => {
        clearInterval(pollInterval);
        if (sessionStatus !== 'Active') {
          sessionStatus = 'Timeout';
        }
      }, 30000);
    } catch (e) {
      console.error('Failed to initiate key exchange:', e);
    }
  }

  async function loadChat(peerPubkey) {
    if (!peerPubkey) return;
    try {
      const msgs = await invoke('get_chat_messages', { peerPubkey });
      messages = msgs || [];
    } catch (e) {
      console.error('Failed to load messages:', e);
      messages = [];
    }
  }

  function handleKeydown(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  }

  function formatTime(timestamp) {
    if (!timestamp) return '';
    const d = new Date(timestamp);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }
</script>

<main>
  <header>
    <div class="header-left">
      <h1>Decentralized IM</h1>
      <span class="status-dot" class:connected={isConnected} class:connecting={status === 'connecting'}></span>
    </div>
    <div class="header-right">
      <a href="/profile" class="btn-profile">个人中心</a>
      {#if !isConnected}
        <input
          type="text"
          bind:value={relayUrl}
          placeholder="Relay URL"
          class="relay-input"
        />
        <button class="btn-primary" onclick={connect}>Connect</button>
      {:else}
        <span class="status-text">{status}</span>
        <button class="btn-secondary" onclick={disconnect}>Disconnect</button>
      {/if}
    </div>
  </header>

  <div class="container">
    <aside class="sidebar">
      <div class="search-box">
        <input type="text" placeholder="Search conversations..." />
      </div>
      <nav class="contact-list">
        {#if contacts.length === 0}
          <div class="empty-contacts">暂无联系人</div>
        {/if}
        {#each contacts as contact}
          <button
            class="contact-item"
            class:active={currentContact?.id === contact.id}
            onclick={() => selectContact(contact)}
          >
            <div class="avatar">
              {contact.name[0].toUpperCase()}
            </div>
            <div class="contact-info">
              <div class="contact-name">
                {contact.name}
                <span class="online-dot" class:online={contact.is_online}></span>
              </div>
              <div class="contact-preview">{contact.lastMessage}</div>
            </div>
            <div class="contact-time">{contact.lastTime}</div>
          </button>
        {/each}
      </nav>
    </aside>

    <section class="chat-area">
      {#if currentContact}
        <div class="chat-header">
          <div class="avatar large">
            {currentContact.name[0].toUpperCase()}
          </div>
          <div class="chat-header-info">
            <div class="chat-header-name">{currentContact.name}</div>
            <div class="chat-header-status">
              {currentContact.is_online ? '在线' : '离线'}
            </div>
          </div>
        </div>

        <div class="messages">
          {#if messages.length === 0}
            <div class="empty-messages">
              <p>No messages yet</p>
              <p class="hint">Send a message to start the conversation</p>
            </div>
          {:else}
            {#each messages as msg}
              <div class="message" class:sent={msg.from_pubkey === myPubkey} class:received={msg.from_pubkey !== myPubkey}>
                <div class="message-content">
                  <div class="message-payload">{msg.payload}</div>
                  <div class="message-meta">
                    <span class="message-time">{formatTime(msg.timestamp)}</span>
                    {#if msg.from_pubkey === myPubkey && !msg.delivered}
                      <span class="message-status">Sending...</span>
                    {/if}
                  </div>
                </div>
              </div>
            {/each}
          {/if}
        </div>

        <div class="chat-input-area">
          {#if sessionStatus !== 'Active'}
            <div class="session-status-bar">
              {#if sessionStatus === 'None' || sessionStatus === 'WaitingForPeer'}
                正在建立安全通道...
              {:else if sessionStatus === 'Timeout'}
                密钥协商失败
                <button onclick={() => selectContact(currentContact)}>重试</button>
              {:else}
                正在确认密钥...
              {/if}
            </div>
          {/if}

          <textarea
            bind:value={inputMessage}
            onkeydown={handleKeydown}
            placeholder={sessionStatus === 'Active' ? 'Type a message...' : 'Waiting for secure channel...'}
            class="chat-input"
            rows="1"
            disabled={sessionStatus !== 'Active'}
          ></textarea>
          <button class="btn-send" onclick={sendMessage} disabled={!inputMessage.trim() || sessionStatus !== 'Active'}>
            Send
          </button>
        </div>
      {:else}
        <div class="no-chat-selected">
          <h2>Select a conversation</h2>
          <p>Choose a contact from the sidebar to start messaging</p>
        </div>
      {/if}
    </section>
  </div>
</main>

<style>
  main {
    height: 100vh;
    display: flex;
    flex-direction: column;
    background: #0d1117;
  }

  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem 1.5rem;
    background: #161b22;
    border-bottom: 1px solid #30363d;
  }

  .header-left {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  header h1 {
    font-size: 1.1rem;
    margin: 0;
    color: #e6edf3;
  }

  .status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6e7681;
  }

  .status-dot.connected {
    background: #3fb950;
  }

  .status-dot.connecting {
    background: #d29922;
    animation: pulse 1s infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .relay-input {
    padding: 0.4rem 0.75rem;
    border: 1px solid #30363d;
    border-radius: 6px;
    background: #0d1117;
    color: #e6edf3;
    font-size: 0.85rem;
    width: 180px;
  }

  .status-text {
    font-size: 0.85rem;
    color: #8b949e;
  }

  .btn-primary, .btn-secondary {
    padding: 0.4rem 1rem;
    border-radius: 6px;
    border: none;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
  }

  .btn-primary {
    background: #238636;
    color: #fff;
  }

  .btn-primary:hover {
    background: #2ea043;
  }

  .btn-secondary {
    background: #30363d;
    color: #e6edf3;
  }

  .btn-secondary:hover {
    background: #484f58;
  }

  .btn-profile {
    padding: 0.4rem 1rem;
    border-radius: 6px;
    border: none;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
    background: #21262d;
    color: #e6edf3;
    text-decoration: none;
    display: inline-flex;
    align-items: center;
  }

  .btn-profile:hover {
    background: #30363d;
  }

  .container {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  .sidebar {
    width: 280px;
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
  }

  .search-box {
    padding: 1rem;
  }

  .empty-contacts {
    padding: 1rem;
    color: #8b949e;
    font-size: 0.85rem;
    text-align: center;
  }

  .search-box input {
    width: 100%;
    padding: 0.6rem 1rem;
    border: 1px solid #30363d;
    border-radius: 6px;
    background: #0d1117;
    color: #e6edf3;
    box-sizing: border-box;
  }

  .contact-list {
    flex: 1;
    overflow-y: auto;
    padding: 0 0.5rem 1rem;
  }

  .contact-item {
    display: flex;
    align-items: center;
    width: 100%;
    padding: 0.75rem;
    border: none;
    background: transparent;
    border-radius: 6px;
    cursor: pointer;
    text-align: left;
    color: #e6edf3;
    margin-bottom: 0.25rem;
  }

  .contact-item:hover {
    background: #1c2128;
  }

  .contact-item.active {
    background: #21262d;
  }

  .avatar {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    background: #30363d;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    color: #8b949e;
    flex-shrink: 0;
  }

  .avatar.large {
    width: 48px;
    height: 48px;
    font-size: 1.2rem;
  }

  .contact-info {
    flex: 1;
    margin-left: 0.75rem;
    min-width: 0;
  }

  .contact-name {
    font-weight: 500;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .online-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: #6e7681;
    flex-shrink: 0;
  }

  .online-dot.online {
    background: #3fb950;
  }

  .group-badge {
    font-size: 0.7rem;
    background: #388bfd33;
    color: #58a6ff;
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
  }

  .contact-preview {
    font-size: 0.85rem;
    color: #8b949e;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .contact-time {
    font-size: 0.75rem;
    color: #6e7681;
    flex-shrink: 0;
    margin-left: 0.5rem;
  }

  .chat-area {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  .chat-header {
    display: flex;
    align-items: center;
    padding: 1rem 1.5rem;
    background: #161b22;
    border-bottom: 1px solid #30363d;
  }

  .chat-header-info {
    margin-left: 1rem;
  }

  .chat-header-name {
    font-weight: 600;
    font-size: 1rem;
  }

  .chat-header-status {
    font-size: 0.8rem;
    color: #3fb950;
  }

  .messages {
    flex: 1;
    overflow-y: auto;
    padding: 1rem;
    display: flex;
    flex-direction: column;
  }

  .empty-messages {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: #8b949e;
  }

  .empty-messages .hint {
    font-size: 0.85rem;
    margin-top: 0.5rem;
  }

  .message {
    max-width: 70%;
    margin-bottom: 0.75rem;
  }

  .message.sent {
    align-self: flex-end;
  }

  .message.received {
    align-self: flex-start;
  }

  .message-content {
    padding: 0.6rem 1rem;
    border-radius: 12px;
  }

  .message.sent .message-content {
    background: #238636;
    color: #fff;
  }

  .message.received .message-content {
    background: #21262d;
    color: #e6edf3;
  }

  .message-payload {
    word-wrap: break-word;
  }

  .message-meta {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    margin-top: 0.25rem;
    font-size: 0.7rem;
    opacity: 0.8;
  }

  .message-status {
    font-style: italic;
  }

  .no-chat-selected {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    color: #8b949e;
  }

  .chat-input-area {
    display: flex;
    flex-direction: column;
    padding: 1rem 1.5rem;
    background: #161b22;
    border-top: 1px solid #30363d;
    gap: 0.75rem;
  }

  .session-status-bar {
    padding: 0.5rem 1rem;
    background: #1c2128;
    border-bottom: 1px solid #30363d;
    font-size: 0.85rem;
    color: #d29922;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    border-radius: 6px;
  }

  .session-status-bar button {
    padding: 0.2rem 0.5rem;
    border: 1px solid #30363d;
    border-radius: 4px;
    background: #21262d;
    color: #e6edf3;
    cursor: pointer;
    font-size: 0.8rem;
  }

  .chat-input {
    flex: 1;
    padding: 0.6rem 1rem;
    border: 1px solid #30363d;
    border-radius: 8px;
    background: #0d1117;
    color: #e6edf3;
    resize: none;
    font-family: inherit;
    font-size: 0.95rem;
    max-height: 120px;
  }

  .chat-input:focus {
    outline: none;
    border-color: #58a6ff;
  }

  .btn-send {
    padding: 0.6rem 1.5rem;
    background: #238636;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn-send:hover:not(:disabled) {
    background: #2ea043;
  }

  .btn-send:disabled {
    background: #21262d;
    color: #6e7681;
    cursor: not-allowed;
  }
</style>