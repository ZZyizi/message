<script>
  import { onMount } from 'svelte';
  import { invoke } from '@tauri-apps/api/core';
  import { showToast } from '$lib/toast.svelte.js';

  let username = $state('');
  let isLoading = $state(false);
  let pubkey = $state('');

  onMount(async () => {
    await loadProfile();
  });

  async function loadProfile() {
    try {
      isLoading = true;
      pubkey = await invoke('get_public_key');
    } catch (e) {
      console.error('Failed to load profile:', e);
    } finally {
      isLoading = false;
    }
  }

  async function createIdentity() {
    if (!username.trim()) {
      showToast('请输入用户名');
      return;
    }
    try {
      isLoading = true;
      const result = await invoke('auto_create_identity');
      pubkey = result;
      showToast('身份创建成功！');
    } catch (e) {
      console.error('Failed to create identity:', e);
      showToast('创建失败: ' + (e?.message || e));
    } finally {
      isLoading = false;
    }
  }
</script>

<main>
  <div class="profile-container">
    <a href="/" class="btn-back">返回聊天</a>
    <h1>个人中心</h1>

    <div class="profile-card">
      <div class="avatar-section">
        <div class="avatar large">
          {username ? username[0].toUpperCase() : '?'}
        </div>
      </div>

      <div class="form-section">
        <div class="form-group">
          <label for="username">用户名</label>
          <input
            id="username"
            type="text"
            bind:value={username}
            placeholder="输入用户名"
            disabled={isLoading}
          />
        </div>

        <div class="form-group">
          <label>公钥</label>
          <div class="pubkey-display">
            {pubkey || '暂无'}
          </div>
        </div>

        <button class="btn-primary" onclick={createIdentity} disabled={isLoading}>
          {isLoading ? '创建中...' : '创建身份'}
        </button>
      </div>
    </div>
  </div>
</main>

<style>
  main {
    flex: 1;
    display: flex;
    flex-direction: column;
    padding: 2rem;
    overflow-y: auto;
  }

  .btn-back {
    display: inline-flex;
    align-items: center;
    padding: 0.4rem 1rem;
    border-radius: 6px;
    border: none;
    font-size: 0.85rem;
    cursor: pointer;
    transition: all 0.2s;
    background: #21262d;
    color: #e6edf3;
    text-decoration: none;
    margin-bottom: 1rem;
    width: fit-content;
  }

  .btn-back:hover {
    background: #30363d;
  }

  h1 {
    margin: 0 0 2rem 0;
    font-size: 1.5rem;
    color: #e6edf3;
  }

  .profile-container {
    max-width: 480px;
    margin: 0 auto;
    width: 100%;
  }

  .profile-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 2rem;
  }

  .avatar-section {
    display: flex;
    justify-content: center;
    margin-bottom: 2rem;
  }

  .avatar {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: #238636;
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 600;
    font-size: 2rem;
    color: #fff;
  }

  .form-section {
    display: flex;
    flex-direction: column;
    gap: 1.25rem;
  }

  .form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  label {
    font-size: 0.875rem;
    color: #8b949e;
  }

  input {
    padding: 0.75rem 1rem;
    border: 1px solid #30363d;
    border-radius: 8px;
    background: #0d1117;
    color: #e6edf3;
    font-size: 1rem;
  }

  input:focus {
    outline: none;
    border-color: #58a6ff;
  }

  input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .pubkey-display {
    padding: 0.75rem 1rem;
    border: 1px solid #30363d;
    border-radius: 8px;
    background: #0d1117;
    color: #8b949e;
    font-size: 0.85rem;
    word-break: break-all;
    font-family: monospace;
    min-height: 2.5rem;
  }

  .btn-primary {
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    border: none;
    background: #238636;
    color: #fff;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.2s;
  }

  .btn-primary:hover:not(:disabled) {
    background: #2ea043;
  }

  .btn-primary:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }
</style>