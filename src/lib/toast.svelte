<script>
  import { getToasts } from './toast.svelte.js';
</script>

<div class="toast-container">
  {#each getToasts() as toast (toast.id)}
    <div class="toast toast-{toast.type}">
      {toast.message}
    </div>
  {/each}
</div>

<style>
  .toast-container {
    position: fixed;
    top: 1rem;
    right: 1rem;
    z-index: 9999;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    pointer-events: none;
  }

  .toast {
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    font-size: 0.9rem;
    color: #fff;
    background: #da3633;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    animation: slideIn 0.2s ease-out;
    max-width: 320px;
  }

  .toast.error {
    background: #da3633;
  }

  .toast.success {
    background: #238636;
  }

  .toast.info {
    background: #388bfd;
  }

  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
</style>