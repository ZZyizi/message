<script>
  import Toast from '$lib/toast.svelte';
  let { children } = $props();
</script>

<div class="app">
  {@render children()}
  <Toast />
</div>

<style>
  :global(body) {
    margin: 0;
    padding: 0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
    background: #0d1117;
    color: #e6edf3;
  }

  .app {
    height: 100vh;
    display: flex;
    flex-direction: column;
  }

  :global(::-webkit-scrollbar) {
    width: 8px;
  }

  :global(::-webkit-scrollbar-track) {
    background: #161b22;
  }

  :global(::-webkit-scrollbar-thumb) {
    background: #30363d;
    border-radius: 4px;
  }

  :global(::-webkit-scrollbar-thumb:hover) {
    background: #484f58;
  }
</style>