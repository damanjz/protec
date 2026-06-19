<script lang="ts">
  export let message = "";
  export let kind: "info" | "error" = "info";
</script>

{#if message}
  <div class="toast {kind}">{message}</div>
{/if}

<style>
  .toast {
    position: fixed; bottom: 16px; left: 50%; transform: translateX(-50%);
    padding: 8px 14px; border-radius: 6px; border: 1px solid var(--border);
    background: var(--bg-elev); color: var(--text); font-size: 12px;
  }
  .error { border-color: var(--danger); color: var(--danger); }
</style>
