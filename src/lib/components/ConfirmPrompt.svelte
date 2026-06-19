<script lang="ts">
  import { onMount, onDestroy } from "svelte";
  import { listen, type UnlistenFn } from "@tauri-apps/api/event";
  import { invoke } from "@tauri-apps/api/core";

  let prompt: string | null = null;
  let unlisten: UnlistenFn | null = null;

  async function answer(allow: boolean) {
    prompt = null;
    await invoke("answer_confirm", { allow });
  }

  onMount(async () => {
    unlisten = await listen<string>("protec://confirm", (e) => {
      prompt = e.payload;
    });
    window.addEventListener("keydown", onKey);
  });
  onDestroy(() => {
    if (unlisten) unlisten();
    window.removeEventListener("keydown", onKey);
  });

  function onKey(e: KeyboardEvent) {
    if (prompt === null) return;
    if (e.key === "Enter") { e.preventDefault(); answer(true); }
    else if (e.key === "Escape") { e.preventDefault(); answer(false); }
  }
</script>

{#if prompt !== null}
  <div class="overlay" role="dialog" aria-label="Confirm request">
    <div class="box">
      <p class="msg">{prompt}</p>
      <p class="hint">A browser extension is requesting access to your vault.</p>
      <div class="row">
        <button class="allow" on:click={() => answer(true)}>Allow ↵</button>
        <button on:click={() => answer(false)}>Deny Esc</button>
      </div>
    </div>
  </div>
{/if}

<style>
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.6); display: flex;
    justify-content: center; align-items: center; z-index: 100; }
  .box { width: 360px; background: var(--bg-elev); border: 1px solid var(--accent);
    border-radius: 10px; padding: 18px; }
  .msg { color: var(--text); font-size: 14px; margin: 0 0 6px; }
  .hint { color: var(--text-dim); font-size: 11px; margin: 0 0 14px; }
  .row { display: flex; gap: 8px; }
  .row button { flex: 1; padding: 8px; background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer; }
  .allow { background: var(--accent); color: #fff; border: 0; }
</style>
