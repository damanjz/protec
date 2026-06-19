<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import { theme } from "../stores/vault";
  export let onClose: () => void;

  let cfg: Record<string, unknown> = {};
  let saved = false;

  onMount(async () => { cfg = await api.getConfig(); });

  async function save() {
    await api.setConfig(cfg);
    const t = (cfg.theme as "slate" | "terminal-green") ?? "slate";
    theme.set(t);
    document.documentElement.setAttribute("data-theme", t);
    saved = true;
    setTimeout(() => (saved = false), 1500);
  }
</script>

<div class="overlay" on:click={onClose} role="presentation">
  <div class="panel" on:click|stopPropagation role="dialog" aria-label="Settings">
    <h3>Settings</h3>
    <label>Auto-lock (seconds, 0 = never)
      <input type="number" min="0" bind:value={cfg.auto_lock_secs} /></label>
    <label>Clipboard clear (seconds, 0 = never)
      <input type="number" min="0" bind:value={cfg.clipboard_clear_secs} /></label>
    <label><input type="checkbox" bind:checked={cfg.auto_save} /> Auto-save after edits</label>
    <label><input type="checkbox" bind:checked={cfg.lock_on_blur} /> Lock when window loses focus</label>
    <label><input type="checkbox" bind:checked={cfg.reveal_on_select} /> Reveal password on select</label>
    <label>Theme
      <select bind:value={cfg.theme}>
        <option value="slate">Slate Dev-Tool</option>
        <option value="terminal-green">Terminal Green</option>
      </select>
    </label>
    <label>Generator length <input type="number" min="1" max="256" bind:value={cfg.gen_length} /></label>
    <div class="row">
      <button class="primary" on:click={save}>Save</button>
      <button on:click={onClose}>Close</button>
      {#if saved}<span class="ok">saved ✓</span>{/if}
    </div>
  </div>
</div>

<style>
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.5); display: flex;
    justify-content: center; align-items: flex-start; padding-top: 10vh; z-index: 50; }
  .panel { width: 460px; background: var(--bg-elev); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; display: flex; flex-direction: column; gap: 10px; }
  h3 { margin: 0 0 4px; }
  label { display: flex; align-items: center; justify-content: space-between;
    gap: 10px; color: var(--text-dim); font-size: 12px; }
  input[type="number"], select { background: var(--bg); border: 1px solid var(--border);
    color: var(--text); border-radius: 5px; padding: 4px 8px; font-family: var(--mono); }
  .row { display: flex; gap: 8px; align-items: center; margin-top: 6px; }
  .row button { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 12px; cursor: pointer; }
  .primary { background: var(--accent); color: #fff; border: 0; }
  .ok { color: var(--live); font-size: 12px; }
</style>
