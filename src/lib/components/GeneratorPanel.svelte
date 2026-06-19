<script lang="ts">
  import { api } from "../api";
  export let onClose: () => void;
  export let onUse: (pw: string) => void = () => {};

  let mode: "chars" | "passphrase" = "chars";
  let length = 20;
  let lowercase = true, uppercase = true, digits = true, symbols = true, excludeAmbiguous = true;
  let words = 4, separator = "-", capitalize = false;
  let result = "";
  let error = "";

  async function gen() {
    error = "";
    try {
      result = await api.generate({
        mode, length, lowercase, uppercase, digits, symbols,
        exclude_ambiguous: excludeAmbiguous, words, separator, capitalize,
      });
    } catch (e) { error = String(e); }
  }

  async function copy() {
    if (!result) return;
    const cfg = await api.getConfig();
    await api.copySecret(result, Number(cfg.clipboard_clear_secs ?? 20));
  }
</script>

<div class="overlay" on:click={onClose} role="presentation">
  <div class="panel" on:click|stopPropagation role="dialog" aria-label="Generator">
    <h3>Generate password</h3>
    <div class="tabs">
      <button class:on={mode === "chars"} on:click={() => (mode = "chars")}>Random</button>
      <button class:on={mode === "passphrase"} on:click={() => (mode = "passphrase")}>Passphrase</button>
    </div>
    {#if mode === "chars"}
      <label>Length: {length}<input type="range" min="8" max="64" bind:value={length} /></label>
      <label><input type="checkbox" bind:checked={lowercase} /> lowercase</label>
      <label><input type="checkbox" bind:checked={uppercase} /> uppercase</label>
      <label><input type="checkbox" bind:checked={digits} /> digits</label>
      <label><input type="checkbox" bind:checked={symbols} /> symbols</label>
      <label><input type="checkbox" bind:checked={excludeAmbiguous} /> exclude ambiguous</label>
    {:else}
      <label>Words: {words}<input type="range" min="4" max="8" bind:value={words} /></label>
      <label>Separator <input class="sep" bind:value={separator} /></label>
      <label><input type="checkbox" bind:checked={capitalize} /> capitalize</label>
    {/if}
    <div class="result">{result || "—"}</div>
    {#if error}<p class="err">{error}</p>{/if}
    <div class="row">
      <button on:click={gen}>Generate</button>
      <button on:click={copy}>Copy</button>
      <button class="primary" on:click={() => onUse(result)} disabled={!result}>Use</button>
      <button on:click={onClose}>Close</button>
    </div>
  </div>
</div>

<style>
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.5); display: flex;
    justify-content: center; align-items: flex-start; padding-top: 12vh; z-index: 50; }
  .panel { width: 420px; background: var(--bg-elev); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px; display: flex; flex-direction: column; gap: 8px; }
  h3 { margin: 0 0 4px; }
  .tabs button { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 5px; padding: 4px 10px; cursor: pointer; margin-right: 6px; }
  .tabs button.on { background: var(--accent); color: #fff; border: 0; }
  label { display: flex; align-items: center; gap: 8px; color: var(--text-dim); font-size: 12px; }
  .sep { width: 40px; background: var(--bg); border: 1px solid var(--border);
    color: var(--text); border-radius: 4px; padding: 2px 6px; }
  .result { padding: 10px; background: var(--bg); border: 1px dashed var(--border);
    border-radius: 6px; color: var(--live); word-break: break-all; }
  .row { display: flex; gap: 6px; margin-top: 4px; }
  .row button { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 6px; padding: 6px 10px; cursor: pointer; }
  .primary { background: var(--accent); color: #fff; border: 0; }
  .err { color: var(--danger); margin: 0; font-size: 12px; }
</style>
