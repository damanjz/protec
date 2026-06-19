<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "../api";
  import { unlocked } from "../stores/vault";
  import { invoke } from "@tauri-apps/api/core";

  let pw = "";
  let error = "";
  let offerRestore = false;
  let helloAvailable = false;

  onMount(async () => {
    try {
      const s = await api.helloStatus();
      helloAvailable = s.available && s.enabled;
    } catch {
      helloAvailable = false;
    }
    if (helloAvailable) void unlockWithHello();
  });

  async function unlockWithHello() {
    try {
      await api.helloUnlock();
      unlocked.set(true);
    } catch {
      error = "Use your master password.";
    }
  }

  async function doUnlock() {
    error = "";
    offerRestore = false;
    try {
      await api.unlock(pw);
      pw = "";
      unlocked.set(true);
    } catch (e) {
      error = String(e);
      pw = "";
      // If the vault looks damaged and a backup exists, offer to restore it.
      if (/damaged|corrupt|authentication/i.test(error)) {
        try { offerRestore = await invoke<boolean>("backup_available"); } catch { offerRestore = false; }
      }
    }
  }

  async function restore() {
    try {
      await invoke<void>("restore_backup");
      error = "Backup restored — try unlocking again.";
      offerRestore = false;
    } catch (e) {
      error = String(e);
    }
  }
</script>

<div class="wrap">
  <h1>protec</h1>
  <p class="sub">● locked</p>
  <input type="password" placeholder="Master password" bind:value={pw} autofocus
         on:keydown={(e) => e.key === "Enter" && doUnlock()} />
  {#if error}<p class="err">{error}</p>{/if}
  <button on:click={doUnlock}>Unlock</button>
  {#if offerRestore}
    <button class="restore" on:click={restore}>Restore from backup (.bak)</button>
  {/if}
  {#if helloAvailable}
    <button class="hello" on:click={unlockWithHello}>Unlock with Windows Hello</button>
  {/if}
</div>

<style>
  .wrap { max-width: 320px; margin: 18vh auto; display: flex; flex-direction: column; gap: 10px; }
  h1 { margin: 0; color: var(--accent); }
  .sub { color: var(--text-dim); margin: 0 0 8px; }
  input { padding: 9px 11px; background: var(--bg-elev); border: 1px solid var(--border);
          color: var(--text); border-radius: 6px; font-family: var(--mono); }
  button { padding: 9px; background: var(--accent); color: #fff; border: 0;
           border-radius: 6px; cursor: pointer; }
  .hello { background: var(--bg-elev); color: var(--text); border: 1px solid var(--border); }
  .restore { background: var(--bg-elev); color: var(--accent); border: 1px solid var(--accent); }
  .err { color: var(--danger); margin: 0; font-size: 12px; }
</style>
