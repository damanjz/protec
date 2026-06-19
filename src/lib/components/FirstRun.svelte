<script lang="ts">
  import { api } from "../api";
  import { vaultExists, unlocked } from "../stores/vault";

  let pw = "";
  let confirm = "";
  let error = "";
  let offerHello = false;

  async function create() {
    error = "";
    if (pw.length < 1) { error = "Choose a master password"; return; }
    if (pw !== confirm) { error = "Passwords do not match"; return; }
    try {
      await api.createVault(pw);
      await api.unlock(pw);
      const s = await api.helloStatus().catch(() => ({ available: false, enabled: false }));
      if (s.available) {
        offerHello = true;
      } else {
        vaultExists.set(true);
        unlocked.set(true);
      }
    } catch (e) {
      error = String(e);
    }
  }

  async function acceptHello() {
    try { await api.helloEnable(); } catch { /* ignore; master password still works */ }
    vaultExists.set(true);
    unlocked.set(true);
  }

  function skipHello() {
    vaultExists.set(true);
    unlocked.set(true);
  }
</script>

<div class="wrap">
  <h1>protec</h1>
  {#if offerHello}
    <div class="offer">
      <p>Enable Windows Hello unlock? You can also do this later in Settings.</p>
      <p class="hint">Your master password will still work.</p>
      <div class="row">
        <button class="primary" on:click={acceptHello}>Enable Windows Hello</button>
        <button on:click={skipHello}>Skip</button>
      </div>
    </div>
  {:else}
    <p class="sub">Create your vault</p>
    <input type="password" placeholder="Master password" bind:value={pw} />
    <input type="password" placeholder="Confirm password" bind:value={confirm}
           on:keydown={(e) => e.key === "Enter" && create()} />
    {#if error}<p class="err">{error}</p>{/if}
    <button on:click={create}>Create vault →</button>
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
  .err { color: var(--danger); margin: 0; font-size: 12px; }
  .offer { display: flex; flex-direction: column; gap: 8px; }
  .offer p { margin: 0; color: var(--text); font-size: 13px; }
  .hint { color: var(--text-dim); font-size: 11px; }
  .row { display: flex; gap: 8px; }
  .row button { flex: 1; }
  .row button:not(.primary) { background: var(--bg-elev); color: var(--text);
    border: 1px solid var(--border); }
</style>
