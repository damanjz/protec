<script lang="ts">
  import { onMount } from "svelte";
  import { api, type EntrySummary, type EntryDetail, type EntryInput } from "../api";
  import { unlocked } from "../stores/vault";
  import EntryList from "./EntryList.svelte";
  import EntryDetailView from "./EntryDetail.svelte";
  import EntryForm from "./EntryForm.svelte";
  import Toast from "./Toast.svelte";

  let items: EntrySummary[] = [];
  let selectedId: string | null = null;
  let detail: EntryDetail | null = null;
  let revealed = false;
  let mode: "view" | "new" | "edit" = "view";
  let toast = "";
  let toastKind: "info" | "error" = "info";

  function notify(msg: string, kind: "info" | "error" = "info") {
    toast = msg; toastKind = kind;
    setTimeout(() => (toast = ""), 2500);
  }

  async function refresh() {
    items = await api.listEntries();
  }

  async function select(id: string) {
    selectedId = id; revealed = false; mode = "view";
    detail = await api.getEntry(id, false);
  }

  async function reveal() {
    if (!selectedId) return;
    revealed = !revealed;
    detail = await api.getEntry(selectedId, revealed);
  }

  async function copyPw() {
    if (!selectedId) return;
    const d = await api.getEntry(selectedId, true);
    const cfg = await api.getConfig();
    const clear = Number(cfg.clipboard_clear_secs ?? 20);
    await api.copySecret(d.password, clear);
    notify(`Copied${clear > 0 ? ` — clears in ${clear}s` : ""}`);
  }

  async function persistIfAuto() {
    const cfg = await api.getConfig();
    if (cfg.auto_save !== false) await api.saveVault();
  }

  async function submitNew(input: EntryInput) {
    await api.addEntry(input, Math.floor(Date.now() / 1000));
    await persistIfAuto();
    await refresh();
    mode = "view";
    notify("Entry added");
  }

  async function submitEdit(input: EntryInput) {
    if (!selectedId) return;
    await api.updateEntry(selectedId, input, Math.floor(Date.now() / 1000));
    await persistIfAuto();
    await refresh();
    await select(selectedId);
    notify("Entry updated");
  }

  async function del() {
    if (!selectedId) return;
    await api.deleteEntry(selectedId);
    await persistIfAuto();
    selectedId = null; detail = null;
    await refresh();
    notify("Entry deleted");
  }

  async function genPassword(): Promise<string> {
    const cfg = await api.getConfig();
    return api.generate({
      mode: "chars",
      length: Number(cfg.gen_length ?? 20),
      lowercase: cfg.gen_lowercase !== false,
      uppercase: cfg.gen_uppercase !== false,
      digits: cfg.gen_digits !== false,
      symbols: cfg.gen_symbols !== false,
      exclude_ambiguous: cfg.gen_exclude_ambiguous !== false,
      words: 4, separator: "-", capitalize: false,
    });
  }

  async function lock() {
    await api.lock();
    unlocked.set(false);
  }

  // exposed for palette/keybindings (wired in Task 15)
  export const actions = {
    newEntry: () => (mode = "new"),
    lock,
    copyPw,
  };

  onMount(refresh);
</script>

<div class="shell">
  <div class="topbar">
    <span class="brand">protec</span>
    <span class="status">● unlocked</span>
    <button on:click={() => (mode = "new")}>＋ New ⌘N</button>
    <button on:click={lock}>Lock ⌘L</button>
  </div>
  <div class="body">
    <div class="pane list"><EntryList {items} {selectedId} onSelect={select} /></div>
    <div class="pane detail">
      {#if mode === "new"}
        <EntryForm initial={null} onSubmit={submitNew} onCancel={() => (mode = "view")} onGenerate={genPassword} />
      {:else if mode === "edit"}
        <EntryForm initial={detail} onSubmit={submitEdit} onCancel={() => (mode = "view")} onGenerate={genPassword} />
      {:else}
        <EntryDetailView {detail} {revealed} onCopy={copyPw} onReveal={reveal}
          onEdit={() => (mode = "edit")} onDelete={del} />
      {/if}
    </div>
  </div>
  <Toast message={toast} kind={toastKind} />
</div>

<style>
  .shell { display: flex; flex-direction: column; height: 100vh; }
  .topbar { display: flex; align-items: center; gap: 10px; padding: 8px 12px;
    background: var(--bg-elev); border-bottom: 1px solid var(--border); }
  .brand { color: var(--accent); } .status { color: var(--live); margin-right: auto; }
  .topbar button { background: var(--bg); color: var(--text); border: 1px solid var(--border);
    border-radius: 5px; padding: 4px 9px; cursor: pointer; }
  .body { display: flex; flex: 1; min-height: 0; }
  .pane { height: 100%; }
  .list { width: 40%; border-right: 1px solid var(--border); }
  .detail { flex: 1; overflow-y: auto; }
</style>
