<script lang="ts">
  import { onMount } from "svelte";
  import { api, type EntrySummary, type EntryDetail, type EntryInput } from "../api";
  import { unlocked } from "../stores/vault";
  import EntryList from "./EntryList.svelte";
  import EntryDetailView from "./EntryDetail.svelte";
  import EntryForm from "./EntryForm.svelte";
  import Toast from "./Toast.svelte";
  import CommandPalette from "./CommandPalette.svelte";
  import GeneratorPanel from "./GeneratorPanel.svelte";
  import Settings from "./Settings.svelte";
  import { theme } from "../stores/vault";
  import { modShortcut } from "../platform";
  import { onDestroy } from "svelte";

  let items: EntrySummary[] = [];
  let selectedId: string | null = null;
  let detail: EntryDetail | null = null;
  let revealed = false;
  let mode: "view" | "new" | "edit" = "view";
  let toast = "";
  let toastKind: "info" | "error" = "info";

  let showPalette = false;
  let showGenerator = false;
  let showSettings = false;
  let injectedPassword: string | null = null;

  function handleCommand(cmd: string) {
    if (cmd === "cmd:new") mode = "new";
    else if (cmd === "cmd:generate") showGenerator = true;
    else if (cmd === "cmd:settings") showSettings = true;
    else if (cmd === "cmd:lock") lock();
    else if (cmd === "cmd:theme") toggleTheme();
  }

  async function toggleTheme() {
    const cfg = await api.getConfig();
    const next = cfg.theme === "terminal-green" ? "slate" : "terminal-green";
    cfg.theme = next;
    await api.setConfig(cfg);
    theme.set(next as "slate" | "terminal-green");
    document.documentElement.setAttribute("data-theme", next);
  }

  // ---- idle auto-lock ----
  let idleTimer: ReturnType<typeof setTimeout> | undefined;
  async function resetIdle() {
    if (idleTimer) clearTimeout(idleTimer);
    const cfg = await api.getConfig();
    const secs = Number(cfg.auto_lock_secs ?? 600);
    if (secs > 0) {
      idleTimer = setTimeout(() => { lock(); }, secs * 1000);
    }
  }

  function globalKeydown(e: KeyboardEvent) {
    resetIdle();
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); showPalette = true; }
    else if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); lock(); }
    else if (mod && e.key.toLowerCase() === "n") { e.preventDefault(); mode = "new"; }
  }

  function globalActivity() { resetIdle(); }

  async function onBlur() {
    const cfg = await api.getConfig();
    if (cfg.lock_on_blur === true) {
      await lock();
    }
  }

  function notify(msg: string, kind: "info" | "error" = "info") {
    toast = msg; toastKind = kind;
    setTimeout(() => (toast = ""), 2500);
  }

  async function refresh() {
    items = await api.listEntries();
  }

  async function select(id: string) {
    selectedId = id; mode = "view";
    const cfg = await api.getConfig();
    revealed = cfg.reveal_on_select === true;
    detail = await api.getEntry(id, revealed);
  }

  async function reveal() {
    if (!selectedId) return;
    const next = !revealed;
    try {
      detail = await api.getEntry(selectedId, next);
      revealed = next;
    } catch (e) {
      notify(String(e), "error");
    }
  }

  async function copyPw() {
    if (!selectedId) return;
    try {
      const d = await api.getEntry(selectedId, true);
      const cfg = await api.getConfig();
      const clear = Number(cfg.clipboard_clear_secs ?? 20);
      await api.copySecret(d.password, clear);
      notify(`Copied${clear > 0 ? ` — clears in ${clear}s` : ""}`);
    } catch (e) {
      notify(String(e), "error");
    }
  }

  async function persistIfAuto() {
    const cfg = await api.getConfig();
    if (cfg.auto_save !== false) await api.saveVault();
  }

  async function submitNew(input: EntryInput) {
    try {
      await api.addEntry(input);
      await persistIfAuto();
      await refresh();
      mode = "view";
      injectedPassword = null;
      notify("Entry added");
    } catch (e) {
      notify(String(e), "error");
    }
  }

  async function submitEdit(input: EntryInput) {
    if (!selectedId) return;
    try {
      await api.updateEntry(selectedId, input);
      await persistIfAuto();
      await refresh();
      await select(selectedId);
      notify("Entry updated");
    } catch (e) {
      notify(String(e), "error");
    }
  }

  async function del() {
    if (!selectedId) return;
    try {
      await api.deleteEntry(selectedId);
      await persistIfAuto();
      selectedId = null; detail = null;
      await refresh();
      notify("Entry deleted");
    } catch (e) {
      notify(String(e), "error");
    }
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

  if (typeof window !== "undefined") {
    window.addEventListener("keydown", globalKeydown);
    window.addEventListener("mousemove", globalActivity);
    window.addEventListener("blur", onBlur);
    resetIdle();
  }
  onDestroy(() => {
    if (typeof window !== "undefined") {
      window.removeEventListener("keydown", globalKeydown);
      window.removeEventListener("mousemove", globalActivity);
      window.removeEventListener("blur", onBlur);
    }
    if (idleTimer) clearTimeout(idleTimer);
  });

  onMount(refresh);
</script>

<div class="shell">
  <div class="topbar">
    <span class="brand">protec</span>
    <span class="status">● unlocked</span>
    <button on:click={() => (mode = "new")}>＋ New {modShortcut("N")}</button>
    <button on:click={lock}>Lock {modShortcut("L")}</button>
  </div>
  <div class="body">
    <div class="pane list"><EntryList {items} {selectedId} onSelect={select} /></div>
    <div class="pane detail">
      {#if mode === "new"}
        <EntryForm initial={null} injectedPassword={injectedPassword} onSubmit={submitNew} onCancel={() => { mode = "view"; injectedPassword = null; }} onGenerate={genPassword} />
      {:else if mode === "edit"}
        <EntryForm initial={detail} onSubmit={submitEdit} onCancel={() => (mode = "view")} onGenerate={genPassword} />
      {:else}
        <EntryDetailView {detail} {revealed} onCopy={copyPw} onReveal={reveal}
          onEdit={() => (mode = "edit")} onDelete={del} />
      {/if}
    </div>
  </div>
  <Toast message={toast} kind={toastKind} />
  {#if showPalette}
    <CommandPalette entries={items} onPick={(id) => { select(id); showPalette = false; }}
      onCommand={handleCommand} onClose={() => (showPalette = false)} />
  {/if}
  {#if showGenerator}
    <GeneratorPanel onClose={() => (showGenerator = false)}
      onUse={(pw) => { showGenerator = false; injectedPassword = pw; if (mode !== "edit") mode = "new"; }} />
  {/if}
  {#if showSettings}
    <Settings onClose={() => (showSettings = false)} />
  {/if}
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
