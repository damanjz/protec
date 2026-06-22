<script lang="ts">
  import type { EntryInput, EntryDetail } from "../api";
  export let initial: EntryDetail | null = null;
  export let injectedPassword: string | null = null;
  export let onSubmit: (input: EntryInput) => void;
  export let onCancel: () => void;
  export let onGenerate: () => Promise<string>;

  let title = initial?.title ?? "";
  let username = initial?.username ?? "";
  // When editing, MainView loads the entry revealed, so initial.password holds the real
  // value (not the mask). Fall back to "" only when there is no initial (new entry).
  // NOTE: these `let` initializers run once at mount. This is correct because MainView
  // renders the form inside an {#if mode === ...} block, which destroys and recreates
  // the component on every mode switch — so `initial` is always fresh. If that {#if}
  // is ever replaced with a keep-alive pattern, these must become reactive.
  let password = initial?.password ?? "";
  let url = initial?.url ?? "";
  let notes = initial?.notes ?? "";
  let tagsText = (initial?.tags ?? []).join(", ");

  $: if (injectedPassword) password = injectedPassword;

  async function fillGenerated() {
    password = await onGenerate();
  }

  function submit() {
    const input: EntryInput = {
      title, username, password, url, notes,
      tags: tagsText.split(",").map((s) => s.trim()).filter(Boolean),
    };
    onSubmit(input);
  }
</script>

<div class="form">
  <input placeholder="Title" bind:value={title} />
  <input placeholder="Username" bind:value={username} />
  <div class="pwrow">
    <input placeholder="Password" bind:value={password} />
    <button on:click={fillGenerated}>generate</button>
  </div>
  <input placeholder="URL" bind:value={url} />
  <textarea placeholder="Notes" bind:value={notes}></textarea>
  <input placeholder="tags, comma, separated" bind:value={tagsText} />
  <div class="row">
    <button class="primary" on:click={submit}>Save</button>
    <button on:click={onCancel}>Cancel</button>
  </div>
</div>

<style>
  .form { padding: 16px; display: flex; flex-direction: column; gap: 8px; }
  input, textarea { padding: 8px 10px; background: var(--bg-elev); border: 1px solid var(--border);
    color: var(--text); border-radius: 6px; font-family: var(--mono); }
  .pwrow { display: flex; gap: 6px; } .pwrow input { flex: 1; }
  button { padding: 7px 12px; background: var(--bg-elev); color: var(--text);
    border: 1px solid var(--border); border-radius: 6px; cursor: pointer; }
  .primary { background: var(--accent); color: #fff; border: 0; }
  .row { display: flex; gap: 8px; margin-top: 4px; }
</style>
