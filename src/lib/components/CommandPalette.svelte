<script lang="ts">
  import { fuzzyFilter } from "../fuzzy";
  import type { EntrySummary } from "../api";

  export let entries: EntrySummary[] = [];
  export let onPick: (id: string) => void;
  export let onCommand: (cmd: string) => void;
  export let onClose: () => void;

  let query = "";
  let active = 0;

  const commands = [
    { id: "cmd:new", label: "New entry" },
    { id: "cmd:generate", label: "Generate password" },
    { id: "cmd:settings", label: "Settings" },
    { id: "cmd:theme", label: "Switch theme" },
    { id: "cmd:lock", label: "Lock vault" },
  ];

  $: filteredEntries = fuzzyFilter(query, entries).slice(0, 6);
  $: filteredCommands = commands.filter((c) =>
    c.label.toLowerCase().includes(query.toLowerCase()),
  );
  $: rows = [
    ...filteredCommands.map((c) => ({ kind: "cmd", id: c.id, label: c.label })),
    ...filteredEntries.map((e) => ({ kind: "entry", id: e.id, label: `${e.title} · ${e.username}` })),
  ];

  function run(i: number) {
    const row = rows[i];
    if (!row) return;
    if (row.kind === "cmd") onCommand(row.id);
    else onPick(row.id);
    onClose();
  }

  function keydown(e: KeyboardEvent) {
    if (e.key === "ArrowDown") { e.preventDefault(); active = Math.min(active + 1, rows.length - 1); }
    else if (e.key === "ArrowUp") { e.preventDefault(); active = Math.max(active - 1, 0); }
    else if (e.key === "Enter") { e.preventDefault(); run(active); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  }
</script>

<div class="overlay" on:click={onClose} role="presentation">
  <div class="palette" on:click|stopPropagation role="dialog" aria-label="Command palette">
    <input class="in" placeholder="Search entries or run a command…" bind:value={query}
           autofocus on:keydown={keydown} on:input={() => (active = 0)} />
    <div class="rows">
      {#each rows as row, i (row.kind + row.id)}
        <div class="row" class:active={i === active} on:click={() => run(i)}
             role="button" tabindex="0" on:keydown={(e) => e.key === "Enter" && run(i)}>
          <span>{row.label}</span>
          <span class="hint">{row.kind === "cmd" ? "command" : "↵ open"}</span>
        </div>
      {/each}
      {#if rows.length === 0}<div class="empty">No matches</div>{/if}
    </div>
  </div>
</div>

<style>
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.5); display: flex;
    justify-content: center; align-items: flex-start; padding-top: 12vh; z-index: 50; }
  .palette { width: 540px; max-width: 90vw; background: var(--bg-elev);
    border: 1px solid var(--border); border-radius: 10px; overflow: hidden;
    box-shadow: 0 12px 40px rgba(0,0,0,.5); }
  .in { width: 100%; padding: 13px 16px; background: transparent; border: 0;
    border-bottom: 1px solid var(--border); color: var(--text);
    font-family: var(--mono); font-size: 14px; outline: none; }
  .row { padding: 9px 16px; display: flex; justify-content: space-between; cursor: pointer; }
  .row.active { background: var(--row-sel); }
  .hint { color: var(--text-dim); font-size: 11px; }
  .empty { padding: 18px 16px; color: var(--text-dim); }
</style>
