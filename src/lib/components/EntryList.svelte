<script lang="ts">
  import type { EntrySummary } from "../api";
  import { modShortcut } from "../platform";
  export let items: EntrySummary[] = [];
  export let selectedId: string | null = null;
  export let onSelect: (id: string) => void;
</script>

<div class="list">
  {#each items as it (it.id)}
    <div class="row" class:sel={it.id === selectedId} on:click={() => onSelect(it.id)}
         role="button" tabindex="0" on:keydown={(e) => e.key === "Enter" && onSelect(it.id)}>
      <span class="t">{it.title}</span>
      <span class="u">{it.username}</span>
    </div>
  {/each}
  {#if items.length === 0}
    <div class="empty">No entries yet. Press {modShortcut("K")} → New entry.</div>
  {/if}
</div>

<style>
  .list { overflow-y: auto; height: 100%; }
  .row { padding: 8px 12px; border-bottom: 1px solid var(--bg-elev);
         display: flex; justify-content: space-between; cursor: pointer; }
  .row.sel { background: var(--row-sel); box-shadow: inset 2px 0 var(--accent); }
  .t { color: var(--text); }
  .u { color: var(--text-dim); }
  .empty { padding: 24px 12px; color: var(--text-dim); text-align: center; }
</style>
