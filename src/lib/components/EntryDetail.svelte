<script lang="ts">
  import type { EntryDetail } from "../api";
  export let detail: EntryDetail | null = null;
  export let revealed = false;
  export let onCopy: () => void;
  export let onReveal: () => void;
  export let onEdit: () => void;
  export let onDelete: () => void;
</script>

{#if detail}
  <div class="detail">
    <div class="hdr">
      <h2>{detail.title}</h2>
      <div class="actions">
        <button on:click={onEdit}>Edit</button>
        <button class="danger" on:click={onDelete}>Delete</button>
      </div>
    </div>
    <div class="fld"><div class="k">username</div><div class="v">{detail.username}</div></div>
    <div class="fld">
      <div class="k">password</div>
      <div class="v pw">
        <span>{detail.password}</span>
        <button on:click={onReveal}>{revealed ? "hide" : "reveal"}</button>
        <button on:click={onCopy}>copy ⌘C</button>
      </div>
    </div>
    {#if detail.url}<div class="fld"><div class="k">url</div><div class="v">{detail.url}</div></div>{/if}
    {#if detail.notes}<div class="fld"><div class="k">notes</div><div class="v">{detail.notes}</div></div>{/if}
    {#if detail.tags.length}
      <div class="fld"><div class="k">tags</div>
        <div class="v">{#each detail.tags as t}<span class="chip">{t}</span>{/each}</div>
      </div>
    {/if}
  </div>
{:else}
  <div class="placeholder">Select an entry</div>
{/if}

<style>
  .detail { padding: 16px; }
  .hdr { display: flex; justify-content: space-between; align-items: center; }
  h2 { margin: 0; }
  .actions button, .v button { background: var(--bg-elev); color: var(--text);
    border: 1px solid var(--border); border-radius: 5px; padding: 3px 8px; cursor: pointer; margin-left: 6px; }
  .danger { color: var(--danger); }
  .fld { margin-top: 14px; }
  .k { color: var(--text-dim); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
  .v { color: var(--text); margin-top: 3px; }
  .pw { display: flex; align-items: center; }
  .pw span { color: var(--live); }
  .chip { background: var(--bg-elev); color: var(--text-dim); padding: 1px 7px;
    border-radius: 4px; font-size: 11px; margin-right: 4px; }
  .placeholder { color: var(--text-dim); padding: 40px; text-align: center; }
</style>
