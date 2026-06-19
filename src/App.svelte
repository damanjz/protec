<script lang="ts">
  import { onMount } from "svelte";
  import { api } from "./lib/api";
  import { unlocked, vaultExists, theme } from "./lib/stores/vault";
  import FirstRun from "./lib/components/FirstRun.svelte";
  import LockScreen from "./lib/components/LockScreen.svelte";
  import MainView from "./lib/components/MainView.svelte";

  let loading = true;

  onMount(async () => {
    try {
      const status = await api.vaultStatus();
      vaultExists.set(status.exists);
      unlocked.set(status.unlocked);
      const cfg = await api.getConfig();
      const t = (cfg.theme as "slate" | "terminal-green") ?? "slate";
      theme.set(t);
      document.documentElement.setAttribute("data-theme", t);
    } catch {
      // backend not ready / no config — defaults already in stores
    } finally {
      loading = false;
    }
  });
</script>

{#if loading}
  <p class="center">…</p>
{:else if !$vaultExists}
  <FirstRun />
{:else if !$unlocked}
  <LockScreen />
{:else}
  <MainView />
{/if}

<style>
  .center { text-align: center; margin-top: 30vh; color: var(--text-dim); }
</style>
