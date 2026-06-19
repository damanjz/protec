import { writable } from "svelte/store";
import type { EntrySummary } from "../api";

export const unlocked = writable(false);
export const vaultExists = writable(false);
export const entries = writable<EntrySummary[]>([]);
export const selectedId = writable<string | null>(null);
export const paletteOpen = writable(false);
export const theme = writable<"slate" | "terminal-green">("slate");
