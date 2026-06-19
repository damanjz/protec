import { invoke } from "@tauri-apps/api/core";

export interface EntrySummary {
  id: string;
  title: string;
  username: string;
  url: string;
  tags: string[];
}

export interface EntryDetail {
  id: string;
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
  has_totp: boolean;
  created_at: number;
  updated_at: number;
}

export interface VaultStatus {
  exists: boolean;
  unlocked: boolean;
}

export interface EntryInput {
  title: string;
  username: string;
  password: string;
  url: string;
  notes: string;
  tags: string[];
}

export const api = {
  vaultStatus: () => invoke<VaultStatus>("vault_status"),
  createVault: (masterPassword: string) =>
    invoke<void>("create_vault", { masterPassword }),
  unlock: (masterPassword: string) => invoke<void>("unlock", { masterPassword }),
  lock: () => invoke<void>("lock"),
  listEntries: () => invoke<EntrySummary[]>("list_entries"),
  getEntry: (id: string, reveal: boolean) =>
    invoke<EntryDetail>("get_entry", { id, reveal }),
  addEntry: (input: EntryInput) => invoke<string>("add_entry", { input }),
  updateEntry: (id: string, input: EntryInput) =>
    invoke<void>("update_entry", { id, input }),
  deleteEntry: (id: string) => invoke<void>("delete_entry", { id }),
  saveVault: () => invoke<void>("save_vault"),
  generate: (req: Record<string, unknown>) => invoke<string>("generate", { req }),
  copySecret: (text: string, clearSecs: number) =>
    invoke<void>("copy_secret", { text, clearSecs }),
  getConfig: () => invoke<Record<string, unknown>>("get_config"),
  setConfig: (newConfig: Record<string, unknown>) =>
    invoke<void>("set_config", { newConfig }),
  helloStatus: () => invoke<{ available: boolean; enabled: boolean }>("hello_status"),
  helloEnable: () => invoke<void>("hello_enable"),
  helloDisable: () => invoke<void>("hello_disable"),
  helloUnlock: () => invoke<void>("hello_unlock"),
};
