# Protec

A fully local, open-source password manager. Your secrets never leave your machine.

> **Status:** early development. `protec-core` (the secure engine) is the first component.

## Security model

- **Argon2id** key derivation; **XChaCha20-Poly1305** authenticated encryption.
- **Envelope encryption:** a random vault key encrypts your data; your master password
  only wraps that vault key — enabling future unlock methods (e.g. Windows Hello) with
  no re-encryption.
- **No cloud, no account, no telemetry.** A single encrypted file you control.
- Key material is wiped from memory on lock.

## Components

| Crate | Status | Purpose |
|-------|--------|---------|
| `protec-core` | done | the secure vault engine |
| `protec-cli`  | dropped | (skipped — see GUI) |
| `protec-gui`  | available (dev) | desktop app (Tauri + Svelte) |

## Running the GUI (development)

Requirements: Rust, Node.js, and (on Windows) the WebView2 runtime — preinstalled on
Windows 11.

```bash
cargo install tauri-cli --version "^2" --locked   # one-time
npm install
cargo tauri dev      # run in development
cargo tauri build    # produce a Windows installer (.msi / NSIS)
```

> **Note:** always build the production binary with `cargo tauri build`, not
> `cargo build --release` — the Tauri CLI embeds the compiled frontend, while a plain
> cargo build produces a binary that expects the dev server.

The GUI is keyboard-driven: press **Ctrl+K** for the command palette (search entries,
generate passwords, switch theme, lock the vault). Everything — auto-lock timeout,
clipboard auto-clear, theme (Slate Dev-Tool / Terminal Green), generator defaults, and the
vault file location — is configurable in **Settings**.

The vault lives at `%APPDATA%\Protec\vault.dat` by default; preferences are stored
(without secrets) in `%APPDATA%\Protec\config.toml`.

## License

Apache-2.0.
