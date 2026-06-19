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
| `protec-host` | available (dev) | native-messaging broker for the browser extension |
| `protec-hello` | available (dev) | optional Windows Hello unlock |
| `protec-extension` | available (dev) | browser autofill (Chrome/Edge/Firefox) |

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

## Browser extension (autofill)

Protec autofills logins in Chrome, Edge, and Firefox via **native messaging** —
no network, no localhost server. The browser talks to a small local host
(`protec-host`) that relays requests to the running desktop app over a Windows
named pipe. The app is the gatekeeper: it stays unlocked, matches the page's
registrable domain (strict — `github.com` never fills on `github.com.evil.com`),
and every fill/save/update requires an explicit Allow in the app.

### Install (development)

```bash
cargo build -p protec-host --release          # build the host
cd extension && npm install && npm run build  # build the extension
```

Load `extension/dist` (with the right manifest copied in as `manifest.json`) as
an unpacked extension, then register the host (run from a normal PowerShell — no
admin needed):

```powershell
extension\scripts\register-host.ps1 -HostExe "<repo>\target\release\protec-host.exe" -ChromiumExtId "<your-unpacked-extension-id>"
```

The desktop app must be running and unlocked for autofill to work.

### Windows Hello unlock (optional)

On devices with a TPM and Windows Hello configured, Protec can unlock with your
fingerprint, face, or PIN in addition to your master password. It is **opt-in**
(enable it in Settings, or accept the offer when you first create your vault) and
**additive** — your master password always still works. Hello uses a
non-exportable, machine-bound TPM key; disabling it deletes that key. On devices
without Hello, the option simply doesn't appear.

## License

Apache-2.0.
