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
| `protec-core` | in progress | the secure vault engine |
| `protec-cli`  | planned | terminal client |
| `protec-gui`  | planned | desktop app (Tauri) |

## License

Apache-2.0.
