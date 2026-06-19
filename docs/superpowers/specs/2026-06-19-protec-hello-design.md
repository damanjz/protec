# protec-hello — Design Spec

**Date:** 2026-06-19
**Status:** Approved (design phase)
**Sub-project:** 4 of 4 (final roadmap feature)

---

## 0. Context

`protec-core`, `protec-gui`, and `protec-ext` are complete and merged on `main`. Two seams
for this feature already exist by deliberate design:

- `protec-core`'s on-disk header stores a **list of key-wraps** (`Vec<KeyWrap>`) with a
  `WrapKind` enum that already contains a commented-out `WindowsHello` variant. The format
  supports multiple independent wraps of the vault key with no schema change.
- `protec-gui`'s lock screen already has a disabled `helloAvailable` seam and a hidden
  "Unlock with Windows Hello" button.

`protec-hello` adds **Windows Hello biometric/PIN unlock** as an optional, opt-in second way
to unlock the vault. The master password always remains a valid unlock method.

---

## 1. Security Model (the locked-in approach)

`protec-core` uses **envelope encryption**: a random *vault key* encrypts the data, and the
header stores *wraps* — the vault key encrypted under each enabled unlock method's key. Today
there is one wrap (master-password-derived). **Hello adds a second wrap; nothing else
changes.**

Hello's wrapping key is a **TPM-bound key**:
- Created in Protec's own named key container via the Windows `KeyCredentialManager` / NCrypt
  APIs.
- **Non-exportable** (key material never leaves the TPM).
- **Hello-gated** (a successful Windows Hello authentication — fingerprint/face/PIN — is
  required to use it).
- **Machine-bound** (bound to this device's TPM).

This is the only model that delivers what "Windows Hello unlock" means: hardware-bound,
biometric-gated, key-never-leaves-the-TPM. It matches the best-practice security bar set for
the project.

### TPM safety (explicitly bounded)
The implementation will **only** create/use/delete Protec's own key. It will **never**: take
TPM ownership, clear the TPM, change TPM/BIOS settings, touch BitLocker or its recovery keys,
or read/modify/delete any key Protec did not create. No admin rights required. Fully
reversible.

---

## 2. The Golden Rule

**The master-password wrap is never removed.** Hello is always strictly additive — a second
door, never the only door. Consequently there is **no failure mode that locks the user out**:
if the TPM/Hello is reset, the device changes, the vault is moved, or any Hello operation
fails, the master password still unlocks the vault.

---

## 3. Components

### New crate `protec-hello` (isolates the Win32 FFI)
- `lib.rs` — a small, clean public API:
  - `is_available() -> bool` — TPM present + Hello configured.
  - `enable(vault_key: &[u8; 32]) -> Result<HelloWrapData, HelloError>` — create the TPM key
    and wrap the vault key; returns the data to store as a `KeyWrap`.
  - `unlock(wrap: &HelloWrapData) -> Result<Zeroizing<[u8; 32]>, HelloError>` — Hello-prompt,
    then unwrap the vault key.
  - `disable() -> Result<(), HelloError>` — delete Protec's TPM key.
- `tpm.rs` — the actual `KeyCredentialManager` / NCrypt calls (create, use/wrap, prompt,
  delete). The **only** file with `unsafe` / FFI, `#[cfg(windows)]`.
- `error.rs` — typed `HelloError` mapping to friendly messages.

The wrap/unwrap envelope logic is separated from the raw TPM calls behind a trait so it can be
tested with an injectable key provider (no hardware needed).

### `protec-core`
- Uncomment the `WindowsHello` variant in `WrapKind`. No format change — the multi-wrap header
  already supports it.

### `protec-gui`
- Enable/disable Tauri commands (in a new `commands/hello.rs`).
- Settings toggle: "Unlock with Windows Hello" (only rendered when `is_available()`).
- First-run offer: a skippable final card after vault creation.
- Lock-screen Hello button (wire the existing `helloAvailable` seam); Hello offered first with
  the master-password field always visible.

---

## 4. Enable / Disable Flow

Two entry points, **same underlying routine**:

### Settings (primary)
Vault must be **unlocked** (so the vault key is in memory) → confirm intent → Hello prompt →
`protec-hello::enable(vault_key)` → add a `KeyWrap { kind: WindowsHello, .. }` to the header →
save. A clear note states "Your master password will still work."

### First-run offer (secondary, same routine)
After the user creates the vault (freshly unlocked — they just typed the master password), an
**optional, skippable** card offers "Enable Windows Hello unlock?". If accepted, it runs the
exact same enable routine (no master-password re-prompt needed; the vault is already unlocked).
Declining is one click and changes nothing; the toggle remains available later in Settings.

### Disable (Settings)
Remove the `WindowsHello` wrap from the header (save) + `protec-hello::disable()` deletes the
TPM key. Master password unaffected.

---

## 5. Data Flow & Error Handling (graceful fallback everywhere)

- **Detect** (`is_available()`): on app start. If false → the Settings toggle and lock-screen
  button do not render. No errors, no dead UI.
- **Enable**: on any failure (Hello cancelled, TPM busy, user backs out) → nothing is written,
  the vault is unchanged, message: "Couldn't enable Windows Hello — your master password still
  works." No half-state.
- **Unlock**: on any failure (not recognized, cancelled, key missing because TPM/Hello was
  reset) → silently fall back to the visible master-password field with "Use your master
  password." Never blocks the user.
- **Disable**: if the TPM key delete fails → still remove the wrap (so Hello stops working) and
  note it; the orphaned key is harmless (Hello-gated, machine-bound). The vault is the source of
  truth.

Across all paths: the master-password wrap is never touched, so every error has a guaranteed
safe fallback.

---

## 6. Testing

- **`protec-core`**: the `WindowsHello` wrap variant round-trips through serde; a vault with
  two wraps opens from *either* (unit-tested with a fake second wrapping key — no TPM).
- **`protec-hello`**: the wrap/unwrap envelope logic is tested with an injectable key provider
  (covers envelope behavior without hardware). The raw TPM/Hello calls in `tpm.rs` cannot be
  unit-tested in CI (no TPM/biometric in a headless runner) — isolated behind the trait and
  verified by manual checklist on a real machine.
- **`protec-gui`**: enable/disable command logic; the "`is_available()` gates the UI" behavior.

---

## 7. Packaging

- `protec-hello` joins the Cargo workspace `members`.
- TPM code is `#[cfg(windows)]`; CI builds the crate on Windows.
- README documents Hello as optional, opt-in, with the "master password always works" note.
- Apache-2.0 throughout.

---

## 8. Manual Verification (needs a real TPM+Hello machine — operator-run)

1. On a supported device: Settings shows the Hello toggle; enable it (Hello prompt succeeds) →
   lock → unlock with fingerprint/PIN → vault opens.
2. Master password still unlocks throughout (golden rule).
3. Disable → the Hello button/toggle disappear; TPM key deleted.
4. First-run offer appears after vault creation and is skippable.
5. On an unsupported device (no TPM/Hello), neither the toggle nor the button render — no errors.
6. Hello failure (cancel the prompt) → clean fallback to the master-password field.

---

## 9. Recap of Locked-In Decisions

- TPM-bound, Hello-gated, non-exportable, machine-bound second wrap on the existing multi-wrap
  header.
- Opt-in via Settings **and** a skippable first-run offer (same routine).
- Lock screen offers Hello first; master-password field always visible.
- Master-password wrap never removed; every failure falls back to the password.
- Feature hidden entirely on unsupported devices.
- Win32 FFI isolated in `protec-hello/tpm.rs`; envelope logic tested without hardware.
- Never touches TPM ownership, BitLocker, settings, or any non-Protec key.
