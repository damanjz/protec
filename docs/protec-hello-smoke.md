# Protec — Windows Hello manual smoke checklist

Run on a real Windows machine with a TPM + Windows Hello configured. The Hello
TPM path cannot be unit-tested (no TPM/biometric in CI), so verify it by hand.

1. **Build & run:** `cargo tauri build` then launch the exe (or `cargo tauri dev`).
2. **First-run offer:** create a new vault → the "Enable Windows Hello?" card appears →
   click "Enable Windows Hello" → Hello prompts → succeeds → main view opens.
3. **Hello unlock:** Lock (Ctrl+L) → the lock screen auto-offers Hello (or click the
   "Unlock with Windows Hello" button) → fingerprint/PIN → vault unlocks.
3a. **Signature determinism (critical):** Lock and unlock with Hello **three times
    in a row**. All three must succeed. This confirms the TPM signature for the
    fixed challenge is deterministic — if any unlock fails while the master
    password still works, Hello's wrapping key is not stable on this device and
    the feature must not be relied upon there.
4. **Golden rule:** Lock → ignore Hello → type the master password → still unlocks.
5. **Settings toggle:** Settings → "Unlock with Windows Hello" shows enabled → toggle OFF →
   on next lock the Hello button no longer appears → toggle ON again → Hello prompts and
   re-enables.
6. **Cancel fallback:** Lock → start Hello → cancel the prompt → the master-password field
   is right there and works.
7. **Disable cleanup:** disable Hello → the TPM credential is deleted (re-enabling prompts to
   create it again).
8. **Unsupported device (if available):** on a machine without a TPM/Hello, confirm neither
   the Settings toggle nor the lock-screen button appear, and no errors occur.

## What "pass" means
- Hello unlock works AND the master password always works (the golden rule).
- The Hello UI appears only when the device supports it and the feature is enabled.
- Every Hello failure (cancel, not recognized) falls back to the master-password field with
  no crash and no scary dialog.
