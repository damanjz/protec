# Protec GUI — manual smoke checklist

1. Launch (`cargo tauri dev`). First run → create vault with a master password.
2. Add an entry (⌘K → New entry, or ＋ New). Save.
3. Lock (⌘L) → unlock with the master password → entry still present.
4. Select entry → reveal password → copy (toast shows clear countdown).
5. ⌘K → Generate password → Use → fills a new entry.
6. Settings → switch theme to Terminal Green → UI recolors.
7. Settings → set clipboard clear to 0 → copy → clipboard not auto-cleared.
8. Close and relaunch → vault persists, opens locked.
9. Idle for the auto-lock timeout → app locks itself.
