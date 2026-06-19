export interface KeyHandlers {
  onPalette: () => void;   // Ctrl/Cmd+K
  onCopy: () => void;      // Ctrl/Cmd+C (when an entry is selected)
  onLock: () => void;      // Ctrl/Cmd+L
  onUp: () => void;        // ArrowUp
  onDown: () => void;      // ArrowDown
  onEnter: () => void;     // Enter
  onEscape: () => void;    // Escape
}

/// Returns a keydown handler. Pure routing — no DOM assumptions beyond the event.
export function makeKeydownHandler(h: KeyHandlers) {
  return (e: KeyboardEvent) => {
    const mod = e.ctrlKey || e.metaKey;
    if (mod && e.key.toLowerCase() === "k") { e.preventDefault(); h.onPalette(); return; }
    if (mod && e.key.toLowerCase() === "l") { e.preventDefault(); h.onLock(); return; }
    if (mod && e.key.toLowerCase() === "c") { h.onCopy(); return; }
    switch (e.key) {
      case "ArrowUp": e.preventDefault(); h.onUp(); break;
      case "ArrowDown": e.preventDefault(); h.onDown(); break;
      case "Enter": h.onEnter(); break;
      case "Escape": h.onEscape(); break;
    }
  };
}
