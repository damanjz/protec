/// OS-aware keyboard modifier presentation.
///
/// Windows/Linux use Ctrl; macOS uses the Command key (⌘). The keybinding
/// handlers already accept either physical key (ctrlKey || metaKey), but the
/// *label* shown in the UI must match the user's platform — a Windows user
/// should never see "⌘K".

/// True when running on macOS. Uses userAgentData when available, falling back
/// to the platform/userAgent string. Safe in non-browser (test) contexts.
export function isMac(): boolean {
  if (typeof navigator === "undefined") return false;
  // navigator.userAgentData?.platform is the modern, non-deprecated source.
  const uaPlatform = (navigator as unknown as { userAgentData?: { platform?: string } })
    .userAgentData?.platform;
  const haystack = `${uaPlatform ?? ""} ${navigator.platform ?? ""} ${navigator.userAgent ?? ""}`;
  return /mac/i.test(haystack);
}

/// The modifier label for the current platform: "⌘" on macOS, "Ctrl" elsewhere.
export function modLabel(): string {
  return isMac() ? "⌘" : "Ctrl";
}

/// Format a shortcut for display, e.g. modShortcut("K") -> "Ctrl+K" or "⌘K".
/// On macOS the convention is no separator (⌘K); elsewhere "Ctrl+K".
export function modShortcut(key: string): string {
  return isMac() ? `⌘${key}` : `Ctrl+${key}`;
}
