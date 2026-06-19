import { describe, it, expect, vi, afterEach } from "vitest";

// Helper to stub navigator for a single test.
function stubNavigator(value: unknown) {
  vi.stubGlobal("navigator", value);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("platform", () => {
  it("formats Ctrl shortcuts on Windows", async () => {
    stubNavigator({ platform: "Win32", userAgent: "Mozilla/5.0 (Windows NT 10.0)" });
    const { modShortcut, modLabel, isMac } = await import("./platform");
    expect(isMac()).toBe(false);
    expect(modLabel()).toBe("Ctrl");
    expect(modShortcut("K")).toBe("Ctrl+K");
  });

  it("formats Cmd shortcuts on macOS", async () => {
    vi.resetModules();
    stubNavigator({ platform: "MacIntel", userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X)" });
    const { modShortcut, modLabel, isMac } = await import("./platform");
    expect(isMac()).toBe(true);
    expect(modLabel()).toBe("⌘");
    expect(modShortcut("K")).toBe("⌘K");
  });

  it("prefers userAgentData.platform when present", async () => {
    vi.resetModules();
    stubNavigator({ userAgentData: { platform: "macOS" }, platform: "", userAgent: "" });
    const { isMac } = await import("./platform");
    expect(isMac()).toBe(true);
  });

  it("defaults to non-mac when navigator is absent", async () => {
    vi.resetModules();
    vi.stubGlobal("navigator", undefined);
    const { isMac, modLabel } = await import("./platform");
    expect(isMac()).toBe(false);
    expect(modLabel()).toBe("Ctrl");
  });
});
