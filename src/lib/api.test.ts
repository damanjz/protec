import { describe, it, expect, vi, beforeEach } from "vitest";

const invokeMock = vi.fn();
vi.mock("@tauri-apps/api/core", () => ({ invoke: (...args: unknown[]) => invokeMock(...args) }));

import { api } from "./api";

describe("api layer", () => {
  beforeEach(() => invokeMock.mockReset());

  it("unlock passes masterPassword through invoke", async () => {
    invokeMock.mockResolvedValue(undefined);
    await api.unlock("hunter2");
    expect(invokeMock).toHaveBeenCalledWith("unlock", { masterPassword: "hunter2" });
  });

  it("getEntry passes id and reveal flag", async () => {
    invokeMock.mockResolvedValue({});
    await api.getEntry("abc", true);
    expect(invokeMock).toHaveBeenCalledWith("get_entry", { id: "abc", reveal: true });
  });

  it("copySecret passes text and clearSecs", async () => {
    invokeMock.mockResolvedValue(undefined);
    await api.copySecret("pw", 20);
    expect(invokeMock).toHaveBeenCalledWith("copy_secret", { text: "pw", clearSecs: 20 });
  });

  it("helloStatus invokes hello_status", async () => {
    invokeMock.mockResolvedValue({ available: true, enabled: false });
    await api.helloStatus();
    expect(invokeMock).toHaveBeenCalledWith("hello_status");
  });

  it("helloEnable invokes hello_enable", async () => {
    invokeMock.mockResolvedValue(undefined);
    await api.helloEnable();
    expect(invokeMock).toHaveBeenCalledWith("hello_enable");
  });

  it("helloUnlock invokes hello_unlock", async () => {
    invokeMock.mockResolvedValue(undefined);
    await api.helloUnlock();
    expect(invokeMock).toHaveBeenCalledWith("hello_unlock");
  });
});
