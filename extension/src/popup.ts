import type { Request, Response } from "./protocol";

const statusEl = document.getElementById("status")!;
const fillBtn = document.getElementById("fill") as HTMLButtonElement;

function sendNative(req: Request): Promise<Response> {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage("dev.protec.host", req, (resp) => {
      if (chrome.runtime.lastError || !resp) resolve({ type: "error", message: "unavailable" });
      else resolve(resp as Response);
    });
  });
}

(async () => {
  const resp = await sendNative({ type: "status" });
  if (resp.type === "status") statusEl.textContent = resp.unlocked ? "● Protec unlocked" : "● Protec locked";
  else if (resp.type === "error") statusEl.textContent = "Protec app not running";
})();

fillBtn.addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) chrome.tabs.sendMessage(tab.id, { type: "manual_fill" });
});
