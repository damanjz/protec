import type { Request, Response } from "./protocol";

const HOST = "dev.protec.host";

/// Send one request to the native host and resolve its response.
function sendNative(req: Request): Promise<Response> {
  return new Promise((resolve) => {
    chrome.runtime.sendNativeMessage(HOST, req, (resp) => {
      if (chrome.runtime.lastError || !resp) {
        resolve({ type: "error", message: "Protec host unavailable" });
      } else {
        resolve(resp as Response);
      }
    });
  });
}

// Content scripts ask the background to talk to the host (content scripts can't
// use native messaging directly).
chrome.runtime.onMessage.addListener((msg: Request, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return; // reject cross-extension messages
  sendNative(msg).then(sendResponse);
  return true; // keep the channel open for the async response
});
