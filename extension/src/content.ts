import type { Request, Response } from "./protocol";
import { detectLoginForm, readCredentials } from "./forms";

/// The page origin as the browser sees it — NOT page-controlled content.
const ORIGIN = window.location.origin;

function ask(req: Request): Promise<Response> {
  return new Promise((resolve) => chrome.runtime.sendMessage(req, resolve));
}

/// Fill the detected form with a credential.
function fill(username: string, password: string) {
  const form = detectLoginForm(document);
  if (form.usernameField) {
    form.usernameField.value = username;
    form.usernameField.dispatchEvent(new Event("input", { bubbles: true }));
  }
  if (form.passwordField) {
    form.passwordField.value = password;
    form.passwordField.dispatchEvent(new Event("input", { bubbles: true }));
  }
}

/// On load, if there's a login form, ask the app for a credential.
async function tryFill() {
  if (!detectLoginForm(document).passwordField) return;
  const resp = await ask({ type: "find", origin: ORIGIN });
  if (resp.type === "credential") {
    fill(resp.username, resp.password);
  }
  // locked / no_match / denied → do nothing (fail closed).
}

/// On submit, report the credential so the app can save/update.
function watchSubmit() {
  document.addEventListener(
    "submit",
    () => {
      const creds = readCredentials(detectLoginForm(document));
      if (creds) {
        void ask({ type: "submit", origin: ORIGIN, username: creds.username, password: creds.password });
      }
    },
    true,
  );
}

// Listen for a manual fill request from the popup.
chrome.runtime.onMessage.addListener((msg: { type?: string }) => {
  if (msg?.type === "manual_fill") void tryFill();
});

void tryFill();
watchSubmit();
