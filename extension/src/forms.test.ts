import { describe, it, expect } from "vitest";
import { detectLoginForm, readCredentials } from "./forms";

function dom(html: string): ParentNode {
  document.body.innerHTML = html;
  return document.body;
}

describe("forms", () => {
  it("detects a standard username+password form", () => {
    const root = dom(`
      <form>
        <input type="text" name="user" value="octocat" />
        <input type="password" name="pass" value="s3cret" />
        <button>Login</button>
      </form>`);
    const f = detectLoginForm(root);
    expect(f.passwordField?.value).toBe("s3cret");
    expect(f.usernameField?.value).toBe("octocat");
  });

  it("detects email-style username", () => {
    const root = dom(`
      <input type="email" value="me@example.com" />
      <input type="password" value="pw" />`);
    const f = detectLoginForm(root);
    expect(f.usernameField?.value).toBe("me@example.com");
  });

  it("returns null password field when none present", () => {
    const root = dom(`<input type="text" value="x" />`);
    const f = detectLoginForm(root);
    expect(f.passwordField).toBeNull();
  });

  it("ignores hidden password fields", () => {
    const root = dom(`
      <input type="password" style="display: none" value="hidden" />
      <input type="text" value="u" />
      <input type="password" value="real" />`);
    const f = detectLoginForm(root);
    expect(f.passwordField?.value).toBe("real");
  });

  it("readCredentials returns null when password empty", () => {
    const root = dom(`<input type="text" value="u" /><input type="password" value="" />`);
    expect(readCredentials(detectLoginForm(root))).toBeNull();
  });

  it("readCredentials captures both fields", () => {
    const root = dom(`<input type="text" value="u" /><input type="password" value="p" />`);
    expect(readCredentials(detectLoginForm(root))).toEqual({ username: "u", password: "p" });
  });
});
