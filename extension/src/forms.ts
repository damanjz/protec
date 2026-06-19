/// Result of scanning a document for a login form.
export interface DetectedForm {
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
}

/// Find the most likely username + password fields in a root element.
/// Heuristic: the password field is the first visible input[type=password];
/// the username field is the nearest preceding text/email input.
export function detectLoginForm(root: ParentNode): DetectedForm {
  const passwords = Array.from(
    root.querySelectorAll<HTMLInputElement>('input[type="password"]'),
  ).filter(isVisible);
  const passwordField = passwords[0] ?? null;
  let usernameField: HTMLInputElement | null = null;

  if (passwordField) {
    const candidates = Array.from(
      root.querySelectorAll<HTMLInputElement>(
        'input[type="text"], input[type="email"], input:not([type])',
      ),
    ).filter(isVisible);
    // Prefer the last text/email input that appears before the password field.
    const pwIndex = allInputs(root).indexOf(passwordField);
    usernameField =
      candidates
        .filter((c) => allInputs(root).indexOf(c) < pwIndex)
        .pop() ?? candidates[0] ?? null;
  }
  return { usernameField, passwordField };
}

function allInputs(root: ParentNode): HTMLInputElement[] {
  return Array.from(root.querySelectorAll<HTMLInputElement>("input"));
}

function isVisible(el: HTMLElement): boolean {
  // jsdom has no layout; treat elements without explicit hiding as visible.
  if (el.hidden) return false;
  const style = (el as HTMLElement).getAttribute("style") ?? "";
  if (/display:\s*none/.test(style) || /visibility:\s*hidden/.test(style)) return false;
  return (el as HTMLInputElement).type !== "hidden";
}

/// Read the current username+password values from a detected form.
export function readCredentials(form: DetectedForm): { username: string; password: string } | null {
  if (!form.passwordField || !form.passwordField.value) return null;
  return {
    username: form.usernameField?.value ?? "",
    password: form.passwordField.value,
  };
}
