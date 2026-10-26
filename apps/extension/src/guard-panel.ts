export interface GuardPrompt {
  title: string;
  body: string;
  allowLabel: string;
  blockLabel: string;
  rememberLabel?: string;
  detail?: string;
}

let queue: Promise<void> = Promise.resolve();

export function claimGuard(target: object, key: string): boolean {
  if (Object.prototype.hasOwnProperty.call(target, key)) return false;
  try {
    Object.defineProperty(target, key, { value: true });
    return true;
  } catch {
    return false;
  }
}

/** In-page choice. The promise resolves only from this dialog, not from a page message. */
export function chooseGuard(prompt: GuardPrompt): Promise<{ ok: boolean; remember: boolean }> {
  const run = queue.then(() => openGuard(prompt), () => openGuard(prompt));
  queue = run.then(() => undefined, () => undefined);
  return run;
}

function openGuard(prompt: GuardPrompt): Promise<{ ok: boolean; remember: boolean }> {
  const root = document.documentElement ?? document.body;
  if (!root) return Promise.resolve({ ok: false, remember: false });
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.setAttribute("data-vigil-guard", "");
    host.style.cssText = "all:initial;position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(8,12,18,.55);";
    const shadow = host.attachShadow({ mode: "closed" });
    const panel = document.createElement("div");
    panel.setAttribute("role", "dialog");
    panel.setAttribute("aria-modal", "true");
    panel.style.cssText = "font:14px/1.4 Segoe UI,sans-serif;background:#0e1520;color:#e7eef6;padding:16px;border-radius:10px;max-width:22rem;box-shadow:0 12px 40px rgba(0,0,0,.4);";
    const title = document.createElement("div");
    title.textContent = prompt.title;
    title.style.fontWeight = "600";
    const body = document.createElement("p");
    body.textContent = prompt.body;
    body.style.margin = "8px 0";
    panel.append(title, body);
    if (prompt.detail) {
      const detail = document.createElement("pre");
      detail.textContent = prompt.detail;
      detail.style.cssText = "white-space:pre-wrap;word-break:break-word;background:#172232;padding:8px;border-radius:6px;max-height:6rem;overflow:auto;margin:0;";
      panel.append(detail);
    }
    let remember: HTMLInputElement | null = null;
    if (prompt.rememberLabel) {
      const label = document.createElement("label");
      label.style.cssText = "display:flex;gap:8px;align-items:center;margin:8px 0;";
      remember = document.createElement("input");
      remember.type = "checkbox";
      const text = document.createElement("span");
      text.textContent = prompt.rememberLabel;
      label.append(remember, text);
      panel.append(label);
    }
    const row = document.createElement("div");
    row.style.cssText = "display:flex;gap:8px;justify-content:flex-end;margin-top:12px;";
    const block = button(prompt.blockLabel);
    const allow = button(prompt.allowLabel);
    row.append(block, allow);
    panel.append(row);
    shadow.append(panel);
    root.append(host);
    const finish = (ok: boolean) => {
      host.remove();
      document.removeEventListener("keydown", onKey, true);
      resolve({ ok, remember: Boolean(ok && remember?.checked) });
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      event.stopPropagation();
      finish(false);
    };
    document.addEventListener("keydown", onKey, true);
    block.addEventListener("click", () => finish(false));
    allow.addEventListener("click", () => finish(true));
    block.focus();
  });
}

function button(label: string): HTMLButtonElement {
  const element = document.createElement("button");
  element.type = "button";
  element.textContent = label;
  element.style.cssText = "font:inherit;background:#172232;color:inherit;border:1px solid #31445c;border-radius:6px;padding:6px 10px;";
  return element;
}
