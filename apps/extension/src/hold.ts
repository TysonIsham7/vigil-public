import { holdStatusText, safeSignalText } from "./text.js";

const title = document.querySelector("#title");
const target = document.querySelector("#target");
const status = document.querySelector("#status");
const reasons = document.querySelector("#reasons");
const actions = document.querySelector("#actions");
const once = document.querySelector("#once");
const always = document.querySelector("#always");

interface Shown {
  id: string;
  title: string;
  summary: string;
}

interface Decision {
  intercept?: boolean;
  action?: string;
  reason?: string;
  host?: string;
  url?: string;
  gating?: Shown[];
  popup?: Shown[];
  error?: string;
}

const decision = await chrome.runtime.sendMessage({ type: "hold-scan" }) as Decision;
if (decision.intercept) render(decision);
else if (title && status) {
  title.textContent = "Continuing";
  status.textContent = "This check did not need to hold the page.";
}

function render(value: Decision): void {
  const held = value.action === "block" ? "Vigil blocked this site" : "Vigil held this site";
  if (title) title.textContent = held;
  if (target) {
    const host = value.host ? safeSignalText(value.host, 253) : "";
    const url = value.url ? safeSignalText(value.url, 300) : "";
    target.textContent = host && url ? `${host} — ${url}` : host || url;
  }
  const items = value.gating?.length ? value.gating : value.popup ?? [];
  if (status) {
    status.textContent = holdStatusText({ reason: value.reason, ids: items.map((item) => item.id) });
  }
  for (const item of items) {
    const li = document.createElement("li");
    const id = document.createElement("div");
    id.className = "id";
    id.textContent = safeSignalText(item.id, 80);
    const text = document.createElement("div");
    text.textContent = safeSignalText(`${item.title}. ${item.summary}`, 160);
    li.append(id, text);
    reasons?.append(li);
  }
  if (value.host) actions?.classList.remove("hidden");
}

once?.addEventListener("click", () => {
  void chrome.runtime.sendMessage({ type: "override-once" });
});
always?.addEventListener("click", () => {
  void chrome.runtime.sendMessage({ type: "allow-always" });
});

export {};
