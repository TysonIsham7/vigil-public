import { safeSignalText } from "./text.js";

const mode = document.querySelector<HTMLInputElement>("#mode");
const helper = document.querySelector<HTMLInputElement>("#helper");
const token = document.querySelector<HTMLInputElement>("#token");
const host = document.querySelector("#host");
const findings = document.querySelector("#findings");

interface Shown { id: string; title: string; summary: string }
interface PopupState {
  mode: "normal" | "high";
  helperOrigin: string | null;
  helperToken: string | null;
  host: string | null;
  decision: { badge?: string; popup?: Shown[]; gating?: Shown[] } | null;
}

const state = await chrome.runtime.sendMessage({ type: "get-popup" }) as PopupState;
if (mode) mode.checked = state.mode === "high";
if (helper) helper.value = state.helperOrigin ?? "";
if (token) token.value = state.helperToken ?? "";
if (host) host.textContent = state.host ? safeSignalText(state.host, 253) : "No site in this tab";
const items = state.decision?.popup?.length ? state.decision.popup : state.decision?.gating ?? [];
if (!items.length && findings) {
  const li = document.createElement("li");
  li.textContent = state.decision ? "No findings for this tab." : "No check yet.";
  findings.append(li);
}
for (const item of items) {
  const li = document.createElement("li");
  const id = document.createElement("div");
  id.className = "id";
  id.textContent = safeSignalText(item.id, 80);
  const text = document.createElement("div");
  text.textContent = safeSignalText(item.title, 160);
  li.append(id, text);
  findings?.append(li);
}

mode?.addEventListener("change", () => {
  void chrome.runtime.sendMessage({ type: "set-mode", mode: mode.checked ? "high" : "normal" });
});
function saveHelper(): void {
  void chrome.runtime.sendMessage({
    type: "set-helper",
    helperOrigin: helper?.value ?? "",
    helperToken: token?.value ?? "",
  });
}
helper?.addEventListener("change", saveHelper);
token?.addEventListener("change", saveHelper);

export {};
