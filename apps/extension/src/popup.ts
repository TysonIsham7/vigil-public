import { safeSignalText } from "./text.js";

const mode = document.querySelector<HTMLInputElement>("#mode");
const helper = document.querySelector<HTMLInputElement>("#helper");
const token = document.querySelector<HTMLInputElement>("#token");
const host = document.querySelector("#host");
const findings = document.querySelector("#findings");

interface Shown { id: string; title: string; summary: string }
interface GuardSettings {
  phpExposure: boolean;
  clickfix: boolean;
  seedPhrase: boolean;
  wallet: boolean;
}

interface PopupState {
  mode: "normal" | "high";
  helperOrigin: string | null;
  helperToken: string | null;
  guards?: GuardSettings;
  host: string | null;
  decision: { badge?: string; popup?: Shown[]; gating?: Shown[] } | null;
}

const phpGuard = document.querySelector<HTMLInputElement>("#guard-php");
const clickfixGuard = document.querySelector<HTMLInputElement>("#guard-clickfix");
const seedGuard = document.querySelector<HTMLInputElement>("#guard-seed");
const walletGuard = document.querySelector<HTMLInputElement>("#guard-wallet");

const state = await chrome.runtime.sendMessage({ type: "get-popup" }) as PopupState;
const guards = state.guards ?? { phpExposure: true, clickfix: true, seedPhrase: true, wallet: true };
if (mode) mode.checked = state.mode === "high";
if (phpGuard) phpGuard.checked = guards.phpExposure;
if (clickfixGuard) clickfixGuard.checked = guards.clickfix;
if (seedGuard) seedGuard.checked = guards.seedPhrase;
if (walletGuard) walletGuard.checked = guards.wallet;
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
if (guards.phpExposure && state.decision && !items.some((item) => item.id === "PHP2SHELL_EXPOSURE") && findings) {
  const li = document.createElement("li");
  const id = document.createElement("div");
  id.className = "id";
  id.textContent = "PHP2SHELL_EXPOSURE";
  const text = document.createElement("div");
  text.textContent = "PHP2Shell: headers were not part of this check.";
  li.append(id, text);
  findings.append(li);
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

function saveGuards(): void {
  void chrome.runtime.sendMessage({
    type: "set-guards",
    guards: {
      phpExposure: phpGuard?.checked ?? true,
      clickfix: clickfixGuard?.checked ?? true,
      seedPhrase: seedGuard?.checked ?? true,
      wallet: walletGuard?.checked ?? true,
    },
  });
}
phpGuard?.addEventListener("change", saveGuards);
clickfixGuard?.addEventListener("change", saveGuards);
seedGuard?.addEventListener("change", saveGuards);
walletGuard?.addEventListener("change", saveGuards);

export {};
