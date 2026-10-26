import {
  canonicalHost,
  classifyNavigation,
  helperInstallToken,
  loopbackHelperOrigin,
  planAfter,
  planBefore,
  returnHostMatches,
  type CacheEntry,
  type NavDecision,
  type SecurityMode,
} from "@vigil/core";
import { INTEL_VERSION } from "@vigil/intel/version";
import { highSecurityRules } from "./dnr.js";
import { extensionMessagePage } from "./messages.js";
import { SESSION_BAG, applySessionRules, hasNativeSession, readEphemeral, sessionAreaFromChrome, setBadge, writeEphemeral, type DnrLike } from "./platform.js";
import { chromeNativeEnabled } from "./chrome-host.js";
import { nativeMessagingEnabled } from "./native.js";
import { DEFAULT_GUARDS, PHP_EXPOSURE_ID, readGuards, type GuardSettings } from "./guard-settings.js";
import { GUARD_SCRIPT_IDS, enabledGuardScripts } from "./page-guards.js";
import { localSignals, runHoldScan } from "./scan.js";
import {
  BLANK_GUARD_ID,
  OPENER_BLANK_MESSAGE,
  acceptOpenerBlank,
  blankGuardScript,
  blankHoldDecision,
  httpPageUrl,
  isScriptlessBlank,
  shouldHoldOpenedUrl,
} from "./blank-guard.js";

interface Persisted {
  mode: SecurityMode;
  helperOrigin: string | null;
  helperToken: string | null;
  allowlist: string[];
  cache: CacheEntry[];
  guards: GuardSettings;
}

interface Stash {
  url: string;
  host: string;
  startedAt: number;
  heldEarly: boolean;
  blank?: boolean;
}

const BADGE_COLOR: Record<NavDecision["badge"], string> = {
  allow: "#1f7a4d",
  warn: "#8a6a12",
  block: "#8f1d1d",
  unknown: "#3e4c5a",
};

const stash = new Map<number, Stash>();
const once = new Set<string>();
const armed = new Set<string>();
let helperUp = true;
let hydrated = false;
let highMode = false;
let rulesActive = false;

chrome.runtime.onInstalled.addListener(() => {
  void chrome.storage.local.get("vigil").then((stored) => {
    if (!stored.vigil) void chrome.storage.local.set({ vigil: defaultState() });
  });
});

chrome.runtime.onStartup?.addListener(() => {
  if (!hasNativeSession(chrome.storage)) void chrome.storage.local.remove(SESSION_BAG);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  stash.delete(tabId);
  forgetTab(tabId);
  void sessionStore().remove(`url:${tabId}`);
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  noteNavigation(details);
});

chrome.webNavigation.onCommitted?.addListener((details) => {
  if (details.frameId === 0 && details.tabId >= 0) void reapplyBadge(details.tabId);
  noteNavigation(details);
});

chrome.webNavigation.onCreatedNavigationTarget?.addListener((details) => {
  if (!highMode || details.tabId < 0 || !shouldHoldOpenedUrl(details.url)) return;
  void holdBlankTab(details.tabId, details.url);
});

chrome.tabs.onUpdated?.addListener((tabId, info) => {
  if (info.status !== "complete" || tabId < 0) return;
  void reapplyBadge(tabId);
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  void onMessage(message, sender).then(sendResponse).catch((error: unknown) => {
    sendResponse({ error: error instanceof Error ? error.message : "failed" });
  });
  return true;
});

/** Record the clock, then hold. Storage reads happen after the hold is already in place. */
function noteNavigation(details: { tabId: number; frameId: number; url: string }): void {
  if (details.tabId < 0 || details.frameId !== 0) return;
  if (details.url.startsWith(chrome.runtime.getURL(""))) return;
  const startedAt = Date.now();
  const classified = classifyNavigation(details.url);
  if (classified.kind === "ignore") return;
  const key = `${details.tabId}\n${details.url}`;
  if (armed.has(key)) return;
  armed.add(key);
  const host = classified.kind === "site" ? classified.host : "";
  const heldEarly = highMode && (classified.kind === "unsafe" || !rulesActive);
  const saved: Stash = { url: details.url, host, startedAt, heldEarly };
  stash.set(details.tabId, saved);
  if (heldEarly) void chrome.tabs.update(details.tabId, { url: chrome.runtime.getURL("hold.html") });
  void sessionStore().set({ [`url:${details.tabId}`]: saved });
  void onNavigate(details.tabId, saved);
}

async function onNavigate(tabId: number, saved: Stash): Promise<void> {
  await hydrate();
  const state = await load();
  const cached = state.cache.find((entry) => entry.host === saved.host) ?? null;
  const plan = planBefore({
    mode: state.mode,
    url: saved.url,
    now: Date.now(),
    allowlist: state.allowlist,
    once: once.has(saved.host) ? [saved.host] : [],
    cache: cached,
    intelVersion: INTEL_VERSION,
    helperEnabled: Boolean(state.helperOrigin) && helperUp,
  });
  if (plan.reason === "once") {
    once.delete(saved.host);
    await persistEphemeral();
  }
  if (!plan.intercept) {
    const decision = state.mode === "normal" && saved.host
      ? planAfter({
          mode: "normal",
          host: saved.host,
          signals: localSignals(saved.host),
          timedOut: false,
          now: Date.now(),
          intelVersion: INTEL_VERSION,
          coverage: "local",
        })
      : plan;
    await show(tabId, decision);
    if (saved.heldEarly && saved.host && returnHostMatches(saved.host, saved.url)) {
      await chrome.tabs.update(tabId, { url: saved.url });
    }
    return;
  }
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("hold.html") });
}

async function onMessage(message: unknown, sender: { url?: string; tab?: { id?: number } }): Promise<unknown> {
  const request = asRecord(message);
  const type = request.type;
  if (type === OPENER_BLANK_MESSAGE) return holdOpenerBlanks(sender);
  const page = extensionMessagePage(sender.url);
  if (type === "get-popup" || type === "set-mode" || type === "set-helper" || type === "set-guards") {
    if (page !== "popup") return { error: "rejected" };
  } else if (type === "hold-scan" || type === "override-once" || type === "allow-always") {
    if (page !== "hold") return { error: "rejected" };
  }
  if (type === "get-popup") return popupState();
  if (type === "set-mode") return setMode(request.mode === "high" ? "high" : "normal");
  if (type === "set-helper") {
    return setHelper(
      typeof request.helperOrigin === "string" ? request.helperOrigin : "",
      typeof request.helperToken === "string" ? request.helperToken : "",
    );
  }
  if (type === "set-guards") return setGuards(request.guards);
  if (type === "hold-scan") return holdScan(sender.tab?.id);
  if (type === "override-once" || type === "allow-always") {
    return release(sender.tab?.id, type === "allow-always");
  }
  return { error: "unknown message" };
}

function nativeScanOptions(): { nativeRuntime?: typeof chrome.runtime; chromeNative?: typeof chrome.runtime } {
  const manifest = chrome.runtime.getManifest();
  if (nativeMessagingEnabled(manifest, chrome.runtime)) return { nativeRuntime: chrome.runtime };
  if (chromeNativeEnabled(manifest, chrome.runtime)) return { chromeNative: chrome.runtime };
  return {};
}

async function holdScan(tabId: number | undefined): Promise<NavDecision & { url?: string; host?: string }> {
  await hydrate();
  const saved = await takeStash(tabId);
  if (!saved || tabId === undefined) return failClosed();
  if (saved.blank || (!saved.host && isScriptlessBlank(saved.url))) {
    const closed = blankHoldDecision();
    await show(tabId, closed);
    return closed;
  }
  if (!saved.host) {
    const closed = failClosed();
    await show(tabId, closed);
    return closed;
  }
  const state = await load();
  const decision = await runHoldScan({
    host: saved.host,
    mode: state.mode,
    helperOrigin: state.helperOrigin,
    helperToken: state.helperToken,
    now: Date.now(),
    startedAt: saved.startedAt,
    includePhpExposure: state.guards.phpExposure,
    ...nativeScanOptions(),
  });
  if (state.helperOrigin) {
    helperUp = decision.helper !== "down";
    await persistEphemeral();
  }
  if (decision.cache) await writeCache(state, decision.cache);
  await show(tabId, decision);
  if (!decision.intercept && returnHostMatches(saved.host, saved.url)) {
    await chrome.tabs.update(tabId, { url: saved.url });
  }
  return { ...decision, url: saved.url, host: saved.host };
}

async function release(tabId: number | undefined, always: boolean): Promise<{ ok: boolean }> {
  await hydrate();
  const saved = await takeStash(tabId);
  if (!saved || tabId === undefined || !returnHostMatches(saved.host, saved.url)) return { ok: false };
  const state = await load();
  if (always) {
    const allowlist = [...new Set([...state.allowlist, saved.host])];
    const cache = state.cache.filter((entry) => entry.host !== saved.host);
    await chrome.storage.local.set({ vigil: { ...state, allowlist, cache } });
  } else {
    once.add(saved.host);
    await persistEphemeral();
  }
  await syncRules();
  await chrome.tabs.update(tabId, { url: saved.url });
  return { ok: true };
}

async function popupState(): Promise<unknown> {
  const state = await load();
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const host = tab?.url ? canonicalHost(tab.url) : null;
  const stored = tab?.id === undefined ? undefined : await sessionStore().get(`decision:${tab.id}`);
  const decision = hidePhp(tab?.id === undefined ? null : stored?.[`decision:${tab.id}`] ?? null, state.guards.phpExposure);
  return { mode: state.mode, helperOrigin: state.helperOrigin, helperToken: state.helperToken, allowlist: state.allowlist, guards: state.guards, host, decision };
}

async function setMode(mode: SecurityMode): Promise<Persisted> {
  highMode = mode === "high";
  if (!highMode) rulesActive = false;
  await hydrate();
  helperUp = true;
  await persistEphemeral();
  const state = await load();
  const next = { ...state, mode };
  await chrome.storage.local.set({ vigil: next });
  await syncRules();
  await syncBlankGuard();
  return next;
}

async function setGuards(value: unknown): Promise<Persisted> {
  await hydrate();
  const state = await load();
  const next = { ...state, guards: readGuards(value, state.guards) };
  await chrome.storage.local.set({ vigil: next });
  await syncPageGuards();
  return next;
}

async function setHelper(originValue: string, tokenValue: string): Promise<Persisted> {
  await hydrate();
  helperUp = true;
  await persistEphemeral();
  const state = await load();
  const helperOrigin = originValue.trim() ? loopbackHelperOrigin(originValue.trim()) : null;
  if (originValue.trim() && !helperOrigin) return state;
  const helperToken = tokenValue.trim() ? helperInstallToken(tokenValue) : null;
  if (tokenValue.trim() && !helperToken) return state;
  const next = { ...state, helperOrigin, helperToken };
  await chrome.storage.local.set({ vigil: next });
  return next;
}

async function show(tabId: number, decision: NavDecision): Promise<void> {
  await badge(tabId, decision.badge);
  const view = {
    action: decision.action,
    badge: decision.badge,
    reason: decision.reason,
    intercept: decision.intercept,
    gating: decision.gating.map(compact),
    popup: decision.popup.map(compact),
  };
  await sessionStore().set({ [`decision:${tabId}`]: view });
}

async function reapplyBadge(tabId: number): Promise<void> {
  const stored = await sessionStore().get(`decision:${tabId}`);
  const decision = stored[`decision:${tabId}`] as { badge?: NavDecision["badge"] } | undefined;
  if (!decision?.badge) return;
  await badge(tabId, decision.badge);
}

async function badge(tabId: number, kind: NavDecision["badge"]): Promise<void> {
  const text = kind === "allow" ? "" : kind === "block" ? "!" : kind === "warn" ? "!" : "?";
  await setBadge(chrome.action, tabId, text, BADGE_COLOR[kind]);
}

async function writeCache(state: Persisted, entry: CacheEntry): Promise<void> {
  const cache = [entry, ...state.cache.filter((item) => item.host !== entry.host)].slice(0, 200);
  await chrome.storage.local.set({ vigil: { ...state, cache } });
  await syncRules();
}

async function syncRules(): Promise<void> {
  await hydrate();
  const state = await load();
  highMode = state.mode === "high";
  const skipped = highMode
    ? [
        ...state.allowlist,
        ...once,
        ...state.cache.filter((entry) => entry.action === "allow" || entry.action === "warn").map((entry) => entry.host),
      ]
    : [];
  const dnr = (chrome as { declarativeNetRequest?: DnrLike }).declarativeNetRequest;
  const applied = await applySessionRules(dnr, highMode ? highSecurityRules(skipped) : []);
  rulesActive = highMode && applied.applied;
}

async function syncPageGuards(): Promise<void> {
  const scripting = chrome.scripting;
  if (!scripting?.unregisterContentScripts || !scripting.registerContentScripts) return;
  const state = await load();
  try {
    await scripting.unregisterContentScripts({ ids: [...GUARD_SCRIPT_IDS] });
  } catch {
    /* None of the guards were registered. */
  }
  const scripts = enabledGuardScripts(state.guards);
  if (scripts.length === 0) return;
  try {
    await scripting.registerContentScripts(scripts);
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map(async (tab) => {
      if (tab.id === undefined || !httpPageUrl(tab.url)) return;
      try {
        await scripting.executeScript?.({
          target: { tabId: tab.id, allFrames: true },
          files: scripts.map((script) => script.js[0]),
          world: "MAIN",
        });
      } catch {
        /* Privileged or discarded tabs cannot be injected. */
      }
    }));
  } catch {
    /* Safari has no scripting permission. The PHP class still arrives with a verdict. */
  }
}

async function syncBlankGuard(): Promise<void> {
  const scripting = chrome.scripting;
  if (!scripting?.unregisterContentScripts || !scripting.registerContentScripts) return;
  try {
    await scripting.unregisterContentScripts({ ids: [BLANK_GUARD_ID] });
  } catch {
    /* The guard was not registered. */
  }
  if (!highMode) return;
  try {
    await scripting.registerContentScripts([blankGuardScript()]);
    const tabs = await chrome.tabs.query({});
    await Promise.all(tabs.map(async (tab) => {
      if (tab.id === undefined || !httpPageUrl(tab.url)) return;
      try {
        await scripting.executeScript?.({
          target: { tabId: tab.id, allFrames: true },
          files: ["blank-guard.js"],
          world: "MAIN",
        });
      } catch {
        /* Privileged or discarded tabs cannot be injected. */
      }
    }));
  } catch {
    /* Safari has no scripting permission. High Security still holds navigations it can see. */
  }
}

async function holdOpenerBlanks(sender: { url?: string; tab?: { id?: number } }): Promise<{ held: number }> {
  const openerId = sender.tab?.id;
  if (!acceptOpenerBlank({ highMode, senderUrl: sender.url, tabId: openerId })) return { held: 0 };
  const tabs = await chrome.tabs.query({});
  let held = 0;
  for (const tab of tabs) {
    if (tab.openerTabId !== openerId || tab.id === undefined) continue;
    if (!shouldHoldOpenedUrl(tab.url)) continue;
    const url = tab.url && tab.url.trim() !== "" ? tab.url : "about:blank";
    await holdBlankTab(tab.id, url);
    held += 1;
  }
  return { held };
}

async function holdBlankTab(tabId: number, url: string): Promise<void> {
  const saved: Stash = { url, host: "", startedAt: Date.now(), heldEarly: true, blank: true };
  stash.set(tabId, saved);
  await sessionStore().set({ [`url:${tabId}`]: saved });
  await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("hold.html") });
}

async function takeStash(tabId: number | undefined): Promise<Stash | null> {
  if (tabId === undefined) return null;
  const memory = stash.get(tabId);
  if (memory) return memory;
  const stored = await sessionStore().get(`url:${tabId}`);
  const value = stored[`url:${tabId}`];
  if (!value || typeof value !== "object") return null;
  const record = value as Partial<Stash>;
  if (typeof record.url !== "string" || typeof record.host !== "string") return null;
  if (record.host && !returnHostMatches(record.host, record.url)) return null;
  return {
    url: record.url,
    host: record.host,
    startedAt: typeof record.startedAt === "number" ? record.startedAt : Date.now(),
    heldEarly: record.heldEarly === true,
    blank: record.blank === true,
  };
}

async function load(): Promise<Persisted> {
  const stored = await chrome.storage.local.get("vigil");
  const value = stored.vigil;
  if (!value || typeof value !== "object") return defaultState();
  const record = value as Partial<Persisted>;
  return {
    mode: record.mode === "high" ? "high" : "normal",
    helperOrigin: typeof record.helperOrigin === "string" ? record.helperOrigin : null,
    helperToken: typeof record.helperToken === "string" ? helperInstallToken(record.helperToken) : null,
    allowlist: Array.isArray(record.allowlist) ? record.allowlist.filter((item) => typeof item === "string") : [],
    cache: Array.isArray(record.cache) ? record.cache as CacheEntry[] : [],
    guards: readGuards(record.guards),
  };
}

function sessionStore() {
  return sessionAreaFromChrome(chrome.storage);
}

async function hydrate(): Promise<void> {
  if (hydrated) return;
  const restored = await readEphemeral(sessionStore());
  hydrated = true;
  for (const host of restored.once) once.add(host);
  helperUp = restored.helperUp;
}

async function persistEphemeral(): Promise<void> {
  await writeEphemeral(sessionStore(), { once: [...once], helperUp });
}

function forgetTab(tabId: number): void {
  const prefix = `${tabId}\n`;
  for (const key of armed) {
    if (key.startsWith(prefix)) armed.delete(key);
  }
}

function defaultState(): Persisted {
  return { mode: "normal", helperOrigin: null, helperToken: null, allowlist: [], cache: [], guards: DEFAULT_GUARDS };
}

void bootstrap();

async function bootstrap(): Promise<void> {
  await hydrate();
  const state = await load();
  highMode = state.mode === "high";
  await syncRules();
  await syncBlankGuard();
  await syncPageGuards();
}

function failClosed(): NavDecision {
  return {
    intercept: true,
    action: "hold",
    badge: "unknown",
    reason: "timeout",
    gating: [],
    popup: [],
  };
}

function compact(signal: { id: string; title: string; summary: string }): { id: string; title: string; summary: string } {
  return { id: signal.id, title: signal.title, summary: signal.summary };
}

function hidePhp(decision: unknown, enabled: boolean): unknown {
  if (enabled || !decision || typeof decision !== "object") return decision;
  const record = decision as { popup?: { id?: string }[]; gating?: { id?: string }[] };
  const strip = <T extends { id?: string }>(list: T[] | undefined) => (
    Array.isArray(list) ? list.filter((item) => item?.id !== PHP_EXPOSURE_ID) : list
  );
  return { ...record, popup: strip(record.popup), gating: strip(record.gating) };
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" ? value as Record<string, unknown> : {};
}
