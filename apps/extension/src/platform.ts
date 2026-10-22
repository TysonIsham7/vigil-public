import type { SessionRule } from "./dnr.js";

/** Bag used when the browser has no storage.session. Cleared on browser startup. */
export const SESSION_BAG = "vigil-session";
export const EPHEMERAL_ONCE = "vigil-once";
export const EPHEMERAL_HELPER_UP = "vigil-helper-up";

export interface StorageAreaLike {
  get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

export interface DnrLike {
  getSessionRules(): Promise<{ id: number }[]>;
  updateSessionRules(options: { removeRuleIds?: number[]; addRules?: SessionRule[] }): Promise<void>;
}

export interface BadgeAction {
  setBadgeText?(details: { text: string; tabId?: number }): Promise<void>;
  setBadgeBackgroundColor?(details: { color: string; tabId?: number }): Promise<void>;
}

export interface BrowserCapabilities {
  sessionStorage: boolean;
  declarativeNetRequest: boolean;
  webNavigation: boolean;
  toolbarBadge: boolean;
}

export function detectCapabilities(api: {
  storage?: { session?: unknown };
  declarativeNetRequest?: { getSessionRules?: unknown; updateSessionRules?: unknown };
  webNavigation?: { onBeforeNavigate?: unknown };
  action?: BadgeAction;
}): BrowserCapabilities {
  const rules = api.declarativeNetRequest;
  return {
    sessionStorage: Boolean(api.storage?.session),
    declarativeNetRequest: typeof rules?.getSessionRules === "function" && typeof rules?.updateSessionRules === "function",
    webNavigation: Boolean(api.webNavigation?.onBeforeNavigate),
    toolbarBadge: typeof api.action?.setBadgeText === "function",
  };
}

export function hasNativeSession(storage: { session?: unknown }): boolean {
  return Boolean(storage.session);
}

/** Prefer storage.session. Fall back to a local bag Safari can clear on startup. */
export function createSessionArea(local: StorageAreaLike, session?: StorageAreaLike): StorageAreaLike {
  if (session) return session;
  return {
    async get(keys) {
      const bag = await readBag(local);
      if (keys == null) return { ...bag };
      const list = typeof keys === "string" ? [keys] : keys;
      const out: Record<string, unknown> = {};
      for (const key of list) {
        if (Object.prototype.hasOwnProperty.call(bag, key)) out[key] = bag[key];
      }
      return out;
    },
    async set(items) {
      const bag = await readBag(local);
      Object.assign(bag, items);
      await local.set({ [SESSION_BAG]: bag });
    },
    async remove(keys) {
      const bag = await readBag(local);
      const list = typeof keys === "string" ? [keys] : keys;
      for (const key of list) delete bag[key];
      await local.set({ [SESSION_BAG]: bag });
    },
  };
}

export function sessionAreaFromChrome(storage: { local: StorageAreaLike; session?: StorageAreaLike }): StorageAreaLike {
  return createSessionArea(storage.local, storage.session);
}

export async function readEphemeral(area: StorageAreaLike): Promise<{ once: string[]; helperUp: boolean }> {
  const stored = await area.get([EPHEMERAL_ONCE, EPHEMERAL_HELPER_UP]);
  const raw = stored[EPHEMERAL_ONCE];
  const once = Array.isArray(raw) ? raw.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
  return { once, helperUp: stored[EPHEMERAL_HELPER_UP] !== false };
}

export async function writeEphemeral(area: StorageAreaLike, value: { once: readonly string[]; helperUp: boolean }): Promise<void> {
  await area.set({
    [EPHEMERAL_ONCE]: [...value.once],
    [EPHEMERAL_HELPER_UP]: value.helperUp,
  });
}

/**
 * Cached hold/block redirects. Safari may omit session rules or reject an extension-page
 * redirect. The navigation handler remains the gate either way.
 */
export async function applySessionRules(dnr: DnrLike | undefined, rules: readonly SessionRule[]): Promise<{ applied: boolean; reason?: string }> {
  if (!dnr || typeof dnr.getSessionRules !== "function" || typeof dnr.updateSessionRules !== "function") {
    return { applied: false, reason: "declarativeNetRequest session rules are not available" };
  }
  try {
    const existing = await dnr.getSessionRules();
    await dnr.updateSessionRules({
      removeRuleIds: existing.map((rule) => rule.id),
      addRules: [...rules],
    });
    return { applied: true };
  } catch (error) {
    return { applied: false, reason: error instanceof Error ? error.message : "session rules rejected" };
  }
}

/** macOS can show a toolbar badge. iOS Safari often has no badge API, and a throw must not skip the hold. */
export async function setBadge(action: BadgeAction | undefined, tabId: number, text: string, color: string): Promise<boolean> {
  if (!action?.setBadgeText || !action.setBadgeBackgroundColor) return false;
  try {
    await action.setBadgeText({ tabId, text });
    await action.setBadgeBackgroundColor({ tabId, color });
    return true;
  } catch {
    return false;
  }
}

async function readBag(local: StorageAreaLike): Promise<Record<string, unknown>> {
  const stored = await local.get(SESSION_BAG);
  const value = stored[SESSION_BAG];
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return { ...(value as Record<string, unknown>) };
}
