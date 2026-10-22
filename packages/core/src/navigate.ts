import type { Severity } from "./types.js";

/** Target for the fast path. The hard timeout is what High Security enforces. */
export const NAV_BUDGET_MS = 1500;
export const NAV_HARD_TIMEOUT_MS = 2000;
export const CACHE_SCHEMA = 1;

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const CLOCK_SKEW_MS = 5_000;

export type SecurityMode = "normal" | "high";
export type NavAction = "allow" | "warn" | "hold" | "block";
export type BadgeState = "allow" | "warn" | "block" | "unknown";
export type GateClass = "cert" | "phishing" | "advisory";
export type CacheCoverage = "local" | "full";

export interface GateSignal {
  id: string;
  severity: Severity;
  recommendationOnly: boolean;
  title: string;
  summary: string;
  confidence?: "high" | "medium" | "low";
}

export interface CacheEntry {
  schema: typeof CACHE_SCHEMA;
  host: string;
  action: NavAction;
  badge: BadgeState;
  coverage: CacheCoverage;
  gatingIds: string[];
  popup: { id: string; title: string; summary: string }[];
  writtenAt: number;
  expiresAt: number;
  intelVersion: string;
}

export interface NavDecision {
  intercept: boolean;
  action: NavAction;
  badge: BadgeState;
  reason: "passive" | "allowlist" | "once" | "cache" | "cert" | "phishing" | "advisory" | "timeout" | "unavailable" | "clean" | "unknown" | "ignored";
  gating: GateSignal[];
  popup: GateSignal[];
  cache?: CacheEntry;
  /** Set when a loopback helper was involved. "down" is a connection failure, which still holds. */
  helper?: "up" | "down";
}

const TTL_MS: Record<NavAction, number> = {
  allow: DAY_MS,
  warn: HOUR_MS,
  hold: HOUR_MS,
  block: HOUR_MS,
};

/** Confirmed certificate failures. Quality notes such as SHA-1 stay in the popup. */
const CERT_HOLD = new Set([
  "CERT_DISTRUSTED_CA",
  "CERT_EXPIRED",
  "CERT_HOSTNAME_MISMATCH",
  "CERT_SELF_SIGNED",
  "TLS_INVALID",
]);

/** Fake-site signals. Weak host patterns (TLD, free hosting, depth) are popup-only. */
const PHISHING_HOLD = new Set([
  "DOMAIN_LOOKALIKE",
  "DOMAIN_SIMILAR",
  "DOMAIN_NEW",
  "DOMAIN_NEW_LOGIN",
  "DOMAIN_MIXED_SCRIPT",
  "DOMAIN_BRAND_IMPERSONATION",
  "DOMAIN_IP_LITERAL",
  "DOMAIN_IP_LOGIN",
  "DOMAIN_CREDENTIAL_CROSS_ORIGIN",
  "DOMAIN_CREDENTIAL_HTTP",
]);

const ADVISORY_HOLD = new Set(["PHP_CVE_2026_109618", "DEP_LITELLM_COMPROMISED"]);

export function gateClass(signal: Pick<GateSignal, "id" | "confidence">): GateClass | null {
  if (CERT_HOLD.has(signal.id)) return "cert";
  if (PHISHING_HOLD.has(signal.id)) return "phishing";
  if (!ADVISORY_HOLD.has(signal.id)) return null;
  if (signal.id === "PHP_CVE_2026_109618" && signal.confidence !== "high") return null;
  return "advisory";
}

export function holdsNavigation(signal: Pick<GateSignal, "id" | "confidence" | "severity">): boolean {
  if (signal.severity === "informational") return false;
  return gateClass(signal) !== null;
}

export function canonicalHost(input: string): string | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  const host = url.hostname.toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || host.includes("\\")) return null;
  return host;
}

export function hopHosts(urls: readonly string[]): string[] {
  return urls.flatMap((url) => {
    const host = canonicalHost(url);
    return host ? [host] : [];
  });
}

export type NavClass = { kind: "ignore" } | { kind: "site"; host: string } | { kind: "unsafe" };

const UNSAFE_PROTOCOLS = new Set(["about:", "blob:", "data:", "javascript:"]);

/** Top-level navigations High Security must hold before page script. Extension pages are ignored by the caller. */
export function classifyNavigation(input: string): NavClass {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { kind: "unsafe" };
  }
  if (UNSAFE_PROTOCOLS.has(url.protocol)) return { kind: "unsafe" };
  if (url.protocol !== "http:" && url.protocol !== "https:") return { kind: "ignore" };
  if (url.username || url.password) return { kind: "unsafe" };
  const host = canonicalHost(input);
  if (!host) return { kind: "unsafe" };
  return { kind: "site", host };
}

/** Per-install secret for `vigil serve`. The native host does not use it. */
export function helperInstallToken(value: string): string | null {
  const token = value.trim();
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(token)) return null;
  return token;
}

/** The address the hold page may open. It must be the host this tab already started loading. */
export function returnHostMatches(stashedHost: string, claimed: string): boolean {
  const host = canonicalHost(claimed);
  return host !== null && host === stashedHost;
}

/** Optional cert/RDAP helper. Only a loopback HTTP origin is accepted, so a page cannot point this at the network. */
export function loopbackHelperOrigin(value: string): string | null {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.protocol !== "http:") return null;
  if (url.hostname !== "127.0.0.1") return null;
  if (url.username || url.password) return null;
  if (url.pathname !== "/" && url.pathname !== "") return null;
  if (url.search || url.hash) return null;
  const port = Number(url.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return `http://127.0.0.1:${port}`;
}

export function readCache(
  entry: CacheEntry | null | undefined,
  host: string,
  now: number,
  intelVersion: string,
  helperEnabled: boolean,
): CacheEntry | null {
  if (!entry || entry.schema !== CACHE_SCHEMA) return null;
  if (entry.host !== host || entry.intelVersion !== intelVersion) return null;
  if (entry.coverage !== "local" && entry.coverage !== "full") return null;
  if (!Number.isFinite(entry.writtenAt) || !Number.isFinite(entry.expiresAt)) return null;
  if (entry.writtenAt > now + CLOCK_SKEW_MS) return null;
  if (now >= entry.expiresAt) return null;
  const ttl = TTL_MS[entry.action];
  if (!ttl || entry.expiresAt > entry.writtenAt + ttl + CLOCK_SKEW_MS) return null;
  const gatingIds = Array.isArray(entry.gatingIds) ? entry.gatingIds : [];
  const wouldHold = gatingIds.some((id) => holdsNavigation({ id, severity: "high", confidence: "high" }));
  if (wouldHold && (entry.action === "allow" || entry.action === "warn")) return null;
  if (helperEnabled && entry.coverage === "local" && (entry.action === "allow" || entry.action === "warn")) return null;
  return entry;
}

export function planBefore(input: {
  mode: SecurityMode;
  url: string;
  now: number;
  allowlist: readonly string[];
  once: readonly string[];
  cache: CacheEntry | null;
  intelVersion: string;
  helperEnabled: boolean;
}): NavDecision {
  const host = canonicalHost(input.url);
  const empty = { gating: [], popup: [] };
  if (!host) {
    if (input.mode === "high") return { intercept: true, action: "hold", badge: "unknown", reason: "unknown", ...empty };
    return { intercept: false, action: "allow", badge: "allow", reason: "ignored", ...empty };
  }
  if (input.mode === "normal") return { intercept: false, action: "allow", badge: "allow", reason: "passive", ...empty };
  const allowed = input.allowlist.some((item) => item.toLowerCase().replace(/\.$/, "") === host);
  if (allowed) return { intercept: false, action: "allow", badge: "allow", reason: "allowlist", ...empty };
  if (input.once.some((item) => item.toLowerCase().replace(/\.$/, "") === host)) {
    return { intercept: false, action: "allow", badge: "unknown", reason: "once", ...empty };
  }
  let cached = readCache(input.cache, host, input.now, input.intelVersion, input.helperEnabled);
  if (cached && cached.coverage === "local" && (cached.action === "allow" || cached.action === "warn")) cached = null;
  if (cached && (cached.action === "allow" || cached.action === "warn")) {
    return {
      intercept: false,
      action: cached.action,
      badge: cached.badge,
      reason: "cache",
      gating: [],
      popup: cached.popup.map((item) => ({ ...item, severity: "medium" as const, recommendationOnly: true })),
    };
  }
  if (cached && (cached.action === "hold" || cached.action === "block")) {
    return {
      intercept: true,
      action: cached.action,
      badge: cached.badge,
      reason: "cache",
      gating: cached.gatingIds.map((id) => ({
        id,
        severity: cached.action === "block" ? "critical" as const : "high" as const,
        recommendationOnly: cached.action !== "block",
        title: cached.popup.find((item) => item.id === id)?.title ?? id,
        summary: cached.popup.find((item) => item.id === id)?.summary ?? "",
        confidence: "high" as const,
      })),
      popup: cached.popup.map((item) => ({ ...item, severity: "medium" as const, recommendationOnly: true })),
    };
  }
  return { intercept: true, action: "hold", badge: "unknown", reason: "unknown", ...empty };
}

export function planAfter(input: {
  mode: SecurityMode;
  host: string;
  signals: readonly GateSignal[];
  timedOut: boolean;
  now: number;
  intelVersion: string;
  coverage: CacheCoverage;
}): NavDecision {
  const popup = [...input.signals];
  const gating = popup.filter((signal) => holdsNavigation(signal));
  const blocking = gating.some((signal) => signal.severity === "critical" && !signal.recommendationOnly);
  let action: NavAction;
  let reason: NavDecision["reason"];
  if (gating.length === 0 && input.timedOut) {
    action = "hold";
    reason = "timeout";
  } else if (blocking) {
    action = "block";
    reason = reasonFor(gating);
  } else if (gating.length > 0) {
    action = "hold";
    reason = reasonFor(gating);
  } else if (popup.length > 0) {
    action = "warn";
    reason = input.mode === "normal" ? "passive" : "clean";
  } else {
    action = "allow";
    reason = input.mode === "normal" ? "passive" : "clean";
  }
  const badge: BadgeState = action === "block" ? "block" : action === "hold" && reason === "timeout" ? "unknown" : action === "allow" ? "allow" : action === "hold" ? "warn" : "warn";
  const intercept = input.mode === "high" && (action === "hold" || action === "block");
  const decision: NavDecision = { intercept, action, badge, reason, gating, popup };
  if (input.mode === "high" && reason !== "timeout") decision.cache = cacheEntry(input, action, badge, gating, popup);
  return decision;
}

export function consumeOnce(once: readonly string[], host: string): { hit: boolean; remaining: string[] } {
  const key = host.toLowerCase().replace(/\.$/, "");
  const hit = once.some((item) => item.toLowerCase().replace(/\.$/, "") === key);
  return { hit, remaining: once.filter((item) => item.toLowerCase().replace(/\.$/, "") !== key) };
}

function reasonFor(gating: readonly GateSignal[]): NavDecision["reason"] {
  if (gating.some((signal) => gateClass(signal) === "cert")) return "cert";
  if (gating.some((signal) => gateClass(signal) === "phishing")) return "phishing";
  return "advisory";
}

function cacheEntry(
  input: { host: string; now: number; intelVersion: string; coverage: CacheCoverage },
  action: NavAction,
  badge: BadgeState,
  gating: readonly GateSignal[],
  popup: readonly GateSignal[],
): CacheEntry {
  return {
    schema: CACHE_SCHEMA,
    host: input.host,
    action,
    badge,
    coverage: input.coverage,
    gatingIds: gating.map((signal) => signal.id),
    popup: popup.map((signal) => ({ id: signal.id, title: signal.title, summary: signal.summary })),
    writtenAt: input.now,
    expiresAt: input.now + TTL_MS[action],
    intelVersion: input.intelVersion,
  };
}
