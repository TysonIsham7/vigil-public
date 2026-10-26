import { describe, expect, it } from "vitest";
import {
  NAV_BUDGET_MS,
  NAV_HARD_TIMEOUT_MS,
  canonicalHost,
  consumeOnce,
  holdsNavigation,
  hopHosts,
  loopbackHelperOrigin,
  planAfter,
  planBefore,
  readCache,
  returnHostMatches,
  type CacheEntry,
  type GateSignal,
} from "../src/index.js";

const NOW = Date.parse("2026-10-21T20:00:00.000Z");
const INTEL = "2026.10.21.2";

function signal(partial: Partial<GateSignal> & Pick<GateSignal, "id">): GateSignal {
  return {
    severity: "high",
    recommendationOnly: true,
    title: partial.id,
    summary: partial.id,
    ...partial,
  };
}

function after(signals: GateSignal[], extra: Partial<Parameters<typeof planAfter>[0]> = {}) {
  return planAfter({
    mode: "high",
    host: "example.com",
    signals,
    timedOut: false,
    now: NOW,
    intelVersion: INTEL,
    coverage: "full",
    ...extra,
  });
}

function before(extra: Partial<Parameters<typeof planBefore>[0]> = {}) {
  return planBefore({
    mode: "high",
    url: "https://example.com/path?q=1",
    now: NOW,
    allowlist: [],
    once: [],
    cache: null,
    intelVersion: INTEL,
    helperEnabled: false,
    ...extra,
  });
}

function entry(partial: Partial<CacheEntry> & Pick<CacheEntry, "action" | "host">): CacheEntry {
  const ttl = partial.action === "allow" ? 24 * 60 * 60 * 1000 : 60 * 60 * 1000;
  return {
    schema: 1,
    badge: partial.action === "block" ? "block" : partial.action === "allow" ? "allow" : "warn",
    coverage: "full",
    gatingIds: [],
    popup: [],
    writtenAt: NOW - 1000,
    expiresAt: NOW - 1000 + ttl,
    intelVersion: INTEL,
    ...partial,
  };
}

describe("navigation gate", () => {
  it("keeps the hard timeout at 2s and the budget under it", () => {
    expect(NAV_BUDGET_MS).toBe(1500);
    expect(NAV_HARD_TIMEOUT_MS).toBe(2000);
  });

  it("does not hold for headers or informational notes", () => {
    const signals = [
      signal({ id: "HEADER_CSP", title: "CSP missing" }),
      signal({ id: "CSP_MISSING" }),
      signal({ id: "HEADER_HSTS" }),
      signal({ id: "KERNEL_SHARED_HOST", severity: "informational", recommendationOnly: true }),
      signal({ id: "CERT_SCT_MISSING", severity: "medium" }),
      signal({ id: "CERT_UNAVAILABLE" }),
      signal({ id: "DOMAIN_SUSPICIOUS_TLD", severity: "medium" }),
      signal({ id: "WP_FINGERPRINT" }),
    ];
    for (const item of signals) expect(holdsNavigation(item)).toBe(false);
    const decision = after(signals);
    expect(decision.intercept).toBe(false);
    expect(decision.action).toBe("warn");
    expect(decision.popup.map((item) => item.id)).toContain("KERNEL_SHARED_HOST");
    expect(decision.gating).toEqual([]);
  });

  it("blocks a distrusted CA and holds other confirmed cert failures", () => {
    const distrusted = after([signal({ id: "CERT_DISTRUSTED_CA", severity: "critical", recommendationOnly: false })]);
    expect(distrusted.intercept).toBe(true);
    expect(distrusted.action).toBe("block");
    expect(distrusted.reason).toBe("cert");
    const invalid = after([signal({ id: "TLS_INVALID" })]);
    expect(invalid.intercept).toBe(true);
    expect(invalid.action).toBe("hold");
    expect(invalid.reason).toBe("cert");
    for (const id of ["CERT_EXPIRED", "CERT_HOSTNAME_MISMATCH", "CERT_SELF_SIGNED"]) {
      const decision = after([signal({ id, severity: "critical", recommendationOnly: false })]);
      expect(decision.action, id).toBe("block");
    }
    expect(after([signal({ id: "CERT_EXPIRING" })]).intercept).toBe(false);
    expect(after([signal({ id: "CERT_SHA1" })]).intercept).toBe(false);
  });

  it("holds lookalike and new-domain signals and leaves weak host patterns in the popup", () => {
    const lookalike = after([signal({ id: "DOMAIN_LOOKALIKE", severity: "critical", recommendationOnly: false })]);
    expect(lookalike.action).toBe("block");
    expect(lookalike.reason).toBe("phishing");
    const fresh = after([signal({ id: "DOMAIN_NEW" })]);
    expect(fresh.intercept).toBe(true);
    expect(fresh.action).toBe("hold");
    expect(after([signal({ id: "DOMAIN_FREE_HOSTING", severity: "medium" })]).intercept).toBe(false);
    expect(after([signal({ id: "DOMAIN_SUBDOMAIN_DEPTH", severity: "medium" })]).intercept).toBe(false);
  });

  it("keeps an informational note without turning the badge into a warning", () => {
    const decision = after([signal({ id: "PHP2SHELL_EXPOSURE", severity: "informational", recommendationOnly: true, title: "PHP2Shell: not-PHP" })]);
    expect(decision.intercept).toBe(false);
    expect(decision.action).toBe("allow");
    expect(decision.badge).toBe("allow");
    expect(decision.popup.map((item) => item.id)).toEqual(["PHP2SHELL_EXPOSURE"]);
    const hidden = after([signal({ id: "PHP2SHELL_EXPOSURE", severity: "high", recommendationOnly: true, title: "PHP2Shell: hidden" })]);
    expect(hidden.intercept).toBe(false);
    expect(hidden.action).toBe("warn");
  });

  it("holds a confirmed advisory and not a version-less PHP hint", () => {
    const confirmed = after([signal({ id: "PHP_CVE_2026_109618", confidence: "high" })]);
    expect(confirmed.intercept).toBe(true);
    expect(confirmed.reason).toBe("advisory");
    const suspected = after([signal({ id: "PHP_CVE_2026_109618", confidence: "medium" })]);
    expect(suspected.intercept).toBe(false);
    const litellm = after([signal({ id: "DEP_LITELLM_COMPROMISED", severity: "critical", recommendationOnly: false })]);
    expect(litellm.action).toBe("block");
    const session = after([signal({ id: "PHP_CVE_2026_115560", severity: "informational", recommendationOnly: true })]);
    expect(session.intercept).toBe(false);
  });

  it("fails closed on timeout in High Security and does not cache an allow", () => {
    const decision = after([], { timedOut: true });
    expect(decision.intercept).toBe(true);
    expect(decision.action).toBe("hold");
    expect(decision.reason).toBe("timeout");
    expect(decision.badge).toBe("unknown");
    expect(decision.cache).toBeUndefined();
  });

  it("is a passive badge in normal mode", () => {
    const decision = after(
      [signal({ id: "CERT_DISTRUSTED_CA", severity: "critical", recommendationOnly: false })],
      { mode: "normal" },
    );
    expect(decision.intercept).toBe(false);
    expect(decision.badge).toBe("block");
    expect(decision.reason).toBe("cert");
    expect(before({ mode: "normal", url: "https://paypa1.com/" }).intercept).toBe(false);
  });

  it("skips the hold page for an allowlist hit, a one-time override, and a fresh allow cache", () => {
    expect(before({ allowlist: ["Example.com"] }).intercept).toBe(false);
    expect(before({ allowlist: ["Example.com"] }).reason).toBe("allowlist");
    expect(before({ once: ["example.com"] }).reason).toBe("once");
    const allow = entry({ host: "example.com", action: "allow" });
    expect(before({ cache: allow }).intercept).toBe(false);
    expect(before({ cache: allow }).reason).toBe("cache");
    const stale = entry({ host: "example.com", action: "allow", expiresAt: NOW - 1 });
    expect(before({ cache: stale }).intercept).toBe(true);
  });

  it("does not let one host's cache or a poisoned allow entry open another decision", () => {
    const other = entry({ host: "evil.example", action: "allow" });
    expect(readCache(other, "example.com", NOW, INTEL, false)).toBeNull();
    expect(before({ cache: other }).intercept).toBe(true);
    const poisoned = entry({
      host: "example.com",
      action: "allow",
      gatingIds: ["CERT_DISTRUSTED_CA"],
    });
    expect(readCache(poisoned, "example.com", NOW, INTEL, false)).toBeNull();
    const distant = entry({
      host: "example.com",
      action: "allow",
      writtenAt: NOW - 1000,
      expiresAt: NOW + 10 * 24 * 60 * 60 * 1000,
    });
    expect(readCache(distant, "example.com", NOW, INTEL, false)).toBeNull();
    const localOnly = entry({ host: "example.com", action: "allow", coverage: "local" });
    expect(readCache(localOnly, "example.com", NOW, INTEL, true)).toBeNull();
    expect(readCache(localOnly, "example.com", NOW, INTEL, false)?.action).toBe("allow");
    expect(before({ cache: localOnly, helperEnabled: false }).intercept).toBe(true);
    expect(before({ cache: localOnly, helperEnabled: false }).reason).toBe("unknown");
  });

  it("keeps IDN and redirect hops on their own cache keys", () => {
    const mixed = "https://www.xn--pple-43d.com/";
    const fromUnicode = canonicalHost("https://аррӏе.com/");
    expect(canonicalHost("https://apple.com/")).toBe("apple.com");
    expect(fromUnicode).not.toBe("apple.com");
    expect(fromUnicode?.startsWith("xn--")).toBe(true);
    expect(canonicalHost(mixed)).not.toBe("apple.com");
    const hops = hopHosts([
      "https://example.com/out?next=https://paypa1.com/",
      "https://paypa1.com/login",
      "javascript:alert(1)",
    ]);
    expect(hops).toEqual(["example.com", "paypa1.com"]);
    const allow = entry({ host: "example.com", action: "allow" });
    expect(before({ url: "https://example.com/out", cache: allow }).intercept).toBe(false);
    expect(before({ url: "https://paypa1.com/login", cache: allow }).intercept).toBe(true);
  });

  it("rejects open-redirect targets that are not the stashed host", () => {
    expect(returnHostMatches("example.com", "https://example.com/a?b=1#c")).toBe(true);
    expect(returnHostMatches("example.com", "https://evil.com@example.com/")).toBe(false);
    expect(returnHostMatches("example.com", "javascript:alert(1)")).toBe(false);
    expect(returnHostMatches("example.com", "data:text/html,hi")).toBe(false);
    expect(returnHostMatches("example.com", "chrome-extension://abcdefghijklmnop/hold.html")).toBe(false);
    expect(returnHostMatches("example.com", "file:///etc/passwd")).toBe(false);
    expect(returnHostMatches("example.com", "https://example.com.evil.com/")).toBe(false);
    expect(returnHostMatches("example.com", "https://evil.com/")).toBe(false);
    expect(canonicalHost("http://169.254.169.254/latest")).toBe("169.254.169.254");
    expect(loopbackHelperOrigin("http://127.0.0.1:8787")).toBe("http://127.0.0.1:8787");
    expect(loopbackHelperOrigin("http://127.0.0.1:8787/extra")).toBeNull();
    expect(loopbackHelperOrigin("https://127.0.0.1:8787")).toBeNull();
    expect(loopbackHelperOrigin("http://localhost:8787")).toBeNull();
    expect(loopbackHelperOrigin("http://example.com:8787")).toBeNull();
  });

  it("consumes a one-time override", () => {
    const consumed = consumeOnce(["example.com", "other.test"], "Example.com");
    expect(consumed.hit).toBe(true);
    expect(consumed.remaining).toEqual(["other.test"]);
  });

  it("caches an allow for 24h and a warn for 1h", () => {
    const allow = after([]);
    expect(allow.cache?.expiresAt).toBe(NOW + 24 * 60 * 60 * 1000);
    const warn = after([signal({ id: "HEADER_CSP" })]);
    expect(warn.cache?.action).toBe("warn");
    expect(warn.cache?.expiresAt).toBe(NOW + 60 * 60 * 1000);
    expect(warn.cache?.popup.some((item) => item.id === "HEADER_CSP")).toBe(true);
  });
});
