import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { NAV_BUDGET_MS } from "@vigil/core";
import { classifyNavigation, planBefore } from "@vigil/core";
import { highSecurityRules } from "../src/dnr.js";
import { extensionMessagePage } from "../src/messages.js";
import { helperReachable, localSignals, runHoldScan } from "../src/scan.js";
import { safeSignalText } from "../src/text.js";

const NOW = Date.parse("2026-10-21T20:00:00.000Z");
const TOKEN = "0123456789abcdef";

function helper(status: number, body: unknown, hang = false): typeof fetch {
  return (async (_url, init) => {
    const signal = init?.signal;
    if (hang) {
      await new Promise((_resolve, reject) => {
        signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      });
    }
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

describe("extension hold scan", () => {
  it("treats a network failure as helper-down and a timeout as still armed", () => {
    expect(helperReachable({ configured: true, coverage: "local", timedOut: false })).toBe(false);
    expect(helperReachable({ configured: true, coverage: null, timedOut: true })).toBe(true);
    expect(helperReachable({ configured: true, coverage: "full", timedOut: false })).toBe(true);
    expect(helperReachable({ configured: false, coverage: "local", timedOut: false })).toBe(false);
  });

  it("blocks a lookalike from the local fast path", async () => {
    const started = Date.now();
    for (let i = 0; i < 200; i++) localSignals(i % 2 === 0 ? "example.com" : "paypa1.com");
    expect(Date.now() - started).toBeLessThan(NAV_BUDGET_MS);
    const decision = await runHoldScan({ host: "paypa1.com", mode: "high", helperOrigin: null, now: NOW });
    expect(decision.intercept).toBe(true);
    expect(decision.action).toBe("block");
    expect(decision.gating.some((signal) => signal.id === "DOMAIN_LOOKALIKE")).toBe(true);
  });

  it("shows header and shared-host notes in the popup and does not hold", async () => {
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: helper(200, {
        host: "example.com",
        signals: [
          { id: "HEADER_CSP", severity: "high", recommendationOnly: true, title: "CSP missing", summary: "No CSP" },
          { id: "KERNEL_SHARED_HOST", severity: "informational", recommendationOnly: true, title: "Shared host", summary: "Not visible" },
        ],
      }),
    });
    expect(decision.intercept).toBe(false);
    expect(decision.action).toBe("warn");
    expect(decision.popup.map((signal) => signal.id)).toEqual(expect.arrayContaining(["HEADER_CSP", "KERNEL_SHARED_HOST"]));
  });

  it("blocks a distrusted CA returned by the loopback helper", async () => {
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: helper(200, {
        host: "example.com",
        signals: [{
          id: "CERT_DISTRUSTED_CA",
          severity: "critical",
          recommendationOnly: false,
          title: "Distrusted CA",
          summary: "EM DV TLS CA - G3B",
          confidence: "high",
        }],
      }),
    });
    expect(decision.action).toBe("block");
    expect(decision.reason).toBe("cert");
    expect(decision.intercept).toBe(true);
  });

  it("fails closed when the helper times out or the connection fails", async () => {
    const closed = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      hardTimeoutMs: 20,
      fetchImpl: helper(200, { host: "example.com", signals: [] }, true),
    });
    expect(closed.intercept).toBe(true);
    expect(closed.reason).toBe("timeout");
    expect(closed.cache).toBeUndefined();
    const down = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: (async () => {
        throw Object.assign(new Error("connect ECONNREFUSED"), { name: "TypeError" });
      }) as typeof fetch,
    });
    expect(down.intercept).toBe(true);
    expect(down.action).toBe("hold");
    expect(down.reason).toBe("timeout");
    expect(down.cache).toBeUndefined();
    expect(down.helper).toBe("down");
    const started = Date.now();
    const stuck = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      hardTimeoutMs: 30,
      fetchImpl: (() => new Promise(() => undefined)) as typeof fetch,
    });
    expect(Date.now() - started).toBeLessThan(500);
    expect(stuck.intercept).toBe(true);
    expect(stuck.reason).toBe("timeout");
    expect(stuck.cache).toBeUndefined();
  });

  it("fails closed when the helper answers for a different host", async () => {
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: helper(200, { host: "evil.test", signals: [] }),
    });
    expect(decision.intercept).toBe(true);
    expect(decision.reason).toBe("timeout");
  });

  it("ignores a helper origin that is not loopback", async () => {
    let called = false;
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "https://example.com",
      now: NOW,
      fetchImpl: (async () => {
        called = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
    });
    expect(called).toBe(false);
    expect(decision.intercept).toBe(false);
  });

  it("keeps normal mode from intercepting a cert failure", async () => {
    const decision = await runHoldScan({
      host: "example.com",
      mode: "normal",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: helper(200, {
        host: "example.com",
        signals: [{
          id: "CERT_DISTRUSTED_CA",
          severity: "critical",
          recommendationOnly: false,
          title: "Distrusted CA",
          summary: "blocked",
        }],
      }),
    });
    expect(decision.intercept).toBe(false);
    expect(decision.badge).toBe("block");
  });

  it("holds http main frames except skipped hosts and blocks subframes", () => {
    const rules = highSecurityRules(["Example.com", "example.com", ""]);
    expect(rules).toHaveLength(2);
    const main = rules.find((rule) => rule.condition.resourceTypes.includes("main_frame"));
    const sub = rules.find((rule) => rule.condition.resourceTypes.includes("sub_frame"));
    expect(main?.action).toEqual({ type: "redirect", redirect: { extensionPath: "/hold.html" } });
    expect(main?.condition.urlFilter).toBe("|http");
    expect(main?.condition.excludedRequestDomains).toEqual(["example.com"]);
    expect(sub?.action).toEqual({ type: "block" });
    expect(highSecurityRules([])[0]?.condition.excludedRequestDomains).toBeUndefined();
  });

  it("starts the fail-closed clock at navigation and does not cache a bad helper answer", async () => {
    const late = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: null,
      now: NOW,
      startedAt: Date.now() - 5_000,
      fetchImpl: helper(200, { host: "example.com", signals: [] }),
    });
    expect(late.intercept).toBe(true);
    expect(late.reason).toBe("timeout");
    expect(late.cache).toBeUndefined();

    let seen: { cache?: string; token?: string | null } = {};
    const unexpected = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: (async (_url, init) => {
        const headers = new Headers(init?.headers);
        seen = { cache: (init as { cache?: string } | undefined)?.cache, token: headers.get("x-vigil-token") };
        return new Response("nope", { status: 500 });
      }) as typeof fetch,
    });
    expect(seen).toEqual({ cache: "no-store", token: TOKEN });
    expect(unexpected.intercept).toBe(true);
    expect(unexpected.cache).toBeUndefined();
    expect(unexpected.helper).toBe("up");

    const limited = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      fetchImpl: helper(429, { error: "rate limit" }),
    });
    expect(limited.intercept).toBe(true);
    expect(limited.cache).toBeUndefined();
    expect(limited.helper).toBe("up");

    let called = false;
    const missing = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      now: NOW,
      fetchImpl: (async () => {
        called = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
    });
    expect(called).toBe(false);
    expect(missing.intercept).toBe(true);
    expect(missing.cache).toBeUndefined();
  });

  it("holds about, blob, and userinfo urls and only accepts extension pages", () => {
    expect(classifyNavigation("about:blank").kind).toBe("unsafe");
    expect(classifyNavigation("blob:https://example.com/11111111-1111-1111-1111-111111111111").kind).toBe("unsafe");
    expect(classifyNavigation("https://user:pass@example.com/").kind).toBe("unsafe");
    expect(classifyNavigation("https://example.com/a")).toEqual({ kind: "site", host: "example.com" });
    expect(classifyNavigation("chrome://settings").kind).toBe("ignore");
    const held = planBefore({
      mode: "high",
      url: "about:blank",
      now: NOW,
      allowlist: [],
      once: [],
      cache: null,
      intelVersion: "2026.10.21.2",
      helperEnabled: false,
    });
    expect(held.intercept).toBe(true);
    expect(extensionMessagePage("chrome-extension://abc/popup.html")).toBe("popup");
    expect(extensionMessagePage("safari-web-extension://abc/hold.html")).toBe("hold");
    expect(extensionMessagePage("https://example.com/popup.html")).toBe("other");
    expect(safeSignalText("pay\u202epa1.com evil", 160)).toBe("paypa1.com evil");
    expect(safeSignalText("a".repeat(200), 20).endsWith("…")).toBe(true);
  });

  it("ships a private MV3 manifest with no remote code and no store update", () => {
    const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8")) as {
      manifest_version: number;
      permissions: string[];
      host_permissions: string[];
      content_security_policy: { extension_pages: string };
      update_url?: string;
      externally_connectable?: unknown;
      background: { service_worker: string; type: string };
      content_scripts?: { matches: string[]; js: string[]; run_at: string; all_frames?: boolean }[];
    };
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions.sort()).toEqual(["declarativeNetRequest", "nativeMessaging", "scripting", "storage", "tabs", "webNavigation"]);
    expect(manifest.host_permissions).toEqual(["http://*/*", "https://*/*"]);
    expect(manifest.content_scripts).toEqual([{
      matches: ["http://*/*", "https://*/*"],
      js: ["blank-relay.js"],
      run_at: "document_start",
      all_frames: true,
    }]);
    expect(manifest.content_security_policy.extension_pages).toContain("script-src 'self'");
    expect(manifest.update_url).toBeUndefined();
    expect(manifest.externally_connectable).toBeUndefined();
    expect(manifest.background.type).toBe("module");
    const sources = ["background.ts", "hold.ts", "popup.ts", "scan.ts", "dnr.ts", "platform.ts", "native.ts", "chrome-host.ts", "messages.ts", "text.ts", "blank-guard.ts", "blank-guard-main.ts", "blank-relay.ts", "guard-settings.ts", "page-guards.ts", "guard-panel.ts", "clickfix-guard.ts", "clickfix-guard-main.ts", "seed-guard.ts", "seed-guard-main.ts", "wallet-guard.ts", "wallet-guard-main.ts"].map((name) =>
      readFileSync(new URL(`../src/${name}`, import.meta.url), "utf8"),
    );
    for (const source of sources) {
      expect(source).not.toMatch(/https?:\/\/(?!127\.0\.0\.1)/);
      expect(source).not.toMatch(/analytics|telemetry|sentry|gtag/i);
    }
  });
});
