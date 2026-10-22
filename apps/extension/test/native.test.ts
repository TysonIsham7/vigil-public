import { describe, expect, it } from "vitest";
import { runHoldScan } from "../src/scan.js";
import {
  NATIVE_APP_IOS,
  NATIVE_APP_MAC,
  httpsHost,
  nativeAppId,
  nativeMessage,
  nativeMessagingEnabled,
  parseNativeVerdict,
  requestNativeVerdict,
} from "../src/native.js";

const NOW = Date.parse("2026-10-21T20:00:00.000Z");
const TOKEN = "0123456789abcdef";

const cert = {
  id: "CERT_DISTRUSTED_CA",
  severity: "critical" as const,
  recommendationOnly: false,
  title: "Certificate chain contains a distrusted key",
  summary: "The chain includes EM DV TLS CA - G3B.",
  confidence: "high" as const,
};

function verdict(host: string, signals: unknown[]): Record<string, unknown> {
  return { host, intelVersion: "2026.10.21.2", coverage: "full", signals };
}

describe("native cert bridge", () => {
  it("builds an https host URL and rejects anything else", () => {
    expect(nativeMessage("Example.COM.")).toEqual({ url: "https://example.com/" });
    expect(nativeMessage("www.xn--80ak6aa92e.com")).toEqual({ url: "https://www.xn--80ak6aa92e.com/" });
    for (const host of ["localhost", "127.0.0.1", "999.1.2.3", "example", "-bad.com", "bad-.com", "exa_mple.com", ""]) {
      expect(nativeMessage(host), host).toBeNull();
    }
    expect(httpsHost("example.com")).toBe("example.com");
  });

  it("picks the containing app and ignores Chrome native messaging", () => {
    expect(nativeAppId("ios")).toBe(NATIVE_APP_IOS);
    expect(nativeAppId("iPadOS")).toBe(NATIVE_APP_IOS);
    expect(nativeAppId("mac")).toBe(NATIVE_APP_MAC);
    expect(nativeAppId(undefined)).toBe(NATIVE_APP_MAC);
    const send = () => Promise.resolve({});
    expect(nativeMessagingEnabled({ host_permissions: ["http://*/*", "https://*/*", "http://127.0.0.1/*"] }, { sendNativeMessage: send })).toBe(true);
    expect(nativeMessagingEnabled({ host_permissions: ["http://*/*", "https://*/*"] }, { sendNativeMessage: send })).toBe(false);
    expect(nativeMessagingEnabled({ host_permissions: ["http://127.0.0.1/*"] }, {})).toBe(false);
  });

  it("accepts only a verdict for the same host", () => {
    expect(parseNativeVerdict("example.com", verdict("example.com", [cert]))?.signals).toEqual([cert]);
    expect(parseNativeVerdict("example.com", verdict("example.com", []))).toEqual({ signals: [] });
    expect(parseNativeVerdict("example.com", { ok: true })).toBeNull();
    expect(parseNativeVerdict("example.com", { ...verdict("other.example", [cert]) })).toBeNull();
    expect(parseNativeVerdict("example.com", { error: "unavailable" })).toBeNull();
    expect(parseNativeVerdict("example.com", { ...verdict("example.com", [{ id: "CERT_DISTRUSTED_CA" }]) })).toBeNull();
  });

  it("uses a native certificate block without calling the loopback helper", async () => {
    let called = false;
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      now: NOW,
      nativeRuntime: {
        async getPlatformInfo() {
          return { os: "ios" };
        },
        async sendNativeMessage(application, message) {
          expect(application).toBe(NATIVE_APP_IOS);
          expect(message).toEqual({ url: "https://example.com/" });
          return verdict("example.com", [cert]);
        },
      },
      fetchImpl: (() => {
        called = true;
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch,
    });
    expect(called).toBe(false);
    expect(decision.action).toBe("block");
    expect(decision.reason).toBe("cert");
    expect(decision.intercept).toBe(true);
  });

  it("falls back to the helper when the native call fails", async () => {
    let called = false;
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      nativeRuntime: {
        async sendNativeMessage() {
          throw new Error("handler missing");
        },
      },
      fetchImpl: (async () => {
        called = true;
        return new Response(JSON.stringify(verdict("example.com", [])), { status: 200 });
      }) as typeof fetch,
    });
    expect(called).toBe(true);
    expect(decision.intercept).toBe(false);
    expect(decision.action).toBe("allow");
  });

  it("fails closed when the native check uses the whole budget and no helper is set", async () => {
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: null,
      now: NOW,
      hardTimeoutMs: 30,
      nativeRuntime: {
        sendNativeMessage() {
          return new Promise(() => undefined);
        },
      },
    });
    expect(decision.intercept).toBe(true);
    expect(decision.reason).toBe("timeout");
    expect(decision.cache).toBeUndefined();
  });

  it("reports a missing runtime as unavailable", async () => {
    expect(await requestNativeVerdict({ host: "example.com", runtime: undefined, timeoutMs: 50 })).toEqual({ status: "unavailable" });
  });
});
