import { createHash, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { runHoldScan } from "../src/scan.js";
import { holdStatusText } from "../src/text.js";
import {
  CHROME_NATIVE_HOST,
  chromeNativeEnabled,
  chromeNativeMessage,
  nativeDisconnectStatus,
  type ChromeNativePort,
  type ChromeNativeRuntime,
} from "../src/chrome-host.js";

const NOW = Date.parse("2026-10-21T20:00:00.000Z");
const TOKEN = "0123456789abcdef";
const EXTENSION_ID = "hldpadjbahmnkhfchiikihdofpelfjne";

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

function port(onPost: (emit: (message: unknown) => void, drop: () => void) => void, expectedHost = "example.com"): ChromeNativeRuntime {
  return {
    connectNative(hostName: string): ChromeNativePort {
      expect(hostName).toBe(CHROME_NATIVE_HOST);
      const messages: ((message: unknown) => void)[] = [];
      const disconnects: (() => void)[] = [];
      return {
        postMessage(message) {
          expect(message).toEqual({ host: expectedHost });
          onPost(
            (response) => { for (const listener of messages) listener(response); },
            () => { for (const listener of disconnects) listener(); },
          );
        },
        disconnect() {},
        onMessage: { addListener(handler) { messages.push(handler); } },
        onDisconnect: { addListener(handler) { disconnects.push(handler); } },
      };
    },
  };
}

describe("chrome native messaging", () => {
  it("enables the stdio host only for the Chrome manifest", () => {
    const connect = () => {
      const runtime = port(() => undefined);
      if (!runtime.connectNative) throw new Error("connectNative missing");
      return runtime.connectNative(CHROME_NATIVE_HOST);
    };
    expect(chromeNativeEnabled(
      { permissions: ["storage", "nativeMessaging"], host_permissions: ["http://*/*", "https://*/*"] },
      { connectNative: connect },
    )).toBe(true);
    expect(chromeNativeEnabled(
      { permissions: ["nativeMessaging"], host_permissions: ["http://127.0.0.1/*"] },
      { connectNative: connect },
    )).toBe(false);
    expect(chromeNativeEnabled(
      { permissions: ["storage"], host_permissions: ["http://*/*"] },
      { sendNativeMessage: async () => ({}) },
    )).toBe(false);
    expect(chromeNativeMessage("example.com")).toEqual({ host: "example.com" });
    expect(chromeNativeMessage("https://example.com/")).toBeNull();
  });

  it("pins the unpacked extension id with a public key", () => {
    const manifest = JSON.parse(readFileSync(new URL("../manifest.json", import.meta.url), "utf8")) as { key?: string; permissions: string[] };
    const key = manifest.key ?? "";
    expect(key).not.toMatch(/PRIVATE/);
    const der = Buffer.from(key, "base64");
    expect(createPublicKey({ key: der, format: "der", type: "spki" }).asymmetricKeyType).toBe("rsa");
    const hash = createHash("sha256").update(der).digest("hex").slice(0, 32);
    const id = [...hash].map((char) => String.fromCharCode(97 + Number.parseInt(char, 16))).join("");
    expect(id).toBe(EXTENSION_ID);
    expect(manifest.permissions).toContain("nativeMessaging");
    expect(readFileSync(new URL("../../../docs/EXTENSION.md", import.meta.url), "utf8")).toContain(EXTENSION_ID);
  });

  it("uses connectNative and does not call the loopback helper", async () => {
    let fetched = false;
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      now: NOW,
      chromeNative: port((emit) => emit(verdict("example.com", [cert]))),
      fetchImpl: (() => {
        fetched = true;
        return Promise.resolve(new Response("{}", { status: 200 }));
      }) as typeof fetch,
    });
    expect(fetched).toBe(false);
    expect(decision.action).toBe("block");
    expect(decision.reason).toBe("cert");
    expect(decision.intercept).toBe(true);
  });

  it("holds when the native port disconnects instead of allowing the hostname", async () => {
    expect(nativeDisconnectStatus(undefined)).toBe("disconnected");
    expect(nativeDisconnectStatus("Native host has exited.")).toBe("disconnected");
    expect(nativeDisconnectStatus("Specified native messaging host not found.")).toBe("unavailable");
    expect(nativeDisconnectStatus("Access to the specified native messaging host is forbidden.")).toBe("unavailable");

    let fetched = false;
    const killed = await runHoldScan({
      host: "example.org",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      chromeNative: port((_emit, drop) => drop(), "example.org"),
      fetchImpl: (async () => {
        fetched = true;
        return new Response(JSON.stringify(verdict("example.org", [])), { status: 200 });
      }) as typeof fetch,
    });
    expect(fetched).toBe(false);
    expect(killed.intercept).toBe(true);
    expect(killed.action).toBe("hold");
    expect(killed.reason).toBe("unavailable");
    expect(killed.cache).toBeUndefined();
    expect(killed.popup.some((item) => item.id === "HELPER_UNAVAILABLE" && item.title === "Helper unavailable")).toBe(true);
    expect(holdStatusText({ reason: killed.reason, ids: killed.popup.map((item) => item.id) }).toLowerCase()).toContain("helper unavailable");

    const localKill = await runHoldScan({
      host: "example.org",
      mode: "high",
      helperOrigin: null,
      now: NOW,
      chromeNative: port((_emit, drop) => drop(), "example.org"),
    });
    expect(localKill.intercept).toBe(true);
    expect(localKill.action).toBe("hold");
    expect(localKill.reason).toBe("unavailable");
    expect(localKill.cache).toBeUndefined();

    const passive = await runHoldScan({
      host: "example.org",
      mode: "normal",
      helperOrigin: null,
      now: NOW,
      chromeNative: port((_emit, drop) => drop(), "example.org"),
    });
    expect(passive.intercept).toBe(false);
    expect(passive.reason).toBe("unavailable");

    let closedFetch = false;
    const closed = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      chromeNative: port(() => {
        throw new Error("The message port closed before a response was received.");
      }),
      fetchImpl: (async () => {
        closedFetch = true;
        return new Response("{}", { status: 200 });
      }) as typeof fetch,
    });
    expect(closedFetch).toBe(false);
    expect(closed.intercept).toBe(true);
    expect(closed.reason).toBe("unavailable");
    expect(closed.cache).toBeUndefined();
  });

  it("falls back to the helper when the host is not installed, then to local checks", async () => {
    let fetched = false;
    const missingPort = port((_emit, drop) => drop());
    missingPort.lastError = { message: "Specified native messaging host not found." };
    const fromHelper = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      chromeNative: missingPort,
      fetchImpl: (async () => {
        fetched = true;
        return new Response(JSON.stringify(verdict("example.com", [cert])), { status: 200 });
      }) as typeof fetch,
    });
    expect(fetched).toBe(true);
    expect(fromHelper.action).toBe("block");

    const local = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: null,
      now: NOW,
      chromeNative: {
        async sendNativeMessage() {
          throw new Error("Specified native messaging host not found.");
        },
      },
    });
    expect(local.intercept).toBe(false);
    expect(local.action).toBe("allow");
    expect(local.reason).not.toBe("timeout");

    let exitedFetch = false;
    const exited = await runHoldScan({
      host: "example.org",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      chromeNative: {
        async sendNativeMessage() {
          throw new Error("Native host has exited.");
        },
      },
      fetchImpl: (async () => {
        exitedFetch = true;
        return new Response(JSON.stringify(verdict("example.org", [])), { status: 200 });
      }) as typeof fetch,
    });
    expect(exitedFetch).toBe(false);
    expect(exited.intercept).toBe(true);
    expect(exited.reason).toBe("unavailable");
    expect(exited.cache).toBeUndefined();
    expect(holdStatusText({ reason: exited.reason, ids: exited.popup.map((item) => item.id) })).toContain("helper unavailable");
  });

  it("uses sendNativeMessage when connectNative is absent and fails closed when the host hangs", async () => {
    let sent = "";
    const decision = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      helperToken: TOKEN,
      now: NOW,
      chromeNative: {
        async sendNativeMessage(hostName, message) {
          sent = `${hostName} ${message.host}`;
          return { error: "timeout" };
        },
      },
      fetchImpl: (async () => new Response(JSON.stringify(verdict("example.com", [])), { status: 200 })) as typeof fetch,
    });
    expect(sent).toBe(`${CHROME_NATIVE_HOST} example.com`);
    expect(decision.intercept).toBe(false);

    const started = Date.now();
    const hung = await runHoldScan({
      host: "example.com",
      mode: "high",
      helperOrigin: "http://127.0.0.1:8787",
      now: NOW,
      hardTimeoutMs: 30,
      chromeNative: port(() => undefined),
      fetchImpl: (async (_url, init) => new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      })) as typeof fetch,
    });
    expect(Date.now() - started).toBeLessThan(500);
    expect(hung.intercept).toBe(true);
    expect(hung.reason).toBe("timeout");
    expect(hung.cache).toBeUndefined();
  });
});
