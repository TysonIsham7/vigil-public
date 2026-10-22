import { createServer, request as httpRequest } from "node:http";
import { planAfter, UrlRejected } from "@vigil/core";
import { intermediatePems } from "@vigil/intel";
import { describe, expect, it } from "vitest";
import { hostVerdict, parseCertificate, startVerdictServer, verdictHost, VerdictTimeout } from "../src/index.js";

const lookup = async () => ["93.184.216.34"];

function fetchImpl(): typeof fetch {
  return (async () => new Response("<!doctype html><title>Example</title>", {
    status: 200,
    headers: { "content-type": "text/html", "x-powered-by": "PHP/8.2.34" },
  })) as typeof fetch;
}

describe("host verdict", () => {
  it("reports a distrusted intermediate even when the page body is discarded", async () => {
    const leaked = intermediatePems()[0];
    const parsed = parseCertificate(leaked?.pem ?? "");
    const result = await hostVerdict("example.com", {
      now: new Date("2026-10-21T00:00:00.000Z"),
      ageDays: 400,
      lookup,
      fetchImpl: fetchImpl(),
      connectImpl: async () => [parsed],
    });
    expect(result.signals.some((signal) => signal.id === "CERT_DISTRUSTED_CA")).toBe(true);
    expect(result.signals.some((signal) => signal.id === "HEADER_CSP")).toBe(true);
    const php = result.signals.find((signal) => signal.id === "PHP_CVE_2026_109618");
    expect(php?.confidence).toBe("high");
    expect(php?.title).toBe("Upgrade PHP");
    expect(php?.summary.startsWith("Upgrade PHP")).toBe(true);
    expect(php?.summary).toMatch(/partial mitigation/);
    expect(result.signals.some((signal) => signal.id === "KERNEL_SHARED_HOST")).toBe(false);
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain("BEGIN CERTIFICATE");
    expect(encoded).not.toContain("<!doctype");
    expect(encoded).not.toContain("<title>");
  });

  it("returns a finished certificate when RDAP never answers, and keeps headers off the hold list", async () => {
    const leaked = intermediatePems()[0];
    const parsed = parseCertificate(leaked?.pem ?? "");
    const hung = (async (input: string) => {
      const url = String(input);
      if (url.includes("iana.org") || url.includes("/rdap")) return new Promise<Response>(() => undefined);
      return new Response("<!doctype html><title>Example</title>", {
        status: 200,
        headers: { "content-type": "text/html" },
      });
    }) as typeof fetch;
    const started = Date.now();
    const blocked = await hostVerdict("example.com", {
      now: new Date("2026-10-21T00:00:00.000Z"),
      timeoutMs: 1500,
      lookup,
      fetchImpl: hung,
      connectImpl: async () => [parsed],
    });
    expect(Date.now() - started).toBeLessThan(1200);
    expect(blocked.signals.some((signal) => signal.id === "CERT_DISTRUSTED_CA")).toBe(true);
    expect(blocked.signals.some((signal) => signal.id === "HEADER_CSP")).toBe(true);

    const headersOnly = await hostVerdict("example.com", {
      now: new Date("2026-10-21T00:00:00.000Z"),
      ageDays: 400,
      lookup,
      fetchImpl: (async () => new Response("<!doctype html><title>Example</title>", {
        status: 200,
        headers: { "content-type": "text/html" },
      })) as typeof fetch,
      connectImpl: async () => {
        throw new Error("tls down");
      },
    });
    expect(headersOnly.signals.some((signal) => signal.id === "CERT_UNAVAILABLE")).toBe(true);
    expect(headersOnly.signals.some((signal) => signal.id === "HEADER_CSP")).toBe(true);
    const decision = planAfter({
      mode: "high",
      host: "example.com",
      signals: headersOnly.signals,
      timedOut: false,
      now: Date.parse("2026-10-21T00:00:00.000Z"),
      intelVersion: headersOnly.intelVersion,
      coverage: "full",
    });
    expect(decision.intercept).toBe(false);
    expect(decision.gating).toEqual([]);
    expect(decision.popup.some((signal) => signal.id.startsWith("HEADER_"))).toBe(true);
  });

  it("rejects a loopback host and times out a stuck check", async () => {
    await expect(hostVerdict("127.0.0.1", { lookup, fetchImpl: fetchImpl() })).rejects.toThrow(/not allowed/i);
    await expect(hostVerdict("example.com", {
      ageDays: 400,
      timeoutMs: 20,
      lookup,
      fetchImpl: (() => new Promise(() => undefined)) as typeof fetch,
      connectImpl: () => new Promise(() => undefined),
    })).rejects.toBeInstanceOf(VerdictTimeout);
    expect(verdictHost("https://example.com/")).toBeNull();
    expect(verdictHost("example.com")).toBe("example.com");
    expect(verdictHost("169.254.169.254")).toBeNull();
  });

  it("refuses a resolved private address before connecting", async () => {
    let connected = false;
    await expect(hostVerdict("example.com", {
      lookup: async () => ["203.0.113.5", "10.1.1.1"],
      fetchImpl: async () => new Response("no"),
      connectImpl: async () => {
        connected = true;
        return [];
      },
    })).rejects.toBeInstanceOf(UrlRejected);
    expect(connected).toBe(false);
  });

  it("serves a loopback verdict and does not echo a page", async () => {
    const server = await startVerdictServer({
      token: "0123456789abcdef",
      verdict: async (host) => ({ host, intelVersion: "test", coverage: "full", signals: [] }),
    });
    const headers = { "x-vigil-token": server.token };
    try {
      const missing = await fetch(`http://127.0.0.1:${server.port}/api/v1/verdict?host=example.com`);
      expect(missing.status).toBe(401);
      const ok = await fetch(`http://127.0.0.1:${server.port}/api/v1/verdict?host=example.com`, { headers });
      expect(ok.status).toBe(200);
      const body = await ok.json() as { host: string; signals: unknown[] };
      expect(body.host).toBe("example.com");
      expect(body.signals).toEqual([]);
      const rejected = await fetch(`http://127.0.0.1:${server.port}/api/v1/verdict?host=127.0.0.1`, { headers });
      expect(rejected.status).toBe(400);
      const scheme = await fetch(`http://127.0.0.1:${server.port}/api/v1/verdict?host=${encodeURIComponent("https://example.com/")}`, { headers });
      expect(scheme.status).toBe(400);
      const wrongHost = await new Promise<number>((resolve, reject) => {
        const req = httpRequest({
          hostname: "127.0.0.1",
          port: server.port,
          path: "/api/v1/verdict?host=example.com",
          headers: { host: "evil.example", "x-vigil-token": server.token },
        }, (res) => {
          res.resume();
          resolve(res.statusCode ?? 0);
        });
        req.on("error", reject);
        req.end();
      });
      expect(wrongHost).toBe(403);
    } finally {
      await server.close();
    }
    await expect(startVerdictServer({ host: "0.0.0.0" })).rejects.toThrow(/127\.0\.0\.1/);
    const squat = createServer();
    await new Promise<void>((resolve) => squat.listen(0, "127.0.0.1", () => resolve()));
    const address = squat.address();
    const port = typeof address === "object" && address ? address.port : 0;
    await expect(startVerdictServer({ port })).rejects.toThrow(/native host/);
    await new Promise<void>((resolve, reject) => squat.close((error) => (error ? reject(error) : resolve())));
  });
});
