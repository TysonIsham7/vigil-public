import { describe, expect, it } from "vitest";
import { UrlRejected } from "@vigil/core";
import { pinAddress, pinnedLookup, safeFetch, connectCertificateChain } from "../src/index.js";

const lookup = async (host: string) => {
  if (host === "example.com" || host === "evil.example") return ["203.0.113.5"];
  return ["203.0.113.9"];
};

describe("safeFetch", () => {
  it("refuses a redirect onto a loopback address before the next request", async () => {
    const calls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      calls.push(String(input));
      return new Response(null, { status: 302, headers: { location: "http://127.0.0.1/secret" } });
    };
    await expect(safeFetch("https://evil.example/start", { lookup, fetchImpl })).rejects.toBeInstanceOf(UrlRejected);
    expect(calls).toEqual(["https://evil.example/start"]);
  });

  it("refuses a DNS answer that includes a private address", async () => {
    const fetchImpl: typeof fetch = async () => new Response("nope");
    await expect(safeFetch("https://example.com/", {
      lookup: async () => ["203.0.113.5", "10.1.1.1"],
      fetchImpl,
    })).rejects.toThrow(/not allowed/);
  });

  it("fails closed when DNS lookup fails", async () => {
    await expect(safeFetch("https://example.com/", {
      lookup: async () => { throw new Error("servfail"); },
      fetchImpl: async () => new Response("nope"),
    })).rejects.toThrow(/DNS lookup failed/);
  });

  it("pins one public address and does not look the name up again", async () => {
    let lookups = 0;
    let dialed = "";
    const result = await safeFetch("https://example.com/a", {
      lookup: async () => {
        lookups += 1;
        return ["203.0.113.50"];
      },
      requestImpl: async (url, pinned) => {
        dialed = `${url.hostname} ${pinned.address}`;
        return new Response("ok");
      },
    });
    expect(lookups).toBe(1);
    expect(dialed).toBe("example.com 203.0.113.50");
    expect(result.body).toBe("ok");
    const pinned = await pinAddress("203.0.113.9");
    expect(pinned).toEqual({ address: "203.0.113.9", family: 4 });
    pinnedLookup(pinned)("example.com", {}, (error: NodeJS.ErrnoException | null, address: string | { address: string; family: number }[], family?: number) => {
      expect(error).toBeNull();
      expect(address).toBe("203.0.113.9");
      expect(family).toBe(4);
    });
  });

  it("does not open a TLS socket when DNS returns a private address", async () => {
    let lookups = 0;
    await expect(connectCertificateChain("example.com", 443, "not-a-cert", 50, async () => {
      lookups += 1;
      return ["10.1.1.1"];
    })).rejects.toThrow(/not allowed/);
    expect(lookups).toBe(1);
    await expect(connectCertificateChain("127.0.0.1", 443, "not-a-cert", 50, async () => ["203.0.113.5"])).rejects.toThrow(/not allowed/);
  });

  it("truncates a body at the size cap", async () => {
    const fetchImpl: typeof fetch = async () => new Response("x".repeat(50));
    const result = await safeFetch("https://example.com/", { lookup, fetchImpl, maxBytes: 10 });
    expect(result.truncated).toBe(true);
    expect(result.body).toBe("x".repeat(10));
  });
});
