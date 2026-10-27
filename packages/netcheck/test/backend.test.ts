import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { describe, expect, it } from "vitest";
import { DEFAULT_LIMITS, TAXONOMY_DOMAIN_IDS, blockDeploy, summarize } from "@vigil/core";
import { completeLegacyHandshake } from "../src/cert.js";
import {
  BACKEND_CIPHER_OFFER,
  BACKEND_ERROR_PATH,
  BACKEND_KNOWN_PATHS,
  LEGACY_PROTOCOL_CIPHERS,
  assessBackend,
  checkBackend,
  observeTlsHandshake,
  probeLegacyProtocols,
  tls12CipherList,
  type BackendHandshakeResult,
  type BackendResponse,
  type BackendTransport,
  type ParsedCert,
} from "../src/index.js";

const now = new Date("2026-10-22T00:00:00.000Z");
const trusted = new Set(["cc".repeat(32)]);

function cert(overrides: Partial<ParsedCert> = {}): ParsedCert {
  return {
    subject: "CN=example.com",
    issuer: "CN=Root",
    sanDns: ["example.com"],
    sanIp: [],
    notBefore: new Date("2026-01-01T00:00:00.000Z"),
    notAfter: new Date("2027-01-01T00:00:00.000Z"),
    sha256: "aa".repeat(32),
    spkiSha256: "bb".repeat(32),
    signatureAlgorithm: "sha256WithRSAEncryption",
    publicKeyAlgorithm: "rsa",
    publicKeyBits: 2048,
    selfSigned: false,
    sct: { present: true, count: 2, wellFormed: true },
    ...overrides,
  };
}

function root(): ParsedCert {
  return cert({
    subject: "CN=Root",
    issuer: "CN=Root",
    sanDns: [],
    selfSigned: true,
    spkiSha256: "cc".repeat(32),
    sha256: "dd".repeat(32),
  });
}

function handshake(overrides: Partial<BackendHandshakeResult> = {}): BackendHandshakeResult {
  return {
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
    offeredCiphers: [...BACKEND_CIPHER_OFFER],
    certs: [cert(), root()],
    ...overrides,
  };
}

function response(partial: Partial<BackendResponse> & Pick<BackendResponse, "url">): BackendResponse {
  return {
    status: 200,
    headers: {},
    body: "<html>ok</html>",
    truncated: false,
    elapsedMs: 40,
    ...partial,
  };
}

function assess(responses: BackendResponse[], tls: BackendHandshakeResult | { error: string } | null = handshake(), pageUrl = "https://example.com/") {
  return assessBackend({ pageUrl, responses, handshake: tls, now, trustedSpki: trusted });
}

describe("check-backend", () => {
  it("keeps the cipher offer inside an ordinary handshake", () => {
    const firstCbc = BACKEND_CIPHER_OFFER.findIndex((name) => /SHA$/i.test(name) && !/GCM|CHACHA|POLY/i.test(name));
    const firstGcm = BACKEND_CIPHER_OFFER.findIndex((name) => /GCM/i.test(name));
    expect(firstGcm).toBeGreaterThanOrEqual(0);
    expect(firstCbc).toBeGreaterThan(firstGcm);
    expect(BACKEND_CIPHER_OFFER.join(" ")).not.toMatch(/RC4|NULL|EXPORT|\bDES\b|MD5|aNULL|3DES/i);
    expect(tls12CipherList()).not.toMatch(/^TLS_|:TLS_|RC4|NULL|EXPORT|\bDES\b|MD5/i);
    expect(LEGACY_PROTOCOL_CIPHERS).toMatch(/AES128-SHA/);
    expect(LEGACY_PROTOCOL_CIPHERS).toMatch(/@SECLEVEL=0$/);
    expect(LEGACY_PROTOCOL_CIPHERS).not.toMatch(/RC4|NULL|EXPORT|3DES|\bDES\b|MD5/i);
    for (const path of [BACKEND_ERROR_PATH, ...BACKEND_KNOWN_PATHS]) {
      expect(path.startsWith("/")).toBe(true);
      expect(path.includes("..")).toBe(false);
      expect(path.includes("?")).toBe(false);
      expect(path.includes("%")).toBe(false);
      expect(path.length).toBeLessThan(40);
    }
  });

  it("tags passive signals with the existing domains", () => {
    const marker = "UNIQUE_BODY_MARKER_SHOULD_NOT_LEAK";
    const result = assess([
      response({
        url: "https://example.com/",
        elapsedMs: 40,
        ttfbMs: 40,
        headers: {
          server: "nginx/1.24.0",
          "x-powered-by": "PHP/7.4.33",
          via: "1.1 varnish",
          "x-aspnet-version": "4.0.30319",
          "set-cookie": ["PHPSESSID=supersecretvalue", "JSESSIONID=supersecretvalue"],
        },
      }),
      response({
        url: "https://example.com/this-page-is-missing",
        status: 404,
        elapsedMs: 50,
        ttfbMs: 50,
        body: [
          "<html><center>nginx</center></html>",
          "Fatal error: Uncaught Exception api_key: \"vigilTestKeyPlaceholder1234567890\" in /var/www/app/index.php on line 3",
          marker,
        ].join("\n"),
      }),
      response({
        url: "https://example.com/.git/HEAD",
        elapsedMs: 30,
        ttfbMs: 30,
        truncated: true,
        body: "ref: refs/heads/main\n",
      }),
      response({
        url: "https://example.com/.svn/entries",
        elapsedMs: 35,
        ttfbMs: 35,
        body: "<wc-entries />",
      }),
      response({
        url: "https://example.com/server-status",
        elapsedMs: 2000,
        ttfbMs: 2000,
        body: "Apache Server Status\nServer uptime: 3 days",
      }),
      response({
        url: "https://example.com/phpinfo.php",
        elapsedMs: 45,
        ttfbMs: 45,
        body: phpinfoPage(),
      }),
      response({
        url: "https://example.com/elmah.axd",
        elapsedMs: 36,
        ttfbMs: 36,
        body: "Error Log for the site",
      }),
    ], handshake({
      protocol: "TLSv1.0",
      cipher: "DES-CBC3-SHA",
      certs: [cert({ sanDns: ["example.com", "db.internal"], sanIp: ["10.1.1.1"] }), root()],
    }));
    const domains = Object.fromEntries(result.findings.map((finding) => [finding.id, finding.taxonomy.domain]));
    expect(domains).toMatchObject({
      BACKEND_HEADER_SERVER: "application-software",
      BACKEND_HEADER_POWERED_BY: "application-software",
      BACKEND_HEADER_ASPNET: "application-software",
      BACKEND_COOKIE_FRAMEWORK: "application-software",
      PHP_CVE_2026_109618: "application-software",
      BACKEND_ERROR_SIGNATURE: "application-software",
      BACKEND_HEADER_VIA: "cloud-hybrid",
      BACKEND_EXPOSED_VCS: "data-security-privacy",
      BACKEND_EXPOSED_PHPINFO: "data-security-privacy",
      BACKEND_EXPOSED_DEBUG: "data-security-privacy",
      BACKEND_STACK_TRACE: "data-security-privacy",
      BACKEND_TLS_INTERNAL_NAME: "data-security-privacy",
      BACKEND_EXPOSED_STATUS: "network-infrastructure",
      BACKEND_TLS_PROTOCOL: "network-infrastructure",
      BACKEND_TLS_CIPHER: "network-infrastructure",
      BACKEND_TIMING: "network-infrastructure",
      FETCH_TRUNCATED: "grc",
    });
    for (const finding of result.findings) expect(TAXONOMY_DOMAIN_IDS).toContain(finding.taxonomy.domain);
    const php = result.findings.find((finding) => finding.id === "PHP_CVE_2026_109618");
    expect(php?.title).toBe("PHP 5-7 was never patched");
    expect(php?.recommendationOnly).toBe(true);
    expect(php?.evidence).toBe("7.4.33");
    expect(php?.remediation[0]).toMatch(/^Upgrade PHP/);
    expect(php?.remediation.join(" ")).toMatch(/CVE-2026-115560/);
    expect(php?.why).toMatch(/Known Exploited Vulnerabilities/);
    expect(php?.remediation.at(-1)).toMatch(/take the PHP system offline/);
    expect(php?.remediation.join(" ")).not.toMatch(/does not block a deploy or hold a page/);
    expect(result.vulns[0]).toMatchObject({ status: "vulnerable", detectedVersion: "7.4.33", audience: "visitor" });
    expect(result.findings.find((finding) => finding.id === "BACKEND_TLS_CIPHER")?.severity).toBe("high");
    expect(result.findings.find((finding) => finding.id === "BACKEND_TLS_INTERNAL_NAME")?.evidence).toContain("db.internal");
    expect(result.findings.find((finding) => finding.id === "BACKEND_EXPOSED_VCS")?.evidence).toBe("/.git/HEAD, /.svn/entries");
    const summary = summarize(result.findings);
    expect(summary.byDomain).toHaveLength(11);
    for (const id of ["identity-access", "endpoint-device", "threat-intel", "operational-resilience", "human-factors", "emerging-tech"]) {
      expect(summary.byDomain.find((row) => row.id === id)?.total).toBe(0);
    }
    expect(blockDeploy(result.findings)).toBe(false);
    const packed = JSON.stringify(result);
    expect(packed).not.toContain("supersecretvalue");
    expect(packed).not.toContain("vigilTestKeyPlaceholder1234567890");
    expect(packed).not.toContain(marker);
    expect(packed).not.toContain("refs/heads/main");
    expect(result.headers["set-cookie"]).toBeUndefined();
    expect(result.cookies.map((cookie) => cookie.name).sort()).toEqual(["JSESSIONID", "PHPSESSID"]);
  });

  it("compares a header version and ignores a version that is only in the body", () => {
    const below = assess([response({
      url: "https://example.com/",
      headers: { "x-powered-by": "PHP/8.2.34" },
    })]);
    const php = below.findings.find((finding) => finding.id === "PHP_CVE_2026_109618");
    expect(php?.title).toBe("Upgrade PHP");
    expect(php?.title).not.toMatch(/never patched/);
    expect(php?.taxonomy.nistCsf.category).toBe("ID.RA");
    expect(php?.recommendationOnly).toBe(true);
    expect(php?.why).toMatch(/26 October 2026/);
    expect(php?.remediation.at(-1)).toMatch(/take the PHP system offline/);
    expect(php?.remediation.join(" ")).not.toMatch(/does not block a deploy or hold a page/);

    const patched = assess([response({
      url: "https://example.com/",
      headers: { "x-powered-by": "PHP/8.5.12" },
    })]);
    expect(patched.findings.some((finding) => finding.id === "PHP_CVE_2026_109618")).toBe(false);
    const session = patched.findings.find((finding) => finding.id === "PHP_CVE_2026_115560");
    expect(session?.severity).toBe("informational");
    expect(session?.recommendationOnly).toBe(true);
    expect(session?.remediation.join(" ")).toMatch(/does not block a deploy or hold a page/);
    expect(patched.vulns[0]?.status).toBe("fixed");
    expect(patched.vulns.find((row) => row.advisoryId === "PHP-CVE-2026-115560")?.status).toBe("suspected");
    expect(patched.findings.some((finding) => finding.id === "BACKEND_HEADER_POWERED_BY")).toBe(true);

    const hidden = assess([response({
      url: "https://example.com/",
      headers: { "x-powered-by": "PHP", "set-cookie": "PHPSESSID=secret-cookie" },
    })]);
    const unknown = hidden.findings.find((finding) => finding.id === "BACKEND_PHP_VERSION_HIDDEN");
    expect(unknown?.summary).toMatch(/unknown/);
    expect(unknown?.summary).not.toMatch(/vulnerable|below the fixed/i);
    expect(hidden.vulns[0]?.status).toBe("unknown");
    expect(hidden.findings.some((finding) => finding.id === "PHP_CVE_2026_109618")).toBe(false);
    expect(JSON.stringify(hidden)).not.toContain("secret-cookie");

    const bodyOnly = assess([response({
      url: "https://example.com/phpinfo.php",
      headers: { server: "nginx" },
      body: phpinfoPage("7.4.33"),
    })]);
    expect(bodyOnly.findings.some((finding) => finding.id === "BACKEND_EXPOSED_PHPINFO")).toBe(true);
    expect(bodyOnly.findings.some((finding) => finding.id === "PHP_CVE_2026_109618" || finding.id === "BACKEND_PHP_VERSION_HIDDEN")).toBe(false);
    expect(bodyOnly.vulns).toEqual([]);
  });

  it("does not treat a soft 404 or a forbidden path as exposure", () => {
    const result = assess([
      response({ url: "https://example.com/.git/HEAD", body: "<html>not a repository</html>" }),
      response({ url: "https://example.com/server-status", status: 403, body: "Apache Server Status" }),
      response({ url: "https://example.com/phpinfo.php", status: 404, body: "<title>phpinfo()</title>" }),
    ]);
    const ids = result.findings.map((finding) => finding.id);
    expect(ids).not.toContain("BACKEND_EXPOSED_VCS");
    expect(ids).not.toContain("BACKEND_EXPOSED_STATUS");
    expect(ids).not.toContain("BACKEND_EXPOSED_PHPINFO");
  });

  it("records a CBC selection and ignores a modern handshake", () => {
    const cbc = assess([
      response({ url: "https://example.com/", elapsedMs: 10 }),
      response({ url: "https://example.com/a", elapsedMs: 12 }),
      response({ url: "https://example.com/b", elapsedMs: 11 }),
    ], handshake({ protocol: "TLSv1.2", cipher: "ECDHE-RSA-AES128-SHA" }));
    const cipher = cbc.findings.find((finding) => finding.id === "BACKEND_TLS_CIPHER");
    expect(cipher?.severity).toBe("medium");
    expect(cbc.findings.some((finding) => finding.id === "BACKEND_TLS_PROTOCOL")).toBe(false);
    expect(cbc.findings.some((finding) => finding.id === "BACKEND_TIMING")).toBe(false);

    const modern = assess([response({ url: "https://example.com/" })]);
    expect(modern.findings.some((finding) => finding.id === "BACKEND_TLS_CIPHER" || finding.id === "BACKEND_TLS_PROTOCOL")).toBe(false);
    expect(modern.tls?.protocol).toBe("TLSv1.3");
  });

  it("reuses certificate rules for expiry and missing SCTs", () => {
    const expired = assess(
      [response({ url: "https://example.com/" })],
      handshake({ certs: [cert({ notAfter: new Date("2020-01-01T00:00:00.000Z") }), root()] }),
    );
    const expiry = expired.findings.find((finding) => finding.id === "CERT_EXPIRED");
    expect(expiry?.taxonomy.domain).toBe("operational-resilience");
    expect(expiry?.recommendationOnly).toBe(false);
    expect(blockDeploy(expired.findings)).toBe(true);

    const logged = assess(
      [response({ url: "https://example.com/" })],
      handshake({ certs: [cert({ sct: { present: false, count: 0, wellFormed: true } }), root()] }),
    );
    const sct = logged.findings.find((finding) => finding.id === "CERT_SCT_MISSING");
    expect(sct?.taxonomy.domain).toBe("threat-intel");
    expect(sct?.recommendationOnly).toBe(true);
    expect(blockDeploy(logged.findings)).toBe(false);
  });

  it("notes http and a failed handshake without dropping header findings", () => {
    const http = assess(
      [response({ url: "http://example.com/", headers: { server: "Apache/2.4.52" } })],
      null,
      "http://example.com/",
    );
    expect(http.findings.some((finding) => finding.id === "TLS_HTTP_ONLY")).toBe(true);
    expect(http.findings.some((finding) => finding.id === "BACKEND_HEADER_SERVER")).toBe(true);
    expect(http.cert).toBeNull();

    const failed = assess(
      [response({ url: "https://example.com/", headers: { server: "cloudflare" } })],
      { error: "TLS handshake failed" },
    );
    const unavailable = failed.findings.find((finding) => finding.id === "CERT_UNAVAILABLE");
    expect(unavailable?.taxonomy.domain).toBe("network-infrastructure");
    expect(failed.findings.some((finding) => finding.id === "BACKEND_HEADER_SERVER")).toBe(true);
    expect(blockDeploy(failed.findings)).toBe(false);
  });

  it("sends only ordinary GETs and one handshake", async () => {
    const calls: { url: string; method: string; body: unknown; ua: string | null; accept: string | null; size: number }[] = [];
    let handshakes = 0;
    const fetchImpl: typeof fetch = async (input, init) => {
      const headers = new Headers(init?.headers);
      let size = 0;
      headers.forEach((value, key) => {
        size += key.length + value.length;
      });
      calls.push({
        url: String(input),
        method: init?.method ?? "GET",
        body: init?.body ?? null,
        ua: headers.get("user-agent"),
        accept: headers.get("accept"),
        size,
      });
      const path = new URL(String(input)).pathname;
      const status = path === BACKEND_ERROR_PATH ? 404 : 200;
      return new Response(status === 404 ? "not found" : "<html>ok</html>", { status });
    };
    const report = await checkBackend("https://example.com/login", {
      lookup: async () => ["203.0.113.10"],
      fetchImpl,
      handshake: async () => {
        handshakes += 1;
        return handshake();
      },
      trustedSpki: trusted,
      now,
    });
    expect(handshakes).toBe(1);
    expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
      "/login",
      BACKEND_ERROR_PATH,
      ...BACKEND_KNOWN_PATHS,
    ]);
    expect(calls.every((call) => call.method === "GET" && call.body === null)).toBe(true);
    expect(calls.every((call) => call.ua === "vigil/2.0" && (call.accept ?? "").includes("text/html"))).toBe(true);
    expect(calls.every((call) => call.size < 500)).toBe(true);
    expect(report.blockDeploy).toBe(false);
    expect(report.verdict).toBe("allow");
    expect(report.findings).toEqual([]);
    expect(report.summary.byDomain).toHaveLength(11);
    expect(report.tls?.cipher).toBe("TLS_AES_128_GCM_SHA256");
  });

  it("stops extra path GETs when the time budget is already spent", async () => {
    const calls: string[] = [];
    let handshakes = 0;
    const transport: BackendTransport = async (url) => {
      calls.push(new URL(url).pathname);
      return response({ url });
    };
    await checkBackend("https://example.com/", {
      transport,
      handshake: async () => {
        handshakes += 1;
        return handshake();
      },
      trustedSpki: trusted,
      now,
      limits: { ...DEFAULT_LIMITS, wallClockMs: 0 },
    });
    expect(calls).toEqual(["/"]);
    expect(handshakes).toBe(1);
  });

  it("refuses a metadata address and a private final URL before probing", async () => {
    let called = false;
    const transport: BackendTransport = async () => {
      called = true;
      throw new Error("network");
    };
    await expect(checkBackend("http://169.254.169.254/", { transport })).rejects.toThrow(/not allowed/);
    expect(called).toBe(false);

    const calls: string[] = [];
    await expect(checkBackend("https://example.com/", {
      transport: async (url) => {
        calls.push(url);
        return response({ url: "http://127.0.0.1/secret" });
      },
      handshake: async () => handshake(),
    })).rejects.toThrow(/not allowed/);
    expect(calls).toEqual(["https://example.com/"]);
  });

  it("does not open a TLS socket for a blocked address", async () => {
    await expect(observeTlsHandshake("127.0.0.1", 443, "not-a-cert", "ECDHE-RSA-AES128-GCM-SHA256", 50, async () => ["203.0.113.5"])).rejects.toThrow(/not allowed/);
    await expect(observeTlsHandshake("example.com", 443, "not-a-cert", "ECDHE-RSA-AES128-GCM-SHA256", 50, async () => ["10.1.1.1"])).rejects.toThrow(/not allowed/);
    await expect(probeLegacyProtocols("127.0.0.1", 443, 50)).rejects.toThrow(/not allowed/);
    await expect(probeLegacyProtocols("example.com", 443, 50, async () => ["10.1.1.1"])).rejects.toThrow(/not allowed/);
  });

  it("reports an expired certificate when the first GET fails TLS", async () => {
    const calls: string[] = [];
    let handshakes = 0;
    const cause = Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" });
    const report = await checkBackend("https://example.com/login", {
      transport: async (url) => {
        calls.push(url);
        throw Object.assign(new TypeError("fetch failed"), { cause });
      },
      handshake: async () => {
        handshakes += 1;
        return handshake({ certs: [cert({ notAfter: new Date("2020-01-01T00:00:00.000Z") }), root()] });
      },
      trustedSpki: trusted,
      now,
    });
    expect(calls).toEqual(["https://example.com/login"]);
    expect(handshakes).toBe(1);
    const expiry = report.findings.find((finding) => finding.id === "CERT_EXPIRED");
    expect(expiry?.recommendationOnly).toBe(false);
    expect(report.blockDeploy).toBe(true);

    let messageHandshakes = 0;
    const fromMessage = await checkBackend("https://example.com/", {
      transport: async () => { throw new Error("self-signed certificate"); },
      handshake: async () => {
        messageHandshakes += 1;
        return handshake({ certs: [cert({ selfSigned: true, issuer: "CN=example.com" }), root()] });
      },
      trustedSpki: trusted,
      now,
    });
    expect(messageHandshakes).toBe(1);
    expect(fromMessage.findings.some((finding) => finding.id === "CERT_SELF_SIGNED")).toBe(true);
    expect(fromMessage.blockDeploy).toBe(true);
  });

  it("still rejects a network error that is not a certificate failure", async () => {
    let handshakes = 0;
    await expect(checkBackend("https://example.com/", {
      transport: async () => {
        throw Object.assign(new Error("connect ECONNREFUSED 203.0.113.10:443"), { code: "ECONNREFUSED" });
      },
      handshake: async () => {
        handshakes += 1;
        return handshake();
      },
    })).rejects.toThrow(/ECONNREFUSED/);
    expect(handshakes).toBe(0);
  });

  it("does not treat a PHP Version sentence as phpinfo", () => {
    const loose = assess([
      response({ url: "https://example.com/info.php", body: "<p>PHP Version 8.2.34 was announced today.</p>" }),
      response({ url: "https://example.com/phpinfo.php", body: "<title>phpinfo()</title>\nPHP Version 7.4.33" }),
    ]);
    expect(loose.findings.some((finding) => finding.id === "BACKEND_EXPOSED_PHPINFO")).toBe(false);
    expect(loose.findings.some((finding) => finding.id === "PHP_CVE_2026_109618")).toBe(false);

    const real = assess([response({ url: "https://example.com/info.php", body: phpinfoPage() })]);
    expect(real.findings.find((finding) => finding.id === "BACKEND_EXPOSED_PHPINFO")?.evidence).toBe("/info.php");
  });

  it("times header arrival and ignores body weight and a zero default", () => {
    const heavy = assess([
      response({ url: "https://example.com/", ttfbMs: 30, elapsedMs: 40 }),
      response({ url: "https://example.com/a", ttfbMs: 28, elapsedMs: 35 }),
      response({ url: "https://example.com/b", ttfbMs: 32, elapsedMs: 5000 }),
    ]);
    expect(heavy.findings.some((finding) => finding.id === "BACKEND_TIMING")).toBe(false);

    const slowHeaders = assess([
      response({ url: "https://example.com/", ttfbMs: 20, elapsedMs: 20 }),
      response({ url: "https://example.com/a", ttfbMs: 25, elapsedMs: 25 }),
      response({ url: "https://example.com/server-status", ttfbMs: 2000, elapsedMs: 2100 }),
    ]);
    const timing = slowHeaders.findings.find((finding) => finding.id === "BACKEND_TIMING");
    expect(timing?.evidence).toBe("/server-status 2000ms");
    expect(timing?.summary).toMatch(/headers/);
    expect(timing?.summary).not.toMatch(/2100/);

    const unset = assess([
      response({ url: "https://example.com/", elapsedMs: 10 }),
      response({ url: "https://example.com/a", elapsedMs: 12 }),
      response({ url: "https://example.com/b", elapsedMs: 5000 }),
    ]);
    expect(unset.findings.some((finding) => finding.id === "BACKEND_TIMING")).toBe(false);

    const zeros = assess([
      response({ url: "https://example.com/", ttfbMs: 0, elapsedMs: 10 }),
      response({ url: "https://example.com/a", ttfbMs: 0, elapsedMs: 20 }),
      response({ url: "https://example.com/b", ttfbMs: 0, elapsedMs: 5000 }),
    ]);
    expect(zeros.findings.some((finding) => finding.id === "BACKEND_TIMING")).toBe(false);
  });

  it("redacts connection strings in error evidence", () => {
    const secret = "vigilTestDbSecret";
    const result = assess([response({
      url: "https://example.com/missing",
      status: 500,
      body: `SQLSTATE[HY000] mysql://app:${secret}@db.internal/app Server=tcp:db.internal,1433;User ID=sa;Password=${secret};`,
    })]);
    const packed = JSON.stringify(result);
    expect(packed).not.toContain(secret);
    expect(packed).not.toContain("User ID=sa");
    expect(packed).not.toContain("mysql://app:");
    expect(packed).toContain("[redacted connection string]");
    expect(result.headers["set-cookie"]).toBeUndefined();
  });

  it("records a completed legacy handshake and ignores a modern one", () => {
    const accepted = assess(
      [response({ url: "https://example.com/" })],
      handshake({ protocol: "TLSv1.3", legacyProtocols: ["TLSv1"] }),
    );
    const finding = accepted.findings.find((item) => item.id === "BACKEND_TLS_PROTOCOL");
    expect(finding?.evidence).toBe("TLSv1");
    expect(finding?.summary).toMatch(/protocol-support/);
    expect(accepted.findings.some((item) => item.id === "BACKEND_TLS_CIPHER")).toBe(false);
    expect(accepted.tls?.protocol).toBe("TLSv1.3");
  });

  it("detects TLS 1.0 and TLS 1.1 on a local server and ignores TLS 1.2", async () => {
    const material = localCertificate();
    const pinned = { address: "127.0.0.1", family: 4 as const };
    try {
      const only10 = await withTlsServer(material, {
        minVersion: "TLSv1",
        maxVersion: "TLSv1",
        ciphers: "ALL@SECLEVEL=0",
      }, async (port) => {
        const legacy = await completeLegacyHandshake(pinned, "localhost", port, "TLSv1", 2_000);
        await expect(completeLegacyHandshake(pinned, "localhost", port, "TLSv1.1", 2_000)).rejects.toThrow();
        return legacy.protocol;
      });
      expect(only10).toBe("TLSv1");
      const noted = assess(
        [response({ url: "https://example.com/" })],
        handshake({ protocol: "TLSv1.3", legacyProtocols: [only10] }),
      );
      expect(noted.findings.some((finding) => finding.id === "BACKEND_TLS_PROTOCOL" && finding.evidence === "TLSv1")).toBe(true);

      const only11 = await withTlsServer(material, {
        minVersion: "TLSv1.1",
        maxVersion: "TLSv1.1",
        ciphers: "ALL@SECLEVEL=0",
      }, async (port) => {
        await expect(completeLegacyHandshake(pinned, "localhost", port, "TLSv1", 2_000)).rejects.toThrow();
        const legacy = await completeLegacyHandshake(pinned, "localhost", port, "TLSv1.1", 2_000);
        return legacy.protocol;
      });
      expect(only11).toBe("TLSv1.1");

      await withTlsServer(material, {
        minVersion: "TLSv1.2",
        maxVersion: "TLSv1.3",
      }, async (port) => {
        await expect(completeLegacyHandshake(pinned, "localhost", port, "TLSv1", 2_000)).rejects.toThrow();
        await expect(completeLegacyHandshake(pinned, "localhost", port, "TLSv1.1", 2_000)).rejects.toThrow();
      });
    } finally {
      material.cleanup();
    }
  });

  it("measures header time separately from a slow body", async () => {
    const lookup = async () => ["203.0.113.10"];
    const handshakeStub = async () => handshake();
    const heavyBody: typeof fetch = async (input) => {
      const path = new URL(String(input)).pathname;
      await delay(15);
      if (path === "/server-status") {
        const stream = new ReadableStream({
          async start(controller) {
            await delay(900);
            controller.enqueue(new TextEncoder().encode("Apache Server Status\nServer uptime: 1"));
            controller.close();
          },
        });
        return new Response(stream, { status: 200 });
      }
      const status = path === BACKEND_ERROR_PATH ? 404 : 200;
      return new Response("ok", { status });
    };
    const heavy = await checkBackend("https://example.com/login", {
      lookup,
      fetchImpl: heavyBody,
      handshake: handshakeStub,
      trustedSpki: trusted,
      now,
    });
    expect(heavy.findings.some((finding) => finding.id === "BACKEND_TIMING")).toBe(false);

    const slowHeaders: typeof fetch = async (input) => {
      const path = new URL(String(input)).pathname;
      await delay(path === "/info.php" ? 900 : 20);
      const status = path === BACKEND_ERROR_PATH ? 404 : 200;
      return new Response("ok", { status });
    };
    const waited = await checkBackend("https://example.com/login", {
      lookup,
      fetchImpl: slowHeaders,
      handshake: handshakeStub,
      trustedSpki: trusted,
      now,
    });
    const timing = waited.findings.find((finding) => finding.id === "BACKEND_TIMING");
    expect(timing?.evidence).toMatch(/^\/info\.php \d+ms$/);
    expect(Number(timing?.evidence?.match(/(\d+)ms$/)?.[1])).toBeGreaterThanOrEqual(800);
  });
});

function phpinfoPage(version = "8.2.34"): string {
  return [
    `<html><head><title>PHP ${version} - phpinfo()</title></head><body>`,
    `<h1 class="p">PHP Version ${version}</h1>`,
    `<table><tr><td class="e">System </td><td class="v">Linux</td></tr></table>`,
    "</body></html>",
  ].join("");
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function localCertificate(): { key: string; cert: string; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), "vigil-tls-"));
  const keyPath = join(dir, "key.pem");
  const certPath = join(dir, "cert.pem");
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048",
    "-keyout", keyPath, "-out", certPath,
    "-days", "1", "-nodes", "-subj", "/CN=localhost",
  ], { stdio: "ignore" });
  return {
    key: readFileSync(keyPath, "utf8"),
    cert: readFileSync(certPath, "utf8"),
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

async function withTlsServer<T>(
  material: { key: string; cert: string },
  options: tls.TlsOptions,
  run: (port: number) => Promise<T>,
): Promise<T> {
  let hits = 0;
  const server = tls.createServer({
    key: material.key,
    cert: material.cert,
    ...options,
  }, (socket) => {
    hits += 1;
    socket.end();
  });
  server.on("tlsClientError", () => undefined);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address() as AddressInfo | null;
  if (!address || address.address !== "127.0.0.1") throw new Error("test server did not bind to 127.0.0.1");
  try {
    if (hits !== 0) throw new Error("test server accepted a connection before the probe");
    return await run(address.port);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
}
