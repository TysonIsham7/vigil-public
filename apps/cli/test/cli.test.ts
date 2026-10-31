import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync, strToU8 } from "fflate";
import { describe, expect, it } from "vitest";
import { buildReport } from "@vigil/core";
import { intermediatePems } from "@vigil/intel";
import { BACKEND_CIPHER_OFFER, BACKEND_ERROR_PATH, BACKEND_KNOWN_PATHS, type BackendResponse, type ParsedCert, type ScanUrlOptions } from "@vigil/netcheck";
import { main } from "../src/main.js";
import type { TrustAuditReport } from "../src/trust-audit.js";

const quietTrust: TrustAuditReport = {
  version: 1,
  probedAt: "2026-10-22T00:00:00.000Z",
  platform: "linux",
  incidents: [],
};

const root = join(import.meta.dirname, "../../..");

function io() {
  let out = "";
  let err = "";
  return {
    stdout: (text: string) => { out += text; },
    stderr: (text: string) => { err += text; },
    text: () => out,
    error: () => err,
  };
}

describe("cli", () => {
  it("exits 2 on the vulnerable fixture and prints domain counts", async () => {
    const output = io();
    const code = await main(["scan", join(root, "fixtures/vulnerable")], output);
    expect(code).toBe(2);
    expect(output.text()).toContain("verdict: block");
    expect(output.text()).toContain("block_deploy: true");
    expect(output.text()).toContain("Application & Software");
    expect(output.text()).toContain("Data Security & Privacy");
    expect(output.text()).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("exits 0 for a clean page", async () => {
    const output = io();
    const code = await main(["scan", join(root, "fixtures/clean"), "--json"], output);
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as { verdict: string; blockDeploy: boolean };
    expect(report.verdict).toBe("allow");
    expect(report.blockDeploy).toBe(false);
    expect(output.text()).not.toContain("KERNEL_SHARED_HOST");
  });

  it("passes owner and visitor audiences", async () => {
    const seen: string[] = [];
    const scanUrl = async (_url: string, options: ScanUrlOptions) => {
      seen.push(options.audience);
      return {
        report: buildReport({ findings: [], sourceType: "url", filesAnalyzed: 1, bytesAnalyzed: 1, intelVersion: "test" }),
        ownedBuffers: [],
        artifactBytes: 0 as const,
        codeDeleted: true as const,
      };
    };
    expect(await main(["scan", "https://example.com/"], io(), { scanUrl })).toBe(0);
    expect(await main(["check-url", "https://example.com/"], io(), { scanUrl })).toBe(0);
    expect(seen).toEqual(["owner", "visitor"]);
  });

  it("exits 2 when deps finds LiteLLM 1.107.0", async () => {
    const output = io();
    const fetchImpl: typeof fetch = async () => new Response(JSON.stringify({ results: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
    const code = await main(["deps", join(root, "fixtures/deps"), "--json"], output, { fetchImpl });
    expect(code).toBe(2);
    const report = JSON.parse(output.text()) as { blockDeploy: boolean; findings: { id: string }[]; summary: { byDomain: { id: string; total: number }[] } };
    expect(report.blockDeploy).toBe(true);
    expect(report.findings.some((finding) => finding.id === "DEP_LITELLM_COMPROMISED")).toBe(true);
    expect(report.summary.byDomain).toHaveLength(11);
  });

  it("exits 0 for doctor even when Go is missing the trust fix", async () => {
    const output = io();
    const code = await main(["doctor", join(root, "fixtures/doctor"), "--json"], output, {
      versions: { curl: "curl 8.5.0", go: "go version go1.22.2 linux/amd64" },
      trustAudit: quietTrust,
    });
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as { blockDeploy: boolean; findings: { id: string; recommendationOnly: boolean }[] };
    expect(report.blockDeploy).toBe(false);
    expect(report.findings.some((finding) => finding.id === "TOOLCHAIN_GO")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "TOOLCHAIN_IMAGE")).toBe(true);
    expect(report.findings.every((finding) => finding.recommendationOnly)).toBe(true);
  });

  it("exits 0 when doctor sees an affected kernel and a local eMudhra trust hit", async () => {
    const output = io();
    const pem = intermediatePems()[0]?.pem ?? "";
    const code = await main(["doctor", "--json"], output, {
      versions: {
        curl: "curl 8.23.0",
        go: "go version go1.27.3 linux/amd64",
        kernel: "6.12.94+",
        kernelOs: "Linux",
        python: "Python 3.12.16rc1",
      },
      trustBundles: [{ label: "node", pem }],
      trustAudit: quietTrust,
    });
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as {
      blockDeploy: boolean;
      findings: { id: string; recommendationOnly: boolean; evidence: string }[];
    };
    expect(report.blockDeploy).toBe(false);
    expect(report.findings.some((finding) => finding.id === "KERNEL_CVE_2026_99999" && finding.evidence === "6.12.94")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "TRUSTSTORE_EMUDHRA" && finding.recommendationOnly)).toBe(true);
    expect(report.findings.some((finding) => finding.id === "TOOLCHAIN_GO")).toBe(false);
    expect(report.findings.some((finding) => finding.id === "TOOLCHAIN_PYTHON" && finding.evidence === "3.12.16rc1" && finding.recommendationOnly)).toBe(true);
    expect(output.text()).not.toContain("BEGIN CERTIFICATE");
  });

  it("strips zip path traversal before scanning", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-zip-"));
    const zipPath = join(dir, "sample.zip");
    writeFileSync(zipPath, zipSync({
      "../secret.js": strToU8('const api_key = "vigilTestKeyPlaceholder1234567890";\n'),
      "ok.html": strToU8("<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head><body>ok</body></html>"),
    }));
    const output = io();
    const code = await main(["scan", zipPath, "--json"], output);
    expect(code).toBe(2);
    const report = JSON.parse(output.text()) as { findings: { file: string; id: string }[] };
    expect(report.findings.some((finding) => finding.id === "SECRET_GENERIC_KEY" && finding.file === "secret.js")).toBe(true);
    expect(report.findings.every((finding) => !finding.file.includes(".."))).toBe(true);
    expect(readFileSync(zipPath).byteLength).toBeGreaterThan(0);
  });

  it("stops reading a zip past the uncompressed cap", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-zip-cap-"));
    const zipPath = join(dir, "big.zip");
    const secret = "const api_key = \"vigilTestKeyPlaceholder1234567890\";\n";
    const page = "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head><body>ok</body></html>";
    writeFileSync(zipPath, zipSync({
      "ok.html": strToU8(page),
      "note.js": strToU8(secret + "a".repeat(8 * 1024 * 1024)),
    }));
    const output = io();
    const code = await main(["scan", zipPath, "--json"], output);
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as { filesAnalyzed: number; bytesAnalyzed: number };
    expect(report.filesAnalyzed).toBe(1);
    expect(report.bytesAnalyzed).toBeLessThan(1024);
    expect(output.text()).not.toContain("vigilTestKeyPlaceholder");
    expect(output.text()).not.toContain("note.js");
  });

  it("exits 1 for a metadata URL", async () => {
    const output = io();
    const code = await main(["check-url", "http://169.254.169.254/"], output);
    expect(code).toBe(1);
    expect(output.error()).toMatch(/not allowed/);
  });

  it("describes the passive backend check in command help", async () => {
    const output = io();
    expect(await main(["check-backend", "--help"], output)).toBe(0);
    const text = output.text();
    expect(text).toMatch(/passive fingerprint/);
    expect(text).toMatch(/no crash payload/);
    expect(text).toMatch(/terms of service/);
    expect(text).toMatch(/computer-misuse/);
    expect(text).toMatch(/8\.5\.12/);
    expect(text).toMatch(/never patched/);
    expect(text).toMatch(/no version is unknown/);
    expect(text).toMatch(/phpinfo\.php/);
  });

  it("warns on an advertised PHP 7 header without calling the network", async () => {
    const paths: string[] = [];
    const output = io();
    const code = await main(["check-backend", "https://example.com/login", "--json"], output, {
      now: new Date("2026-10-22T00:00:00.000Z"),
      backendTransport: async (url) => {
        const path = new URL(url).pathname;
        paths.push(path);
        const body: BackendResponse = {
          url,
          status: path === BACKEND_ERROR_PATH ? 404 : 200,
          headers: path === "/login" ? { "x-powered-by": "PHP/7.4.33" } : {},
          body: path === BACKEND_ERROR_PATH ? "<html><center>nginx</center></html>" : "<html>ok</html>",
          truncated: false,
          elapsedMs: path === "/server-status" ? 4000 : 40,
          ttfbMs: path === "/server-status" ? 2000 : 25,
        };
        return body;
      },
      backendHandshake: async () => ({
        protocol: "TLSv1.3",
        cipher: "TLS_AES_128_GCM_SHA256",
        offeredCiphers: [...BACKEND_CIPHER_OFFER],
        certs: [leafCert(), rootCert()],
      }),
    });
    expect(code).toBe(0);
    expect(paths).toEqual(["/login", BACKEND_ERROR_PATH, ...BACKEND_KNOWN_PATHS]);
    const report = JSON.parse(output.text()) as {
      blockDeploy: boolean;
      verdict: string;
      findings: { id: string; recommendationOnly: boolean; taxonomy: { domain: string } }[];
      summary: { byDomain: unknown[] };
      checks: { vulns: { status: string; detectedVersion?: string }[] };
    };
    expect(report.blockDeploy).toBe(false);
    expect(report.verdict).toBe("warn");
    expect(report.summary.byDomain).toHaveLength(11);
    const php = report.findings.find((finding) => finding.id === "PHP_CVE_2026_109618");
    expect(php?.recommendationOnly).toBe(true);
    expect(php?.taxonomy.domain).toBe("application-software");
    expect(report.findings.some((finding) => finding.id === "BACKEND_ERROR_SIGNATURE" && finding.taxonomy.domain === "application-software")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "BACKEND_TIMING" && finding.taxonomy.domain === "network-infrastructure")).toBe(true);
    expect(report.checks.vulns[0]).toMatchObject({ status: "vulnerable", detectedVersion: "7.4.33" });
    expect(output.text()).not.toContain("supersecret");
  });

  it("exits 2 when check-backend sees an expired certificate", async () => {
    const output = io();
    const code = await main(["check-backend", "https://example.com/"], output, {
      now: new Date("2026-10-22T00:00:00.000Z"),
      backendTransport: async (url) => ({
        url,
        status: 200,
        headers: {},
        body: "<html>ok</html>",
        truncated: false,
        elapsedMs: 20,
      }),
      backendHandshake: async () => ({
        protocol: "TLSv1.3",
        cipher: "TLS_AES_128_GCM_SHA256",
        offeredCiphers: [...BACKEND_CIPHER_OFFER],
        certs: [leafCert({ notAfter: new Date("2020-01-01T00:00:00.000Z") }), rootCert()],
      }),
    });
    expect(code).toBe(2);
    expect(output.text()).toContain("CERT_EXPIRED");
    expect(output.text()).toContain("operational-resilience");
  });

  it("exits 2 when the first GET throws a certificate error", async () => {
    const output = io();
    let handshakes = 0;
    const cause = Object.assign(new Error("certificate has expired"), { code: "CERT_HAS_EXPIRED" });
    const code = await main(["check-backend", "https://example.com/"], output, {
      now: new Date("2026-10-22T00:00:00.000Z"),
      backendTransport: async () => {
        throw Object.assign(new TypeError("fetch failed"), { cause });
      },
      backendHandshake: async () => {
        handshakes += 1;
        return {
          protocol: "TLSv1.3",
          cipher: "TLS_AES_128_GCM_SHA256",
          offeredCiphers: [...BACKEND_CIPHER_OFFER],
          certs: [leafCert({ notAfter: new Date("2020-01-01T00:00:00.000Z") }), rootCert()],
        };
      },
    });
    expect(handshakes).toBe(1);
    expect(code).toBe(2);
    expect(output.text()).toContain("CERT_EXPIRED");
    expect(output.error()).toBe("");
  });

  it("exits 1 when check-backend cannot connect", async () => {
    const output = io();
    let handshakes = 0;
    const cause = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    const code = await main(["check-backend", "https://example.com/"], output, {
      backendTransport: async () => {
        throw Object.assign(new TypeError("fetch failed"), { cause });
      },
      backendHandshake: async () => {
        handshakes += 1;
        return {
          protocol: "TLSv1.3",
          cipher: "TLS_AES_128_GCM_SHA256",
          offeredCiphers: [...BACKEND_CIPHER_OFFER],
          certs: [leafCert(), rootCert()],
        };
      },
    });
    expect(handshakes).toBe(0);
    expect(code).toBe(1);
    expect(output.error()).toMatch(/ECONNREFUSED|fetch failed/);
  });

  it("rejects check-backend usage and a metadata URL before any probe", async () => {
    const missing = io();
    expect(await main(["check-backend"], missing)).toBe(1);
    expect(missing.error()).toMatch(/http\(s\) URL/);
    const extra = io();
    expect(await main(["check-backend", "https://example.com/", "more"], extra)).toBe(1);
    expect(extra.error()).toMatch(/one URL/);
    const blocked = io();
    expect(await main(["check-backend", "http://169.254.169.254/"], blocked)).toBe(1);
    expect(blocked.error()).toMatch(/not allowed/);
  });
});

function leafCert(overrides: Partial<ParsedCert> = {}): ParsedCert {
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

function rootCert(): ParsedCert {
  return leafCert({
    subject: "CN=Root",
    issuer: "CN=Root",
    sanDns: [],
    selfSigned: true,
    spkiSha256: "cc".repeat(32),
    sha256: "dd".repeat(32),
  });
}
