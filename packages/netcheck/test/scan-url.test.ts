import { describe, expect, it } from "vitest";
import { evaluateCertificateChain, scanUrl, type ParsedCert } from "../src/index.js";

const now = new Date("2026-10-21T00:00:00.000Z");

function leaf(): ParsedCert {
  return {
    subject: "CN=example.com",
    issuer: "CN=Root",
    sanDns: ["example.com"],
    sanIp: [],
    notBefore: new Date("2026-01-01T00:00:00.000Z"),
    notAfter: new Date("2027-01-01T00:00:00.000Z"),
    sha256: "11".repeat(32),
    spkiSha256: "22".repeat(32),
    signatureAlgorithm: "sha256WithRSAEncryption",
    publicKeyAlgorithm: "rsa",
    publicKeyBits: 2048,
    selfSigned: false,
    sct: { present: true, count: 2, wellFormed: true },
  };
}

describe("scanUrl", () => {
  const html = "<!doctype html><html><head><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self'\"></head><body>ok</body></html>";
  const fetchImpl: typeof fetch = async () => new Response(html, {
    status: 200,
    headers: {
      "content-security-policy": "default-src 'self'",
      "x-powered-by": "PHP/8.2.34",
    },
  });

  async function run(audience: "owner" | "visitor") {
    return scanUrl("https://example.com/", {
      audience,
      lookup: async () => ["203.0.113.10"],
      fetchImpl,
      now,
      inspectChain: async () => evaluateCertificateChain(
        [leaf(), { ...leaf(), subject: "CN=Root", issuer: "CN=Root", selfSigned: true, sanDns: [], spkiSha256: "33".repeat(32) }],
        { host: "example.com", now, trustedSpki: new Set(["33".repeat(32)]) },
      ),
    });
  }

  it("blocks a confirmed PHP version for the owner and warns a visitor", async () => {
    const owner = await run("owner");
    const visitor = await run("visitor");
    expect(owner.ownedBuffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    expect(owner.report.blockDeploy).toBe(true);
    const php = owner.report.findings.find((finding) => finding.id === "PHP_CVE_2026_109618");
    expect(php && !php.recommendationOnly).toBe(true);
    expect(php?.title).toBe("Upgrade PHP");
    expect(php?.remediation[0] ?? "").toMatch(/^Upgrade PHP/);
    expect(php?.remediation[1] ?? "").toMatch(/partial mitigation/);
    expect(php?.remediation[0] ?? "").not.toMatch(/session\.upload_progress/);
    expect(php?.remediation[2] ?? "").toMatch(/CVE-2026-115560/);
    expect(owner.report.checks.vulns?.[0]?.mitigation ?? "").toMatch(/^Upgrade PHP/);
    expect(owner.report.checks.vulns?.[1]?.advisoryId).toBe("PHP-CVE-2026-115560");
    expect(owner.report.findings.some((finding) => finding.id === "PHP_CVE_2026_115560")).toBe(false);
    expect(owner.report.checks.vulns?.[0]?.audience).toBe("owner");
    expect(owner.report.summary.byDomain).toHaveLength(11);
    expect(visitor.report.blockDeploy).toBe(false);
    expect(visitor.report.verdict).toBe("warn");
    expect(visitor.report.findings.find((finding) => finding.id === "PHP_CVE_2026_109618")?.recommendationOnly).toBe(true);
    expect(visitor.report.checks.domain?.reputation.every((row) => row.status === "not-configured")).toBe(true);
    const note = owner.report.findings.find((finding) => finding.id === "KERNEL_SHARED_HOST");
    expect(note?.severity).toBe("informational");
    expect(note?.recommendationOnly).toBe(true);
    expect(note?.summary).toMatch(/cannot see the host kernel/);
  });

  it("notes CVE-2026-115560 on a PHP release that already has the 21 October fixes", async () => {
    const patched: typeof fetch = async () => new Response(html, {
      status: 200,
      headers: {
        "content-security-policy": "default-src 'self'",
        "x-powered-by": "PHP/8.5.12",
      },
    });
    const owner = await scanUrl("https://example.com/", {
      audience: "owner",
      lookup: async () => ["203.0.113.10"],
      fetchImpl: patched,
      now,
      inspectChain: async () => evaluateCertificateChain(
        [leaf(), { ...leaf(), subject: "CN=Root", issuer: "CN=Root", selfSigned: true, sanDns: [], spkiSha256: "33".repeat(32) }],
        { host: "example.com", now, trustedSpki: new Set(["33".repeat(32)]) },
      ),
    });
    expect(owner.report.blockDeploy).toBe(false);
    expect(owner.report.findings.some((finding) => finding.id === "PHP_CVE_2026_109618")).toBe(false);
    const note = owner.report.findings.find((finding) => finding.id === "PHP_CVE_2026_115560");
    expect(note?.recommendationOnly).toBe(true);
    expect(note?.severity).toBe("informational");
    expect(note?.summary).toMatch(/8\.5\.12/);
    expect(note?.summary).toMatch(/no patched release|no fixed version|has not published a fixed version/);
    expect(owner.report.checks.vulns?.find((row) => row.advisoryId === "PHP-CVE-2026-115560")?.status).toBe("suspected");
  });
});
