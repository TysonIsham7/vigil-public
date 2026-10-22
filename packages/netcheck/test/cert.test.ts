import { describe, expect, it } from "vitest";
import { intermediatePems } from "@vigil/intel";
import {
  anchorSpkiHashes,
  countEmbeddedScts,
  evaluateCertificateChain,
  parseCertificate,
  readMozillaPem,
  type ParsedCert,
} from "../src/index.js";

const now = new Date("2026-10-21T00:00:00.000Z");

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
    sct: { present: true, count: 1, wellFormed: true },
    ...overrides,
  };
}

describe("certificate chain", () => {
  const root = cert({
    subject: "CN=Root",
    issuer: "CN=Root",
    sanDns: [],
    selfSigned: true,
    spkiSha256: "cc".repeat(32),
    signatureAlgorithm: "sha1WithRSAEncryption",
  });
  const trusted = new Set([root.spkiSha256]);

  it("accepts a chain that ends at a pinned root", () => {
    const result = evaluateCertificateChain([cert(), root], { host: "example.com", now, trustedSpki: trusted });
    expect(result.cert.authorized).toBe(true);
    expect(result.cert.sct.signaturesVerified).toBe(false);
    expect(result.findings.map((finding) => finding.id)).not.toContain("CERT_SHA1");
  });

  it("blocks a distrusted SPKI even when that key is still in the trust set", () => {
    const leaked = intermediatePems()[0];
    expect(leaked).toBeDefined();
    const parsed = parseCertificate(leaked?.pem ?? "");
    expect(parsed.spkiSha256).toBe(leaked?.spkiSha256);
    const result = evaluateCertificateChain([parsed], {
      host: "example.com",
      now,
      trustedSpki: new Set([parsed.spkiSha256]),
    });
    const finding = result.findings.find((item) => item.id === "CERT_DISTRUSTED_CA");
    expect(finding?.recommendationOnly).toBe(false);
    expect(finding?.severity).toBe("critical");
    expect(finding?.taxonomy.domain).toBe("threat-intel");
    expect(result.cert.authorized).toBe(false);
  });

  it("blocks expiry, hostname mismatch, and an untrusted self-signed leaf", () => {
    const expired = evaluateCertificateChain(
      [cert({ notAfter: new Date("2026-10-01T00:00:00.000Z") }), root],
      { host: "example.com", now, trustedSpki: trusted },
    );
    expect(expired.findings.some((finding) => finding.id === "CERT_EXPIRED" && !finding.recommendationOnly)).toBe(true);
    const mismatch = evaluateCertificateChain([cert({ sanDns: ["other.example"] }), root], { host: "example.com", now, trustedSpki: trusted });
    expect(mismatch.findings.some((finding) => finding.id === "CERT_HOSTNAME_MISMATCH")).toBe(true);
    const selfSigned = evaluateCertificateChain([cert({ selfSigned: true, subject: "CN=example.com", issuer: "CN=example.com" })], {
      host: "example.com",
      now,
      trustedSpki: trusted,
    });
    expect(selfSigned.findings.some((finding) => finding.id === "CERT_SELF_SIGNED" && !finding.recommendationOnly)).toBe(true);
  });

  it("recommends on a short key, SHA-1, a near expiry, and a missing SCT", () => {
    const result = evaluateCertificateChain(
      [cert({
        publicKeyBits: 1024,
        signatureAlgorithm: "sha1WithRSAEncryption",
        notAfter: new Date("2026-10-30T00:00:00.000Z"),
        sct: { present: false, count: 0, wellFormed: true },
      }), root],
      { host: "example.com", now, trustedSpki: trusted },
    );
    const ids = result.findings.map((finding) => finding.id);
    expect(ids).toEqual(expect.arrayContaining(["CERT_EXPIRING", "CERT_WEAK_KEY", "CERT_SHA1", "CERT_SCT_MISSING"]));
    expect(result.findings.every((finding) => finding.recommendationOnly)).toBe(true);
  });

  it("loads the pinned Mozilla bundle", () => {
    const anchors = anchorSpkiHashes(readMozillaPem());
    expect(anchors.size).toBeGreaterThan(100);
  });

  it("parses an embedded SCT oid", () => {
    const oid = Uint8Array.from([0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x04, 0x02]);
    expect(countEmbeddedScts(oid).present).toBe(true);
    expect(countEmbeddedScts(Uint8Array.from([0x30, 0x00])).present).toBe(false);
  });
});
