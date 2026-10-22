import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCertificate } from "../scripts/x509-der.mjs";

const dataPath = join(dirname(fileURLToPath(import.meta.url)), "../../../packages/intel/data/distrusted-cas.json");

function derFromPem(pem: string): Buffer {
  const body = pem.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, "");
  return Buffer.from(body, "base64");
}

describe("x509 der walker", () => {
  it("matches Node SPKI, fingerprint, and dates for every published block certificate", () => {
    const data = JSON.parse(readFileSync(dataPath, "utf8")) as {
      intermediates: { action: string; pem?: string; spkiSha256: string; sha256: string; name: string }[];
    };
    const rows = data.intermediates.filter((item) => item.action === "block" && item.pem);
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) {
      const der = derFromPem(row.pem ?? "");
      const parsed = parseCertificate(der);
      const node = new X509Certificate(der);
      expect(parsed, row.name).not.toBeNull();
      const spki = createHash("sha256").update(parsed!.spki).digest("hex");
      expect(spki).toBe(row.spkiSha256);
      expect(createHash("sha256").update(der).digest("hex")).toBe(row.sha256);
      expect(parsed!.notBefore).toBe(Date.parse(node.validFrom));
      expect(parsed!.notAfter).toBe(Date.parse(node.validTo));
      expect(node.publicKey.export({ type: "spki", format: "der" }).equals(parsed!.spki)).toBe(true);
      expect(parsed!.commonName).toBe(row.name);
      expect(parsed!.selfSigned).toBe(false);
      expect(parsed!.sanDns).toEqual([]);
    }
  });
});
