import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { parseCertificate } from "../scripts/x509-der.mjs";

const repo = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const dataPath = join(repo, "packages/intel/data/distrusted-cas.json");
const versionPath = join(repo, "packages/intel/src/version.ts");
const outPath = join(repo, "apps/safari/Shared (Extension)/Generated/DistrustedCAs.swift");

interface Row {
  name: string;
  action: string;
  sha256?: string | null;
  spkiSha256?: string | null;
  pem?: string;
  crossSigns?: { sha256?: string; spkiSha256: string }[];
}

function blockedSpki(data: { intermediates: Row[]; roots: Row[] }): Set<string> {
  const hashes = new Set<string>();
  for (const item of data.intermediates) {
    if (item.action !== "block" || !item.spkiSha256) continue;
    hashes.add(item.spkiSha256.toLowerCase());
    for (const cross of item.crossSigns ?? []) hashes.add(cross.spkiSha256.toLowerCase());
  }
  for (const root of data.roots) {
    if (root.action === "block" && root.spkiSha256) hashes.add(root.spkiSha256.toLowerCase());
  }
  return hashes;
}

describe("generated distrust blocklist", () => {
  it("copies block SPKIs from the shared intel file and keeps record-only roots out", () => {
    const generated = spawnSync("python3", ["apps/safari/scripts/generate-blocklist.py"], { cwd: repo, encoding: "utf8" });
    expect(generated.status, generated.stderr).toBe(0);
    const data = JSON.parse(readFileSync(dataPath, "utf8")) as { intermediates: Row[]; roots: Row[] };
    const swift = readFileSync(outPath, "utf8");
    const version = versionPath && readFileSync(versionPath, "utf8").match(/INTEL_VERSION = "([^"]+)"/)?.[1];
    expect(swift).toContain(`static let intelVersion = "${version}"`);
    const [entries, recordOnly] = swift.split("static let recordOnlySpki");
    expect(entries && recordOnly).toBeTruthy();
    for (const hash of blockedSpki(data)) expect(entries).toContain(hash);
    for (const root of data.roots) {
      if (root.action !== "record-only" || !root.spkiSha256) continue;
      expect(recordOnly).toContain(root.spkiSha256.toLowerCase());
      expect(entries).not.toContain(root.spkiSha256.toLowerCase());
    }
    const fixture = swift.match(/static let derBase64 = "([^"]+)"/)?.[1] ?? "";
    const parsed = parseCertificate(Buffer.from(fixture, "base64"));
    const spki = createHash("sha256").update(parsed!.spki).digest("hex");
    expect(swift).toContain(`static let spkiSha256 = "${spki}"`);
    expect(blockedSpki(data).has(spki)).toBe(true);
  });
});