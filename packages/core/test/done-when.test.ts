import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  DISCLAIMER,
  EphemeralReports,
  REPORT_TTL_MS,
  TAXONOMY_DOMAIN_IDS,
  inspectUrl,
  isBlockedIp,
  scanFiles,
} from "../src/index.js";

const root = join(import.meta.dirname, "../../..");

function filesIn(dir: string) {
  return readdirSync(join(root, dir)).map((name) => ({
    name,
    content: readFileSync(join(root, dir, name), "utf8"),
  }));
}

describe("done when", () => {
  const now = new Date("2026-10-21T12:00:00.000Z");

  it("blocks the vulnerable sample and zeroes owned buffers", () => {
    const result = scanFiles(filesIn("fixtures/vulnerable"), { sourceType: "sample", now, intelVersion: "test" });
    expect(result.report.blockDeploy).toBe(true);
    expect(result.report.verdict).toBe("block");
    expect(result.report.findings.some((finding) => finding.severity === "critical" && !finding.recommendationOnly)).toBe(true);
    expect(result.codeDeleted).toBe(true);
    expect(result.artifactBytes).toBe(0);
    expect(result.report.artifactBytes).toBe(0);
    expect(result.ownedBuffers.length).toBeGreaterThan(0);
    expect(result.ownedBuffers.every((buffer) => buffer.every((byte) => byte === 0))).toBe(true);
    const encoded = JSON.stringify(result.report);
    expect(encoded).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(encoded).not.toContain("sk_live_vigiltestplaceholder000");
    expect(encoded).not.toContain("not-a-real-key");
    expect(encoded).not.toContain("ghp_vigilTestPlaceholderToken1234567890");
    expect(result.report.findings.every((finding) => !("source" in finding))).toBe(true);
    expect(result.report.disclaimer).toBe(DISCLAIMER);
    expect(result.report.expiresAt).toBe(new Date(now.getTime() + REPORT_TTL_MS).toISOString());
    expect(result.report.summary.byDomain.map((row) => row.id)).toEqual([...TAXONOMY_DOMAIN_IDS]);
  });

  it("does not block a clean static page", () => {
    const result = scanFiles(filesIn("fixtures/clean"), { now, intelVersion: "test" });
    expect(result.report.blockDeploy).toBe(false);
    expect(result.report.verdict).toBe("allow");
    expect(result.report.findings).toEqual([]);
  });

  it("keeps the same finding ids for the same input", () => {
    const first = scanFiles(filesIn("fixtures/vulnerable"), { now }).report.findings.map((finding) => finding.occurrenceId);
    const second = scanFiles(filesIn("fixtures/vulnerable"), { now }).report.findings.map((finding) => finding.occurrenceId);
    expect(first).toEqual(second);
  });

  it("drops the full report after 15 minutes and keeps titles only", () => {
    let clock = Date.parse("2026-10-21T12:00:00.000Z");
    const cache = new EphemeralReports(REPORT_TTL_MS, () => clock);
    const report = scanFiles(filesIn("fixtures/vulnerable"), { now: new Date(clock) }).report;
    cache.put(report);
    const saved = cache.saveLightweight(report);
    expect(saved.findings.every((finding) => !("evidence" in finding) && finding.domain.length > 0)).toBe(true);
    expect(JSON.stringify(saved)).not.toContain("innerHTML");
    clock += REPORT_TTL_MS;
    expect(cache.get(report.id)).toBeUndefined();
    expect(cache.getSaved(report.id)?.findings.map((finding) => finding.id)).toEqual(saved.findings.map((finding) => finding.id));
  });

  it("refuses private, loopback, metadata, and non-http targets", () => {
    const blocked = [
      "http://127.0.0.1/",
      "http://127.1.2.3/",
      "http://0.0.0.0/",
      "http://10.1.2.3/",
      "http://172.16.0.1/",
      "http://192.168.1.1/",
      "http://169.254.169.254/",
      "http://100.64.0.1/",
      "http://100.127.1.1/",
      "http://[::1]/",
      "http://[fe80::1]/",
      "http://[fc00::1]/",
      "http://[::ffff:127.0.0.1]/",
      "http://2130706433/",
      "http://0x7f000001/",
      "http://localhost/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://foo.localhost/",
      "http://foo.internal/",
      "http://user:pass@example.com/",
      "file:///etc/passwd",
      "ftp://example.com/",
      "http://0177.0.0.1/",
      "http://224.0.0.1/",
      "http://255.255.255.255/",
      "http://[64:ff9b::7f00:1]/",
      "http://[64:ff9b::127.0.0.1]/",
      "http://[64:ff9b::8.8.8.8]/",
      "http://[2002:7f00:1::]/",
      "http://[fec0::1]/",
    ];
    for (const target of blocked) {
      expect(() => inspectUrl(target), target).toThrow();
    }
    expect(isBlockedIp("172.15.0.1")).toBe(false);
    expect(isBlockedIp("172.32.0.1")).toBe(false);
    expect(isBlockedIp("100.128.0.1")).toBe(false);
    expect(isBlockedIp("8.8.8.8")).toBe(false);
    expect(isBlockedIp("2002:808:808::")).toBe(false);
    expect(inspectUrl("https://example.com/path").hostname).toBe("example.com");
  });
});
