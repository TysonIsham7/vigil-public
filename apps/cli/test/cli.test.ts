import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zipSync, strToU8 } from "fflate";
import { describe, expect, it } from "vitest";
import { buildReport } from "@vigil/core";
import { intermediatePems } from "@vigil/intel";
import type { ScanUrlOptions } from "@vigil/netcheck";
import { main } from "../src/main.js";

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
      },
      trustBundles: [{ label: "node", pem }],
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
});
