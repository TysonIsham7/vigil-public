import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, symlinkSync, writeFileSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { GATE_LIMITS } from "@vigil/core";
import { main } from "../src/main.js";
import { runGate } from "../src/gate.js";

const root = join(import.meta.dirname, "../../..");
const home = homedir();

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

function putOctal(header: Buffer, offset: number, length: number, value: number): void {
  const text = value.toString(8).padStart(length - 1, "0").slice(-(length - 1));
  header.write(text, offset, "utf8");
  header[offset + length - 1] = 0;
}

function tarHeader(name: string, size: number, type: number): Buffer {
  const header = Buffer.alloc(512);
  header.write(name, 0, "utf8");
  header.write("0000644\0", 100);
  header.write("0000000\0", 108);
  header.write("0000000\0", 116);
  putOctal(header, 124, 12, size);
  putOctal(header, 136, 12, 0);
  header.write("        ", 148);
  header[156] = type;
  header.write("ustar\0", 257);
  header.write("00", 263);
  let sum = 0;
  for (const byte of header) sum += byte;
  const checksum = sum.toString(8).padStart(6, "0");
  header.write(checksum, 148, "utf8");
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function pad512(body: Buffer): Buffer {
  return Buffer.concat([body, Buffer.alloc((512 - (body.byteLength % 512)) % 512)]);
}

function paxRecord(key: string, value: string): string {
  const suffix = ` ${key}=${value}\n`;
  let digits = 1;
  while (String(digits + suffix.length).length !== digits) digits = String(digits + suffix.length).length;
  return `${digits + suffix.length}${suffix}`;
}

function packNpm(files: Record<string, string>): Buffer {
  return packEntries(Object.entries(files).map(([name, content]) => ({ name, content })));
}

function packEntries(files: { name: string; content: string; paxPath?: string }[]): Buffer {
  const chunks: Buffer[] = [];
  for (const file of files) {
    if (file.paxPath) {
      const pax = Buffer.from(paxRecord("path", file.paxPath));
      chunks.push(tarHeader("./PaxHeaders.0/file", pax.byteLength, 0x78), pad512(pax));
    }
    const body = Buffer.from(file.content);
    chunks.push(tarHeader(`package/${file.name}`, body.byteLength, 0x30), pad512(body));
  }
  chunks.push(Buffer.alloc(1024));
  return gzipSync(Buffer.concat(chunks));
}

describe("vigil gate", () => {
  it("is listed in help", async () => {
    const output = io();
    expect(await main(["--help"], output)).toBe(0);
    expect(output.text()).toContain("vigil gate");
    expect(output.text()).toContain("without installing");
    expect(output.text()).toContain("still skips dist");
  });

  it("blocks a dist bin that scan still allows", async () => {
    const dir = join(root, "fixtures/install-gate/dist-bin");
    const scanned = io();
    expect(await main(["scan", dir, "--json"], scanned)).toBe(0);
    const scan = JSON.parse(scanned.text()) as { verdict: string; filesAnalyzed: number; findings: { id: string }[] };
    expect(scan.verdict).toBe("allow");
    expect(scan.findings).toEqual([]);
    expect(scan.filesAnalyzed).toBe(2);

    const output = io();
    expect(await main(["gate", dir, "--json"], output)).toBe(2);
    const report = JSON.parse(output.text()) as { verdict: string; blockDeploy: boolean; findings: { id: string; file: string }[] };
    expect(report.verdict).toBe("block");
    expect(report.blockDeploy).toBe(true);
    const ids = new Set(report.findings.map((finding) => finding.id));
    expect(ids.has("INSTALL_CHILD_PROCESS")).toBe(true);
    expect(ids.has("INSTALL_RUNTIME_FETCH")).toBe(true);
    expect(ids.has("INSTALL_AGENT_HOME")).toBe(true);
    expect(ids.has("INSTALL_MCP_CONFIG")).toBe(true);
    expect(report.findings.some((finding) => finding.file === "dist/index.js")).toBe(true);
    expect(report.findings.some((finding) => finding.file === "dist/setup.js")).toBe(true);
    expect(output.text()).not.toContain(home);
  });

  it("notes prepare without blocking a registry install", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-prepare-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: "prepare-only",
      version: "1.0.0",
      bin: "bin/hello.js",
      scripts: { prepare: "npm run build" },
    }));
    mkdirSync(join(dir, "bin"));
    writeFileSync(join(dir, "bin/hello.js"), "console.log('hello');\n");
    const report = await runGate(dir);
    expect(report.blockDeploy).toBe(false);
    expect(report.verdict).toBe("allow");
    expect(report.findings.map((finding) => finding.id)).toEqual(["INSTALL_PREPARE_SCRIPT"]);
  });

  it("allows a bin that only prints hello", async () => {
    const output = io();
    const code = await main(["gate", join(root, "fixtures/install-gate/hello-bin"), "--json"], output);
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as { verdict: string; blockDeploy: boolean; findings: unknown[] };
    expect(report.verdict).toBe("allow");
    expect(report.blockDeploy).toBe(false);
    expect(report.findings).toEqual([]);
  });

  it("blocks a postinstall shell script", async () => {
    const dir = join(root, "fixtures/install-gate/postinstall-shell");
    const scanned = io();
    expect(await main(["scan", dir, "--json"], scanned)).toBe(0);
    const output = io();
    expect(await main(["gate", dir, "--json"], output)).toBe(2);
    const report = JSON.parse(output.text()) as { findings: { id: string }[] };
    expect(report.findings.some((finding) => finding.id === "INSTALL_LIFECYCLE_SCRIPT")).toBe(true);
  });

  it("blocks a computed require, a missing file, and a file-budget hit", async () => {
    const dynamic = mkdtempSync(join(tmpdir(), "vigil-gate-dyn-"));
    writeFileSync(join(dynamic, "package.json"), JSON.stringify({ name: "dyn", version: "1.0.0", bin: "index.js" }));
    writeFileSync(join(dynamic, "index.js"), "require(name);\n");
    const dynamicReport = await runGate(dynamic);
    expect(dynamicReport.blockDeploy).toBe(true);
    expect(dynamicReport.findings.some((finding) => finding.id === "INSTALL_DYNAMIC_CODE")).toBe(true);

    const missing = mkdtempSync(join(tmpdir(), "vigil-gate-miss-"));
    writeFileSync(join(missing, "package.json"), JSON.stringify({ name: "miss", version: "1.0.0", bin: "index.js" }));
    writeFileSync(join(missing, "index.js"), "import './missing.js';\n");
    const missingReport = await runGate(missing);
    expect(missingReport.blockDeploy).toBe(true);
    expect(missingReport.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);

    const budget = await runGate(join(root, "fixtures/install-gate/hello-bin"), {
      limits: { ...GATE_LIMITS, fileCount: 1 },
    });
    expect(budget.blockDeploy).toBe(true);
    expect(budget.findings.some((finding) => finding.id === "INSTALL_FILE_BUDGET")).toBe(true);
    expect(budget.verdict).not.toBe("allow");
  });

  it("blocks exact bad dependency pins and reports a range without a lockfile", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-deps-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: "deps",
      version: "1.0.0",
      bin: "bin/hello.js",
      dependencies: {
        axios: "1.14.1",
        "@modelcontextprotocol/sdk": "1.31.0",
        litellm: "1.107.0",
        left: "^1.0.0",
      },
    }));
    mkdirSync(join(dir, "bin"));
    writeFileSync(join(dir, "bin/hello.js"), "console.log('hello');\n");
    const blocked = await runGate(dir);
    const ids = new Set(blocked.findings.map((finding) => finding.id));
    expect(blocked.blockDeploy).toBe(true);
    expect(ids.has("DEP_AXIOS_COMPROMISED")).toBe(true);
    expect(ids.has("DEP_MCP_SDK")).toBe(true);
    expect(ids.has("DEP_LITELLM_COMPROMISED")).toBe(true);
    expect(ids.has("DEP_RANGE")).toBe(true);

    const safe = mkdtempSync(join(tmpdir(), "vigil-gate-range-"));
    writeFileSync(join(safe, "package.json"), JSON.stringify({
      name: "range",
      version: "1.0.0",
      bin: "bin/hello.js",
      dependencies: { axios: "^1.14.0", "@modelcontextprotocol/sdk": "^1.32.0" },
    }));
    mkdirSync(join(safe, "bin"));
    writeFileSync(join(safe, "bin/hello.js"), "console.log('hello');\n");
    const ranged = await runGate(safe);
    expect(ranged.blockDeploy).toBe(false);
    expect(ranged.verdict).toBe("allow");
    expect(ranged.findings.every((finding) => finding.id === "DEP_RANGE")).toBe(true);

    const locked = mkdtempSync(join(tmpdir(), "vigil-gate-lock-"));
    writeFileSync(join(locked, "package.json"), JSON.stringify({
      name: "locked",
      version: "1.0.0",
      bin: "bin/hello.js",
      dependencies: { axios: "^1.0.0" },
    }));
    writeFileSync(join(locked, "package-lock.json"), JSON.stringify({
      packages: { "node_modules/axios": { version: "1.14.1" } },
    }));
    mkdirSync(join(locked, "bin"));
    writeFileSync(join(locked, "bin/hello.js"), "console.log('hello');\n");
    const lockReport = await runGate(locked);
    expect(lockReport.blockDeploy).toBe(true);
    expect(lockReport.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED")).toBe(true);
    expect(lockReport.findings.some((finding) => finding.id === "DEP_RANGE")).toBe(false);
  });

  it("reads a local tarball and a registry tarball without running the package", async () => {
    const hello = packNpm({
      "package.json": JSON.stringify({ name: "hello-bin", version: "1.0.0", bin: "bin/hello.js" }),
      "bin/hello.js": "console.log('hello');\n",
    });
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-tgz-"));
    const tgz = join(dir, "hello.tgz");
    writeFileSync(tgz, hello);
    const local = await runGate(tgz);
    expect(local.blockDeploy).toBe(false);
    expect(local.verdict).toBe("allow");

    const integrity = `sha512-${createHash("sha512").update(hello).digest("base64")}`;
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/hello-bin/1.0.0")) {
        return new Response(JSON.stringify({
          dist: { integrity, tarball: "https://registry.npmjs.org/hello-bin/-/hello-bin-1.0.0.tgz" },
        }), { status: 200 });
      }
      return new Response(hello, { status: 200 });
    };
    const output = io();
    const code = await main(["gate", "npm:hello-bin@1.0.0", "--json"], output, {
      fetchImpl,
      lookup: async () => ["203.0.113.20"],
    });
    expect(code).toBe(0);
    const report = JSON.parse(output.text()) as { verdict: string };
    expect(report.verdict).toBe("allow");

    const mismatch: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/hello-bin/1.0.0")) {
        return new Response(JSON.stringify({
          dist: {
            integrity: `sha512-${createHash("sha512").update("nope").digest("base64")}`,
            tarball: "https://registry.npmjs.org/hello-bin/-/hello-bin-1.0.0.tgz",
          },
        }), { status: 200 });
      }
      return new Response(hello, { status: 200 });
    };
    const failed = io();
    expect(await main(["gate", "npm:hello-bin@1.0.0"], failed, {
      fetchImpl: mismatch,
      lookup: async () => ["203.0.113.20"],
    })).toBe(1);
    expect(failed.error()).toMatch(/integrity/);
  });

  it("blocks an oversized package.json instead of skipping the bin graph", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-big-json-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({
      name: "big",
      version: "1.0.0",
      bin: "bin/hello.js",
      description: "x".repeat(400),
    }));
    mkdirSync(join(dir, "bin"));
    writeFileSync(join(dir, "bin/hello.js"), "console.log('hello');\n");
    const report = await runGate(dir, { limits: { ...GATE_LIMITS, perFileBytes: 80 } });
    expect(report.blockDeploy).toBe(true);
    expect(report.verdict).not.toBe("allow");
    expect(report.findings.some((finding) => finding.id === "INSTALL_FILE_BUDGET")).toBe(true);
  });

  it("blocks absolute and file URL requires that npm would load", async () => {
    for (const source of [
      "require('/tmp/payload.js');\n",
      "import('file:///tmp/payload.js');\n",
      "require('file:///tmp/payload.js');\n",
    ]) {
      const dir = mkdtempSync(join(tmpdir(), "vigil-gate-abs-"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "abs", version: "1.0.0", bin: "index.js" }));
      writeFileSync(join(dir, "index.js"), source);
      const report = await runGate(dir);
      expect(report.blockDeploy).toBe(true);
      expect(report.verdict).not.toBe("allow");
      expect(report.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);
    }

    const named = mkdtempSync(join(tmpdir(), "vigil-gate-named-"));
    writeFileSync(join(named, "package.json"), JSON.stringify({ name: "named", version: "1.0.0", bin: "index.js" }));
    writeFileSync(join(named, "index.js"), "require('fs');\n");
    const allowed = await runGate(named);
    expect(allowed.blockDeploy).toBe(false);
    expect(allowed.verdict).toBe("allow");
  });

  it("opens a directory bin and prefers package.json main over index.js", async () => {
    const binDir = mkdtempSync(join(tmpdir(), "vigil-gate-dir-bin-"));
    writeFileSync(join(binDir, "package.json"), JSON.stringify({ name: "dirbin", version: "1.0.0", bin: "cli" }));
    mkdirSync(join(binDir, "cli"));
    writeFileSync(join(binDir, "cli/index.js"), "const { execSync } = require('child_process');\nexecSync('true');\n");
    const opened = await runGate(binDir);
    expect(opened.blockDeploy).toBe(true);
    expect(opened.findings.some((finding) => finding.id === "INSTALL_CHILD_PROCESS" && finding.file === "cli/index.js")).toBe(true);

    const mainDir = mkdtempSync(join(tmpdir(), "vigil-gate-dir-main-"));
    writeFileSync(join(mainDir, "package.json"), JSON.stringify({ name: "dirmain", version: "1.0.0", main: "dist" }));
    mkdirSync(join(mainDir, "dist"));
    writeFileSync(join(mainDir, "dist/index.js"), "console.log('hello');\n");
    writeFileSync(join(mainDir, "dist/package.json"), JSON.stringify({ main: "payload.js" }));
    writeFileSync(join(mainDir, "dist/payload.js"), "const { execSync } = require('child_process');\nexecSync('true');\n");
    const mainReport = await runGate(mainDir);
    expect(mainReport.blockDeploy).toBe(true);
    expect(mainReport.findings.some((finding) => finding.id === "INSTALL_CHILD_PROCESS" && finding.file === "dist/payload.js")).toBe(true);

    const missingMain = mkdtempSync(join(tmpdir(), "vigil-gate-dir-miss-"));
    writeFileSync(join(missingMain, "package.json"), JSON.stringify({ name: "missmain", version: "1.0.0", main: "dist" }));
    mkdirSync(join(missingMain, "dist"));
    writeFileSync(join(missingMain, "dist/index.js"), "console.log('hello');\n");
    writeFileSync(join(missingMain, "dist/package.json"), JSON.stringify({ main: "missing.js" }));
    const missed = await runGate(missingMain);
    expect(missed.blockDeploy).toBe(true);
    expect(missed.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);
    expect(missed.findings.some((finding) => finding.id === "INSTALL_CHILD_PROCESS")).toBe(false);
  });

  it("blocks a directory symlink that points outside the package", async () => {
    const outside = mkdtempSync(join(tmpdir(), "vigil-gate-outside-"));
    writeFileSync(join(outside, "index.js"), "console.log('hello');\n");
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-symlink-"));
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "linked", version: "1.0.0", bin: "cli" }));
    symlinkSync(outside, join(dir, "cli"), "dir");
    const escaped = await runGate(dir);
    expect(escaped.blockDeploy).toBe(true);
    expect(escaped.verdict).not.toBe("allow");
    expect(escaped.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);

    const inside = mkdtempSync(join(tmpdir(), "vigil-gate-symlink-in-"));
    mkdirSync(join(inside, "bin"));
    writeFileSync(join(inside, "bin/index.js"), "console.log('hello');\n");
    writeFileSync(join(inside, "package.json"), JSON.stringify({ name: "inner", version: "1.0.0", bin: "cli" }));
    symlinkSync(join(inside, "bin"), join(inside, "cli"), "dir");
    const stayed = await runGate(inside);
    expect(stayed.blockDeploy).toBe(false);
    expect(stayed.verdict).toBe("allow");
  });

  it("honors a pax path when the ustar name looks safe", async () => {
    const dir = mkdtempSync(join(tmpdir(), "vigil-gate-pax-"));
    const escaped = packEntries([
      { name: "package.json", content: JSON.stringify({ name: "pax", version: "1.0.0", bin: "bin/hello.js" }) },
      { name: "bin/hello.js", content: "console.log('hello');\n", paxPath: "../../tmp/payload.js" },
    ]);
    const escapedPath = join(dir, "escape.tgz");
    writeFileSync(escapedPath, escaped);
    const escapeReport = await runGate(escapedPath);
    expect(escapeReport.blockDeploy).toBe(true);
    expect(escapeReport.verdict).not.toBe("allow");
    expect(escapeReport.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);

    const absolute = packEntries([
      { name: "package.json", content: JSON.stringify({ name: "pax", version: "1.0.0", bin: "bin/hello.js" }) },
      { name: "bin/hello.js", content: "console.log('hello');\n", paxPath: "/tmp/payload.js" },
    ]);
    const absolutePath = join(dir, "absolute.tgz");
    writeFileSync(absolutePath, absolute);
    const absoluteReport = await runGate(absolutePath);
    expect(absoluteReport.blockDeploy).toBe(true);
    expect(absoluteReport.findings.some((finding) => finding.id === "INSTALL_UNREAD")).toBe(true);

    const renamed = packEntries([
      { name: "package.json", content: JSON.stringify({ name: "pax", version: "1.0.0", bin: "bin/hello.js" }) },
      { name: "ignored.js", content: "console.log('hello');\n", paxPath: "package/bin/hello.js" },
    ]);
    const renamedPath = join(dir, "renamed.tgz");
    writeFileSync(renamedPath, renamed);
    const renamedReport = await runGate(renamedPath);
    expect(renamedReport.blockDeploy).toBe(false);
    expect(renamedReport.verdict).toBe("allow");
  });

  it("blocks disguised require calls without following a literal path", async () => {
    for (const source of [
      "(require)('./payload.js');\n",
      "require?.('./payload.js');\n",
      "const load = require;\nload('./payload.js');\n",
    ]) {
      const dir = mkdtempSync(join(tmpdir(), "vigil-gate-disguise-"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "disguise", version: "1.0.0", bin: "index.js" }));
      writeFileSync(join(dir, "index.js"), source);
      writeFileSync(join(dir, "payload.js"), "console.log('hello');\n");
      const report = await runGate(dir);
      expect(report.blockDeploy).toBe(true);
      expect(report.verdict).not.toBe("allow");
      expect(report.findings.some((finding) => finding.id === "INSTALL_DYNAMIC_CODE")).toBe(true);
    }
  });

  it("keeps the version on an npm: alias pin", async () => {
    for (const spec of ["npm:axios@1.14.1", "npm:axios@0.30.4"]) {
      const dir = mkdtempSync(join(tmpdir(), "vigil-gate-alias-"));
      writeFileSync(join(dir, "package.json"), JSON.stringify({
        name: "alias",
        version: "1.0.0",
        bin: "bin/hello.js",
        dependencies: { request: spec },
      }));
      mkdirSync(join(dir, "bin"));
      writeFileSync(join(dir, "bin/hello.js"), "console.log('hello');\n");
      const report = await runGate(dir);
      expect(report.blockDeploy).toBe(true);
      expect(report.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED")).toBe(true);
      expect(report.findings.some((finding) => finding.id === "DEP_RANGE")).toBe(false);
    }
  });

  it("applies exact pins from a lockfileVersion 1 tree and a pnpm peer suffix", async () => {
    const v1 = mkdtempSync(join(tmpdir(), "vigil-gate-lock1-"));
    writeFileSync(join(v1, "package.json"), JSON.stringify({
      name: "lock1",
      version: "1.0.0",
      bin: "bin/hello.js",
      dependencies: { axios: "^1.0.0" },
    }));
    mkdirSync(join(v1, "bin"));
    writeFileSync(join(v1, "bin/hello.js"), "console.log('hello');\n");
    writeFileSync(join(v1, "package-lock.json"), JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        wrapper: {
          version: "1.0.0",
          dependencies: { axios: { version: "1.14.1" } },
        },
      },
    }));
    const v1Report = await runGate(v1);
    expect(v1Report.blockDeploy).toBe(true);
    expect(v1Report.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED")).toBe(true);
    expect(v1Report.findings.some((finding) => finding.id === "DEP_RANGE")).toBe(false);

    const pnpm = mkdtempSync(join(tmpdir(), "vigil-gate-pnpm-peer-"));
    writeFileSync(join(pnpm, "package.json"), JSON.stringify({
      name: "peer",
      version: "1.0.0",
      bin: "bin/hello.js",
      dependencies: { axios: "^1.0.0" },
    }));
    mkdirSync(join(pnpm, "bin"));
    writeFileSync(join(pnpm, "bin/hello.js"), "console.log('hello');\n");
    writeFileSync(join(pnpm, "pnpm-lock.yaml"), [
      "lockfileVersion: '9.0'",
      "",
      "packages:",
      "",
      "  axios@1.14.1(react@18.2.0):",
      "    resolution: {integrity: sha}",
      "",
    ].join("\n"));
    const pnpmReport = await runGate(pnpm);
    expect(pnpmReport.blockDeploy).toBe(true);
    expect(pnpmReport.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED" && finding.evidence === "axios@1.14.1")).toBe(true);
    expect(pnpmReport.findings.some((finding) => finding.id === "DEP_RANGE")).toBe(false);
  });
});
