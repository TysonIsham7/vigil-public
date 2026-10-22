import { spawnSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const allow = [
  /(^|\/)fixtures\//,
  /(^|\/)packages\/[^/]+\/test\//,
  /(^|\/)apps\/[^/]+\/test\//,
  /(^|\/)packages\/netcheck\/certs\//,
  /(^|\/)packages\/intel\/data\/distrusted-cas\.json$/,
  /(^|\/)node_modules\//,
  /(^|\/)dist\//,
  /(^|\/)\.git\//,
];
const patterns = [
  { name: "aws-access-key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "private-key", re: /^\s*-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----\s*$/ },
  { name: "stripe-live", re: /sk_live_[A-Za-z0-9]{8,}/ },
  { name: "github-pat", re: /ghp_[A-Za-z0-9]{20,}/ },
  { name: "vigil-live-key", re: /vg_live_[A-Za-z0-9_-]{8,}/ },
];
const skipDir = new Set(["node_modules", "dist", ".git", "coverage"]);
const hits = [];

function walk(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (skipDir.has(entry.name)) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile()) continue;
    const rel = relative(root, full).replaceAll("\\", "/");
    if (allow.some((pattern) => pattern.test(rel))) continue;
    const stat = statSync(full);
    if (stat.size > 2_000_000) continue;
    const text = readFileSync(full);
    if (text.subarray(0, 1024).includes(0)) continue;
    const lines = text.toString("utf8").split("\n");
    lines.forEach((line, index) => {
      for (const pattern of patterns) {
        if (pattern.re.test(line)) hits.push(`${rel}:${index + 1} ${pattern.name}`);
      }
    });
  }
}

walk(root);
if (hits.length > 0) {
  console.error(hits.join("\n"));
  process.exit(1);
}

const gitleaks = spawnSync("gitleaks", ["detect", "--source", root, "--config", join(root, ".gitleaks.toml"), "--redact", "--no-git"], {
  encoding: "utf8",
});
if (gitleaks.error && gitleaks.error.code === "ENOENT") {
  process.exit(0);
}
if (gitleaks.status !== 0 && gitleaks.status !== null) {
  process.stderr.write(gitleaks.stdout || "");
  process.stderr.write(gitleaks.stderr || "");
  process.exit(gitleaks.status ?? 1);
}
