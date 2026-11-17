/**
 * Fail when a workflow, script, package script, or doc would install
 * fixtures/deps/requirements.txt. The file is a detection sample.
 * This script only reads text. It does not install anything.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(fileURLToPath(new URL(".", import.meta.url)), "..");
const skipDir = new Set(["node_modules", "dist", ".git", "coverage"]);

const pythonInstall = /(?:^|[;&|]\s*|^\s*RUN\s+)(?:sudo\s+)?(?:python(?:3)?\s+-m\s+pip|py\s+-m\s+pip|pip3?|uv\s+pip|conda)\s+install\b|(?:^|[;&|]\s*|^\s*RUN\s+)(?:sudo\s+)?(?:poetry\s+install|uv\s+sync|pip-sync)\b|(?:^|[;&|]\s*|^\s*RUN\s+)(?:sudo\s+)?(?:uv|poetry)\s+add\b/;
const fixtureReq = /(?:^|[\s"'=])(?:\.\.?[/\\])*fixtures[/\\](?:[\w.-]+[/\\])*requirements\.txt\b/;
const fixtureDirMove = /\b(?:cd|pushd)\s+["']?(?:\.\.?[/\\])*fixtures\b|\b(?:working-directory:|WORKDIR)\s+["']?(?:\.\.?[/\\])*fixtures\b/;
const fixturePin = /\b(?:litellm\s*==\s*1\.107\.0|requests\s*==\s*2\.32\.3)\b/;
const relativeReq = /(?:^|[;&|]\s*|^\s*RUN\s+)(?:sudo\s+)?(?:poetry\s+install|uv\s+sync|pip-sync)\b|(?:-r|--requirement(?:=|\s+))\s*["']?(?:\.\.?[/\\])*requirements\.txt\b/;

function normalize(text) {
  return text.replace(/\\\r?\n/g, " ");
}

function isPythonInstall(line) {
  const text = line.trim().replace(/^(?:-\s*)?run:\s*/, "");
  return pythonInstall.test(text);
}

/**
 * @param {string} text
 * @returns {string[]}
 */
export function fixtureRequirementInstalls(text) {
  const lines = normalize(text).split("\n");
  const hits = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i] ?? "";
    if (isPythonInstall(line) && (fixtureReq.test(line) || fixturePin.test(line))) {
      hits.push(`${i + 1}:${line.trim()}`);
      continue;
    }
    if (!fixtureDirMove.test(line)) continue;
    const later = lines.slice(i, i + 30).find((candidate) => isPythonInstall(candidate));
    if (later) hits.push(`${i + 1}:${line.trim()} / ${later.trim()}`);
  }
  return hits;
}

/**
 * @param {string} rel
 * @param {string} text
 * @returns {string[]}
 */
export function fixtureInstallsInFile(rel, text) {
  const hits = fixtureRequirementInstalls(text).map((hit) => `${rel}:${hit}`);
  if (!rel.startsWith("fixtures/")) return hits;
  const lines = normalize(text).split("\n");
  lines.forEach((line, index) => {
    if (!isPythonInstall(line) || !relativeReq.test(line.trim())) return;
    hits.push(`${rel}:${index + 1}:${line.trim()}`);
  });
  return hits;
}

/**
 * @param {string} [scanRoot]
 * @returns {string[]}
 */
export function scanFixtureInstalls(scanRoot = root) {
  /** @type {string[]} */
  const hits = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (skipDir.has(entry.name)) continue;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
        continue;
      }
      if (!entry.isFile()) continue;
      const stat = statSync(full);
      if (stat.size > 2_000_000) continue;
      const buf = readFileSync(full);
      if (buf.subarray(0, Math.min(buf.length, 1024)).includes(0)) continue;
      const rel = relative(scanRoot, full).replaceAll("\\", "/");
      hits.push(...fixtureInstallsInFile(rel, buf.toString("utf8")));
    }
  };
  walk(scanRoot);
  return hits;
}

const entry = process.argv[1] ? resolve(process.argv[1]) : "";
if (entry && fileURLToPath(import.meta.url) === entry) {
  const hits = scanFixtureInstalls(root);
  if (hits.length > 0) {
    console.error("fixture requirements must not be installed:");
    console.error(hits.join("\n"));
    process.exit(1);
  }
}
