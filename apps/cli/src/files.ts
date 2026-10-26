import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, extname, join, relative } from "node:path";
import { unzipSync } from "fflate";
import { sanitizeRelativePath } from "@vigil/core";
import { isDockerfile } from "@vigil/netcheck";

const TEXT_EXT = new Set([
  ".html", ".htm", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".php",
  ".css", ".json", ".txt", ".md", ".yml", ".yaml", ".toml", ".lock", ".sum", ".xml", ".svg",
]);
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "coverage", ".next", "build"]);

export interface TextFile {
  name: string;
  content: string;
}

export function collectFiles(path: string): TextFile[] {
  const stat = statSync(path);
  if (stat.isFile() && path.toLowerCase().endsWith(".zip")) return unzipFile(path);
  if (stat.isFile()) return [readText(path, basename(path))];
  const files: TextFile[] = [];
  walk(path, path, files);
  return files;
}

export function collectLockfiles(path: string): TextFile[] {
  return collectFiles(path).filter((file) => isLockfile(file.name));
}

export function isLockfile(name: string): boolean {
  const base = basename(name);
  return (
    base === "package-lock.json" ||
    base === "npm-shrinkwrap.json" ||
    base === "pnpm-lock.yaml" ||
    base === "yarn.lock" ||
    base === "poetry.lock" ||
    base === "go.sum" ||
    base === "composer.lock" ||
    /^requirements.*\.txt$/i.test(base) ||
    isDockerfile(base)
  );
}

function walk(root: string, dir: string, files: TextFile[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name.startsWith(".")) continue;
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIR.has(entry.name)) continue;
      walk(root, full, files);
      continue;
    }
    if (!entry.isFile()) continue;
    const extension = extname(entry.name).toLowerCase();
    if (!TEXT_EXT.has(extension) && !isLockfile(entry.name)) continue;
    files.push(readText(full, relative(root, full)));
  }
}

function readText(path: string, name: string): TextFile {
  const buffer = readFileSync(path);
  if (buffer.subarray(0, 1024).includes(0)) return { name, content: "" };
  return { name: name.replaceAll("\\", "/"), content: buffer.toString("utf8") };
}

const ZIP_UNCOMPRESSED_CAP = 8 * 1024 * 1024;

function unzipFile(path: string): TextFile[] {
  const entries = unzipSync(new Uint8Array(readFileSync(path)));
  const files: TextFile[] = [];
  let total = 0;
  for (const [name, bytes] of Object.entries(entries)) {
    if (total + bytes.byteLength > ZIP_UNCOMPRESSED_CAP) break;
    total += bytes.byteLength;
    if (name.endsWith("/")) continue;
    if (bytes.subarray(0, 1024).includes(0)) continue;
    let safe: string;
    try {
      safe = sanitizeRelativePath(name);
    } catch {
      continue;
    }
    files.push({ name: safe, content: new TextDecoder().decode(bytes) });
  }
  return files;
}
