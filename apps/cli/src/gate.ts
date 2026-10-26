import { gunzipSync } from "node:zlib";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, relative, resolve } from "node:path";
import {
  GATE_LIMITS,
  LimitError,
  budgetFinding,
  buildReport,
  dynamicFindings,
  installBehaviorFindings,
  lifecyclePlan,
  moduleGraph,
  resolveRelative,
  sanitizeRelativePath,
  unreadFinding,
  type Finding,
  type Report,
  type ScanLimits,
} from "@vigil/core";
import { INTEL_VERSION } from "@vigil/intel";
import { fetchNpmTarball, gateDependencyReport, type AddressLookup } from "@vigil/netcheck";

export interface GateOptions {
  fetchImpl?: typeof fetch;
  lookup?: AddressLookup;
  now?: Date;
  cwd?: string;
  limits?: ScanLimits;
}

type ReadResult =
  | { kind: "ok"; content: string; bytes: number }
  | { kind: "missing" }
  | { kind: "binary" }
  | { kind: "oversize" }
  | { kind: "escape" };

interface PackageSource {
  budgetHit: boolean;
  rejected: string[];
  read(rel: string): ReadResult;
}

const LOCKS = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"];
const CODE_EXT = [".js", ".mjs", ".cjs", ".json", ".ts", ".tsx", ".jsx", ".sh"];

/**
 * Read what an npm install would run. Does not install the package, run lifecycle
 * scripts, or execute the bin.
 */
export async function runGate(target: string, options: GateOptions = {}): Promise<Report> {
  const limits = options.limits ?? GATE_LIMITS;
  const now = options.now ?? new Date();
  if (target.startsWith("npm:")) {
    const packed = await fetchNpmTarball(target, {
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
      ...(options.lookup ? { lookup: options.lookup } : {}),
      limits,
    });
    return review(tarballSource(packed.bytes, limits), limits, now);
  }
  const full = resolve(options.cwd ?? process.cwd(), target);
  let stat;
  try {
    stat = statSync(full);
  } catch {
    throw new LimitError("gate target was not found");
  }
  if (stat.isDirectory()) return review(directorySource(full, limits), limits, now);
  if (stat.isFile() && (full.endsWith(".tgz") || full.endsWith(".tar.gz"))) {
    return review(tarballSource(new Uint8Array(readFileSync(full)), limits), limits, now);
  }
  throw new LimitError("gate expects npm:name@version, a .tgz path, or a package directory");
}

function review(source: PackageSource, limits: ScanLimits, now: Date): Report {
  const findings: Finding[] = [];
  for (const name of source.rejected) findings.push(unreadFinding(name, "tarball entry was rejected"));
  let filesAnalyzed = 0;
  let bytesAnalyzed = 0;
  let budget = source.budgetHit;

  const finish = (deps: Report["checks"]["deps"] = []) => {
    if (budget) findings.push(budgetFinding(`file budget is ${limits.fileCount} files and ${limits.totalBytes} bytes`));
    return buildReport({
      findings,
      sourceType: "files",
      filesAnalyzed,
      bytesAnalyzed,
      checks: { deps },
      now,
      intelVersion: INTEL_VERSION,
    });
  };

  const take = (bytes: number): boolean => {
    if (budget || filesAnalyzed >= limits.fileCount || bytesAnalyzed + bytes > limits.totalBytes) {
      budget = true;
      return false;
    }
    filesAnalyzed += 1;
    bytesAnalyzed += bytes;
    return true;
  };

  const pkg = source.read("package.json");
  if (pkg.kind !== "ok") {
    if (budget || pkg.kind === "oversize") {
      budget = true;
      return finish();
    }
    throw new LimitError("package.json is missing");
  }
  if (!take(pkg.bytes)) return finish();
  let manifest: Record<string, unknown>;
  try {
    manifest = JSON.parse(pkg.content) as Record<string, unknown>;
  } catch {
    throw new LimitError("package.json is not json");
  }

  const scripts = manifest.scripts;
  const plan = lifecyclePlan(pkg.content, scripts && typeof scripts === "object" ? scripts as Record<string, unknown> : undefined);
  findings.push(...plan.findings);

  const locks: { name: string; content: string }[] = [];
  for (const name of LOCKS) {
    if (budget) break;
    const file = source.read(name);
    if (file.kind === "missing") continue;
    if (file.kind === "oversize") {
      budget = true;
      break;
    }
    if (file.kind !== "ok") {
      findings.push(unreadFinding(name, file.kind));
      continue;
    }
    if (!take(file.bytes)) break;
    locks.push({ name, content: file.content });
  }

  const dependencies = gateDependencyReport({ name: "package.json", content: pkg.content }, locks);
  findings.push(...dependencies.findings);

  const queue: string[] = [];
  const queued = new Set<string>();
  const outsideNoted = new Set<string>();
  const noteOutside = (spec: string) => {
    const key = spec.trim();
    if (!key || outsideNoted.has(key)) return;
    outsideNoted.add(key);
    findings.push(unreadFinding(key, "absolute or file URL is outside the package"));
  };
  const enqueue = (spec: string, fromFile: string | null) => {
    let rel = spec.replaceAll("\\", "/").trim();
    if (isOutsideSpecifier(rel)) {
      noteOutside(rel);
      return;
    }
    if (rel.startsWith(".")) {
      const base = fromFile ?? "package.json";
      const resolved = resolveRelative(base, rel);
      if (!resolved) {
        findings.push(unreadFinding(rel, "relative path leaves the package"));
        return;
      }
      rel = resolved;
    } else {
      rel = rel.replace(/^\.\//, "");
    }
    if (!rel || queued.has(rel)) return;
    queued.add(rel);
    queue.push(rel);
  };

  for (const entry of entryPoints(manifest)) enqueue(entry, null);
  for (const extra of plan.follow) enqueue(extra, null);

  const opened = new Set<string>();
  while (queue.length > 0 && !budget) {
    const next = queue.shift() ?? "";
    const located = openFile(source, next);
    if (opened.has(located.path)) continue;
    if (located.result.kind === "missing") {
      if (!budget) findings.push(unreadFinding(next, "file was not in the package"));
      continue;
    }
    if (located.result.kind === "escape") {
      findings.push(unreadFinding(next, "path leaves the package"));
      continue;
    }
    if (located.result.kind === "binary") {
      findings.push(unreadFinding(located.path, "file is not text"));
      continue;
    }
    if (located.result.kind === "oversize") {
      budget = true;
      break;
    }
    if (!take(located.result.bytes)) break;
    opened.add(located.path);
    const content = located.result.content;
    findings.push(...installBehaviorFindings(located.path, content));
    const graph = moduleGraph(content);
    findings.push(...dynamicFindings(located.path, graph));
    for (const spec of graph.specifiers) {
      if (isOutsideSpecifier(spec.specifier)) {
        noteOutside(spec.specifier);
        continue;
      }
      if (!spec.relative) continue;
      enqueue(spec.specifier, located.path);
    }
  }

  return finish(dependencies.deps);
}

function entryPoints(manifest: Record<string, unknown>): string[] {
  const out: string[] = [];
  const add = (value: unknown) => {
    if (typeof value !== "string") return;
    const cleaned = value.trim().replaceAll("\\", "/");
    if (!cleaned || cleaned.startsWith("node:")) return;
    if (/^[a-z][a-z0-9+.-]*:/i.test(cleaned) && !cleaned.toLowerCase().startsWith("file:")) return;
    out.push(cleaned);
  };
  if (typeof manifest.bin === "string") add(manifest.bin);
  else if (manifest.bin && typeof manifest.bin === "object") {
    for (const value of Object.values(manifest.bin as Record<string, unknown>)) add(value);
  }
  add(manifest.main);
  walkExports(manifest.exports, add, 0);
  return out;
}

function walkExports(value: unknown, add: (value: unknown) => void, depth: number): void {
  if (depth > 8 || value == null) return;
  if (typeof value === "string") {
    add(value);
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) walkExports(item, add, depth + 1);
    return;
  }
  if (typeof value === "object") {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (key === "types" || key === "typings") continue;
      walkExports(item, add, depth + 1);
    }
  }
}

const DIR_INDEX_EXT = [".js", ".mjs", ".cjs", ".json", ".ts", ".tsx", ".jsx"];

function isOutsideSpecifier(specifier: string): boolean {
  const spec = specifier.trim().replaceAll("\\", "/");
  if (spec.toLowerCase().startsWith("file:")) return true;
  if (spec.startsWith("/")) return true;
  return /^[A-Za-z]:\//.test(spec);
}

/**
 * Node's LOAD_AS_FILE, then LOAD_AS_DIRECTORY.
 * A directory package.json main is loaded and does not fall through to index.js when it is missing.
 */
function openFile(source: PackageSource, rel: string, depth = 0): { path: string; result: ReadResult } {
  if (depth > 8) return { path: rel, result: { kind: "missing" } };
  const file = loadAsFile(source, rel);
  if (file) return file;
  return loadAsDirectory(source, rel, depth);
}

function loadAsFile(source: PackageSource, rel: string): { path: string; result: ReadResult } | null {
  const hasExt = /\.[a-z0-9]+$/i.test(rel);
  const candidates = hasExt ? [rel] : [rel, ...CODE_EXT.map((ext) => `${rel}${ext}`)];
  for (const candidate of candidates) {
    const result = source.read(candidate);
    if (result.kind === "missing") continue;
    return { path: candidate, result };
  }
  return null;
}

function loadAsDirectory(source: PackageSource, rel: string, depth: number): { path: string; result: ReadResult } {
  const manifestPath = `${rel}/package.json`;
  const pkg = source.read(manifestPath);
  if (pkg.kind === "escape" || pkg.kind === "oversize" || pkg.kind === "binary") {
    return { path: manifestPath, result: pkg };
  }
  if (pkg.kind === "ok") {
    let manifest: Record<string, unknown>;
    try {
      manifest = JSON.parse(pkg.content) as Record<string, unknown>;
    } catch {
      return { path: manifestPath, result: { kind: "binary" } };
    }
    if (typeof manifest.main === "string" && manifest.main.trim()) {
      const main = manifest.main.trim().replaceAll("\\", "/");
      if (isOutsideSpecifier(main)) return { path: main, result: { kind: "escape" } };
      const relativeMain = main.startsWith(".") ? main : `./${main}`;
      const resolved = resolveRelative(manifestPath, relativeMain);
      if (!resolved) return { path: main, result: { kind: "escape" } };
      return openFile(source, resolved, depth + 1);
    }
  }
  return loadIndex(source, rel);
}

function loadIndex(source: PackageSource, rel: string): { path: string; result: ReadResult } {
  for (const ext of DIR_INDEX_EXT) {
    const candidate = `${rel}/index${ext}`;
    const result = source.read(candidate);
    if (result.kind !== "missing") return { path: candidate, result };
  }
  return { path: rel, result: { kind: "missing" } };
}

function directorySource(root: string, limits: ScanLimits): PackageSource {
  const rootReal = realpathSync(root);
  return {
    budgetHit: false,
    rejected: [],
    read(rel: string): ReadResult {
      let safe: string;
      try {
        safe = sanitizeRelativePath(rel);
      } catch {
        return { kind: "escape" };
      }
      const parts = safe.split("/").filter((part) => part.length > 0);
      let current = rootReal;
      for (const part of parts) {
        current = resolve(current, part);
        let linked;
        try {
          linked = lstatSync(current);
        } catch {
          return { kind: "missing" };
        }
        if (!linked.isSymbolicLink()) continue;
        let real: string;
        try {
          real = realpathSync(current);
        } catch {
          return { kind: "escape" };
        }
        const escaped = relative(rootReal, real);
        if (escaped.startsWith("..") || isAbsolute(escaped)) return { kind: "escape" };
        current = real;
      }
      let info;
      try {
        info = statSync(current);
      } catch {
        return { kind: "missing" };
      }
      if (!info.isFile()) return { kind: "missing" };
      if (info.size > limits.perFileBytes) return { kind: "oversize" };
      const buf = readFileSync(current);
      if (buf.subarray(0, 1024).includes(0)) return { kind: "binary" };
      return { kind: "ok", content: buf.toString("utf8"), bytes: buf.byteLength };
    },
  };
}

interface Archive {
  entries: Map<string, ReadResult>;
  budgetHit: boolean;
  rejected: string[];
}

function tarballSource(bytes: Uint8Array, limits: ScanLimits): PackageSource {
  const archive = unpackNpmTarball(bytes, limits);
  return {
    budgetHit: archive.budgetHit,
    rejected: archive.rejected,
    read(rel: string): ReadResult {
      let safe: string;
      try {
        safe = sanitizeRelativePath(rel);
      } catch {
        return { kind: "escape" };
      }
      return archive.entries.get(safe) ?? { kind: "missing" };
    },
  };
}

function unpackNpmTarball(bytes: Uint8Array, limits: ScanLimits): Archive {
  let raw: Buffer;
  try {
    raw = gunzipSync(bytes, { maxOutputLength: limits.totalBytes });
  } catch (error) {
    const code = error && typeof error === "object" && "code" in error ? String(error.code) : "";
    if (code === "ERR_BUFFER_TOO_LARGE" || code === "Z_BUF_ERROR") {
      return { entries: new Map(), budgetHit: true, rejected: [] };
    }
    throw new LimitError("tarball could not be read");
  }
  const entries = new Map<string, ReadResult>();
  const rejected: string[] = [];
  let offset = 0;
  let longName: string | null = null;
  let localPaxPath: string | null = null;
  let globalPaxPath: string | null = null;
  while (offset + 512 <= raw.length) {
    const header = raw.subarray(offset, offset + 512);
    offset += 512;
    if (header.every((byte) => byte === 0)) break;
    if (!checksumOk(header)) throw new LimitError("tarball could not be read");
    if ((header[124] ?? 0) & 0x80) throw new LimitError("tarball could not be read");
    const size = readOctal(header, 124, 12);
    if (offset + size > raw.length) throw new LimitError("tarball could not be read");
    const data = raw.subarray(offset, offset + size);
    offset += Math.ceil(size / 512) * 512;
    const type = header[156] ?? 0;
    if (type === 0x4c) {
      longName = textName(data);
      continue;
    }
    if (type === 0x78 || type === 0x67) {
      const records = parsePax(data);
      if (records.path) {
        if (type === 0x78) localPaxPath = records.path;
        else globalPaxPath = records.path;
      }
      continue;
    }
    const rawName = (localPaxPath ?? longName ?? globalPaxPath ?? headerName(header)).replaceAll("\\", "/");
    longName = null;
    localPaxPath = null;
    if (type === 0x35 || type === 0x4b) {
      if (!packagePath(rawName).ok) rejected.push(rawName || "(entry)");
      continue;
    }
    const placed = packagePath(rawName);
    if (!placed.ok) {
      rejected.push(rawName || "(entry)");
      continue;
    }
    if (!placed.name) continue;
    const regular = type === 0x30 || type === 0;
    if (!regular) {
      rejected.push(placed.name);
      continue;
    }
    if (data.byteLength > limits.perFileBytes) {
      entries.set(placed.name, { kind: "oversize" });
      continue;
    }
    if (data.subarray(0, 1024).includes(0)) {
      entries.set(placed.name, { kind: "binary" });
      continue;
    }
    entries.set(placed.name, { kind: "ok", content: new TextDecoder().decode(data), bytes: data.byteLength });
  }
  return { entries, budgetHit: false, rejected };
}

function packagePath(raw: string): { ok: true; name: string } | { ok: false } {
  const normalized = raw.replaceAll("\\", "/").replaceAll("\0", "");
  if (!normalized || isArchiveAbsolute(normalized) || hasDotDot(normalized)) return { ok: false };
  const stripped = normalized.replace(/^package\//, "").replace(/^\.\//, "");
  if (!stripped || stripped.endsWith("/")) return { ok: true, name: "" };
  if (isArchiveAbsolute(stripped) || hasDotDot(stripped)) return { ok: false };
  try {
    return { ok: true, name: sanitizeRelativePath(stripped) };
  } catch {
    return { ok: false };
  }
}

function hasDotDot(path: string): boolean {
  return path.split("/").some((part) => part === "..");
}

function isArchiveAbsolute(path: string): boolean {
  return path.startsWith("/") || /^[A-Za-z]:\//.test(path);
}

/** Pax records are `LENGTH key=value\\n`, and LENGTH counts the whole record. */
function parsePax(data: Uint8Array): Record<string, string> {
  const records: Record<string, string> = {};
  let offset = 0;
  while (offset < data.length) {
    let space = offset;
    while (space < data.length && data[space] !== 0x20) space++;
    if (space >= data.length) break;
    const lenText = new TextDecoder().decode(data.subarray(offset, space));
    if (!/^\d+$/.test(lenText)) break;
    const len = Number.parseInt(lenText, 10);
    if (len <= 0 || offset + len > data.length) break;
    const record = new TextDecoder().decode(data.subarray(offset, offset + len));
    const eq = record.indexOf("=");
    if (eq > lenText.length) {
      const key = record.slice(lenText.length + 1, eq);
      let value = record.slice(eq + 1);
      if (value.endsWith("\n")) value = value.slice(0, -1);
      if (key) records[key] = value;
    }
    offset += len;
  }
  return records;
}

function headerName(header: Uint8Array): string {
  const name = textName(header.subarray(0, 100));
  const magic = textName(header.subarray(257, 262));
  if (magic !== "ustar") return name;
  const prefix = textName(header.subarray(345, 500));
  return prefix ? `${prefix}/${name}` : name;
}

function textName(bytes: Uint8Array): string {
  let end = 0;
  while (end < bytes.length && bytes[end] !== 0) end++;
  return new TextDecoder().decode(bytes.subarray(0, end));
}

function readOctal(bytes: Uint8Array, start: number, length: number): number {
  let text = "";
  for (let i = start; i < start + length; i++) {
    const byte = bytes[i] ?? 0;
    if (byte === 0 || byte === 32) continue;
    text += String.fromCharCode(byte);
  }
  if (!text) return 0;
  if (!/^[0-7]+$/.test(text)) throw new LimitError("tarball could not be read");
  return Number.parseInt(text, 8);
}

function checksumOk(header: Uint8Array): boolean {
  const recorded = readOctal(header, 148, 8);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += i >= 148 && i < 156 ? 32 : (header[i] ?? 0);
  return sum === recorded;
}
