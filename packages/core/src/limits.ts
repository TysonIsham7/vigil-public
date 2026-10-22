import { DEFAULT_LIMITS, type ScanLimits, type SourceFile } from "./types.js";
import { utf8Encode } from "./utf8.js";

export class LimitError extends Error {
  readonly code = "limit" as const;

  constructor(message: string) {
    super(message);
    this.name = "LimitError";
  }
}

/** Strip parent segments and absolute prefixes. Zip entries use this before they are scanned. */
export function sanitizeRelativePath(name: string): string {
  const normalized = name.replaceAll("\\", "/").replaceAll("\0", "");
  const parts = normalized.split("/").filter((part) => part && part !== "." && part !== "..");
  const safe = parts.join("/");
  if (!safe || safe === ".." || safe.startsWith("/")) {
    throw new LimitError("File path is empty after traversal stripping");
  }
  return safe;
}

export function prepareFiles(files: SourceFile[], limits: ScanLimits = DEFAULT_LIMITS): SourceFile[] {
  if (files.length === 0) throw new LimitError("No files to scan");
  if (files.length > limits.fileCount) {
    throw new LimitError(`File count exceeds the limit of ${limits.fileCount}`);
  }
  const prepared: SourceFile[] = [];
  let total = 0;
  const seen = new Map<string, number>();
  for (const file of files) {
    const safeName = sanitizeRelativePath(file.name);
    const count = seen.get(safeName) ?? 0;
    seen.set(safeName, count + 1);
    const name = count === 0 ? safeName : `${safeName}#${count + 1}`;
    const bytes = byteLength(file.content);
    if (bytes > limits.perFileBytes) {
      throw new LimitError(`A file exceeds the per-file limit of ${limits.perFileBytes} bytes`);
    }
    total += bytes;
    if (total > limits.totalBytes) {
      throw new LimitError(`Upload exceeds the total limit of ${limits.totalBytes} bytes`);
    }
    prepared.push({ name, content: file.content });
  }
  return prepared;
}

function byteLength(content: string): number {
  return utf8Encode(content).byteLength;
}
