import type { Readable, Writable } from "node:stream";
import { VerdictTimeout, hostVerdict, verdictHost, type HostVerdict } from "./verdict.js";

/** Chrome's hard cap is 1 MiB. A hostname request is much smaller, and a larger frame is rejected. */
export const NATIVE_HOST_MAX_INCOMING_BYTES = 2048;
/** A finished verdict is a handful of signals. Anything larger is replaced with a rejection. */
export const NATIVE_HOST_MAX_OUTGOING_BYTES = 64 * 1024;
const MAX_MESSAGES = 32;

/**
 * One native-messaging request: `{ "host": "<bare hostname>" }`.
 * Schemes, paths, userinfo, extra fields, and hosts `vigil serve` would reject are refused before any network call.
 */
export function nativeRequestHost(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== 1 || keys[0] !== "host" || typeof record.host !== "string") return null;
  if (record.host.length === 0 || record.host.length > 253) return null;
  return verdictHost(record.host);
}

/**
 * Chrome native messaging on stdio. Reads length-prefixed JSON and writes the same verdict shape as `vigil serve`.
 * The process does not log the request, the host, or the reply.
 */
export async function runNativeHost(options: {
  input: Readable;
  output: Writable;
  verdict?: (host: string) => Promise<HostVerdict>;
}): Promise<void> {
  const reader = new ByteQueue(options.input);
  const verdict = options.verdict ?? ((host: string) => hostVerdict(host));
  for (let count = 0; count < MAX_MESSAGES; count += 1) {
    const frame = await readFrame(reader);
    if (frame === null) return;
    if (frame === "rejected") {
      writeFrame(options.output, { error: "rejected" });
      return;
    }
    const host = nativeRequestHost(frame);
    if (!host) {
      writeFrame(options.output, { error: "rejected" });
      continue;
    }
    try {
      writeFrame(options.output, await verdict(host));
    } catch (error) {
      writeFrame(options.output, { error: error instanceof VerdictTimeout ? "timeout" : "rejected" });
    }
  }
}

async function readFrame(reader: ByteQueue): Promise<unknown | "rejected" | null> {
  if (reader.overflow) return "rejected";
  const header = await reader.take(4);
  if (header === null) return null;
  if (reader.overflow || header.length !== 4) return "rejected";
  const length = header.readUInt32LE(0);
  if (length === 0 || length > NATIVE_HOST_MAX_INCOMING_BYTES) return "rejected";
  const body = await reader.take(length);
  if (body === null || body.length !== length || reader.overflow) return "rejected";
  try {
    return JSON.parse(body.toString("utf8")) as unknown;
  } catch {
    return "rejected";
  }
}

function writeFrame(output: Writable, value: unknown): void {
  let body = Buffer.from(JSON.stringify(value));
  if (body.length === 0 || body.length > NATIVE_HOST_MAX_OUTGOING_BYTES) {
    body = Buffer.from(JSON.stringify({ error: "rejected" }));
  }
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  output.write(Buffer.concat([header, body]));
}

class ByteQueue {
  overflow = false;
  private chunks: Buffer[] = [];
  private size = 0;
  private ended = false;
  private waiter: (() => void) | null = null;

  constructor(input: Readable) {
    input.on("data", (chunk: Buffer | string) => {
      if (this.overflow) return;
      const next = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
      if (this.size + next.length > NATIVE_HOST_MAX_INCOMING_BYTES + 4) {
        this.overflow = true;
        this.ended = true;
        this.pulse();
        return;
      }
      this.chunks.push(next);
      this.size += next.length;
      this.pulse();
    });
    input.on("end", () => {
      this.ended = true;
      this.pulse();
    });
    input.on("error", () => {
      this.ended = true;
      this.pulse();
    });
    input.resume();
  }

  async take(count: number): Promise<Buffer | null> {
    while (this.size < count && !this.ended) {
      await new Promise<void>((resolve) => {
        this.waiter = resolve;
      });
    }
    if (this.size === 0) return null;
    if (this.size < count) return this.consume(this.size);
    return this.consume(count);
  }

  private pulse(): void {
    const waiter = this.waiter;
    this.waiter = null;
    waiter?.();
  }

  private consume(count: number): Buffer {
    const out = Buffer.alloc(count);
    let filled = 0;
    while (filled < count && this.chunks.length > 0) {
      const head = this.chunks[0];
      if (!head) break;
      const need = count - filled;
      if (head.length <= need) {
        head.copy(out, filled);
        filled += head.length;
        this.chunks.shift();
      } else {
        head.copy(out, filled, 0, need);
        this.chunks[0] = head.subarray(need);
        filled += need;
      }
    }
    this.size -= filled;
    return out;
  }
}
