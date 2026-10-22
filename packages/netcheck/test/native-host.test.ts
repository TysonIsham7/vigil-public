import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { VerdictTimeout, type HostVerdict } from "../src/index.js";
import { NATIVE_HOST_MAX_INCOMING_BYTES, nativeRequestHost, runNativeHost } from "../src/native-host.js";

const verdict: HostVerdict = {
  host: "example.com",
  intelVersion: "2026.10.21.2",
  coverage: "full",
  signals: [{
    id: "CERT_DISTRUSTED_CA",
    severity: "critical",
    recommendationOnly: false,
    title: "Certificate chain contains a distrusted key",
    summary: "The chain includes EM DV TLS CA - G3B.",
    confidence: "high",
  }],
};

function frame(value: unknown): Buffer {
  const body = Buffer.from(JSON.stringify(value));
  const header = Buffer.alloc(4);
  header.writeUInt32LE(body.length, 0);
  return Buffer.concat([header, body]);
}

function decode(buffer: Buffer): unknown[] {
  const out: unknown[] = [];
  let offset = 0;
  while (offset + 4 <= buffer.length) {
    const length = buffer.readUInt32LE(offset);
    offset += 4;
    out.push(JSON.parse(buffer.subarray(offset, offset + length).toString("utf8")));
    offset += length;
  }
  expect(offset).toBe(buffer.length);
  return out;
}

async function exchange(inputBytes: Buffer, respond: (host: string) => Promise<HostVerdict> = async () => verdict): Promise<unknown[]> {
  const input = new PassThrough();
  const output = new PassThrough();
  const chunks: Buffer[] = [];
  output.on("data", (chunk: Buffer | string) => chunks.push(Buffer.from(chunk)));
  const pending = runNativeHost({ input, output, verdict: respond });
  input.end(inputBytes);
  await pending;
  return decode(Buffer.concat(chunks));
}

describe("chrome native host", () => {
  it("returns the serve verdict for one bare hostname and nothing else", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => undefined);
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const seen: string[] = [];
    const replies = await exchange(frame({ host: "Example.COM." }), async (host) => {
      seen.push(host);
      return verdict;
    });
    expect(seen).toEqual(["example.com"]);
    expect(replies).toEqual([verdict]);
    expect(log).not.toHaveBeenCalled();
    expect(error).not.toHaveBeenCalled();
    log.mockRestore();
    error.mockRestore();
  });

  it("rejects anything that is not one https hostname before calling the checker", async () => {
    let calls = 0;
    const respond = async (): Promise<HostVerdict> => {
      calls += 1;
      return verdict;
    };
    const replies = await exchange(Buffer.concat([
      frame({ host: "example.com", url: "https://example.com/" }),
      frame({ host: "https://example.com/" }),
      frame({ host: "127.0.0.1" }),
      frame(["example.com"]),
      frame({ host: "example.com" }),
    ]), respond);
    expect(calls).toBe(1);
    expect(replies.slice(0, 4).every((reply) => JSON.stringify(reply) === "{\"error\":\"rejected\"}")).toBe(true);
    expect(replies[4]).toEqual(verdict);
  });

  it("stops on an oversized frame and maps a verdict timeout", async () => {
    const huge = Buffer.alloc(4);
    huge.writeUInt32LE(NATIVE_HOST_MAX_INCOMING_BYTES + 1, 0);
    expect(await exchange(huge)).toEqual([{ error: "rejected" }]);
    const timedOut = await exchange(frame({ host: "example.com" }), async () => {
      throw new VerdictTimeout();
    });
    expect(timedOut).toEqual([{ error: "timeout" }]);
    const failed = await exchange(frame({ host: "example.com" }), async () => {
      throw new Error("certificate for example.com failed");
    });
    expect(failed).toEqual([{ error: "rejected" }]);
    expect(JSON.stringify(failed)).not.toContain("example.com");
  });

  it("accepts only the host field", () => {
    expect(nativeRequestHost({ host: "example.com" })).toBe("example.com");
    expect(nativeRequestHost({ host: "example.com", other: 1 })).toBeNull();
    expect(nativeRequestHost(null)).toBeNull();
  });
});
