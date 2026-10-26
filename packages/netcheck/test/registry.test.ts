import { createHash, randomBytes } from "node:crypto";
import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import { LimitError } from "@vigil/core";
import { fetchNpmTarball, npmIntegrityMatches, parseNpmSpec } from "../src/index.js";

const lookup = async () => ["203.0.113.20"];

describe("npm registry fetch", () => {
  it("parses an exact npm spec and checks a sha512 integrity", () => {
    expect(parseNpmSpec("npm:@scope/pkg@1.2.3")).toEqual({ name: "@scope/pkg", version: "1.2.3" });
    expect(() => parseNpmSpec("npm:pkg")).toThrow(LimitError);
    expect(() => parseNpmSpec("npm:pkg@latest")).toThrow(LimitError);
    const bytes = randomBytes(32);
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    expect(npmIntegrityMatches(bytes, integrity)).toBe(true);
    expect(npmIntegrityMatches(bytes, "sha512-aaaaaaaa")).toBe(false);
  });

  it("downloads a tarball only after the registry integrity hash is present and matching", async () => {
    const bytes = gzipSync(Buffer.from("not-unpacked-here"));
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    const calls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      calls.push(url);
      if (url.endsWith("/hello-bin/1.0.0")) {
        return new Response(JSON.stringify({
          dist: {
            integrity,
            tarball: "https://registry.npmjs.org/hello-bin/-/hello-bin-1.0.0.tgz",
          },
        }), { status: 200 });
      }
      return new Response(bytes, { status: 200 });
    };
    const packed = await fetchNpmTarball("npm:hello-bin@1.0.0", { fetchImpl, lookup });
    expect(packed.version).toBe("1.0.0");
    expect(Buffer.from(packed.bytes)).toEqual(bytes);
    expect(calls).toHaveLength(2);
  });

  it("does not download a tarball when the integrity hash is missing or the host is not the registry", async () => {
    const calls: string[] = [];
    const fetchImpl: typeof fetch = async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({
        dist: { tarball: "https://registry.npmjs.org/hello-bin/-/hello-bin-1.0.0.tgz" },
      }), { status: 200 });
    };
    await expect(fetchNpmTarball("npm:hello-bin@1.0.0", { fetchImpl, lookup })).rejects.toThrow(/integrity/);
    expect(calls).toHaveLength(1);

    calls.length = 0;
    const redirected: typeof fetch = async (input) => {
      calls.push(String(input));
      return new Response(JSON.stringify({
        dist: {
          integrity: "sha512-aaaaaaaa",
          tarball: "https://example.com/hello-bin-1.0.0.tgz",
        },
      }), { status: 200 });
    };
    await expect(fetchNpmTarball("npm:hello-bin@1.0.0", { fetchImpl: redirected, lookup })).rejects.toThrow(/host/);
    expect(calls).toHaveLength(1);
  });

  it("rejects a hash mismatch", async () => {
    const bytes = gzipSync(Buffer.from("bytes"));
    const fetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url.endsWith("/hello-bin/1.0.0")) {
        return new Response(JSON.stringify({
          dist: {
            integrity: `sha512-${createHash("sha512").update("other").digest("base64")}`,
            tarball: "https://registry.npmjs.org/hello-bin/-/hello-bin-1.0.0.tgz",
          },
        }), { status: 200 });
      }
      return new Response(bytes, { status: 200 });
    };
    await expect(fetchNpmTarball("npm:hello-bin@1.0.0", { fetchImpl, lookup })).rejects.toThrow(/did not match/);
  });
});
