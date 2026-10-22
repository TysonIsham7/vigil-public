import { createHash, X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

/** Source tree, esbuild output, and a cwd-relative fallback. */
export function resolveMozillaBundle(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "mozilla-cacert.pem"),
    join(here, "../certs/mozilla-cacert.pem"),
    join(here, "../../netcheck/certs/mozilla-cacert.pem"),
    join(here, "../../../packages/netcheck/certs/mozilla-cacert.pem"),
  ];
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error("Pinned Mozilla CA bundle was not found");
}

export function readMozillaPem(path = resolveMozillaBundle()): string {
  return readFileSync(path, "utf8");
}

export function anchorSpkiHashes(pem: string): Set<string> {
  const hashes = new Set<string>();
  for (const part of pem.split(/-----END CERTIFICATE-----/)) {
    const begin = part.indexOf("-----BEGIN CERTIFICATE-----");
    if (begin < 0) continue;
    const cert = new X509Certificate(`${part.slice(begin).trim()}\n-----END CERTIFICATE-----\n`);
    const spki = cert.publicKey.export({ type: "spki", format: "der" });
    hashes.add(createHash("sha256").update(spki).digest("hex"));
  }
  return hashes;
}
