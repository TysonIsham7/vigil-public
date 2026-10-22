import { execFile } from "node:child_process";
import { createHash, X509Certificate } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import tls from "node:tls";
import { promisify } from "node:util";
import { matchDistrust } from "@vigil/intel";

const execFileAsync = promisify(execFile);

export interface TrustBundle {
  label: string;
  pem: string;
}

export interface TrustHit {
  label: string;
  name: string;
  spkiSha256: string;
}

const CA_FILES: { label: string; path: string }[] = [
  { label: "ca-certificates", path: "/etc/ssl/certs/ca-certificates.crt" },
  { label: "ssl-cert", path: "/etc/ssl/cert.pem" },
  { label: "ca-bundle", path: "/etc/pki/tls/certs/ca-bundle.crt" },
  { label: "ca-bundle", path: "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" },
];

/** SPKIs in a PEM bundle that Vigil already blocks. Record-only roots are ignored. */
export function distrustedInBundle(label: string, pem: string): TrustHit[] {
  const hits: TrustHit[] = [];
  const seen = new Set<string>();
  for (const part of pem.split(/-----END CERTIFICATE-----/)) {
    const begin = part.indexOf("-----BEGIN CERTIFICATE-----");
    if (begin < 0) continue;
    try {
      const cert = new X509Certificate(`${part.slice(begin).trim()}\n-----END CERTIFICATE-----\n`);
      const spki = createHash("sha256").update(cert.publicKey.export({ type: "spki", format: "der" })).digest("hex");
      const hit = matchDistrust({ spkiSha256: spki });
      if (!hit || seen.has(hit.spkiSha256)) continue;
      seen.add(hit.spkiSha256);
      hits.push({ label, name: hit.name, spkiSha256: hit.spkiSha256 });
    } catch {
      continue;
    }
  }
  return hits;
}

/**
 * Read the system CA bundle, Python certifi, and Node's compiled-in roots.
 * Go on Linux uses the system bundle, and its eMudhra filter is the Go version check.
 * Paths are not returned. A missing store is skipped.
 */
export async function collectTrustBundles(): Promise<TrustBundle[]> {
  const bundles: TrustBundle[] = [];
  const seenLabels = new Set<string>();
  for (const item of CA_FILES) {
    if (seenLabels.has(item.label) || !existsSync(item.path)) continue;
    try {
      const pem = readFileSync(item.path, "utf8");
      if (!pem.includes("BEGIN CERTIFICATE")) continue;
      seenLabels.add(item.label);
      bundles.push({ label: item.label, pem });
    } catch {
      continue;
    }
  }
  const certifi = await certifiBundle();
  if (certifi) bundles.push(certifi);
  const nodePem = tls.rootCertificates.join("\n");
  if (nodePem.includes("BEGIN CERTIFICATE")) bundles.push({ label: "node", pem: nodePem });
  return bundles;
}

async function certifiBundle(): Promise<TrustBundle | undefined> {
  try {
    const { stdout } = await execFileAsync("python3", ["-c", "import certifi; print(certifi.where())"], {
      timeout: 4000,
      maxBuffer: 4096,
    });
    const path = stdout.trim();
    if (!path.startsWith("/") || path.includes("\n") || path.includes("\0") || !existsSync(path)) return undefined;
    const pem = readFileSync(path, "utf8");
    if (!pem.includes("BEGIN CERTIFICATE")) return undefined;
    return { label: "certifi", pem };
  } catch {
    return undefined;
  }
}
