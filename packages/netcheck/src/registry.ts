import { createHash, timingSafeEqual } from "node:crypto";
import { GATE_LIMITS, LimitError, type ScanLimits } from "@vigil/core";
import { safeFetch, type AddressLookup } from "./fetch.js";

const REGISTRY_HOST = "registry.npmjs.org";

export interface NpmPackage {
  name: string;
  version: string;
  bytes: Uint8Array;
}

export function parseNpmSpec(spec: string): { name: string; version: string } {
  if (!spec.startsWith("npm:")) throw new LimitError("gate npm spec must start with npm:");
  const rest = spec.slice("npm:".length);
  const at = rest.lastIndexOf("@");
  if (at <= 0) throw new LimitError("gate npm spec requires name@version");
  const name = rest.slice(0, at);
  const version = rest.slice(at + 1);
  if (!/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i.test(name)) {
    throw new LimitError("gate npm package name was rejected");
  }
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(version)) {
    throw new LimitError("gate npm spec requires an exact version");
  }
  return { name, version };
}

/** True when the tarball bytes match an npm integrity token (sha256 or sha512). */
export function npmIntegrityMatches(bytes: Uint8Array, integrity: string): boolean {
  const tokens = integrity.trim().split(/\s+/).filter(Boolean);
  for (const token of tokens) {
    const match = /^(sha512|sha256)-([A-Za-z0-9+/]+={0,2})$/.exec(token);
    const algo = match?.[1];
    const expected = match?.[2];
    if (!algo || !expected) continue;
    const digest = createHash(algo).update(bytes).digest("base64");
    if (digest.length !== expected.length) continue;
    if (timingSafeEqual(Buffer.from(digest), Buffer.from(expected))) return true;
  }
  return false;
}

function supportedIntegrity(integrity: string): boolean {
  return integrity.trim().split(/\s+/).some((token) => /^(sha512|sha256)-[A-Za-z0-9+/]+={0,2}$/.test(token));
}

/**
 * Download one exact npm version through the guarded fetch and check the registry integrity hash
 * before the bytes are returned. This does not install the package.
 */
export async function fetchNpmTarball(
  spec: string,
  options: {
    fetchImpl?: typeof fetch;
    lookup?: AddressLookup;
    limits?: ScanLimits;
  } = {},
): Promise<NpmPackage> {
  const { name, version } = parseNpmSpec(spec);
  const limits = options.limits ?? GATE_LIMITS;
  const metaUrl = `https://${REGISTRY_HOST}/${name.replace("/", "%2f")}/${encodeURIComponent(version)}`;
  const meta = await safeFetch(metaUrl, {
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.lookup ? { lookup: options.lookup } : {}),
    timeoutMs: limits.wallClockMs,
  });
  if (meta.status !== 200) throw new LimitError(`registry returned ${meta.status}`);
  if (meta.truncated) throw new LimitError("registry metadata was truncated");
  let body: { dist?: { tarball?: string; integrity?: string } };
  try {
    body = JSON.parse(meta.body) as { dist?: { tarball?: string; integrity?: string } };
  } catch {
    throw new LimitError("registry metadata was not json");
  }
  const tarball = body.dist?.tarball ?? "";
  const integrity = body.dist?.integrity ?? "";
  let tarballUrl: URL;
  try {
    tarballUrl = new URL(tarball);
  } catch {
    throw new LimitError("registry tarball URL was rejected");
  }
  if (tarballUrl.protocol !== "https:" || tarballUrl.hostname !== REGISTRY_HOST) {
    throw new LimitError("registry tarball host was rejected");
  }
  if (!supportedIntegrity(integrity)) throw new LimitError("registry integrity hash is missing");
  const packed = await safeFetch(tarballUrl.toString(), {
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.lookup ? { lookup: options.lookup } : {}),
    binary: true,
    maxBytes: limits.liveResponseBytes,
    timeoutMs: limits.wallClockMs,
  });
  if (packed.status !== 200) throw new LimitError(`registry tarball returned ${packed.status}`);
  if (packed.truncated || !packed.bytes) throw new LimitError("registry tarball was truncated");
  let finalHost: string;
  try {
    finalHost = new URL(packed.url).hostname;
  } catch {
    throw new LimitError("registry tarball host was rejected");
  }
  if (finalHost !== REGISTRY_HOST) throw new LimitError("registry tarball host was rejected");
  if (!npmIntegrityMatches(packed.bytes, integrity)) throw new LimitError("registry integrity hash did not match");
  return { name, version, bytes: packed.bytes };
}
