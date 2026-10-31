import { isCompromisedAxios, isCompromisedLitellm, isVulnerableMcpSdk, litellmImage } from "@vigil/intel";
import type { DepCheck, Finding } from "@vigil/core";
import { netFinding } from "./finding.js";

export interface PackageRef {
  ecosystem: "npm" | "PyPI" | "Go" | "Packagist";
  name: string;
  version: string;
  source: string;
}

export interface ImageRef {
  image: string;
  tag: string;
  source: string;
  line: number;
}

export function parseDependencies(files: { name: string; content: string }[]): PackageRef[] {
  const refs: PackageRef[] = [];
  for (const file of files) {
    const base = file.name.split("/").pop() ?? file.name;
    if (base === "package-lock.json" || base === "npm-shrinkwrap.json") refs.push(...npmLock(file));
    else if (base === "pnpm-lock.yaml") refs.push(...pnpmLock(file));
    else if (base === "yarn.lock") refs.push(...yarnLock(file));
    else if (/^requirements.*\.txt$/i.test(base)) refs.push(...requirements(file));
    else if (base === "poetry.lock") refs.push(...poetryLock(file));
    else if (base === "go.sum") refs.push(...goSum(file));
    else if (base === "composer.lock") refs.push(...composerLock(file));
    else if (isDockerfile(base)) refs.push(...dockerPackages(file));
  }
  return dedupe(refs);
}

/**
 * Repository name from an image reference.
 * Strip a digest, then remove `:tag` only when the colon is in the last path segment.
 * `localhost:5000/nginx:1.31.6` is `nginx`. `nginx:1.31.6@sha256:…` is `nginx`.
 */
export function dockerImageName(ref: string): string {
  const withoutDigest = ref.split("@")[0] ?? ref;
  const slash = withoutDigest.lastIndexOf("/");
  const last = slash >= 0 ? withoutDigest.slice(slash + 1) : withoutDigest;
  const colon = last.indexOf(":");
  return (colon >= 0 ? last.slice(0, colon) : last).toLowerCase();
}

/** Tag from the same split. Empty when the reference has no tag. */
export function dockerImageTag(ref: string): string {
  const withoutDigest = ref.split("@")[0] ?? ref;
  const slash = withoutDigest.lastIndexOf("/");
  const last = slash >= 0 ? withoutDigest.slice(slash + 1) : withoutDigest;
  const colon = last.indexOf(":");
  return colon >= 0 ? last.slice(colon + 1) : "";
}

/** Image reference after FROM flags. `--platform=linux/amd64` and `--platform linux/amd64` are both skipped. */
function fromImageReference(line: string): string | null {
  const match = /^\s*FROM\s+(\S.*)$/i.exec(line);
  if (!match?.[1]) return null;
  const tokens = match[1].trim().split(/\s+/);
  let index = 0;
  while (index < tokens.length && (tokens[index] ?? "").startsWith("--")) {
    const flag = tokens[index] ?? "";
    index += flag.includes("=") ? 1 : 2;
  }
  const image = tokens[index];
  if (!image || image.toLowerCase() === "as") return null;
  return image;
}

export function parseDockerImages(name: string, content: string): ImageRef[] {
  const images: ImageRef[] = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const image = fromImageReference(lines[index] ?? "");
    if (!image || image.toLowerCase() === "scratch") continue;
    images.push({ image, tag: dockerImageTag(image), source: name, line: index + 1 });
  }
  return images;
}

export function isDockerfile(name: string): boolean {
  const base = name.split("/").pop() ?? name;
  return base === "Dockerfile" || base.startsWith("Dockerfile.") || base.endsWith(".dockerfile") || base.toLowerCase() === "dockerfile";
}

export interface OsvHit {
  pkg: PackageRef;
  ids: string[];
  high: boolean;
}

export async function queryOsv(packages: PackageRef[], fetchImpl: typeof fetch = fetch): Promise<{ hits: OsvHit[]; error?: string }> {
  const hits: OsvHit[] = [];
  const queried = packages.filter((pkg) => pkg.version && pkg.version !== "latest" && !pkg.version.includes("*"));
  try {
    for (let offset = 0; offset < queried.length; offset += 100) {
      const chunk = queried.slice(offset, offset + 100);
      const response = await fetchImpl("https://api.osv.dev/v1/querybatch", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          queries: chunk.map((pkg) => ({
            package: { name: pkg.name, ecosystem: pkg.ecosystem },
            version: pkg.ecosystem === "Go" ? (pkg.version.startsWith("v") ? pkg.version : `v${pkg.version}`) : pkg.version.replace(/^v/, ""),
          })),
        }),
      });
      if (!response.ok) throw new Error(`OSV status ${response.status}`);
      const body = (await response.json()) as {
        results?: { vulns?: { id?: string; severity?: { score?: string }[] }[] }[];
      };
      chunk.forEach((pkg, index) => {
        const vulns = body.results?.[index]?.vulns ?? [];
        const ids = vulns.flatMap((vuln) => (vuln.id ? [vuln.id] : []));
        if (ids.length === 0) return;
        hits.push({ pkg, ids, high: vulns.some((vuln) => isHigh(vuln.severity)) });
      });
    }
    return { hits };
  } catch (error) {
    return { hits, error: error instanceof Error ? error.message : "OSV lookup failed" };
  }
}

export function dependencyFindings(packages: PackageRef[], osv: { hits: OsvHit[]; error?: string }): { findings: Finding[]; deps: DepCheck[] } {
  const findings: Finding[] = [];
  const deps: DepCheck[] = [];
  for (const pkg of packages) {
    if (!isCompromisedLitellm(pkg.name, pkg.version)) continue;
    findings.push(netFinding({
      id: "DEP_LITELLM_COMPROMISED",
      severity: "critical",
      title: "Compromised LiteLLM 1.107.0",
      summary: `${pkg.source} pins litellm ${pkg.version}.`,
      why: "That exact release on PyPI and the matching image tags carried a credential stealer. Floating tags such as latest are not permanently flagged.",
      remediation: ["Remove cook.pth, cook.py, and sitecustomize.py, pin litellm==1.106.2, and rotate credentials the host could reach."],
      recommendationOnly: false,
      category: "dependency",
      file: pkg.source,
      evidence: `${pkg.name}@${pkg.version}`,
    }));
    deps.push({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      version: pkg.version,
      source: pkg.source,
      advisoryId: "LITELLM-1.107.0",
      level: "block",
      summary: "Exact match for the compromised LiteLLM 1.107.0 release.",
    });
  }
  for (const pkg of packages) {
    if (!isCompromisedAxios(pkg.name, pkg.version)) continue;
    findings.push(netFinding({
      id: "DEP_AXIOS_COMPROMISED",
      severity: "critical",
      title: "Compromised axios npm release",
      summary: `${pkg.source} pins ${pkg.name} ${pkg.version}.`,
      why: "axios 1.14.1 and 0.30.4, and plain-crypto-js 4.2.0 and 4.2.1, were malicious npm releases. The axios versions pulled in a postinstall dropper.",
      remediation: ["Remove the pinned release and use an axios version that was not part of that incident."],
      recommendationOnly: false,
      category: "dependency",
      file: pkg.source,
      evidence: `${pkg.name}@${pkg.version}`,
    }));
    deps.push({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      version: pkg.version,
      source: pkg.source,
      advisoryId: "AXIOS-2026-03-31",
      level: "block",
      summary: "Exact match for a malicious axios release or its dropper.",
    });
  }
  for (const pkg of packages) {
    if (!isVulnerableMcpSdk(pkg.name, pkg.version)) continue;
    findings.push(netFinding({
      id: "DEP_MCP_SDK",
      severity: "critical",
      title: "MCP SDK below 1.32.0",
      summary: `${pkg.source} pins ${pkg.name} ${pkg.version}.`,
      why: "Exact versions of @modelcontextprotocol/sdk below 1.32.0 are in the affected range for the October 2026 SDK advisories. A range without a resolved version is not an exact match.",
      remediation: ["Upgrade @modelcontextprotocol/sdk to 1.32.0 or newer and pin it in the lockfile."],
      recommendationOnly: false,
      category: "dependency",
      file: pkg.source,
      evidence: `${pkg.name}@${pkg.version}`,
    }));
    deps.push({
      ecosystem: pkg.ecosystem,
      name: pkg.name,
      version: pkg.version,
      source: pkg.source,
      advisoryId: "MCP-SDK-1.32.0",
      level: "block",
      summary: "Exact match below @modelcontextprotocol/sdk 1.32.0.",
    });
  }
  for (const hit of osv.hits) {
    findings.push(netFinding({
      id: "DEP_OSV",
      severity: hit.high ? "high" : "medium",
      title: `OSV advisory for ${hit.pkg.name}`,
      summary: `${hit.pkg.name}@${hit.pkg.version} matches ${hit.ids.join(", ")}.`,
      why: "OSV results are recommendations. Vigil does not install the package or decide that the vulnerable code path is reachable.",
      remediation: ["Read the advisory and upgrade or remove the package if the vulnerable code is shipped."],
      recommendationOnly: true,
      category: "dependency",
      file: hit.pkg.source,
      evidence: hit.ids.join(", "),
    }));
    deps.push({
      ecosystem: hit.pkg.ecosystem,
      name: hit.pkg.name,
      version: hit.pkg.version,
      source: hit.pkg.source,
      osvIds: hit.ids,
      level: "warn",
      summary: hit.ids.join(", "),
    });
  }
  if (osv.error) {
    deps.push({
      ecosystem: "osv",
      name: "osv.dev",
      version: "",
      source: "querybatch",
      level: "unknown",
      summary: `OSV lookup failed (${osv.error}). Local advisories still ran.`,
    });
  }
  return { findings, deps };
}

export function imageLitellm(images: ImageRef[]): PackageRef[] {
  return images.flatMap((image) => {
    if (!litellmImage(image.image) && !isCompromisedLitellm("litellm", image.tag)) return [];
    return [{ ecosystem: "PyPI" as const, name: "litellm", version: image.tag.replace(/^v/, ""), source: image.source }];
  });
}

function npmLock(file: { name: string; content: string }): PackageRef[] {
  let json: { packages?: Record<string, { version?: string }>; dependencies?: unknown };
  try {
    json = JSON.parse(file.content) as { packages?: Record<string, { version?: string }>; dependencies?: unknown };
  } catch {
    return [];
  }
  const refs: PackageRef[] = [];
  for (const [path, meta] of Object.entries(json.packages ?? {})) {
    if (!meta.version || !path.includes("node_modules/")) continue;
    const name = path.split("node_modules/").pop() ?? "";
    if (!name) continue;
    refs.push({ ecosystem: "npm", name, version: meta.version, source: file.name });
  }
  walkNpmTree(json.dependencies, refs, file.name);
  return refs;
}

function walkNpmTree(tree: unknown, refs: PackageRef[], source: string): void {
  if (!tree || typeof tree !== "object") return;
  for (const [name, meta] of Object.entries(tree as Record<string, unknown>)) {
    if (!meta || typeof meta !== "object") continue;
    const record = meta as { version?: unknown; dependencies?: unknown };
    if (typeof record.version === "string" && record.version) {
      refs.push({ ecosystem: "npm", name, version: record.version, source });
    }
    if (record.dependencies) walkNpmTree(record.dependencies, refs, source);
  }
}

function pnpmLock(file: { name: string; content: string }): PackageRef[] {
  const refs: PackageRef[] = [];
  let inPackages = false;
  for (const line of file.content.split("\n")) {
    if (/^packages:\s*$/.test(line)) {
      inPackages = true;
      continue;
    }
    if (inPackages && /^\S/.test(line)) break;
    if (!inPackages) continue;
    const match = /^ {2,}['"]?\/?((?:@[^\s/'"]+\/)?[^@\s'"]+)@([^:'"\s]+)['"]?:\s*$/.exec(line);
    if (!match?.[1] || !match[2]) continue;
    const version = stripPnpmPeers(match[2]);
    if (!version) continue;
    refs.push({ ecosystem: "npm", name: match[1], version, source: file.name });
  }
  return refs;
}

function yarnLock(file: { name: string; content: string }): PackageRef[] {
  const refs: PackageRef[] = [];
  let current: string | undefined;
  for (const line of file.content.split("\n")) {
    const version = /^ {2}version "([^"]+)"/.exec(line);
    if (version?.[1] && current) {
      refs.push({ ecosystem: "npm", name: current, version: version[1], source: file.name });
      current = undefined;
      continue;
    }
    const scoped = /^"(@[^@"\s]+)@[^"]*":\s*$/.exec(line);
    const plain = /^([^@"\s]+)@[^:\s]*:\s*$/.exec(line);
    if (scoped?.[1]) current = scoped[1];
    else if (plain?.[1]) current = plain[1];
  }
  return refs;
}

function requirements(file: { name: string; content: string }): PackageRef[] {
  const refs: PackageRef[] = [];
  for (const line of file.content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) continue;
    const match = /^([A-Za-z0-9_.-]+)\s*==\s*([A-Za-z0-9.*+_=-]+)/.exec(trimmed);
    if (!match?.[1] || !match[2]) continue;
    refs.push({ ecosystem: "PyPI", name: match[1], version: match[2], source: file.name });
  }
  return refs;
}

function poetryLock(file: { name: string; content: string }): PackageRef[] {
  const refs: PackageRef[] = [];
  for (const block of file.content.split("[[package]]").slice(1)) {
    const name = /^name\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    const version = /^version\s*=\s*"([^"]+)"/m.exec(block)?.[1];
    if (!name || !version) continue;
    refs.push({ ecosystem: "PyPI", name, version, source: file.name });
  }
  return refs;
}

function goSum(file: { name: string; content: string }): PackageRef[] {
  const refs: PackageRef[] = [];
  for (const line of file.content.split("\n")) {
    const match = /^(\S+)\s+(v[^\s]+)\s+/.exec(line.trim());
    if (!match?.[1] || !match[2] || match[2].includes("/")) continue;
    refs.push({ ecosystem: "Go", name: match[1], version: match[2], source: file.name });
  }
  return refs;
}

function composerLock(file: { name: string; content: string }): PackageRef[] {
  let json: { packages?: { name?: string; version?: string }[]; "packages-dev"?: { name?: string; version?: string }[] };
  try {
    json = JSON.parse(file.content) as typeof json;
  } catch {
    return [];
  }
  const refs: PackageRef[] = [];
  for (const pkg of [...(json.packages ?? []), ...(json["packages-dev"] ?? [])]) {
    if (!pkg.name || !pkg.version) continue;
    refs.push({ ecosystem: "Packagist", name: pkg.name, version: pkg.version.replace(/^v/, ""), source: file.name });
  }
  return refs;
}

function dockerPackages(file: { name: string; content: string }): PackageRef[] {
  return parseDockerImages(file.name, file.content).flatMap((image) => {
    if (!image.image.toLowerCase().includes("litellm")) return [];
    const version = image.tag.replace(/^v/, "");
    if (!/^\d+\.\d+\.\d+$/.test(version)) return [];
    return [{ ecosystem: "PyPI" as const, name: "litellm", version, source: file.name }];
  });
}

export interface ManifestDep {
  name: string;
  spec: string;
  version: string | null;
  source: string;
}

const EXACT_SPEC = /^=?v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$/;

/** Direct dependency specs from a package.json. An exact x.y.z pin sets version. Anything else is a range. */
export function manifestDependencies(file: { name: string; content: string }): ManifestDep[] {
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(file.content) as Record<string, unknown>;
  } catch {
    return [];
  }
  const out: ManifestDep[] = [];
  for (const field of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const block = json[field];
    if (!block || typeof block !== "object") continue;
    for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
      if (typeof spec !== "string") continue;
      const trimmed = spec.trim();
      const parsed = manifestNameAndVersion(name, trimmed);
      out.push({ name: parsed.name, spec: trimmed, version: parsed.version, source: file.name });
    }
  }
  return out;
}

/**
 * Exact advisory matches for a packed package. Lockfile versions are exact.
 * With no lockfile, exact package.json pins are checked and ranges are reported.
 * Ranges do not block.
 */
export function gateDependencyReport(
  manifest: { name: string; content: string } | null,
  lockfiles: { name: string; content: string }[],
): { findings: Finding[]; deps: DepCheck[] } {
  const locked = parseDependencies(lockfiles);
  const specs = manifest ? manifestDependencies(manifest) : [];
  const exactFromManifest: PackageRef[] = specs.flatMap((dep) => (
    dep.version ? [{ ecosystem: "npm" as const, name: dep.name, version: dep.version, source: dep.source }] : []
  ));
  const advisory = dependencyFindings(lockfiles.length > 0 ? locked : exactFromManifest, { hits: [] });
  if (lockfiles.length > 0 && exactFromManifest.length > 0) {
    const extra = dependencyFindings(exactFromManifest, { hits: [] });
    advisory.findings.push(...extra.findings);
    advisory.deps.push(...extra.deps);
  }
  const findings = dedupeFindings(advisory.findings);
  const deps = advisory.deps;
  if (lockfiles.length === 0) {
    for (const dep of specs) {
      if (dep.version) continue;
      findings.push(netFinding({
        id: "DEP_RANGE",
        severity: "informational",
        title: "Dependency range was not resolved",
        summary: `${dep.name}@${dep.spec} has no lockfile pin.`,
        why: "A range can install more than one version. The gate does not install the package to find out which one.",
        remediation: ["Pin an exact version in a lockfile and review that version."],
        recommendationOnly: true,
        category: "dependency",
        file: dep.source,
        evidence: `${dep.name}@${dep.spec}`,
      }));
      deps.push({
        ecosystem: "npm",
        name: dep.name,
        version: dep.spec,
        source: dep.source,
        level: "info",
        summary: "Range without a lockfile. Not an exact advisory match.",
      });
    }
  }
  return { findings, deps };
}

function manifestNameAndVersion(key: string, spec: string): { name: string; version: string | null } {
  let name = key;
  let versionText = spec;
  const alias = /^npm:(.*)$/i.exec(spec);
  if (alias) {
    const body = alias[1] ?? "";
    const at = body.lastIndexOf("@");
    if (at > 0) {
      name = body.slice(0, at);
      versionText = body.slice(at + 1);
    } else {
      name = body;
      versionText = "";
    }
  }
  const exact = EXACT_SPEC.exec(versionText);
  return { name, version: exact?.[1] ?? null };
}

/** Drop trailing pnpm peer parentheticals, including nested ones. */
function stripPnpmPeers(version: string): string {
  let end = version.length;
  while (end > 0 && version[end - 1] === ")") {
    let depth = 0;
    let found = -1;
    for (let i = end - 1; i >= 0; i--) {
      const char = version[i];
      if (char === ")") depth++;
      else if (char === "(") {
        depth--;
        if (depth === 0) {
          found = i;
          break;
        }
      }
    }
    if (found <= 0) break;
    end = found;
  }
  return version.slice(0, end);
}

function dedupeFindings(findings: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const item of findings) {
    const key = `${item.id}\0${item.evidence}\0${item.file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function dedupe(refs: PackageRef[]): PackageRef[] {
  const seen = new Set<string>();
  const out: PackageRef[] = [];
  for (const ref of refs) {
    const key = `${ref.ecosystem}\0${ref.name}\0${ref.version}\0${ref.source}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(ref);
  }
  return out;
}

function isHigh(severity: { score?: string }[] | undefined): boolean {
  if (!severity) return false;
  return severity.some((item) => /(?:^|[/:])(?:CRITICAL|HIGH)\b/i.test(item.score ?? "") || /\/[CIA]:H\b/.test(item.score ?? ""));
}
