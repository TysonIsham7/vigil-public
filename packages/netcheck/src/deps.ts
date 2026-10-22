import { isCompromisedLitellm, litellmImage } from "@vigil/intel";
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
    if (base === "package-lock.json") refs.push(...npmLock(file));
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

export function parseDockerImages(name: string, content: string): ImageRef[] {
  const images: ImageRef[] = [];
  const lines = content.split("\n");
  for (let index = 0; index < lines.length; index++) {
    const match = /^\s*FROM\s+([^\s]+)/i.exec(lines[index] ?? "");
    const image = match?.[1];
    if (!image || image.toLowerCase() === "scratch") continue;
    const tag = image.includes(":") ? (image.split(":").pop()?.split("@")[0] ?? "") : "";
    images.push({ image, tag, source: name, line: index + 1 });
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
  let json: { packages?: Record<string, { version?: string }> };
  try {
    json = JSON.parse(file.content) as { packages?: Record<string, { version?: string }> };
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
  return refs;
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
    refs.push({ ecosystem: "npm", name: match[1], version: match[2], source: file.name });
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
