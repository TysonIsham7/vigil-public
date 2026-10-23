import curlAdvisory from "../advisories/curl-cve-2026-92392.json" with { type: "json" };
import goAdvisory from "../advisories/go-1.27.3-emudhra.json" with { type: "json" };
import kernelAdvisory from "../advisories/kernel-cve-2026-99999.json" with { type: "json" };
import litellmAdvisory from "../advisories/litellm-1.107.0.json" with { type: "json" };
import nodeAdvisory from "../advisories/node-2026-10-21.json" with { type: "json" };
import phpAdvisory from "../advisories/php-cve-2026-109618.json" with { type: "json" };
import phpSessionAdvisory from "../advisories/php-cve-2026-115560.json" with { type: "json" };

export { curlAdvisory, goAdvisory, kernelAdvisory, litellmAdvisory, nodeAdvisory, phpAdvisory, phpSessionAdvisory };

export const PHP_SESSION_PROGRESS_ID = "PHP_CVE_2026_115560";

export function parseVersion(input: string): number[] | null {
  const match = /(\d+)\.(\d+)\.(\d+)/.exec(input);
  if (!match) return null;
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

export function cmpVersion(left: number[], right: number[]): number {
  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i++) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

export function phpVulnerable(version: string): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return false;
  const [major, minor, patch] = parsed;
  const line = phpAdvisory.fixed.find((item) => item.major === major && item.minor === minor);
  if (line) return (patch ?? 0) < line.patch;
  if (major > 8 || (major === 8 && minor > 5)) return false;
  return true;
}

/** Informational note for CVE-2026-115560. PHP has not published a fixed version. */
export function phpSessionProgressNote(version?: string): {
  id: typeof PHP_SESSION_PROGRESS_ID;
  title: string;
  summary: string;
  remediation: string[];
} {
  const prefix = version
    ? `PHP ${version} meets the 21 October 2026 releases. Those releases do not close CVE-2026-115560. `
    : "PHP was detected. CVE-2026-115560 has no patched release yet. ";
  return {
    id: PHP_SESSION_PROGRESS_ID,
    title: "PHP session upload progress",
    summary: `${prefix}PHP has not published a fixed version. This note does not mean the unusual session configuration is present.`,
    remediation: [phpSessionAdvisory.mitigation],
  };
}

export function parsePhpVersion(headers: Record<string, string | undefined>): string | undefined {
  const powered = headers["x-powered-by"] ?? headers["X-Powered-By"] ?? "";
  const server = headers["server"] ?? headers["Server"] ?? "";
  const match = /PHP\/(\d+\.\d+\.\d+)/i.exec(`${powered} ${server}`);
  if (match?.[1]) return match[1];
  return undefined;
}

export function phpDetected(input: {
  headers: Record<string, string | undefined>;
  url?: string;
  body?: string;
  setCookies?: string[];
}): boolean {
  const powered = input.headers["x-powered-by"] ?? "";
  const server = input.headers["server"] ?? "";
  if (/php/i.test(`${powered} ${server}`)) return true;
  if ((input.setCookies ?? []).some((cookie) => /PHPSESSID/i.test(cookie))) return true;
  if (input.url && /\.php(?:$|\?)/i.test(input.url)) return true;
  if (input.body && /\.php(?:["'\s?]|$)/i.test(input.body)) return true;
  return false;
}

export interface PhpVerdict {
  status: "vulnerable" | "suspected" | "fixed" | "not-applicable";
  version?: string;
  level: "block" | "warn" | "info" | "ok";
  recommendationOnly: boolean;
  severity: "critical" | "high" | "informational";
}

export function evaluatePhp(input: {
  headers: Record<string, string | undefined>;
  url?: string;
  body?: string;
  setCookies?: string[];
  audience: "owner" | "visitor";
}): PhpVerdict {
  if (!phpDetected(input)) return { status: "not-applicable", level: "ok", recommendationOnly: true, severity: "informational" };
  const version = parsePhpVersion(input.headers);
  if (!version) {
    return { status: "suspected", level: "warn", recommendationOnly: true, severity: "high" };
  }
  if (!phpVulnerable(version)) {
    return { status: "fixed", version, level: "info", recommendationOnly: true, severity: "informational" };
  }
  if (input.audience === "visitor") {
    return { status: "vulnerable", version, level: "warn", recommendationOnly: true, severity: "high" };
  }
  return { status: "vulnerable", version, level: "block", recommendationOnly: false, severity: "critical" };
}

export function wordpressSignals(html: string): { present: boolean; version?: string } {
  if (!/wp-content|wp-includes|wordpress/i.test(html)) return { present: false };
  const generator = /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)/i.exec(html)
    ?? /<meta[^>]+content=["']WordPress\s+([\d.]+)["'][^>]+name=["']generator["']/i.exec(html);
  const result: { present: boolean; version?: string } = { present: true };
  if (generator?.[1]) result.version = generator[1];
  return result;
}

export function wordpressReadmeVersion(text: string): string | undefined {
  return /Version\s+(\d+\.\d+(?:\.\d+)?)/i.exec(text)?.[1];
}

export function curlAffected(version: string): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return false;
  const [major, minor, patch] = parsed;
  if (major !== 8) return false;
  const introduced = parseVersion(curlAdvisory.introduced);
  const fixed = parseVersion(curlAdvisory.fixed);
  if (!introduced || !fixed) return false;
  if (cmpVersion(parsed, introduced) < 0) return false;
  if (cmpVersion(parsed, fixed) >= 0) return false;
  const branch = curlAdvisory.patchedBranches.find((item) => item.minor === minor);
  if (branch && patch >= branch.patch) return false;
  return true;
}

/** True when this Node is below the patched release on its line, or is not one of those lines. */
export function nodeMissingSecurityRelease(version: string): boolean {
  const parsed = parseVersion(version.replace(/^v/, ""));
  if (!parsed) return false;
  const line = nodeAdvisory.fixedLines.find((item) => item.major === parsed[0]);
  if (line) return cmpVersion(parsed, [line.major, line.minor, line.patch]) < 0;
  const newest = nodeAdvisory.fixedLines.reduce((best, item) => (item.major > best.major ? item : best));
  return parsed[0] < newest.major;
}

export function goMissingTrustFix(version: string): boolean {
  const parsed = parseVersion(version.replace(/^go/, ""));
  if (!parsed) return false;
  for (const line of goAdvisory.fixedLines) {
    if (parsed[0] === line.major && parsed[1] === line.minor) {
      return (parsed[2] ?? 0) < line.patch;
    }
  }
  const newest = goAdvisory.fixedLines[0];
  if (!newest) return false;
  return cmpVersion(parsed, [newest.major, newest.minor, newest.patch]) < 0;
}

export function isCompromisedLitellm(name: string, version: string): boolean {
  const normalized = name.toLowerCase().replaceAll("_", "-");
  if (normalized !== "litellm" && !normalized.endsWith("/litellm")) return false;
  const tag = version.trim().replace(/^v/, "");
  return litellmAdvisory.dockerTags.some((item) => item.replace(/^v/, "") === tag) || tag === litellmAdvisory.version;
}

export interface KernelAssessment {
  version: string;
  affected: boolean;
  fixedIn?: string;
}

/** Leading upstream version from `uname -r`. Distro suffixes are ignored. */
export function kernelRelease(text: string): string | undefined {
  return /(\d+\.\d+\.\d+)/.exec(text)?.[1];
}

/**
 * True when the upstream version is in the announced affected range.
 * A lower uname can still be a backported fix. This function cannot see that.
 */
export function assessKernel(text: string): KernelAssessment | undefined {
  const version = kernelRelease(text);
  const parsed = version ? parseVersion(version) : null;
  if (!version || !parsed) return undefined;
  const introduced = parseVersion(kernelAdvisory.introduced);
  if (cmpVersion(parsed, [7, 3, 0]) >= 0) return { version, affected: false };
  const line = kernelAdvisory.fixedLines.find((item) => item.major === parsed[0] && item.minor === parsed[1]);
  if (line) {
    const fixedIn = `${line.major}.${line.minor}.${line.patch}`;
    return { version, affected: (parsed[2] ?? 0) < line.patch, fixedIn };
  }
  if (introduced && cmpVersion(parsed, introduced) < 0) return { version, affected: false };
  return { version, affected: true };
}

export function litellmImage(image: string): boolean {
  const lower = image.toLowerCase();
  if (!lower.includes("litellm")) return false;
  const tag = image.split(":").pop()?.split("@")[0] ?? "";
  return isCompromisedLitellm("litellm", tag);
}
