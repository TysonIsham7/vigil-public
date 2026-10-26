import axiosAdvisory from "../advisories/axios-2026-03-31.json" with { type: "json" };
import curlAdvisory from "../advisories/curl-cve-2026-92392.json" with { type: "json" };
import goAdvisory from "../advisories/go-1.27.3-emudhra.json" with { type: "json" };
import kernelAdvisory from "../advisories/kernel-cve-2026-99999.json" with { type: "json" };
import litellmAdvisory from "../advisories/litellm-1.107.0.json" with { type: "json" };
import mcpSdkAdvisory from "../advisories/mcp-sdk-1.32.0.json" with { type: "json" };
import nginxAdvisory from "../advisories/nginx-2026-10-14.json" with { type: "json" };
import nodeAdvisory from "../advisories/node-2026-10-21.json" with { type: "json" };
import phpAdvisory from "../advisories/php-cve-2026-109618.json" with { type: "json" };
import phpSessionAdvisory from "../advisories/php-cve-2026-115560.json" with { type: "json" };
import pipAdvisory from "../advisories/pip-26.2.2-emudhra.json" with { type: "json" };

export {
  axiosAdvisory,
  curlAdvisory,
  goAdvisory,
  kernelAdvisory,
  litellmAdvisory,
  mcpSdkAdvisory,
  nginxAdvisory,
  nodeAdvisory,
  phpAdvisory,
  phpSessionAdvisory,
  pipAdvisory,
};

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

/** Names CVE-2026-115560 on an upgrade finding. It does not say the note is non-blocking. */
export function phpSessionUnfixedLine(): string {
  return "CVE-2026-115560 has no fixed PHP release yet. The 21 October 2026 releases do not close it.";
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
  const blob = ["x-powered-by", "server"].flatMap((name) => headerValues(headers, name)).join("\n");
  const versions = [...new Set([...blob.matchAll(/PHP\/(\d+\.\d+\.\d+)/gi)].map((match) => match[1] ?? "").filter(Boolean))];
  return versions.find((version) => phpVulnerable(version)) ?? versions[0];
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

export const PHP2SHELL_RULE = "PHP2SHELL_EXPOSURE";

export type PhpExposureStatus = "exposed" | "patched" | "hidden" | "not-PHP";

export interface PhpExposure {
  status: PhpExposureStatus;
  version?: string;
  title: string;
  summary: string;
  severity: "high" | "informational";
  confidence: "high" | "medium";
}

/** Header-only PHP2Shell class. X-Powered-By and Server are the only inputs. */
export function classifyPhpExposure(headers: Record<string, string | undefined>): PhpExposure {
  const blob = ["x-powered-by", "server"].flatMap((name) => headerValues(headers, name)).join("\n");
  if (!/(^|[^a-z0-9])php([^a-z0-9]|$)/i.test(blob)) {
    return exposure("not-PHP", undefined, "informational", "high");
  }
  const versions = [...blob.matchAll(/PHP\/(\d+)\.(\d+)\.(\d+)/gi)].map((match) => `${match[1]}.${match[2]}.${match[3]}`);
  if (versions.length === 0) return exposure("hidden", undefined, "high", "medium");
  const exposed = versions.find((version) => phpLineExposed(version));
  if (exposed) return exposure("exposed", exposed, "high", "high");
  return exposure("patched", versions[0], "informational", "high");
}

function headerValues(headers: Record<string, string | undefined>, name: string): string[] {
  const values: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name && value) values.push(value);
  }
  return values;
}

function phpLineExposed(version: string): boolean {
  const parsed = parseVersion(version);
  if (!parsed) return true;
  const [major, minor, patch] = parsed;
  const eol = phpAdvisory.exposure.eolUnpatchedAtOrBelow;
  if (major < eol.major || (major === eol.major && minor <= eol.minor)) return true;
  const line = phpAdvisory.fixed.find((item) => item.major === major && item.minor === minor);
  if (line) return (patch ?? 0) < line.patch;
  if (major > 8 || (major === 8 && (minor ?? 0) > 5)) return false;
  return true;
}

function exposure(
  status: PhpExposureStatus,
  version: string | undefined,
  severity: PhpExposure["severity"],
  confidence: PhpExposure["confidence"],
): PhpExposure {
  const label = `PHP2Shell: ${status}`;
  if (status === "exposed") {
    return {
      status,
      ...(version ? { version } : {}),
      title: label,
      summary: version
        ? `PHP ${version} is exposed to CVE-2026-109618 and CVE-2026-109619. ${phpAdvisory.upgrade} Versions at or below 8.1 are end of life and have no fix.`
        : `The disclosed PHP version is exposed to CVE-2026-109618 and CVE-2026-109619. ${phpAdvisory.upgrade}`,
      severity,
      confidence,
    };
  }
  if (status === "patched") {
    return {
      status,
      ...(version ? { version } : {}),
      title: label,
      summary: version
        ? `PHP ${version} is at or above the fixed release for CVE-2026-109618 and CVE-2026-109619.`
        : "The disclosed PHP version is at or above the fixed release for CVE-2026-109618 and CVE-2026-109619.",
      severity,
      confidence,
    };
  }
  if (status === "hidden") {
    return {
      status,
      title: label,
      summary: `X-Powered-By or Server names PHP but not a PHP/x.y.z version. That is not a patched release. ${phpAdvisory.upgrade} Versions at or below 8.1 have no fix.`,
      severity,
      confidence,
    };
  }
  return {
    status,
    title: label,
    summary: "X-Powered-By and Server do not name PHP.",
    severity,
    confidence,
  };
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

export interface PhpHeaderExposure {
  status: "not-applicable" | "unknown" | "patched" | "below-patch" | "never-patched";
  version?: string;
}

/**
 * Header-only PHP exposure. Versions come from X-Powered-By and Server via
 * parsePhpVersion. The patched-line comparison is phpVulnerable. PHP 5-7 has
 * no fix in this advisory, so it is never patched. PHP with no version is
 * unknown. This does not read page bodies and it does not send probes.
 */
export function classifyPhpHeaders(inputs: {
  headers: Record<string, string | undefined>;
  setCookies?: string[];
}[]): PhpHeaderExposure {
  let present = false;
  const versions: string[] = [];
  for (const input of inputs) {
    const headers = lowerHeaders(input.headers);
    if (phpDetected({ headers, setCookies: input.setCookies })) present = true;
    const version = parsePhpVersion(headers);
    if (version && !versions.includes(version)) versions.push(version);
  }
  if (versions.length === 0) return present ? { status: "unknown" } : { status: "not-applicable" };
  const never = versions.find((version) => {
    const major = parseVersion(version)?.[0];
    return major !== undefined && major <= 7;
  });
  if (never) return { status: "never-patched", version: never };
  const below = versions.find((version) => phpVulnerable(version));
  if (below) return { status: "below-patch", version: below };
  const patched = versions[0];
  return patched ? { status: "patched", version: patched } : { status: "unknown" };
}

function lowerHeaders(headers: Record<string, string | undefined>): Record<string, string | undefined> {
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(headers)) out[key.toLowerCase()] = value;
  return out;
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

/**
 * True for a build inside the 14 October 2026 nginx range.
 * 1.31.7+ and the 1.30.6+ stable line are the fixed releases. Newer majors are left alone.
 * A tag that is only major.minor on 1.31 or 1.30 is not padded to patch 0.
 * Docker Hub groups `1.31` and `1.31-alpine3.24` with 1.31.7, and `1.30` and `1.30-alpine` with 1.30.6.
 * Older two-component lines such as 1.29 and 1.28 are still flagged.
 */
export function nginxMissingSecurityRelease(version: string): boolean {
  const parts = nginxVersionParts(version);
  if (!parts) return false;
  const { major, minor, patch } = parts;
  if (patch === undefined) {
    const floatingFixed = nginxAdvisory.fixedLines.some((item) => item.major === major && item.minor === minor);
    if (floatingFixed) return false;
  }
  const concrete = [major, minor, patch ?? 0];
  const line = nginxAdvisory.fixedLines.find((item) => item.major === major && item.minor === minor);
  if (line) return (concrete[2] ?? 0) < line.patch;
  const mainline = nginxAdvisory.fixedLines.find((item) => item.major === 1 && item.minor === 31);
  if (mainline && cmpVersion(concrete, [mainline.major, mainline.minor, mainline.patch]) >= 0) return false;
  const introduced = parseVersion(nginxAdvisory.introduced);
  if (introduced && cmpVersion(concrete, introduced) < 0) return false;
  return major === 0 || major === 1;
}

function nginxVersionParts(input: string): { major: number; minor: number; patch?: number } | null {
  const match = /(\d+)\.(\d+)(?:\.(\d+))?/.exec(input);
  if (!match?.[1] || !match[2]) return null;
  const major = Number(match[1]);
  const minor = Number(match[2]);
  if (match[3] === undefined) return { major, minor };
  return { major, minor, patch: Number(match[3]) };
}

/** True when pip still vendors a certifi from before the eMudhra removal. */
export function pipMissingCertifiFix(version: string): boolean {
  return belowFixed(version, pipAdvisory.pipFixed);
}

/** True when uv is older than the release that picked up certifi 2026.10.19. */
export function uvMissingCertifiFix(version: string): boolean {
  return belowFixed(version, pipAdvisory.uvFixed);
}

function belowFixed(version: string, fixed: string): boolean {
  const parsed = parseVersion(version.replace(/^[a-z]+/i, ""));
  const floor = parseVersion(fixed);
  if (!parsed || !floor) return false;
  return cmpVersion(parsed, floor) < 0;
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

function exactVersion(version: string): string {
  return version.trim().replace(/^v/, "").split("+")[0] ?? "";
}

/** True for the March 2026 malicious axios releases and the plain-crypto-js dropper versions. */
export function isCompromisedAxios(name: string, version: string): boolean {
  const normalized = name.toLowerCase();
  const tag = exactVersion(version);
  if (normalized === axiosAdvisory.package) return axiosAdvisory.versions.some((item) => item === tag);
  if (normalized === axiosAdvisory.dropper.package) return axiosAdvisory.dropper.versions.some((item) => item === tag);
  return false;
}

/** True when an exact @modelcontextprotocol/sdk version is below the 1.32.0 fix. Ranges are not exact. */
export function isVulnerableMcpSdk(name: string, version: string): boolean {
  if (name !== mcpSdkAdvisory.package) return false;
  const tag = exactVersion(version);
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(tag)) return false;
  const parsed = parseVersion(tag);
  const fixed = parseVersion(mcpSdkAdvisory.fixed);
  if (!parsed || !fixed) return false;
  return cmpVersion(parsed, fixed) < 0;
}

export function litellmImage(image: string): boolean {
  const lower = image.toLowerCase();
  if (!lower.includes("litellm")) return false;
  const tag = image.split(":").pop()?.split("@")[0] ?? "";
  return isCompromisedLitellm("litellm", tag);
}
