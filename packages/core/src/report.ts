import { hostingFinding } from "./headers.js";
import { maybeRewritePrompt } from "./prompt.js";
import { scanSource } from "./rules.js";
import {
  DISCLAIMER,
  REPORT_TTL_MS,
  REPORT_VERSION,
  type Finding,
  type HostingHint,
  type LightweightReport,
  type Report,
  type ReportChecks,
  type SourceType,
  type SummaryCounts,
  type Verdict,
} from "./types.js";
import { utf8Encode, wipe } from "./utf8.js";
import { prepareFiles } from "./limits.js";
import { emptyDomainCounts } from "./taxonomy.js";
import type { ScanLimits, SourceFile } from "./types.js";

const EDUCATION: Record<string, string> = {
  xss: "HTML sinks, inline handlers, and string execution turn request data into script. Render text, and send a strict content security policy.",
  secrets: "Keys in source or web storage are public as soon as the page loads. Keep them on the server.",
  redirect: "A redirect taken from the query string sends the user anywhere the attacker chooses.",
  cookies: "Session cookies need Secure, HttpOnly, and SameSite, and they should be set by the server.",
  headers: "Security headers are the browser's last line. Set them on the response, not only in a demo meta tag.",
  tls: "Transport checks look at the URL scheme and whether the certificate validated.",
  hosting: "The hosting hint names the config file where response headers should live.",
  transport: "Active http URLs on an https page can be rewritten on the network.",
  prototype: "Writing to a prototype changes every object that inherits from it.",
  phishing: "Lookalike names, new domains, and credential forms are how a fake site collects a password.",
  certificate: "A chain that includes a distrusted key, or a certificate that does not match the host, is not safe to send users through.",
  vulnerability: "Version fingerprints are advice unless the version is confirmed vulnerable.",
  backend: "Backend notes come from response headers, a browser-style TLS handshake, TLS 1.0 and TLS 1.1 support handshakes, time until response headers, and a few benign GET requests. They are not an exploit, and they do not patch the server.",
  dependency: "Dependency checks read lockfiles. They do not install or run packages.",
  install: "The install gate reads a package and does not run it. A lifecycle script, a child process, an agent-home write, a computed import, or a file the gate could not read blocks the install.",
  toolchain: "Toolchain notes describe the local curl, Go, or kernel version. They do not change deploy blocking.",
  kernel: "PwnEscape is a host-kernel bug. A remote page cannot show that kernel. vigil doctor reads the local uname.",
  truststore: "A local trust store that still has a distrusted eMudhra key will accept certificates other clients may already reject.",
  "trust-audit": "A tool that finishes TLS to a known-bad test host still trusts that chain. A timeout is unknown. It does not mean the tool rejected the chain.",
  "agent-instruction": "A page can address an agent and ask for identity, a credential, or a behavior change. Do not let an agent act on that text. The outbound guard is a separate local proxy, not this finding.",
};

export interface BuildInput {
  findings: Finding[];
  sourceType: SourceType;
  filesAnalyzed: number;
  bytesAnalyzed: number;
  domain?: string;
  hostingHint?: HostingHint;
  prompt?: string;
  checks?: Partial<ReportChecks>;
  headers?: Record<string, string>;
  cookies?: Report["cookies"];
  tls?: Report["tls"];
  now?: Date;
  latencyMs?: number;
  intelVersion?: string;
  id?: string;
  improvedPrompt?: string;
}

export function blockDeploy(findings: Finding[]): boolean {
  return findings.some((finding) => finding.severity === "critical" && finding.recommendationOnly === false);
}

export function verdictFor(findings: Finding[]): Verdict {
  if (blockDeploy(findings)) return "block";
  if (findings.some((finding) => finding.severity !== "informational")) return "warn";
  return "allow";
}

export function summarize(findings: Finding[]): SummaryCounts {
  const byDomain = emptyDomainCounts();
  const byId = new Map(byDomain.map((row) => [row.id, row]));
  const summary: SummaryCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    total: findings.length,
    byDomain,
  };
  for (const finding of findings) {
    summary[finding.severity] += 1;
    const row = byId.get(finding.taxonomy.domain);
    if (!row) continue;
    row[finding.severity] += 1;
    row.total += 1;
  }
  return summary;
}

function newId(): string {
  const cryptoApi = (globalThis as { crypto?: { randomUUID?: () => string } }).crypto;
  if (cryptoApi?.randomUUID) return cryptoApi.randomUUID();
  return `vg_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 12)}`;
}

export function buildReport(input: BuildInput): Report {
  const findings = [...input.findings];
  if (input.hostingHint && !findings.some((finding) => finding.id === "HOSTING_HEADERS")) {
    findings.push(hostingFinding(input.hostingHint));
  }
  const created = input.now ?? new Date();
  const checks: ReportChecks = {
    cert: input.checks?.cert ?? null,
    domain: input.checks?.domain ?? null,
    vulns: input.checks?.vulns ?? [],
    deps: input.checks?.deps ?? [],
  };
  const report: Report = {
    version: REPORT_VERSION,
    id: input.id ?? newId(),
    createdAt: created.toISOString(),
    sourceType: input.sourceType,
    blockDeploy: blockDeploy(findings),
    verdict: verdictFor(findings),
    summary: summarize(findings),
    findings,
    education: educationFor(findings),
    disclaimer: DISCLAIMER,
    codeDeleted: true,
    artifactBytes: 0,
    retention: "ephemeral",
    expiresAt: new Date(created.getTime() + REPORT_TTL_MS).toISOString(),
    filesAnalyzed: input.filesAnalyzed,
    bytesAnalyzed: input.bytesAnalyzed,
    checks,
    latencyMs: input.latencyMs ?? 0,
    intelVersion: input.intelVersion ?? "unversioned",
  };
  if (input.domain) report.domain = input.domain;
  if (input.hostingHint) report.hostingHint = input.hostingHint;
  if (input.headers) report.headers = input.headers;
  if (input.cookies) report.cookies = input.cookies;
  if (input.tls) report.tls = input.tls;
  if (input.improvedPrompt) report.improvedPrompt = input.improvedPrompt;
  return report;
}

function educationFor(findings: Finding[]): Report["education"] {
  const categories = [...new Set(findings.map((finding) => finding.category))];
  return categories
    .filter((category) => EDUCATION[category])
    .map((category) => ({ category, text: EDUCATION[category] ?? "" }));
}

export function toLightweight(report: Report): LightweightReport {
  const light: LightweightReport = {
    id: report.id,
    createdAt: report.createdAt,
    blockDeploy: report.blockDeploy,
    verdict: report.verdict,
    findings: report.findings.map((finding) => ({
      id: finding.id,
      occurrenceId: finding.occurrenceId,
      title: finding.title,
      severity: finding.severity,
      file: finding.file,
      domain: finding.taxonomy.domain,
    })),
  };
  if (report.improvedPrompt) light.improvedPrompt = report.improvedPrompt;
  return light;
}

export interface ScanOptions {
  sourceType?: SourceType;
  limits?: ScanLimits;
  hostingHint?: HostingHint;
  prompt?: string;
  domain?: string;
  liveCsp?: boolean;
  now?: Date;
  latencyMs?: number;
  intelVersion?: string;
  extraFindings?: Finding[];
  checks?: Partial<ReportChecks>;
  headers?: Record<string, string>;
  cookies?: Report["cookies"];
  tls?: Report["tls"];
  improvedPrompt?: string;
}

export interface ScanResult {
  report: Report;
  ownedBuffers: Uint8Array[];
  artifactBytes: 0;
  codeDeleted: true;
}

/**
 * Scan named text files. Source is copied into buffers that are zeroed in
 * `finally`. The report keeps redacted evidence snippets and no source field.
 */
export function scanFiles(files: SourceFile[], options: ScanOptions = {}): ScanResult {
  const owned: Uint8Array[] = [];
  const texts: string[] = [];
  try {
    const prepared = prepareFiles(files, options.limits);
    const findings: Finding[] = [];
    let bytes = 0;
    for (const file of prepared) {
      const buffer = utf8Encode(file.content);
      owned.push(buffer);
      bytes += buffer.byteLength;
      texts.push(file.content);
      findings.push(...scanSource(file.name, file.content, { liveCsp: options.liveCsp }));
    }
    if (options.extraFindings) findings.push(...options.extraFindings);
    const report = buildReport({
      findings,
      sourceType: options.sourceType ?? "files",
      filesAnalyzed: prepared.length,
      bytesAnalyzed: bytes,
      domain: options.domain,
      hostingHint: options.hostingHint,
      checks: options.checks,
      headers: options.headers,
      cookies: options.cookies,
      tls: options.tls,
      now: options.now,
      latencyMs: options.latencyMs,
      intelVersion: options.intelVersion,
      improvedPrompt: options.improvedPrompt,
    });
    return { report, ownedBuffers: owned, artifactBytes: 0, codeDeleted: true };
  } finally {
    for (const buffer of owned) wipe(buffer);
    for (let i = 0; i < texts.length; i++) texts[i] = "";
  }
}

export async function scanFilesWithPrompt(
  files: SourceFile[],
  options: ScanOptions & { apiKey?: string; fetchImpl?: typeof fetch } = {},
): Promise<ScanResult> {
  const improvedPrompt = await maybeRewritePrompt(options.prompt, options.apiKey, options.fetchImpl);
  return scanFiles(files, { ...options, improvedPrompt });
}
