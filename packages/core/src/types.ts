export const REPORT_VERSION = "2.0" as const;

export const DISCLAIMER =
  "Vigil is a first-pass filter, not an audit. Sites that handle money, health, or credentials still need a professional review.";

export type Severity = "critical" | "high" | "medium" | "low" | "informational";
export type Confidence = "high" | "medium" | "low";
export type Verdict = "allow" | "warn" | "block";
export type SourceType = "files" | "url" | "drive" | "sample";
export type HostingHint = "vercel" | "netlify" | "cloudflare";
export type CheckLevel = "ok" | "warn" | "block" | "unknown";

/** Closed set. Labels and per-rule mappings live in data/rule-catalog.json. */
export const TAXONOMY_DOMAIN_IDS = [
  "grc",
  "identity-access",
  "data-security-privacy",
  "network-infrastructure",
  "endpoint-device",
  "application-software",
  "cloud-hybrid",
  "threat-intel",
  "operational-resilience",
  "human-factors",
  "emerging-tech",
] as const;

export type TaxonomyDomainId = (typeof TAXONOMY_DOMAIN_IDS)[number];
export type NistCsfFunction = "GV" | "ID" | "PR" | "DE" | "RS" | "RC";

export interface FindingTaxonomy {
  domain: TaxonomyDomainId;
  domainLabel: string;
  nistCsf: {
    function: NistCsfFunction;
    functionLabel: string;
    category: string;
    categoryLabel: string;
  };
  cis: {
    version: "8.1";
    control: number;
    controlTitle: string;
    safeguard?: string;
    safeguardTitle?: string;
  } | null;
}

export interface Finding {
  id: string;
  occurrenceId: string;
  severity: Severity;
  confidence: Confidence;
  title: string;
  summary: string;
  why: string;
  remediation: string[];
  file: string;
  line: number;
  evidence: string;
  agentAction: string;
  category: string;
  recommendationOnly: boolean;
  taxonomy: FindingTaxonomy;
}

export interface DomainCount {
  id: TaxonomyDomainId;
  label: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface SummaryCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
  byDomain: DomainCount[];
}

export interface CertCheck {
  host: string;
  level: CheckLevel;
  authorized: boolean | null;
  issuer?: string;
  daysRemaining?: number | null;
  hostnameMatches?: boolean | null;
  distrusted: { name: string; spkiSha256: string }[];
  selfSigned: boolean;
  weakKey: boolean;
  sha1: boolean;
  sct: {
    present: boolean;
    count: number;
    wellFormed: boolean;
    signaturesVerified: false;
    note: string;
  };
  error?: string;
}

export interface DomainCheck {
  host: string;
  registrableDomain?: string;
  level: CheckLevel;
  ageDays?: number | null;
  registeredAt?: string;
  lookalike?: { brand: string; confidence: "high" | "medium"; reason: string };
  mixedScript: boolean;
  ipLiteral: boolean;
  suspiciousTld: boolean;
  freeHosting: boolean;
  subdomainDepth: number;
  credentialForm: boolean;
  credentialCrossOrigin: boolean;
  credentialInsecure: boolean;
  brandImpersonation?: { brand: string; withCredential: boolean };
  reputation: { provider: string; status: string; detail?: string }[];
  error?: string;
}

export interface VulnCheck {
  advisoryId: string;
  cves: string[];
  component: string;
  detectedVersion?: string;
  status: "vulnerable" | "suspected" | "fingerprint" | "fixed" | "not-applicable" | "unknown";
  audience: "owner" | "visitor" | "local";
  level: CheckLevel | "info";
  mitigation?: string;
}

export interface DepCheck {
  ecosystem: string;
  name: string;
  version: string;
  source: string;
  advisoryId?: string;
  osvIds?: string[];
  level: CheckLevel | "info";
  summary: string;
}

export interface ReportChecks {
  cert: CertCheck | null;
  domain: DomainCheck | null;
  vulns: VulnCheck[];
  deps: DepCheck[];
}

export interface Report {
  version: typeof REPORT_VERSION;
  id: string;
  createdAt: string;
  sourceType: SourceType;
  domain?: string;
  hostingHint?: HostingHint;
  blockDeploy: boolean;
  verdict: Verdict;
  summary: SummaryCounts;
  findings: Finding[];
  headers?: Record<string, string>;
  cookies?: { name: string; secure: boolean; httpOnly: boolean; sameSite: boolean }[];
  tls?: {
    authorized: boolean | null;
    issuer?: string;
    daysRemaining?: number | null;
    error?: string;
    protocol?: string;
    cipher?: string;
  };
  improvedPrompt?: string;
  education: { category: string; text: string }[];
  disclaimer: string;
  codeDeleted: true;
  artifactBytes: 0;
  retention: "ephemeral";
  expiresAt: string;
  filesAnalyzed: number;
  bytesAnalyzed: number;
  checks: ReportChecks;
  latencyMs: number;
  intelVersion: string;
}

export interface LightweightFinding {
  id: string;
  occurrenceId: string;
  title: string;
  severity: Severity;
  file: string;
  domain: TaxonomyDomainId;
}

export interface LightweightReport {
  id: string;
  createdAt: string;
  blockDeploy: boolean;
  verdict: Verdict;
  findings: LightweightFinding[];
  improvedPrompt?: string;
}

export interface SourceFile {
  name: string;
  content: string;
}

export interface ScanLimits {
  perFileBytes: number;
  totalBytes: number;
  fileCount: number;
  liveResponseBytes: number;
  wallClockMs: number;
}

export const DEFAULT_LIMITS: ScanLimits = {
  perFileBytes: 2 * 1024 * 1024,
  totalBytes: 8 * 1024 * 1024,
  fileCount: 40,
  liveResponseBytes: Math.floor(1.5 * 1024 * 1024),
  wallClockMs: 12_000,
};

export const REPORT_TTL_MS = 15 * 60 * 1000;
