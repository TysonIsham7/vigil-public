import { NAV_BUDGET_MS, UrlRejected, headerFindings, inspectUrl, tlsRecommendation, type GateSignal } from "@vigil/core";
import { INTEL_VERSION, assessSite, classifyPhpExposure, evaluatePhp, phpSessionProgressNote, wordpressSignals } from "@vigil/intel";
import { anchorSpkiHashes, readMozillaPem } from "./bundle.js";
import {
  connectCertificateChain,
  evaluateCertificateChain,
  unavailableCertificate,
  type ParsedCert,
} from "./cert.js";
import { pinAddress, safeFetch, systemLookup, type AddressLookup } from "./fetch.js";
import { lookupDomainAge } from "./rdap.js";

export class VerdictTimeout extends Error {
  readonly code = "verdict_timeout" as const;

  constructor() {
    super("Host verdict exceeded the fast-path budget");
    this.name = "VerdictTimeout";
  }
}

export interface HostVerdict {
  host: string;
  intelVersion: string;
  coverage: "full";
  signals: GateSignal[];
}

/** RDAP is optional on the fast path. A hung registry must not discard a finished certificate. */
const RDAP_BUDGET_MS = 700;

interface PageSnapshot {
  body: string;
  headers: Record<string, string>;
  headerMap: Record<string, string | string[]>;
  setCookies: string[];
}

export async function hostVerdict(
  host: string,
  options: {
    now?: Date;
    fetchImpl?: typeof fetch;
    lookup?: AddressLookup;
    connectImpl?: (host: string, port: number, pem: string) => Promise<ParsedCert[]>;
    ageDays?: number | null;
    timeoutMs?: number;
    pem?: string;
  } = {},
): Promise<HostVerdict> {
  const target = inspectUrl(`https://${host}/`);
  await pinAddress(target.hostname, options.lookup ?? systemLookup);
  const timeoutMs = options.timeoutMs ?? NAV_BUDGET_MS;
  const now = options.now ?? new Date();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timedOut = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => resolve("timeout"), timeoutMs);
  });
  const pem = options.pem ?? readMozillaPem();
  const connect = options.connectImpl
    ?? ((name: string, port: number, bundle: string) => connectCertificateChain(name, port, bundle, 10_000, options.lookup));
  const certTask = certSignalsFor(target.hostname, pem, connect, now);
  const pageTask = pageSignals(target, options).catch((error: unknown) => {
    if (error instanceof UrlRejected) throw error;
    return null;
  });
  const ageTask = domainAge(target.hostname, now, options);
  try {
    const cert = await Promise.race([certTask.then((signals) => ({ signals })), timedOut]);
    if (cert === "timeout") throw new VerdictTimeout();
    const side = await Promise.race([
      Promise.all([pageTask, ageTask]).then(([page, age]) => ({ page, age })),
      timedOut.then(() => null),
    ]);
    return assemble(target, cert.signals, side?.page ?? null, side?.age ?? null);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function domainAge(
  host: string,
  now: Date,
  options: { fetchImpl?: typeof fetch; lookup?: AddressLookup; ageDays?: number | null },
): Promise<number | null> {
  if (options.ageDays !== undefined) return options.ageDays;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RDAP_BUDGET_MS);
  let capTimer: ReturnType<typeof setTimeout> | undefined;
  const lookup = lookupDomainAge(host, {
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.lookup ? { lookup: options.lookup } : {}),
    now,
    signal: controller.signal,
  }).then((result) => result.ageDays).catch(() => null);
  const cap = new Promise<null>((resolve) => {
    capTimer = setTimeout(() => resolve(null), RDAP_BUDGET_MS);
  });
  try {
    return await Promise.race([lookup, cap]);
  } finally {
    if (capTimer) clearTimeout(capTimer);
    clearTimeout(timer);
    controller.abort();
  }
}

function assemble(
  target: URL,
  certSignals: GateSignal[],
  page: PageSnapshot | null,
  age: number | null,
): HostVerdict {
  const body = page?.body ?? "";
  const headers = page?.headers ?? {};
  const setCookies = page?.setCookies ?? [];
  const host = target.hostname;
  const php = evaluatePhp({ headers, url: target.toString(), body, setCookies, audience: "visitor" });
  const wp = wordpressSignals(body);
  const site = assessSite({ host, ageDays: age, html: body, pageUrl: target.toString() });
  const headerSignals = page ? headerFindings(target.toString(), page.headerMap).findings.map(findingToSignal) : [];
  const signals = [...certSignals, ...headerSignals, ...site.signals.map(toSignal)];
  if (page) {
    const exposure = classifyPhpExposure(headers);
    signals.push({
      id: "PHP2SHELL_EXPOSURE",
      severity: exposure.severity,
      recommendationOnly: true,
      title: exposure.title,
      summary: exposure.summary,
      confidence: exposure.confidence,
    });
  }
  if (php.status === "vulnerable" || php.status === "suspected") {
    signals.push({
      id: "PHP_CVE_2026_109618",
      severity: php.severity === "informational" ? "high" : php.severity,
      recommendationOnly: php.recommendationOnly,
      title: php.status === "vulnerable" ? "Upgrade PHP" : "PHP detected without a version",
      summary: php.version
        ? `Upgrade PHP. PHP ${php.version} is below the fixed release. session.upload_progress.enabled=0 is only a partial mitigation for one path of CVE-2026-109619. CVE-2026-115560 still has no patched release.`
        : "The response looks like PHP, but no PHP/x.y.z version was disclosed. Upgrade PHP if this server runs it. CVE-2026-115560 still has no patched release.",
      confidence: php.version ? "high" : "medium",
    });
  }
  if (php.status === "fixed") {
    const note = phpSessionProgressNote(php.version);
    signals.push({
      id: note.id,
      severity: "informational",
      recommendationOnly: true,
      title: note.title,
      summary: note.summary,
      confidence: "medium",
    });
  }
  if (wp.present) {
    signals.push({
      id: "WP_FINGERPRINT",
      severity: "medium",
      recommendationOnly: true,
      title: "WordPress fingerprint",
      summary: wp.version ? `WordPress ${wp.version} is mentioned in public HTML.` : "The public HTML mentions WordPress.",
      confidence: "medium",
    });
  }
  return { host, intelVersion: INTEL_VERSION, coverage: "full", signals: dedupe(signals) };
}

async function certSignalsFor(
  host: string,
  pem: string,
  connect: (host: string, port: number, pem: string) => Promise<ParsedCert[]>,
  now: Date,
): Promise<GateSignal[]> {
  try {
    const chain = await connect(host, 443, pem);
    const evaluated = evaluateCertificateChain(chain, { host, now, trustedSpki: anchorSpkiHashes(pem) });
    const tls = tlsRecommendation({
      scheme: "https:",
      authorized: evaluated.cert.authorized,
      ...(evaluated.cert.error ? { error: evaluated.cert.error } : {}),
    });
    return [...evaluated.findings, ...tls].map(findingToSignal);
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
    const message = error instanceof Error ? error.message : "Certificate inspection failed";
    return unavailableCertificate(host, message).findings.map(findingToSignal);
  }
}

async function pageSignals(
  target: URL,
  options: { fetchImpl?: typeof fetch; lookup?: AddressLookup },
): Promise<PageSnapshot> {
  const page = await safeFetch(target.toString(), {
    ...(options.lookup ? { lookup: options.lookup } : {}),
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    maxBytes: 256 * 1024,
    timeoutMs: 1000,
  });
  const headers: Record<string, string> = {};
  for (const [key, value] of Object.entries(page.headers)) headers[key] = Array.isArray(value) ? value.join(", ") : value;
  const raw = page.headers["set-cookie"];
  return { body: page.body, headers, headerMap: page.headers, setCookies: raw ? (Array.isArray(raw) ? raw : [raw]) : [] };
}

function findingToSignal(finding: { id: string; severity: GateSignal["severity"]; recommendationOnly: boolean; title: string; summary: string; confidence?: GateSignal["confidence"] }): GateSignal {
  return {
    id: finding.id,
    severity: finding.severity,
    recommendationOnly: finding.recommendationOnly,
    title: finding.title,
    summary: finding.summary,
    ...(finding.confidence ? { confidence: finding.confidence } : {}),
  };
}

function toSignal(signal: { id: string; severity: GateSignal["severity"]; recommendationOnly: boolean; title: string; summary: string }): GateSignal {
  return { ...signal, confidence: signal.severity === "critical" ? "high" : "medium" };
}

function dedupe(signals: GateSignal[]): GateSignal[] {
  const seen = new Set<string>();
  return signals.filter((signal) => {
    if (seen.has(signal.id)) return false;
    seen.add(signal.id);
    return true;
  });
}

/** A bare hostname. Schemes, paths, and userinfo are rejected before any network call. */
export function verdictHost(value: string): string | null {
  const host = value.trim().toLowerCase().replace(/\.$/, "");
  if (!host || host.length > 253 || /[/\\@\s?#]/.test(host)) return null;
  const literal = host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
  try {
    return inspectUrl(`https://${literal}/`).hostname;
  } catch {
    return null;
  }
}
