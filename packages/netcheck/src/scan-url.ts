import {
  DEFAULT_LIMITS,
  UrlRejected,
  dropCspMissing,
  headerFindings,
  scanFilesWithPrompt,
  tlsRecommendation,
  type Finding,
  type HostingHint,
  type ReportChecks,
  type ScanLimits,
  type ScanResult,
} from "@vigil/core";
import {
  INTEL_VERSION,
  assessSite,
  disabledReputation,
  PHP2SHELL_RULE,
  classifyPhpExposure,
  evaluatePhp,
  phpAdvisory,
  phpSessionAdvisory,
  phpSessionProgressNote,
  phpSessionUnfixedLine,
  registrableDomain,
  wordpressReadmeVersion,
  wordpressSignals,
} from "@vigil/intel";
import { anchorSpkiHashes, readMozillaPem } from "./bundle.js";
import { sharedHostFinding } from "./doctor.js";
import {
  connectCertificateChain,
  evaluateCertificateChain,
  unavailableCertificate,
  type ChainEvaluation,
} from "./cert.js";
import type { AddressLookup } from "./fetch.js";
import { safeFetch } from "./fetch.js";
import { agentPageFindings, redactInstructionHeaders } from "./agent-page.js";
import { netFinding } from "./finding.js";
import { crtShEarliest, lookupDomainAge } from "./rdap.js";

export interface ScanUrlOptions {
  audience: "owner" | "visitor";
  hostingHint?: HostingHint;
  allowHosts?: string[];
  ct?: boolean;
  lookup?: AddressLookup;
  fetchImpl?: typeof fetch;
  inspectChain?: (host: string, port: number) => Promise<ChainEvaluation>;
  now?: Date;
  prompt?: string;
  apiKey?: string;
  limits?: ScanLimits;
  intelVersion?: string;
}

export async function scanUrl(input: string, options: ScanUrlOptions): Promise<ScanResult> {
  const started = Date.now();
  const now = options.now ?? new Date();
  const limits = options.limits ?? DEFAULT_LIMITS;
  const fetchImpl = options.fetchImpl ?? fetch;
  const page = await safeFetch(input, {
    ...(options.lookup ? { lookup: options.lookup } : {}),
    fetchImpl,
    maxBytes: limits.liveResponseBytes,
    timeoutMs: limits.wallClockMs,
  });
  const finalUrl = new URL(page.url);
  const budget = () => Date.now() - started < limits.wallClockMs;
  const files = [{ name: safeName(finalUrl.pathname, "index.html"), content: page.body }];
  if (budget()) {
    for (const src of scriptSources(page.body).slice(0, 4)) {
      const target = sameOrigin(finalUrl, src);
      if (!target || !budget()) continue;
      try {
        const script = await safeFetch(target.toString(), {
          ...(options.lookup ? { lookup: options.lookup } : {}),
          fetchImpl,
          maxBytes: limits.liveResponseBytes,
          timeoutMs: Math.max(1, limits.wallClockMs - (Date.now() - started)),
        });
        files.push({ name: safeName(target.pathname, "script.js"), content: script.body });
      } catch {
        continue;
      }
    }
  }

  const headerResult = headerFindings(page.url, page.headers);
  const certPromise = finalUrl.protocol === "https:" ? loadCert(finalUrl, options, now) : Promise.resolve(null);
  const rdapPromise = lookupDomainAge(finalUrl.hostname, {
    fetchImpl,
    now,
    ...(options.lookup ? { lookup: options.lookup } : {}),
  });
  const [certResult, rdap] = await Promise.all([certPromise, rdapPromise]);
  const html = page.body;
  const wp = wordpressSignals(html);
  if (wp.present && !wp.version && budget()) {
    try {
      const readme = await safeFetch(new URL("/readme.html", finalUrl.origin).toString(), {
        ...(options.lookup ? { lookup: options.lookup } : {}),
        fetchImpl,
        maxBytes: limits.liveResponseBytes,
        timeoutMs: Math.max(1, limits.wallClockMs - (Date.now() - started)),
      });
      const version = wordpressReadmeVersion(readme.body);
      if (version) wp.version = version;
    } catch {
      // One public readme fetch is optional.
    }
  }

  const setCookies = cookieValues(page.headers["set-cookie"]);
  const php = evaluatePhp({
    headers: stringHeaders(page.headers),
    url: page.url,
    body: html,
    setCookies,
    audience: options.audience,
  });
  const assessment = assessSite({
    host: finalUrl.hostname,
    allowlist: options.allowHosts,
    ageDays: rdap.ageDays,
    html,
    pageUrl: page.url,
  });
  const reputation = [
    await disabledReputation("safe-browsing").check({ host: finalUrl.hostname, registrableDomain: assessment.registrableDomain }),
    await disabledReputation("phishtank").check({ host: finalUrl.hostname, registrableDomain: assessment.registrableDomain }),
  ];
  if (options.ct) {
    const ct = await crtShEarliest(registrableDomain(finalUrl.hostname), fetchImpl);
    reputation.push({
      provider: "crt.sh",
      status: ct.error ? "unknown" : "clean",
      ...(ct.earliest ? { detail: `earliest ${ct.earliest}` } : {}),
      ...(ct.error ? { detail: ct.error } : {}),
    });
  }

  const extra: Finding[] = [...headerResult.findings];
  if (certResult) extra.push(...certResult.findings, ...tlsRecommendation({ scheme: finalUrl.protocol, authorized: certResult.cert.authorized, ...(certResult.cert.error ? { error: certResult.cert.error } : {}) }));
  else extra.push(...tlsRecommendation({ scheme: finalUrl.protocol, authorized: null }));
  for (const signal of assessment.signals) {
    extra.push(netFinding({
      id: signal.id,
      severity: signal.severity,
      title: signal.title,
      summary: signal.summary,
      why: "The hostname, page text, or domain age matched a bundled fake-site check. No page content is stored.",
      remediation: ["Treat the host as untrusted until the name, certificate, and form target are confirmed."],
      recommendationOnly: signal.recommendationOnly,
      category: "phishing",
      evidence: signal.summary,
    }));
  }
  const exposure = classifyPhpExposure(stringHeaders(page.headers));
  extra.push(netFinding({
    id: PHP2SHELL_RULE,
    severity: exposure.severity,
    title: exposure.title,
    summary: exposure.summary,
    why: exposure.status === "exposed"
      ? `The class comes from the X-Powered-By and Server headers already on this response. Vigil did not send another request. ${phpAdvisory.knownExploited}`
      : "The class comes from the X-Powered-By and Server headers already on this response. Vigil did not send another request.",
    remediation: exposure.status === "exposed"
      ? [phpAdvisory.upgrade, phpAdvisory.mitigation, phpAdvisory.kevAction]
      : exposure.status === "hidden"
        ? [phpAdvisory.upgrade, phpAdvisory.mitigation]
        : ["Those headers do not show an unpatched PHP version."],
    recommendationOnly: true,
    category: "vulnerability",
    confidence: exposure.confidence,
    evidence: exposure.version ? `${exposure.status} PHP/${exposure.version}` : exposure.status,
  }));
  if (php.status === "vulnerable" || php.status === "suspected") {
    extra.push(netFinding({
      id: "PHP_CVE_2026_109618",
      severity: php.severity === "informational" ? "high" : php.severity,
      title: php.status === "vulnerable" ? "Upgrade PHP" : "PHP detected without a version",
      summary: php.version
        ? `Upgrade PHP. PHP ${php.version} is below the fixed release for CVE-2026-109618 and CVE-2026-109619. CVE-2026-115560 still has no patched release.`
        : "The response looks like PHP, but no PHP/x.y.z version was disclosed. Upgrade PHP if this server runs it. CVE-2026-115560 still has no patched release.",
      why: `${options.audience === "owner"
        ? "A confirmed vulnerable version on the owner's scan is a critical deploy block. A missing version stays a recommendation."
        : "A visitor scan warns instead of blocking, because the visitor does not control the server."}${php.version ? ` ${phpAdvisory.knownExploited}` : ""}`,
      remediation: php.version
        ? [phpAdvisory.upgrade, phpAdvisory.mitigation, phpSessionUnfixedLine(), phpAdvisory.kevAction]
        : [phpAdvisory.upgrade, phpAdvisory.mitigation, phpSessionUnfixedLine()],
      recommendationOnly: php.recommendationOnly,
      category: "vulnerability",
      confidence: php.version ? "high" : "medium",
      evidence: php.version ?? "version not disclosed",
    }));
  }
  if (php.status === "fixed") {
    const note = phpSessionProgressNote(php.version);
    extra.push(netFinding({
      id: note.id,
      severity: "informational",
      title: note.title,
      summary: note.summary,
      why: "The 21 October 2026 PHP releases fix CVE-2026-109618 and CVE-2026-109619. PHP's 23 October note says they do not fix CVE-2026-115560, and no patched release exists yet.",
      remediation: note.remediation,
      recommendationOnly: true,
      category: "vulnerability",
      confidence: "medium",
      evidence: php.version ?? "version not disclosed",
    }));
  }
  if (wp.present) {
    extra.push(netFinding({
      id: "WP_FINGERPRINT",
      severity: "informational",
      title: "WordPress fingerprint",
      summary: wp.version ? `WordPress ${wp.version} was disclosed by public markup.` : "The page references WordPress paths or a generator tag.",
      why: "This is a passive fingerprint. Vigil fetched at most one extra public readme when the version was missing.",
      remediation: ["Remove the generator tag and public readme if the version does not need to be disclosed."],
      recommendationOnly: true,
      category: "vulnerability",
      evidence: wp.version ?? "wordpress",
    }));
  }
  extra.push(...await agentPageFindings({
    html: page.body,
    headers: page.headers,
    budget,
    origin: finalUrl.origin,
    fetchExtra: (url) => safeFetch(url, {
      ...(options.lookup ? { lookup: options.lookup } : {}),
      fetchImpl,
      maxBytes: limits.liveResponseBytes,
      timeoutMs: Math.max(1, limits.wallClockMs - (Date.now() - started)),
    }),
  }));
  extra.push(sharedHostFinding());
  if (page.truncated) {
    extra.push(netFinding({
      id: "FETCH_TRUNCATED",
      severity: "medium",
      title: "Response exceeded the size cap",
      summary: `The body was truncated at ${limits.liveResponseBytes} bytes.`,
      why: "Vigil stops reading so a large response cannot exhaust the scanner. Findings below that cut may be missed.",
      remediation: ["Scan the source files directly if the live page is larger than the cap."],
      recommendationOnly: true,
      category: "limits",
      evidence: `${limits.liveResponseBytes} bytes`,
    }));
  }

  const filtered = dropCspMissing(extra, page.headers);
  const checks: ReportChecks = {
    cert: certResult?.cert ?? null,
    domain: {
      host: assessment.host,
      registrableDomain: assessment.registrableDomain,
      level: assessment.level,
      ageDays: rdap.ageDays,
      ...(rdap.registeredAt ? { registeredAt: rdap.registeredAt } : {}),
      ...(assessment.lookalike ? { lookalike: assessment.lookalike } : {}),
      mixedScript: assessment.mixedScript,
      ipLiteral: assessment.ipLiteral,
      suspiciousTld: assessment.suspiciousTld,
      freeHosting: assessment.freeHosting,
      subdomainDepth: assessment.subdomainDepth,
      credentialForm: assessment.credentialForm,
      credentialCrossOrigin: assessment.credentialCrossOrigin,
      credentialInsecure: assessment.credentialInsecure,
      ...(assessment.brandImpersonation ? { brandImpersonation: assessment.brandImpersonation } : {}),
      reputation,
      ...(rdap.error ? { error: rdap.error } : {}),
    },
    vulns: [
      ...(php.status === "not-applicable"
        ? []
        : [{
            advisoryId: phpAdvisory.id,
            cves: [...phpAdvisory.cves],
            component: "php",
            ...(php.version ? { detectedVersion: php.version } : {}),
            status: php.status,
            audience: options.audience,
            level: php.level === "ok" ? "ok" as const : php.level === "block" ? "block" as const : php.level === "info" ? "info" as const : "warn" as const,
            mitigation: `${phpAdvisory.upgrade} ${phpAdvisory.mitigation}`,
          }]),
      ...(php.status === "not-applicable"
        ? []
        : [{
            advisoryId: phpSessionAdvisory.id,
            cves: [...phpSessionAdvisory.cves],
            component: "php",
            ...(php.version ? { detectedVersion: php.version } : {}),
            status: "suspected" as const,
            audience: options.audience,
            level: "info" as const,
            mitigation: php.status === "fixed" ? phpSessionAdvisory.mitigation : phpSessionUnfixedLine(),
          }]),
      ...(wp.present
        ? [{
            advisoryId: "WP-FINGERPRINT",
            cves: [],
            component: "wordpress",
            ...(wp.version ? { detectedVersion: wp.version } : {}),
            status: "fingerprint" as const,
            audience: options.audience,
            level: "info" as const,
          }]
        : []),
    ],
    deps: [],
  };
  const result = await scanFilesWithPrompt(files, {
    sourceType: "url",
    limits,
    ...(options.hostingHint ? { hostingHint: options.hostingHint } : {}),
    ...(options.prompt ? { prompt: options.prompt } : {}),
    ...(options.apiKey ? { apiKey: options.apiKey } : {}),
    domain: finalUrl.hostname,
    liveCsp: Boolean(stringHeaders(page.headers)["content-security-policy"]),
    now,
    latencyMs: Date.now() - started,
    intelVersion: options.intelVersion ?? INTEL_VERSION,
    extraFindings: filtered,
    checks,
    headers: flatHeaders(redactInstructionHeaders(page.headers)),
    cookies: headerResult.cookies.map((cookie) => ({
      name: cookie.name,
      secure: cookie.secure,
      httpOnly: cookie.httpOnly,
      sameSite: cookie.sameSite,
    })),
    ...(certResult
      ? {
          tls: {
            authorized: certResult.cert.authorized,
            ...(certResult.cert.issuer ? { issuer: certResult.cert.issuer } : {}),
            daysRemaining: certResult.cert.daysRemaining ?? null,
            ...(certResult.cert.error ? { error: certResult.cert.error } : {}),
          },
        }
      : {}),
    fetchImpl,
  });
  return result;
}

async function loadCert(url: URL, options: ScanUrlOptions, now: Date): Promise<ChainEvaluation> {
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const port = url.port ? Number(url.port) : 443;
  try {
    if (options.inspectChain) return await options.inspectChain(host, port);
    const pem = readMozillaPem();
    const chain = await connectCertificateChain(host, port, pem, 10_000, options.lookup);
    return evaluateCertificateChain(chain, { host, now, trustedSpki: anchorSpkiHashes(pem) });
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
    return unavailableCertificate(host, error instanceof Error ? error.message : "Certificate inspection failed");
  }
}

function safeName(pathname: string, fallback: string): string {
  const trimmed = pathname.replace(/^\/+/, "").replaceAll("\\", "/");
  return trimmed && trimmed !== "." && trimmed !== ".." ? trimmed : fallback;
}

function scriptSources(html: string): string[] {
  return [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*['"]([^'"]+)['"]/gi)].flatMap((match) => (match[1] ? [match[1]] : []));
}

function sameOrigin(page: URL, src: string): URL | undefined {
  try {
    const next = new URL(src, page);
    if (next.origin !== page.origin) return undefined;
    if (next.protocol !== "http:" && next.protocol !== "https:") return undefined;
    return next;
  } catch {
    return undefined;
  }
}

function cookieValues(value: string | string[] | undefined): string[] {
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function stringHeaders(headers: Record<string, string | string[]>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    out[key] = Array.isArray(value) ? value.join(", ") : value;
  }
  return out;
}

function flatHeaders(headers: Record<string, string | string[]>): Record<string, string> {
  return stringHeaders(headers);
}
