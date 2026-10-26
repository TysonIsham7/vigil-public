/**
 * Passive backend exposure check for a site the operator visits as a client.
 * Requests are ordinary GETs, one browser-style TLS handshake, and two
 * protocol-support handshakes. Do not add crash payloads, oversized headers,
 * request bodies, or exploit probes here.
 */
import {
  DEFAULT_LIMITS,
  UrlRejected,
  buildReport,
  inspectUrl,
  isBlockedHostname,
  isBlockedIp,
  parseCookieFlags,
  redactEvidence,
  type CertCheck,
  type Finding,
  type Report,
  type ScanLimits,
  type VulnCheck,
} from "@vigil/core";
import { INTEL_VERSION, classifyPhpHeaders, phpAdvisory, phpSessionAdvisory, phpSessionProgressNote, phpSessionUnfixedLine, type PhpHeaderExposure } from "@vigil/intel";
import { anchorSpkiHashes, readMozillaPem } from "./bundle.js";
import {
  evaluateCertificateChain,
  observeTlsHandshake,
  probeLegacyProtocols,
  unavailableCertificate,
  type ParsedCert,
} from "./cert.js";
import { safeFetch, type AddressLookup } from "./fetch.js";
import { netFinding } from "./finding.js";

export const BACKEND_ERROR_PATH = "/this-page-is-missing";

export const BACKEND_KNOWN_PATHS = [
  "/.git/HEAD",
  "/.svn/entries",
  "/server-status",
  "/server-info",
  "/phpinfo.php",
  "/info.php",
  "/elmah.axd",
  "/trace.axd",
] as const;

const PROBE_PATHS = [BACKEND_ERROR_PATH, ...BACKEND_KNOWN_PATHS];

/** AEAD suites first, then ordinary CBC suites. No export, null, RC4, or DES. */
export const BACKEND_CIPHER_OFFER = [
  "TLS_AES_128_GCM_SHA256",
  "TLS_AES_256_GCM_SHA384",
  "TLS_CHACHA20_POLY1305_SHA256",
  "ECDHE-ECDSA-AES128-GCM-SHA256",
  "ECDHE-RSA-AES128-GCM-SHA256",
  "ECDHE-ECDSA-AES256-GCM-SHA384",
  "ECDHE-RSA-AES256-GCM-SHA384",
  "ECDHE-ECDSA-CHACHA20-POLY1305",
  "ECDHE-RSA-CHACHA20-POLY1305",
  "ECDHE-ECDSA-AES128-SHA",
  "ECDHE-RSA-AES128-SHA",
  "ECDHE-ECDSA-AES256-SHA",
  "ECDHE-RSA-AES256-SHA",
  "AES128-GCM-SHA256",
  "AES256-GCM-SHA384",
  "AES128-SHA",
  "AES256-SHA",
] as const;

const TIMING_MIN_SAMPLES = 3;
const TIMING_RATIO = 4;
const TIMING_DELTA_MS = 800;
const BODY_SCAN_CHARS = 64 * 1024;

const COOKIE_HINTS: { name: string; product: string }[] = [
  { name: "PHPSESSID", product: "PHP" },
  { name: "JSESSIONID", product: "Java" },
  { name: "ASP.NET_SessionId", product: "ASP.NET" },
  { name: "laravel_session", product: "Laravel" },
  { name: "rack.session", product: "Ruby Rack" },
  { name: "connect.sid", product: "Express" },
  { name: "_session_id", product: "Ruby on Rails" },
];

const FRAMEWORKS: { name: string; pattern: RegExp }[] = [
  { name: "nginx", pattern: /<center>nginx<\/center>|nginx\/\d+\.\d+\.\d+/i },
  { name: "Apache httpd", pattern: /Apache\/\d+\.\d+\.\d+|The requested URL was not found on this server/i },
  { name: "Microsoft IIS", pattern: /Microsoft-IIS\/\d+|Internet Information Services/i },
  { name: "Apache Tomcat", pattern: /Apache Tomcat\/\d+/i },
  { name: "ASP.NET", pattern: /Server Error in '\/' Application/i },
  { name: "Express", pattern: /Cannot (?:GET|HEAD) \// },
  { name: "Django", pattern: /Django Version:|DEBUG = True/i },
  { name: "Werkzeug", pattern: /Werkzeug Debugger/i },
  { name: "Laravel", pattern: /Illuminate\\Foundation|Whoops\\Exception/ },
  { name: "Ruby on Rails", pattern: /Action Controller: Exception caught|Rails\.root/ },
  { name: "PHP", pattern: /(?:Fatal error|Parse error): .+\.php on line \d+/i },
  { name: "Java", pattern: /java\.lang\.\w+(?:Exception|Error)/ },
  { name: "Python", pattern: /Traceback \(most recent call last\)/ },
];

const TRACES: { name: string; pattern: RegExp }[] = [
  { name: "a stack trace", pattern: /Stack trace:|Traceback \(most recent call last\)/i },
  { name: "a filesystem path", pattern: /(?:\/var\/www\/|\/home\/[A-Za-z0-9._-]+\/|\/srv\/|C:\\inetpub\\|C:\\Windows\\)/ },
  { name: "a SQL error", pattern: /SQLSTATE\[|You have an error in your SQL syntax|PSQLException/i },
];

export function tls12CipherList(offer: readonly string[] = BACKEND_CIPHER_OFFER): string {
  return offer.filter((name) => !name.startsWith("TLS_")).join(":");
}

export interface BackendResponse {
  url: string;
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  truncated: boolean;
  /** Full GET, including the body download. Timing findings do not use this. */
  elapsedMs: number;
  /** Milliseconds until response headers. Absent means the sample is not timed. */
  ttfbMs?: number;
}

export interface BackendHandshakeResult {
  protocol: string;
  cipher: string;
  offeredCiphers: readonly string[];
  certs: ParsedCert[];
  /** Protocols that completed a TLS 1.0 or TLS 1.1 handshake. Empty when the server refused both. */
  legacyProtocols?: readonly string[];
}

export type BackendTransport = (url: string) => Promise<BackendResponse>;
export type BackendHandshake = (host: string, port: number) => Promise<BackendHandshakeResult>;

export interface CheckBackendOptions {
  transport?: BackendTransport;
  handshake?: BackendHandshake;
  lookup?: AddressLookup;
  fetchImpl?: typeof fetch;
  trustedSpki?: ReadonlySet<string>;
  now?: Date;
  limits?: ScanLimits;
}

export interface BackendAssessment {
  findings: Finding[];
  cert: CertCheck | null;
  vulns: VulnCheck[];
  headers: Record<string, string>;
  cookies: NonNullable<Report["cookies"]>;
  tls?: Report["tls"];
}

export function assessBackend(input: {
  pageUrl: string;
  responses: BackendResponse[];
  handshake: BackendHandshakeResult | { error: string } | null;
  now: Date;
  trustedSpki: ReadonlySet<string>;
  maxBytes?: number;
}): BackendAssessment {
  const findings: Finding[] = [];
  const headers = mergedHeaders(input.responses);
  const cookies = allCookies(input.responses);
  headerFindings(findings, headers, cookies);
  const php = classifyPhpHeaders(input.responses.map((response) => ({
    headers: flatHeaders(response.headers),
    setCookies: cookieList(response.headers),
  })));
  phpFinding(findings, php);
  pathFindings(findings, input.responses);
  errorFindings(findings, input.responses);
  const tls = tlsFindings(findings, input);
  if (input.responses.some((response) => response.truncated)) {
    add(findings, {
      id: "FETCH_TRUNCATED",
      severity: "medium",
      confidence: "high",
      title: "Response exceeded the size cap",
      summary: `A response body was truncated at ${input.maxBytes ?? DEFAULT_LIMITS.liveResponseBytes} bytes.`,
      why: "Vigil stops reading so a large response cannot exhaust the scanner.",
      remediation: ["The notes above cover only the bytes that were read."],
      category: "limits",
      evidence: "truncated",
    });
  }
  const vuln = phpVuln(php);
  const session = phpSessionVuln(php);
  return {
    findings,
    cert: tls.cert,
    vulns: [vuln, session].filter((item): item is VulnCheck => item !== undefined),
    headers,
    cookies: cookies.map((raw) => {
      const parsed = parseCookieFlags(raw);
      return { name: parsed.name, secure: parsed.secure, httpOnly: parsed.httpOnly, sameSite: parsed.sameSite };
    }),
    ...(tls.view ? { tls: tls.view } : {}),
  };
}

export async function checkBackend(input: string, options: CheckBackendOptions = {}): Promise<Report> {
  const started = Date.now();
  const now = options.now ?? new Date();
  const limits = options.limits ?? DEFAULT_LIMITS;
  const page = inspectUrl(input);
  const transport = options.transport ?? ((url: string) => defaultTransport(url, options, limits));
  const responses: BackendResponse[] = [];
  let landed = page;
  try {
    const first = await transport(page.toString());
    landed = inspectUrl(first.url);
    responses.push(first);
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
    if (page.protocol !== "https:" || !tlsCertificateFailure(error)) throw error;
  }
  for (const path of PROBE_PATHS) {
    if (responses.length === 0) break;
    if (Date.now() - started >= limits.wallClockMs) break;
    const next = inspectUrl(new URL(path, landed.origin).toString());
    if (next.origin !== landed.origin) continue;
    if (responses.some((response) => pathnameOf(response.url) === next.pathname)) continue;
    try {
      const response = await transport(next.toString());
      const responseUrl = new URL(response.url);
      if (responseUrl.origin !== landed.origin) continue;
      responses.push(response);
    } catch (error) {
      if (error instanceof UrlRejected) throw error;
    }
  }

  let handshake: BackendHandshakeResult | { error: string } | null = null;
  if (landed.protocol === "https:") {
    const host = landed.hostname.replace(/^\[|\]$/g, "");
    const port = landed.port ? Number(landed.port) : 443;
    try {
      handshake = options.handshake
        ? await options.handshake(host, port)
        : await defaultHandshake(host, port, options.lookup);
    } catch (error) {
      if (error instanceof UrlRejected) throw error;
      handshake = { error: error instanceof Error ? error.message : "TLS handshake failed" };
    }
  }

  const bytes = responses.reduce((sum, response) => sum + Buffer.byteLength(response.body), 0);
  const trusted = handshake && !("error" in handshake)
    ? (options.trustedSpki ?? anchorSpkiHashes(readMozillaPem()))
    : new Set<string>();
  const assessment = assessBackend({
    pageUrl: landed.toString(),
    responses,
    handshake,
    now,
    trustedSpki: trusted,
    maxBytes: limits.liveResponseBytes,
  });
  for (const response of responses) response.body = "";
  return buildReport({
    findings: assessment.findings,
    sourceType: "url",
    filesAnalyzed: responses.length,
    bytesAnalyzed: bytes,
    domain: landed.hostname.replace(/^\[|\]$/g, ""),
    checks: { cert: assessment.cert, vulns: assessment.vulns },
    headers: assessment.headers,
    cookies: assessment.cookies,
    ...(assessment.tls ? { tls: assessment.tls } : {}),
    now,
    latencyMs: Date.now() - started,
    intelVersion: INTEL_VERSION,
  });
}

function defaultTransport(url: string, options: CheckBackendOptions, limits: ScanLimits): Promise<BackendResponse> {
  const started = Date.now();
  return safeFetch(url, {
    ...(options.lookup ? { lookup: options.lookup } : {}),
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    maxBytes: limits.liveResponseBytes,
    timeoutMs: limits.wallClockMs,
    headers: { accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" },
  }).then((page) => ({
    url: page.url,
    status: page.status,
    headers: page.headers,
    body: page.body,
    truncated: page.truncated,
    elapsedMs: Date.now() - started,
    ttfbMs: page.ttfbMs,
  }));
}

async function defaultHandshake(host: string, port: number, lookup?: AddressLookup): Promise<BackendHandshakeResult> {
  const ca = readMozillaPem();
  let observed: Awaited<ReturnType<typeof observeTlsHandshake>> | undefined;
  let failure: unknown;
  try {
    observed = await observeTlsHandshake(host, port, ca, tls12CipherList(), 10_000, lookup);
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
    failure = error;
  }
  let legacyProtocols: string[] = [];
  let legacyCerts: ParsedCert[] = [];
  try {
    const legacy = await probeLegacyProtocols(host, port, 5_000, lookup);
    legacyProtocols = [...legacy.protocols];
    legacyCerts = legacy.certs;
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
  }
  if (observed) return { ...observed, offeredCiphers: BACKEND_CIPHER_OFFER, legacyProtocols };
  const legacyProtocol = legacyProtocols[0];
  if (legacyProtocol) {
    return {
      protocol: legacyProtocol,
      cipher: "",
      offeredCiphers: BACKEND_CIPHER_OFFER,
      certs: legacyCerts,
      legacyProtocols,
    };
  }
  throw failure instanceof Error ? failure : new Error("TLS handshake failed");
}

const TLS_CERTIFICATE_CODES = new Set([
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "CERT_DATE_INVALID",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "ERR_TLS_CERT_ALTNAME_INVALID",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_SIGNATURE_FAILURE",
  "CERT_REVOKED",
  "CERT_UNTRUSTED",
  "CERT_REJECTED",
  "CERT_CHAIN_TOO_LONG",
]);

function tlsCertificateFailure(error: unknown): boolean {
  const seen = new Set<unknown>();
  let current: unknown = error;
  while (current && typeof current === "object" && !seen.has(current)) {
    seen.add(current);
    const record = current as { code?: unknown; message?: unknown; cause?: unknown };
    if (typeof record.code === "string" && TLS_CERTIFICATE_CODES.has(record.code)) return true;
    if (typeof record.message === "string" && /certificate has expired|not yet valid|self[- ]signed certificate|unable to verify the first certificate|altnames|does not match certificate/i.test(record.message)) return true;
    current = record.cause;
  }
  return false;
}

type BackendFinding = Omit<Parameters<typeof netFinding>[0], "recommendationOnly" | "category"> & {
  recommendationOnly?: boolean;
  category?: string;
};

function add(findings: Finding[], input: BackendFinding): void {
  findings.push(netFinding({
    category: "backend",
    ...input,
    recommendationOnly: input.recommendationOnly ?? true,
    evidence: redactEvidence(input.evidence ?? input.title),
    line: findings.length + 1,
  }));
}

function headerFindings(findings: Finding[], headers: Record<string, string>, cookies: string[]): void {
  const server = headers["server"]?.trim() ?? "";
  if (server) {
    const versioned = /\d+\.\d+/.test(server);
    add(findings, {
      id: "BACKEND_HEADER_SERVER",
      severity: versioned ? "medium" : "informational",
      confidence: versioned ? "high" : "medium",
      title: "Server header names the backend",
      summary: versioned ? `The Server header advertises a version: ${server}.` : `The Server header names the software: ${server}.`,
      why: "The header was on a normal response.",
      remediation: ["Remove the product version from the Server header if the site does not need to publish it."],
      evidence: server,
    });
  }
  const powered = headers["x-powered-by"]?.trim() ?? "";
  if (powered) {
    const versioned = /\d+\.\d+/.test(powered);
    add(findings, {
      id: "BACKEND_HEADER_POWERED_BY",
      severity: versioned ? "medium" : "informational",
      confidence: versioned ? "high" : "medium",
      title: "X-Powered-By names the runtime",
      summary: `The X-Powered-By header names the runtime: ${powered}.`,
      why: "The header was on a normal response.",
      remediation: ["Remove X-Powered-By if the site does not need to publish the runtime."],
      evidence: powered,
    });
  }
  const aspnet = [headers["x-aspnet-version"], headers["x-aspnetmvc-version"]].filter((value): value is string => Boolean(value?.trim()));
  if (aspnet.length > 0) {
    add(findings, {
      id: "BACKEND_HEADER_ASPNET",
      severity: "medium",
      confidence: "high",
      title: "ASP.NET version header is present",
      summary: `An ASP.NET version header is present: ${aspnet.join(", ")}.`,
      why: "The header was on a normal response.",
      remediation: ["Remove X-AspNet-Version and X-AspNetMvc-Version."],
      evidence: aspnet.join(", "),
    });
  }
  const via = headers["via"]?.trim() ?? "";
  if (via) {
    add(findings, {
      id: "BACKEND_HEADER_VIA",
      severity: "informational",
      confidence: "high",
      title: "Via header names a proxy",
      summary: `The Via header names a proxy or hop: ${via}.`,
      why: "The header was on a normal response. It is a hosting hint, not a claim that the proxy is vulnerable.",
      remediation: ["Remove Via if the hop name does not need to be public."],
      evidence: via,
    });
  }
  const seen = new Set<string>();
  for (const raw of cookies) {
    const name = cookieName(raw);
    const hint = COOKIE_HINTS.find((item) => item.name.toLowerCase() === name.toLowerCase());
    if (!hint || seen.has(hint.product)) continue;
    seen.add(hint.product);
    add(findings, {
      id: "BACKEND_COOKIE_FRAMEWORK",
      severity: "informational",
      confidence: "medium",
      title: "Session cookie names the framework",
      summary: `The cookie ${name} is a ${hint.product} session hint.`,
      why: "The cookie name was on a normal Set-Cookie header. The cookie value is not stored.",
      remediation: ["Renaming a session cookie is optional. Keeping that software patched matters more."],
      evidence: `${hint.product} ${name}`,
    });
  }
}

function phpFinding(findings: Finding[], php: PhpHeaderExposure): void {
  if (php.status === "never-patched" && php.version) {
    add(findings, {
      id: "PHP_CVE_2026_109618",
      severity: "high",
      confidence: "high",
      title: "PHP 5-7 was never patched",
      summary: `PHP ${php.version} is in the 5, 6, or 7 line. Those lines were never patched for CVE-2026-109618 and CVE-2026-109619.`,
      why: "The version was advertised in a response header. Vigil compared it with the patched PHP releases and did not probe the server.",
      remediation: [phpAdvisory.upgrade, phpAdvisory.mitigation, phpSessionUnfixedLine()],
      category: "vulnerability",
      evidence: php.version,
    });
    return;
  }
  if (php.status === "below-patch" && php.version) {
    add(findings, {
      id: "PHP_CVE_2026_109618",
      severity: "high",
      confidence: "high",
      title: "Upgrade PHP",
      summary: `Upgrade PHP. PHP ${php.version} is below the fixed release for CVE-2026-109618 and CVE-2026-109619. CVE-2026-115560 still has no patched release.`,
      why: "The version was advertised in a response header. Vigil compared it with the patched PHP releases and did not probe the server.",
      remediation: [phpAdvisory.upgrade, phpAdvisory.mitigation, phpSessionUnfixedLine()],
      category: "vulnerability",
      evidence: php.version,
    });
    return;
  }
  if (php.status === "patched" && php.version) {
    const note = phpSessionProgressNote(php.version);
    add(findings, {
      id: note.id,
      severity: "informational",
      confidence: "medium",
      title: note.title,
      summary: note.summary,
      why: "The 21 October 2026 PHP releases fix CVE-2026-109618 and CVE-2026-109619. PHP's 23 October note says they do not fix CVE-2026-115560, and no patched release exists yet.",
      remediation: note.remediation,
      category: "vulnerability",
      evidence: php.version,
    });
    return;
  }
  if (php.status === "unknown") {
    add(findings, {
      id: "BACKEND_PHP_VERSION_HIDDEN",
      severity: "medium",
      confidence: "medium",
      title: "PHP present, version hidden",
      summary: "A response header or cookie shows PHP, and no PHP/x.y.z version was advertised. Patch status is unknown.",
      why: "Vigil only compares a version that the server put in a header. A hidden version is not treated as patched or as vulnerable.",
      remediation: ["If you operate this server, upgrade PHP and keep the version out of public headers once it is current."],
      evidence: "version not advertised",
    });
  }
}

function phpVuln(php: PhpHeaderExposure): VulnCheck | undefined {
  if (php.status === "not-applicable") return undefined;
  const status = php.status === "patched" ? "fixed" : php.status === "unknown" ? "unknown" : "vulnerable";
  const level = php.status === "patched" ? "info" : php.status === "unknown" ? "unknown" : "warn";
  return {
    advisoryId: phpAdvisory.id,
    cves: [...phpAdvisory.cves],
    component: "php",
    ...(php.version ? { detectedVersion: php.version } : {}),
    status,
    audience: "visitor",
    level,
    mitigation: php.status === "unknown"
      ? "No PHP/x.y.z version was advertised. Patch status is unknown."
      : `${phpAdvisory.upgrade} ${phpAdvisory.mitigation}`,
  };
}

function phpSessionVuln(php: PhpHeaderExposure): VulnCheck | undefined {
  if (php.status === "not-applicable") return undefined;
  return {
    advisoryId: phpSessionAdvisory.id,
    cves: [...phpSessionAdvisory.cves],
    component: "php",
    ...(php.version ? { detectedVersion: php.version } : {}),
    status: "suspected",
    audience: "visitor",
    level: "info",
    mitigation: php.status === "patched" ? phpSessionAdvisory.mitigation : phpSessionUnfixedLine(),
  };
}

function pathFindings(findings: Finding[], responses: BackendResponse[]): void {
  const hits = new Map<string, string[]>();
  for (const rule of PATH_RULES) {
    const matched = responses.some((response) => (
      response.status === 200
      && pathnameOf(response.url) === rule.path
      && rule.match(response.body.slice(0, BODY_SCAN_CHARS))
    ));
    if (!matched) continue;
    const paths = hits.get(rule.id) ?? [];
    paths.push(rule.path);
    hits.set(rule.id, paths);
  }
  for (const [id, paths] of hits) {
    const copy = PATH_COPY[id];
    if (!copy) continue;
    add(findings, {
      id,
      severity: "high",
      confidence: "high",
      title: copy.title,
      summary: copy.summary(paths),
      why: "The body matched a known public file. The request was a short GET with no payload.",
      remediation: [copy.remediation],
      evidence: paths.join(", "),
    });
  }
}

const PATH_RULES: { path: string; id: string; match: (body: string) => boolean }[] = [
  { path: "/.git/HEAD", id: "BACKEND_EXPOSED_VCS", match: isGitHead },
  { path: "/.svn/entries", id: "BACKEND_EXPOSED_VCS", match: isSvnEntries },
  { path: "/server-status", id: "BACKEND_EXPOSED_STATUS", match: (body) => /Apache Server Status|Server uptime:|Total accesses:/i.test(body) },
  { path: "/server-info", id: "BACKEND_EXPOSED_STATUS", match: (body) => /Apache Server Information/i.test(body) },
  { path: "/phpinfo.php", id: "BACKEND_EXPOSED_PHPINFO", match: isPhpInfo },
  { path: "/info.php", id: "BACKEND_EXPOSED_PHPINFO", match: isPhpInfo },
  { path: "/elmah.axd", id: "BACKEND_EXPOSED_DEBUG", match: (body) => /Error Log for|ELMAH/i.test(body) },
  { path: "/trace.axd", id: "BACKEND_EXPOSED_DEBUG", match: (body) => /Application Trace/i.test(body) },
];

const PATH_COPY: Record<string, { title: string; summary: (paths: string[]) => string; remediation: string }> = {
  BACKEND_EXPOSED_VCS: {
    title: "Version-control metadata is public",
    summary: (paths) => `A normal GET for ${paths.join(" and ")} returned version-control metadata.`,
    remediation: "Stop publishing the version-control directory.",
  },
  BACKEND_EXPOSED_STATUS: {
    title: "Server status page is public",
    summary: (paths) => `A normal GET for ${paths.join(" and ")} returned a server status page.`,
    remediation: "Turn off the public server-status and server-info handlers, or restrict them to an operator network.",
  },
  BACKEND_EXPOSED_PHPINFO: {
    title: "phpinfo page is public",
    summary: (paths) => `A normal GET for ${paths.join(" and ")} returned a phpinfo page.`,
    remediation: "Remove phpinfo pages from the public site.",
  },
  BACKEND_EXPOSED_DEBUG: {
    title: "Debug trace page is public",
    summary: (paths) => `A normal GET for ${paths.join(" and ")} returned a debug trace page.`,
    remediation: "Remove public ELMAH and ASP.NET trace handlers.",
  },
};

function errorFindings(findings: Finding[], responses: BackendResponse[]): void {
  const bodies = responses
    .filter((response) => response.status === 404 || response.status >= 500)
    .map((response) => response.body.slice(0, BODY_SCAN_CHARS));
  const frameworks: string[] = [];
  let frameworkLine = "";
  for (const rule of FRAMEWORKS) {
    for (const body of bodies) {
      if (!rule.pattern.test(body)) continue;
      if (!frameworks.includes(rule.name)) frameworks.push(rule.name);
      if (!frameworkLine) frameworkLine = matchingLine(body, rule.pattern);
      break;
    }
  }
  if (frameworks.length > 0) {
    add(findings, {
      id: "BACKEND_ERROR_SIGNATURE",
      severity: "medium",
      confidence: "high",
      title: "Error page names the stack",
      summary: `An ordinary error response matches ${frameworks.join(", ")}.`,
      why: "The signature was on a 404 or 5xx response to a normal GET. Vigil did not send a payload to cause the error.",
      remediation: ["Replace the default error page and turn off framework debug output for public requests."],
      evidence: frameworkLine || frameworks.join(", "),
    });
  }
  const traces: string[] = [];
  let traceLine = "";
  for (const rule of TRACES) {
    for (const body of bodies) {
      if (!rule.pattern.test(body)) continue;
      if (!traces.includes(rule.name)) traces.push(rule.name);
      if (!traceLine) traceLine = matchingLine(body, rule.pattern);
      break;
    }
  }
  if (traces.length > 0) {
    add(findings, {
      id: "BACKEND_STACK_TRACE",
      severity: "high",
      confidence: "high",
      title: "Error page includes a trace or path",
      summary: `An ordinary error response includes ${traces.join(", ")}.`,
      why: "The text was on a 404 or 5xx response to a normal GET. The stored evidence is one redacted line.",
      remediation: ["Turn off detailed errors for public requests."],
      evidence: traceLine || traces.join(", "),
    });
  }
}

function tlsFindings(findings: Finding[], input: {
  pageUrl: string;
  responses: BackendResponse[];
  handshake: BackendHandshakeResult | { error: string } | null;
  now: Date;
  trustedSpki: ReadonlySet<string>;
}): { cert: CertCheck | null; view?: Report["tls"] } {
  const page = new URL(input.pageUrl);
  const host = page.hostname.replace(/^\[|\]$/g, "");
  if (page.protocol !== "https:") {
    add(findings, {
      id: "TLS_HTTP_ONLY",
      severity: "high",
      confidence: "high",
      title: "Page was fetched over http",
      summary: "The URL is not https, so the response can be modified on the network.",
      why: "The final URL after an ordinary fetch was http. No TLS probe was sent.",
      remediation: ["Serve the site only over https."],
      category: "tls",
      evidence: page.protocol,
    });
    timingFinding(findings, input.responses);
    return { cert: null, view: { authorized: null, daysRemaining: null } };
  }
  if (!input.handshake || "error" in input.handshake) {
    const failure = unavailableCertificate(host, input.handshake?.error ?? "TLS handshake failed");
    findings.push(...failure.findings);
    timingFinding(findings, input.responses);
    return {
      cert: failure.cert,
      view: {
        authorized: null,
        daysRemaining: null,
        ...(failure.cert.error ? { error: failure.cert.error } : {}),
      },
    };
  }
  const handshake = input.handshake;
  if (handshake.certs.length === 0) {
    const failure = unavailableCertificate(host, "TLS peer did not present a certificate");
    findings.push(...failure.findings);
    legacyProtocolFinding(findings, handshake);
    timingFinding(findings, input.responses);
    return { cert: failure.cert, view: { authorized: null, daysRemaining: null, error: failure.cert.error } };
  }
  const evaluated = evaluateCertificateChain(handshake.certs, { host, now: input.now, trustedSpki: input.trustedSpki });
  findings.push(...evaluated.findings);
  legacyProtocolFinding(findings, handshake);
  const cipherNote = cipherFinding(handshake);
  if (cipherNote) add(findings, cipherNote);
  const leaf = handshake.certs[0];
  if (leaf) {
    const names = internalLabels(leaf);
    if (names.length > 0) {
      add(findings, {
        id: "BACKEND_TLS_INTERNAL_NAME",
        severity: "medium",
        confidence: "high",
        title: "Certificate lists an internal name",
        summary: `The certificate lists an internal name or private address: ${names.join(", ")}.`,
        why: "The name was on the certificate from a normal handshake.",
        remediation: ["Reissue the certificate without internal names or private addresses."],
        evidence: names.join(", "),
      });
    }
  }
  timingFinding(findings, input.responses);
  return {
    cert: evaluated.cert,
    view: {
      authorized: evaluated.cert.authorized,
      ...(evaluated.cert.issuer ? { issuer: evaluated.cert.issuer } : {}),
      daysRemaining: evaluated.cert.daysRemaining ?? null,
      ...(evaluated.cert.error ? { error: evaluated.cert.error } : {}),
      protocol: handshake.protocol,
      cipher: handshake.cipher,
    },
  };
}

function cipherFinding(handshake: BackendHandshakeResult): BackendFinding | undefined {
  if (!handshake.cipher) return undefined;
  if (isWeakCipher(handshake.cipher)) {
    return {
      id: "BACKEND_TLS_CIPHER",
      severity: "high",
      confidence: "high",
      title: "TLS handshake selected a weak cipher",
      summary: `The handshake selected ${handshake.cipher}.`,
      why: "This is the cipher from one normal handshake. The client offer does not include export, null, RC4, or DES suites.",
      remediation: ["Disable weak ciphers and prefer the AEAD suites a current browser offers."],
      evidence: handshake.cipher,
    };
  }
  const offeredAead = handshake.offeredCiphers.some((name) => isAead(name));
  if (offeredAead && !isAead(handshake.cipher)) {
    return {
      id: "BACKEND_TLS_CIPHER",
      severity: "medium",
      confidence: "medium",
      title: "TLS handshake selected a cipher below the offered AEAD suites",
      summary: `The server selected ${handshake.cipher} from an offer that listed AEAD suites first.`,
      why: "Cipher order is whatever the server chose during one normal handshake. This is not a repeated probe.",
      remediation: ["Prefer the AEAD suites a current browser offers, and disable CBC if the server still selects it."],
      evidence: handshake.cipher,
    };
  }
  return undefined;
}

function timingFinding(findings: Finding[], responses: BackendResponse[]): void {
  const samples = responses.filter((response): response is BackendResponse & { ttfbMs: number } => (
    typeof response.ttfbMs === "number" && Number.isFinite(response.ttfbMs) && response.ttfbMs > 0
  ));
  if (samples.length < TIMING_MIN_SAMPLES) return;
  const ranked = [...samples].sort((left, right) => left.ttfbMs - right.ttfbMs);
  const fast = ranked[0];
  const slow = ranked[ranked.length - 1];
  if (!fast || !slow) return;
  const delta = slow.ttfbMs - fast.ttfbMs;
  const ratio = slow.ttfbMs / fast.ttfbMs;
  if (ratio < TIMING_RATIO || delta < TIMING_DELTA_MS) return;
  const slowPath = pathnameOf(slow.url) || slow.url;
  const fastPath = pathnameOf(fast.url) || fast.url;
  add(findings, {
    id: "BACKEND_TIMING",
    severity: "low",
    confidence: "low",
    title: "Time to response headers differs",
    summary: `${slowPath} returned headers in ${slow.ttfbMs}ms and ${fastPath} returned headers in ${fast.ttfbMs}ms. Each path was requested once. Body download time is not included.`,
    why: "These are the times until response headers for the GETs this check already sent. Vigil does not repeat requests to build a timing sample.",
    remediation: ["A slower path can be a different handler. This note is not a vulnerability by itself."],
    evidence: `${slowPath} ${slow.ttfbMs}ms`,
  });
}

function legacyProtocolFinding(findings: Finding[], handshake: BackendHandshakeResult): void {
  const probed = (handshake.legacyProtocols ?? []).filter((protocol) => isLegacyProtocol(protocol));
  const negotiated = isLegacyProtocol(handshake.protocol) ? [handshake.protocol] : [];
  const versions = [...new Set([...probed, ...negotiated])];
  if (versions.length === 0) return;
  add(findings, {
    id: "BACKEND_TLS_PROTOCOL",
    severity: "high",
    confidence: "high",
    title: "Server accepts a legacy TLS protocol",
    summary: probed.length > 0
      ? `A protocol-support handshake completed with ${probed.join(", ")}.`
      : `The handshake negotiated ${negotiated.join(", ")}.`,
    why: probed.length > 0
      ? "The browser-style handshake offers TLS 1.2 and newer. Two further handshakes cap the maximum version at TLS 1.0 and TLS 1.1 and send no HTTP request. A completed handshake means the server still accepts that version."
      : "The negotiated protocol is below TLS 1.2.",
    remediation: ["Disable TLS versions below 1.2."],
    evidence: versions.join(", "),
  });
}

function isGitHead(body: string): boolean {
  const text = body.trim();
  return /^ref: refs\/[A-Za-z0-9_./-]+\s*$/.test(text) || /^[0-9a-f]{40}\s*$/i.test(text);
}

function isSvnEntries(body: string): boolean {
  return /<wc-entries\b/.test(body) || /\bsvn:(?:special|eol-style|keywords)\b/.test(body);
}

function isPhpInfo(body: string): boolean {
  const cells = /class=["']e["']/i.test(body) && /class=["']v["']/i.test(body);
  if (!cells) return false;
  const title = /<title>[^<]*phpinfo\(\)[^<]*<\/title>/i.test(body);
  const heading = /<h1\b[^>]*class=["']p["'][^>]*>[^<]*PHP Version\b/i.test(body);
  return title || heading;
}

function isLegacyProtocol(protocol: string): boolean {
  return /SSLv/i.test(protocol) || /^TLSv1(?:\.0)?$/i.test(protocol) || /TLSv1\.1/i.test(protocol);
}

function isAead(name: string): boolean {
  return /GCM|CHACHA|POLY1305|CCM/i.test(name);
}

function isWeakCipher(name: string): boolean {
  return /NULL|EXPORT|RC4|3DES|CBC3|\bDES\b|ANON|\bADH\b/i.test(name);
}

function isInternalLabel(name: string): boolean {
  const bare = name.trim().toLowerCase().replace(/\.$/, "");
  if (!bare || bare === "*") return false;
  if (isBlockedIp(bare)) return true;
  const host = bare.replace(/^\*\./, "");
  if (!host) return false;
  if (isBlockedHostname(host)) return true;
  return /\.(?:lan|home|corp|localdomain|intranet)$/i.test(bare);
}

function internalLabels(cert: ParsedCert): string[] {
  const names = [...cert.sanDns, ...(cert.commonName ? [cert.commonName] : []), ...cert.sanIp];
  const found: string[] = [];
  for (const name of names) {
    if (!isInternalLabel(name) || found.includes(name)) continue;
    found.push(name);
  }
  return found;
}

function matchingLine(body: string, pattern: RegExp): string {
  for (const line of body.split(/\r?\n/)) {
    if (pattern.test(line)) return line;
  }
  return pattern.exec(body)?.[0] ?? "";
}

function mergedHeaders(responses: BackendResponse[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const response of responses) {
    for (const [key, value] of Object.entries(flatHeaders(response.headers))) {
      if (key === "set-cookie" || !value.trim() || out[key] !== undefined) continue;
      out[key] = value;
    }
  }
  return out;
}

function flatHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[key.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
  }
  return out;
}

function cookieList(headers: Record<string, string | string[] | undefined>): string[] {
  const value = headers["set-cookie"] ?? headers["Set-Cookie"];
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function allCookies(responses: BackendResponse[]): string[] {
  return responses.flatMap((response) => cookieList(response.headers));
}

function cookieName(raw: string): string {
  return /^[^=;\s]+/.exec(raw.trim())?.[0] ?? "";
}

function pathnameOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return "";
  }
}
