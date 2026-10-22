import { visibleLines } from "./lines.js";
import { redactEvidence } from "./redact.js";
import { createFinding, taxonomyFor } from "./taxonomy.js";
import type { Finding, FindingTaxonomy } from "./types.js";

interface RuleMeta {
  id: string;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  title: string;
  summary: string;
  why: string;
  remediation: string[];
  agentAction: string;
  category: string;
  recommendationOnly: boolean;
}

const SINK = /\.innerHTML\b|\.outerHTML\b|insertAdjacentHTML\s*\(|document\.write\s*\(/;
const UNTRUSTED =
  /(?:document\.)?location\b|searchParams|localStorage|sessionStorage|req\.(?:query|body|params)|request\.(?:query|body|params)|document\.cookie|\.cookie\b|document\.referrer|\breferrer\b/;

function meta(partial: RuleMeta): RuleMeta {
  return partial;
}

const RULES = {
  unsafeSink: meta({
    id: "XSS_UNSAFE_SINK",
    severity: "critical",
    confidence: "high",
    title: "HTML sink uses untrusted data",
    summary: "An HTML sink on this line also reads location, request, storage, cookie, or referrer data.",
    why: "The browser will parse that data as HTML. A query parameter or request field can run script in the user's session.",
    remediation: [
      "Write text with textContent, or sanitize with a reviewed HTML policy.",
      "Keep request and URL data out of HTML sinks.",
    ],
    agentAction: "Replace the HTML sink with a text assignment or a sanitized template.",
    category: "xss",
    recommendationOnly: false,
  }),
  literalSink: meta({
    id: "XSS_INNERHTML_LITERAL",
    severity: "high",
    confidence: "high",
    title: "HTML sink without a proven source",
    summary: "An HTML sink is present, but this line does not show an untrusted source.",
    why: "The sink is safe only while every caller passes a constant. A later edit can turn it into script execution.",
    remediation: ["Prefer textContent or a framework binding that escapes by default."],
    agentAction: "Replace the HTML sink unless the value is a reviewed constant.",
    category: "xss",
    recommendationOnly: true,
  }),
  evalRule: meta({
    id: "XSS_EVAL",
    severity: "critical",
    confidence: "high",
    title: "Code is built from a string",
    summary: "eval, new Function, or a string timer will execute text as code.",
    why: "String execution is an injection sink. Generated apps use it to stitch together untrusted fragments.",
    remediation: ["Delete eval and new Function.", "Pass a function, not a string, to setTimeout and setInterval."],
    agentAction: "Remove string execution and call a real function.",
    category: "xss",
    recommendationOnly: false,
  }),
  inlineHandler: meta({
    id: "XSS_INLINE_HANDLER",
    severity: "critical",
    confidence: "high",
    title: "Inline event handler",
    summary: "An HTML on* attribute runs script from the markup.",
    why: "Inline handlers force a weak content security policy and are a common place for injected script.",
    remediation: ["Move the behavior to an external script and add a listener from code."],
    agentAction: "Remove the on* attribute and register an event listener.",
    category: "xss",
    recommendationOnly: false,
  }),
  javascriptUri: meta({
    id: "XSS_JAVASCRIPT_URI",
    severity: "critical",
    confidence: "high",
    title: "javascript: URL",
    summary: "A navigation attribute points at a javascript: URL.",
    why: "The browser runs that URL as script when the link or form is used.",
    remediation: ["Use an https URL or a button with a script listener."],
    agentAction: "Replace the javascript: URL.",
    category: "xss",
    recommendationOnly: false,
  }),
  openRedirect: meta({
    id: "OPEN_REDIRECT",
    severity: "critical",
    confidence: "high",
    title: "Redirect taken from the request",
    summary: "location is assigned from the query string, hash, or request data.",
    why: "An attacker can send a user from a trusted site to a credential prompt they control.",
    remediation: ["Allow only relative paths, or match the target against a fixed list of origins."],
    agentAction: "Stop assigning location from request data.",
    category: "redirect",
    recommendationOnly: false,
  }),
  aws: meta({
    id: "SECRET_AWS_ACCESS_KEY",
    severity: "critical",
    confidence: "high",
    title: "AWS access key id",
    summary: "A line contains an AKIA-shaped access key id.",
    why: "A committed access key id is a credential. Paired with a secret, it can spend the account.",
    remediation: ["Remove the key, rotate it, and load credentials from the host environment."],
    agentAction: "Delete the key and read it from the environment at runtime.",
    category: "secrets",
    recommendationOnly: false,
  }),
  privateKey: meta({
    id: "SECRET_PRIVATE_KEY",
    severity: "critical",
    confidence: "high",
    title: "Private key material",
    summary: "A PEM private key block is in the source.",
    why: "Anyone with the source can impersonate the key owner.",
    remediation: ["Remove the key from source and rotate it. Keep private keys in a secret store."],
    agentAction: "Delete the PEM block.",
    category: "secrets",
    recommendationOnly: false,
  }),
  stripe: meta({
    id: "SECRET_STRIPE_LIVE",
    severity: "critical",
    confidence: "high",
    title: "Stripe live secret",
    summary: "A sk_live_ secret is in the source.",
    why: "A live Stripe secret can create charges and read customer data.",
    remediation: ["Revoke the key in the Stripe dashboard and move it to server configuration."],
    agentAction: "Delete the live secret from client and source files.",
    category: "secrets",
    recommendationOnly: false,
  }),
  openai: meta({
    id: "SECRET_OPENAI",
    severity: "critical",
    confidence: "high",
    title: "API key with an sk- prefix",
    summary: "A long sk- token is in the source.",
    why: "Client-side model keys are stolen from the page and billed to the owner.",
    remediation: ["Call the model from a server that holds the key."],
    agentAction: "Remove the sk- token from the client bundle.",
    category: "secrets",
    recommendationOnly: false,
  }),
  github: meta({
    id: "SECRET_GITHUB_PAT",
    severity: "critical",
    confidence: "high",
    title: "GitHub personal access token",
    summary: "A ghp_ token is in the source.",
    why: "The token can read or write repositories and packages until it is revoked.",
    remediation: ["Revoke the token and use a short-lived credential on the server."],
    agentAction: "Delete the ghp_ token.",
    category: "secrets",
    recommendationOnly: false,
  }),
  generic: meta({
    id: "SECRET_GENERIC_KEY",
    severity: "critical",
    confidence: "high",
    title: "Hard-coded credential",
    summary: "api_key, secret_key, auth_token, or bearer is assigned a long quoted token.",
    why: "Generated apps often paste a working key into the client so the demo runs.",
    remediation: ["Remove the literal and read the secret from server-side configuration."],
    agentAction: "Replace the quoted token with an environment read on the server.",
    category: "secrets",
    recommendationOnly: false,
  }),
  dangerousHtml: meta({
    id: "XSS_DANGEROUSLY_SET_INNER_HTML",
    severity: "high",
    confidence: "high",
    title: "dangerouslySetInnerHTML",
    summary: "React will render this object as HTML.",
    why: "The prop skips escaping. Untrusted HTML in it is script execution.",
    remediation: ["Render text children, or sanitize the HTML with a reviewed policy."],
    agentAction: "Remove dangerouslySetInnerHTML.",
    category: "xss",
    recommendationOnly: true,
  }),
  proto: meta({
    id: "PROTO_POLLUTION",
    severity: "high",
    confidence: "high",
    title: "Prototype write",
    summary: "The line writes __proto__ or constructor prototype.",
    why: "A prototype write changes objects across the program and can turn into a gadget.",
    remediation: ["Use Object.create(null) for maps and reject __proto__ keys from user input."],
    agentAction: "Delete the prototype assignment.",
    category: "prototype",
    recommendationOnly: true,
  }),
  mixed: meta({
    id: "MIXED_CONTENT",
    severity: "high",
    confidence: "high",
    title: "Active URL uses http",
    summary: "src, href, action, or formaction points at http://.",
    why: "An https page that loads http resources can be modified on the network.",
    remediation: ["Use https URLs for scripts, frames, images, and form actions."],
    agentAction: "Change the URL to https.",
    category: "transport",
    recommendationOnly: true,
  }),
  cookieWrite: meta({
    id: "COOKIE_JS_WRITE",
    severity: "high",
    confidence: "high",
    title: "Cookie written from script without Secure",
    summary: "document.cookie is assigned and the line does not set Secure.",
    why: "A script-visible cookie without Secure is sent to http origins and can be stolen by XSS.",
    remediation: ["Set session cookies from the server with Secure, HttpOnly, and SameSite."],
    agentAction: "Remove the document.cookie write.",
    category: "cookies",
    recommendationOnly: true,
  }),
  storage: meta({
    id: "TOKEN_IN_STORAGE",
    severity: "high",
    confidence: "high",
    title: "Secret written to web storage",
    summary: "A token, secret, password, or API key is written to localStorage or sessionStorage.",
    why: "Any script on the origin can read web storage. XSS becomes account takeover.",
    remediation: ["Keep session state in an HttpOnly cookie set by the server."],
    agentAction: "Delete the storage write for that secret.",
    category: "secrets",
    recommendationOnly: true,
  }),
  cspWeak: meta({
    id: "CSP_WEAK",
    severity: "high",
    confidence: "high",
    title: "Content Security Policy allows injected script",
    summary: "A CSP includes unsafe-inline or unsafe-eval.",
    why: "Those tokens disable the policy's protection against injected script.",
    remediation: ["Use a nonce or hash for legitimate scripts and drop both unsafe tokens."],
    agentAction: "Remove unsafe-inline and unsafe-eval from the policy.",
    category: "headers",
    recommendationOnly: true,
  }),
  cspMissing: meta({
    id: "CSP_MISSING",
    severity: "high",
    confidence: "high",
    title: "HTML document has no Content Security Policy",
    summary: "No CSP meta element was found. This is dropped when the live response already sends a CSP header.",
    why: "Without a policy, an HTML injection becomes script execution.",
    remediation: ["Send a strict Content-Security-Policy from the host, or add a CSP meta element."],
    agentAction: "Add a strict Content-Security-Policy.",
    category: "headers",
    recommendationOnly: true,
  }),
  postMessage: meta({
    id: "POSTMESSAGE_WILDCARD",
    severity: "medium",
    confidence: "high",
    title: "postMessage uses a wildcard origin",
    summary: "postMessage is called with target origin \"*\".",
    why: "Any window that gets the reference can read the payload.",
    remediation: ["Pass the exact origin you intend to message."],
    agentAction: "Replace \"*\" with a specific origin.",
    category: "xss",
    recommendationOnly: true,
  }),
};

function emit(rule: RuleMeta, file: string, line: number, evidence: string): Finding {
  return createFinding({
    id: rule.id,
    severity: rule.severity,
    confidence: rule.confidence,
    title: rule.title,
    summary: rule.summary,
    why: rule.why,
    remediation: rule.remediation,
    file,
    line,
    evidence: redactEvidence(evidence),
    agentAction: rule.agentAction,
    category: rule.category,
    recommendationOnly: rule.recommendationOnly,
  });
}

function isHtmlDocument(filename: string, content: string): boolean {
  if (/\.(html?|xhtml)$/i.test(filename)) return true;
  const head = content.slice(0, 500).toLowerCase();
  return head.includes("<!doctype html") || head.includes("<html");
}

const REDIRECT =
  /(?:window\.)?location(?:\.href)?\s*=|(?:window\.)?location\.(?:assign|replace)\s*\(/;
const REDIRECT_SOURCE =
  /searchParams|(?:location|window\.location)\.(?:hash|search)|req\.(?:query|body|params)|request\.(?:query|body|params)|URLSearchParams|(?:^|[^\w.])(?:query|hash|params)\b/;

export function scanSource(filename: string, content: string, options?: { liveCsp?: boolean }): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const add = (rule: RuleMeta, line: number, evidence: string) => {
    const key = `${rule.id}:${filename}:${line}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(emit(rule, filename, line, evidence));
  };

  for (const row of visibleLines(content)) {
    const line = row.code;
    if (SINK.test(line)) {
      add(UNTRUSTED.test(line) ? RULES.unsafeSink : RULES.literalSink, row.lineNo, line);
    }
    if (/\beval\s*\(|new\s+Function\s*\(/.test(line) || /set(?:Timeout|Interval)\s*\(\s*['"`]/.test(line)) {
      add(RULES.evalRule, row.lineNo, line);
    }
    if (/<[^>]*\son[a-z]{3,}\s*=/i.test(line)) add(RULES.inlineHandler, row.lineNo, line);
    if (/(?:href|src|action|formaction)\s*=\s*['"]?\s*javascript:/i.test(line)) add(RULES.javascriptUri, row.lineNo, line);
    if (REDIRECT.test(line) && REDIRECT_SOURCE.test(line)) add(RULES.openRedirect, row.lineNo, line);
    if (/AKIA[0-9A-Z]{16}/.test(line)) add(RULES.aws, row.lineNo, line);
    if (/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(line)) add(RULES.privateKey, row.lineNo, line);
    if (/sk_live_[A-Za-z0-9]+/.test(line)) add(RULES.stripe, row.lineNo, line);
    if (/sk-[A-Za-z0-9_-]{20,}/.test(line)) add(RULES.openai, row.lineNo, line);
    if (/ghp_[A-Za-z0-9]+/.test(line)) add(RULES.github, row.lineNo, line);
    if (/(?:api_key|secret_key|auth_token|bearer)\s*[:=]\s*['"][^'"]{20,}['"]/i.test(line)) {
      add(RULES.generic, row.lineNo, line);
    }
    if (/dangerouslySetInnerHTML/.test(line)) add(RULES.dangerousHtml, row.lineNo, line);
    if (/__proto__\s*=|__proto__\s*\.\w+\s*=|__proto__\s*\]\s*=|constructor\s*\[\s*['"]prototype['"]\s*\]\s*=/.test(line)) {
      add(RULES.proto, row.lineNo, line);
    }
    if (/(?:src|href|action|formaction)\s*=\s*['"]http:\/\//i.test(line)) add(RULES.mixed, row.lineNo, line);
    if (/document\.cookie\s*=/.test(line) && !/secure/i.test(line)) add(RULES.cookieWrite, row.lineNo, line);
    if (
      /(?:localStorage|sessionStorage)\.setItem\(\s*['"][^'"]*(?:token|secret|password|api[_-]?key)/i.test(line) ||
      /(?:localStorage|sessionStorage)\.(?:token|secret|password|api[_-]?key)\w*\s*=/i.test(line)
    ) {
      add(RULES.storage, row.lineNo, line);
    }
    if (/content-security-policy/i.test(line) && /unsafe-(?:inline|eval)/i.test(line)) add(RULES.cspWeak, row.lineNo, line);
    if (/postMessage\s*\([^)]*['"]\*['"]/.test(line)) add(RULES.postMessage, row.lineNo, line);
  }

  if (isHtmlDocument(filename, content) && !options?.liveCsp && !/content-security-policy/i.test(content)) {
    add(RULES.cspMissing, 1, filename);
  }
  return findings;
}

export const PHASE1_BLOCKERS = [
  "XSS_UNSAFE_SINK",
  "XSS_EVAL",
  "XSS_INLINE_HANDLER",
  "XSS_JAVASCRIPT_URI",
  "OPEN_REDIRECT",
  "SECRET_AWS_ACCESS_KEY",
  "SECRET_PRIVATE_KEY",
  "SECRET_STRIPE_LIVE",
  "SECRET_OPENAI",
  "SECRET_GITHUB_PAT",
  "SECRET_GENERIC_KEY",
] as const;

export const PHASE1_RECOMMENDATIONS = [
  "XSS_INNERHTML_LITERAL",
  "XSS_DANGEROUSLY_SET_INNER_HTML",
  "PROTO_POLLUTION",
  "MIXED_CONTENT",
  "COOKIE_JS_WRITE",
  "TOKEN_IN_STORAGE",
  "CSP_WEAK",
  "CSP_MISSING",
  "POSTMESSAGE_WILDCARD",
  "HEADER_CSP",
  "HEADER_CSP_REPORT_ONLY",
  "HEADER_HSTS",
  "HEADER_CONTENT_TYPE_OPTIONS",
  "HEADER_FRAME_OPTIONS",
  "HEADER_REFERRER_POLICY",
  "HEADER_PERMISSIONS_POLICY",
  "HEADER_COOP",
  "COOKIE_FLAGS",
  "TLS_INVALID",
  "TLS_HTTP_ONLY",
  "HOSTING_HEADERS",
] as const;

export interface CatalogEntry {
  id: string;
  severity: Finding["severity"];
  recommendationOnly: boolean;
  taxonomy: FindingTaxonomy;
}

export function ruleCatalog(): CatalogEntry[] {
  const fromScan = Object.values(RULES).map((rule) => ({
    id: rule.id,
    severity: rule.severity,
    recommendationOnly: rule.recommendationOnly,
  }));
  const extras: { id: string; severity: Finding["severity"]; recommendationOnly: boolean }[] = [
    { id: "HEADER_CSP", severity: "high", recommendationOnly: true },
    { id: "HEADER_CSP_REPORT_ONLY", severity: "medium", recommendationOnly: true },
    { id: "HEADER_HSTS", severity: "medium", recommendationOnly: true },
    { id: "HEADER_CONTENT_TYPE_OPTIONS", severity: "medium", recommendationOnly: true },
    { id: "HEADER_FRAME_OPTIONS", severity: "medium", recommendationOnly: true },
    { id: "HEADER_REFERRER_POLICY", severity: "medium", recommendationOnly: true },
    { id: "HEADER_PERMISSIONS_POLICY", severity: "medium", recommendationOnly: true },
    { id: "HEADER_COOP", severity: "medium", recommendationOnly: true },
    { id: "COOKIE_FLAGS", severity: "high", recommendationOnly: true },
    { id: "TLS_INVALID", severity: "high", recommendationOnly: true },
    { id: "TLS_HTTP_ONLY", severity: "high", recommendationOnly: true },
    { id: "HOSTING_HEADERS", severity: "informational", recommendationOnly: true },
  ];
  return [...fromScan, ...extras].map((rule) => ({ ...rule, taxonomy: taxonomyFor(rule.id) }));
}
