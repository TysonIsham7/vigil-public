import { redactEvidence } from "./redact.js";
import { createFinding } from "./taxonomy.js";
import type { Finding, HostingHint } from "./types.js";

export type HeaderMap = Record<string, string | string[] | undefined>;

function one(headers: HeaderMap, name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  if (Array.isArray(value)) return value.join(", ");
  return value;
}

function cookies(headers: HeaderMap): string[] {
  const value = headers["set-cookie"] ?? headers["Set-Cookie"];
  if (!value) return [];
  return Array.isArray(value) ? value : [value];
}

function base(
  partial: Omit<Finding, "evidence" | "occurrenceId" | "file" | "line" | "taxonomy"> & { evidence: string; line?: number },
): Finding {
  const line = partial.line ?? 1;
  return createFinding({
    ...partial,
    file: "(response)",
    line,
    occurrenceId: `${partial.id}:(response):${line}`,
    evidence: redactEvidence(partial.evidence),
  });
}

export interface CookieFlag {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: boolean;
  raw: string;
}

export function parseCookieFlags(raw: string): CookieFlag {
  const name = raw.split("=", 1)[0]?.trim() || "(cookie)";
  return {
    name,
    secure: /(?:^|;)\s*secure(?:\s*;|$)/i.test(raw) || /;\s*secure\b/i.test(raw),
    httpOnly: /httponly/i.test(raw),
    sameSite: /samesite\s*=/i.test(raw),
    raw,
  };
}

export function headerFindings(pageUrl: string, headers: HeaderMap): { findings: Finding[]; cookies: CookieFlag[] } {
  const findings: Finding[] = [];
  let scheme = "https:";
  try {
    scheme = new URL(pageUrl).protocol;
  } catch {
    scheme = "https:";
  }
  const https = scheme === "https:";
  const csp = one(headers, "content-security-policy");
  const reportOnly = one(headers, "content-security-policy-report-only");
  const hsts = one(headers, "strict-transport-security");
  const xcto = one(headers, "x-content-type-options");
  const xfo = one(headers, "x-frame-options");
  const referrer = one(headers, "referrer-policy");
  const permissions = one(headers, "permissions-policy");
  const coop = one(headers, "cross-origin-opener-policy");

  if (!csp) {
    findings.push(headerFinding("HEADER_CSP", "high", "Content-Security-Policy is missing", "The response does not send a Content-Security-Policy header.", "Add a strict Content-Security-Policy."));
  } else if (/unsafe-(?:inline|eval)/i.test(csp)) {
    findings.push(headerFinding("CSP_WEAK", "high", "Content-Security-Policy allows injected script", "The CSP header includes unsafe-inline or unsafe-eval.", "Drop unsafe-inline and unsafe-eval."));
  }
  if (!reportOnly) {
    findings.push(headerFinding("HEADER_CSP_REPORT_ONLY", "medium", "Content-Security-Policy-Report-Only is missing", "The response does not send a report-only policy.", "Add a report-only policy while tightening the enforcing policy."));
  }
  if (https && !/max-age\s*=\s*[1-9]/i.test(hsts ?? "")) {
    findings.push(headerFinding("HEADER_HSTS", "medium", "HSTS is missing or empty", "HTTPS responses should send Strict-Transport-Security with a positive max-age.", "Send Strict-Transport-Security with a max-age of at least six months."));
  }
  if ((xcto ?? "").toLowerCase() !== "nosniff") {
    findings.push(headerFinding("HEADER_CONTENT_TYPE_OPTIONS", "medium", "X-Content-Type-Options is not nosniff", "The browser may sniff a response into an executable type.", "Send X-Content-Type-Options: nosniff."));
  }
  const framed = /^(deny|sameorigin)$/i.test((xfo ?? "").trim()) || /frame-ancestors/i.test(csp ?? "");
  if (!framed) {
    findings.push(headerFinding("HEADER_FRAME_OPTIONS", "medium", "Clickjacking control is missing", "Neither X-Frame-Options nor CSP frame-ancestors is set.", "Set frame-ancestors or X-Frame-Options."));
  }
  if (!referrer || /unsafe-url/i.test(referrer)) {
    findings.push(headerFinding("HEADER_REFERRER_POLICY", "medium", "Referrer-Policy is missing or unsafe", "The response does not set a safe Referrer-Policy.", "Send Referrer-Policy: strict-origin-when-cross-origin or stricter."));
  }
  if (!permissions) {
    findings.push(headerFinding("HEADER_PERMISSIONS_POLICY", "medium", "Permissions-Policy is missing", "Powerful features are left at browser defaults.", "Send a Permissions-Policy that disables features the site does not use."));
  }
  if (!coop || /unsafe-none/i.test(coop)) {
    findings.push(headerFinding("HEADER_COOP", "medium", "Cross-Origin-Opener-Policy is missing", "The page can be scripted by a window that opened it.", "Send Cross-Origin-Opener-Policy: same-origin."));
  }

  const parsed = cookies(headers).map(parseCookieFlags);
  parsed.forEach((cookie, index) => {
    if (!cookie.secure || !cookie.httpOnly || !cookie.sameSite) {
      findings.push({
        ...headerFinding(
          "COOKIE_FLAGS",
          "high",
          "Set-Cookie is missing Secure, HttpOnly, or SameSite",
          `Cookie ${cookie.name} is missing one or more of Secure, HttpOnly, and SameSite.`,
          "Set Secure, HttpOnly, and SameSite on every session cookie.",
        ),
        line: index + 1,
        occurrenceId: `COOKIE_FLAGS:(response):${index + 1}:${cookie.name}`,
        evidence: redactEvidence(cookie.raw),
      });
    }
  });

  if (!https) {
    findings.push(headerFinding("TLS_HTTP_ONLY", "high", "Page was fetched over http", "The URL is not https, so the response can be modified on the network.", "Serve the site only over https."));
  }
  return { findings, cookies: parsed };
}

function headerFinding(id: string, severity: Finding["severity"], title: string, summary: string, action: string): Finding {
  return base({
    id,
    severity,
    confidence: "high",
    title,
    summary,
    why: "This is a response header check from a URL scan. It does not by itself block deploy.",
    remediation: [action],
    agentAction: action,
    category: id === "COOKIE_FLAGS" ? "cookies" : id.startsWith("TLS_") ? "tls" : "headers",
    recommendationOnly: true,
    evidence: title,
  });
}

export function tlsRecommendation(input: { scheme: string; authorized: boolean | null; error?: string }): Finding[] {
  if (input.scheme !== "https:" || input.authorized !== false) return [];
  return [
    base({
      id: "TLS_INVALID",
      severity: "high",
      confidence: "high",
      title: "TLS certificate did not validate",
      summary: input.error || "The certificate was not authorized by the pinned root set.",
      why: "Phase 1 records an unauthorized certificate as a recommendation. Stricter certificate blocks are separate critical findings.",
      remediation: ["Install a certificate that chains to a root the pinned Mozilla set still trusts."],
      agentAction: "Replace the certificate.",
      category: "tls",
      recommendationOnly: true,
      evidence: input.error || "unauthorized",
    }),
  ];
}

export function hostingFinding(hint: HostingHint): Finding {
  const notes: Record<HostingHint, string> = {
    vercel: "On Vercel, set the headers in vercel.json or next.config rather than only in HTML.",
    netlify: "On Netlify, set the headers in _headers or netlify.toml.",
    cloudflare: "On Cloudflare, set the headers in a Transform Rule or _headers so they survive the edge.",
  };
  return base({
    id: "HOSTING_HEADERS",
    severity: "informational",
    confidence: "high",
    title: "Hosting hint",
    summary: notes[hint],
    why: "The scan was given a hosting target so the header advice can name the right config file.",
    remediation: [notes[hint]],
    agentAction: "Apply header changes in the host configuration.",
    category: "hosting",
    recommendationOnly: true,
    evidence: hint,
  });
}

export function dropCspMissing(findings: Finding[], headers: HeaderMap): Finding[] {
  if (!one(headers, "content-security-policy")) return findings;
  return findings.filter((finding) => finding.id !== "CSP_MISSING");
}
