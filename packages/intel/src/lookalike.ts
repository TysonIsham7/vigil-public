import hosts from "../data/hosts.json" with { type: "json" };
import homoglyphs from "../data/homoglyphs.json" with { type: "json" };
import { decodeHostname } from "./punycode.js";

export interface Brand {
  id: string;
  names: string[];
  domains: string[];
}

const GLYPHS = homoglyphs as Record<string, string>;
const SUFFIXES = [...hosts.publicSuffixes].sort((a, b) => b.length - a.length);
const FREE = new Set(hosts.freeHosting);
const SUSPICIOUS = new Set(hosts.suspiciousTlds);
const BRANDS = hosts.brands as Brand[];

export interface LookalikeHit {
  brand: string;
  confidence: "high" | "medium";
  reason: string;
}

export interface SiteSignal {
  id: string;
  severity: "critical" | "high" | "medium";
  recommendationOnly: boolean;
  title: string;
  summary: string;
}

export interface SiteAssessment {
  host: string;
  registrableDomain: string;
  mixedScript: boolean;
  ipLiteral: boolean;
  suspiciousTld: boolean;
  freeHosting: boolean;
  subdomainDepth: number;
  lookalike?: LookalikeHit;
  credentialForm: boolean;
  credentialCrossOrigin: boolean;
  credentialInsecure: boolean;
  brandImpersonation?: { brand: string; withCredential: boolean };
  ageDays: number | null;
  level: "ok" | "warn" | "block";
  signals: SiteSignal[];
}

export function skeleton(input: string): string {
  let out = "";
  for (const char of input.normalize("NFKD").toLowerCase()) {
    if (/\p{M}/u.test(char)) continue;
    out += GLYPHS[char] ?? char;
  }
  return out;
}

export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().split(".").filter(Boolean);
  const name = labels.join(".");
  for (const suffix of SUFFIXES) {
    if (name === suffix) return name;
    if (name.endsWith(`.${suffix}`)) {
      const extra = name.slice(0, -(suffix.length + 1)).split(".");
      const left = extra[extra.length - 1];
      return left ? `${left}.${suffix}` : name;
    }
  }
  return labels.slice(-2).join(".");
}

function scriptOf(char: string): "latin" | "cyrillic" | "greek" | "other" {
  if (/\p{Script=Latin}/u.test(char)) return "latin";
  if (/\p{Script=Cyrillic}/u.test(char)) return "cyrillic";
  if (/\p{Script=Greek}/u.test(char)) return "greek";
  return "other";
}

export function mixedScriptLabel(label: string): boolean {
  const scripts = new Set<string>();
  for (const char of label) {
    const script = scriptOf(char);
    if (script !== "other") scripts.add(script);
  }
  return scripts.size > 1;
}

function levenshtein(a: string, b: string, max: number): number {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const row = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    let prev = i - 1;
    row[0] = i;
    let best = row[0];
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      const next = Math.min((row[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, prev + cost);
      prev = row[j] ?? 0;
      row[j] = next;
      if (next < best) best = next;
    }
    if (best > max) return max + 1;
  }
  return row[b.length] ?? max + 1;
}

function isIp(host: string): boolean {
  if (host.includes(":")) return true;
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function official(brand: Brand, registrable: string): boolean {
  return brand.domains.some((domain) => registrable === domain || registrable.endsWith(`.${domain}`));
}

function findLookalike(labels: string[], registrable: string): LookalikeHit | undefined {
  const sld = registrable.split(".")[0] ?? "";
  const candidates = labels.map((label) => skeleton(label));
  const sldSkeleton = skeleton(sld);
  let medium: LookalikeHit | undefined;
  for (const brand of BRANDS) {
    if (official(brand, registrable)) continue;
    const names = [brand.id, ...brand.names].filter((name) => name.length >= 5);
    for (const name of names) {
      const target = skeleton(name);
      if (sldSkeleton === target || candidates.includes(target)) {
        return { brand: brand.id, confidence: "high", reason: `Name matches ${brand.id} on another registrable domain` };
      }
      const distance = levenshtein(sldSkeleton, target, 2);
      if (distance === 1 && target.length >= 5) {
        return { brand: brand.id, confidence: "high", reason: `Edit distance 1 from ${brand.id}` };
      }
      if (!medium && distance === 2 && target.length >= 6) {
        medium = { brand: brand.id, confidence: "medium", reason: `Edit distance 2 from ${brand.id}` };
      }
    }
  }
  return medium;
}

function mentionedBrand(text: string, registrable: string): string | undefined {
  const hay = text.toLowerCase();
  for (const brand of BRANDS) {
    if (official(brand, registrable)) continue;
    for (const name of [brand.id, ...brand.names]) {
      if (name.length < 5) continue;
      const pattern = new RegExp(`\\b${name}\\b`, "i");
      if (pattern.test(hay)) return brand.id;
    }
  }
  return undefined;
}

function credential(html: string, pageUrl: string, registrable: string): {
  present: boolean;
  crossOrigin: boolean;
  insecure: boolean;
} {
  const password = /<input\b[^>]*type\s*=\s*['"]?password\b/i.test(html);
  const otp = /<input\b[^>]*(?:name|id)\s*=\s*['"][^'"]*(?:otp|passcode|mfa)\b/i.test(html);
  const card = /<input\b[^>]*(?:name|id)\s*=\s*['"][^'"]*(?:cardnumber|cc-number|cvv|cvc)\b/i.test(html);
  const present = password || otp || card;
  const action = /<form\b[^>]*\baction\s*=\s*['"]([^'"]+)['"]/i.exec(html)?.[1];
  let crossOrigin = false;
  let insecure = false;
  try {
    const page = new URL(pageUrl);
    insecure = page.protocol === "http:";
    if (action) {
      const target = new URL(action, page);
      if (target.protocol === "http:") insecure = true;
      const targetReg = registrableDomain(decodeHostname(target.hostname));
      crossOrigin = target.origin !== page.origin || targetReg !== registrable;
    }
  } catch {
    insecure = pageUrl.startsWith("http://");
  }
  return { present, crossOrigin, insecure };
}

export function assessSite(input: {
  host: string;
  allowlist?: string[];
  ageDays?: number | null;
  html?: string;
  pageUrl?: string;
}): SiteAssessment {
  const decoded = decodeHostname(input.host);
  const lower = decoded.toLowerCase();
  const registrable = registrableDomain(lower);
  const labels = lower.split(".").filter(Boolean);
  const allow = new Set((input.allowlist ?? []).map((item) => item.toLowerCase()));
  const allowed = allow.has(lower) || allow.has(registrable);
  const ipLiteral = isIp(lower);
  const mixedScript = labels.some(mixedScriptLabel);
  const tld = labels[labels.length - 1] ?? "";
  const suspiciousTld = SUSPICIOUS.has(tld);
  const freeHosting = [...FREE].some((suffix) => lower === suffix || lower.endsWith(`.${suffix}`));
  const suffixLabels = registrable.split(".").length;
  const subdomainDepth = Math.max(0, labels.length - suffixLabels);
  const lookalike = !allowed && !ipLiteral ? findLookalike(labels, registrable) : undefined;
  const pageUrl = input.pageUrl ?? `https://${input.host}/`;
  const html = input.html ?? "";
  const creds = html ? credential(html, pageUrl, registrable) : { present: false, crossOrigin: false, insecure: false };
  const title = /<title[^>]*>([^<]*)<\/title>/i.exec(html)?.[1] ?? "";
  const alts = [...html.matchAll(/\balt\s*=\s*['"]([^'"]+)['"]/gi)].map((match) => match[1] ?? "");
  const brand = html && !allowed ? mentionedBrand(`${title} ${alts.join(" ")}`, registrable) : undefined;
  const ageDays = input.ageDays ?? null;
  const signals: SiteSignal[] = [];

  if (lookalike?.confidence === "high") {
    signals.push({
      id: "DOMAIN_LOOKALIKE",
      severity: "critical",
      recommendationOnly: false,
      title: `Lookalike of ${lookalike.brand}`,
      summary: lookalike.reason,
    });
  } else if (lookalike) {
    signals.push({
      id: "DOMAIN_SIMILAR",
      severity: "high",
      recommendationOnly: true,
      title: `Similar to ${lookalike.brand}`,
      summary: lookalike.reason,
    });
  }
  if (mixedScript) {
    signals.push({
      id: "DOMAIN_MIXED_SCRIPT",
      severity: "high",
      recommendationOnly: true,
      title: "Mixed-script hostname",
      summary: "A label mixes Latin letters with Cyrillic or Greek letters.",
    });
  }
  if (ageDays !== null && ageDays < 7 && creds.present) {
    signals.push({
      id: "DOMAIN_NEW_LOGIN",
      severity: "critical",
      recommendationOnly: false,
      title: "New domain asks for credentials",
      summary: `The registrable domain is ${ageDays} days old and the page has a credential form.`,
    });
  } else if (ageDays !== null && ageDays < 30) {
    signals.push({
      id: "DOMAIN_NEW",
      severity: "high",
      recommendationOnly: true,
      title: "Newly registered domain",
      summary: `The registrable domain is ${ageDays} days old.`,
    });
  }
  if (ipLiteral && creds.present) {
    signals.push({
      id: "DOMAIN_IP_LOGIN",
      severity: "critical",
      recommendationOnly: false,
      title: "Credential form on an IP address",
      summary: "A password, OTP, or card field is served from an IP literal.",
    });
  } else if (ipLiteral) {
    signals.push({
      id: "DOMAIN_IP_LITERAL",
      severity: "high",
      recommendationOnly: true,
      title: "Host is an IP address",
      summary: "The URL uses an IP literal instead of a name.",
    });
  }
  if (suspiciousTld) {
    signals.push({
      id: "DOMAIN_SUSPICIOUS_TLD",
      severity: "medium",
      recommendationOnly: true,
      title: "Suspicious TLD",
      summary: `The domain uses .${tld}.`,
    });
  }
  if (freeHosting && !lookalike) {
    signals.push({
      id: "DOMAIN_FREE_HOSTING",
      severity: "medium",
      recommendationOnly: true,
      title: "Free-hosting suffix",
      summary: "The host is on a free-hosting suffix.",
    });
  }
  if (subdomainDepth >= 3) {
    signals.push({
      id: "DOMAIN_SUBDOMAIN_DEPTH",
      severity: "medium",
      recommendationOnly: true,
      title: "Deep subdomain",
      summary: `The hostname has ${subdomainDepth} labels in front of the registrable domain.`,
    });
  }
  if (brand) {
    signals.push({
      id: "DOMAIN_BRAND_IMPERSONATION",
      severity: creds.present ? "critical" : "high",
      recommendationOnly: !creds.present,
      title: `Page names ${brand}`,
      summary: creds.present
        ? `Visible text names ${brand} on a non-${brand} domain, next to a credential field.`
        : `Visible text names ${brand} on a non-${brand} domain.`,
    });
  }
  if (creds.present && creds.crossOrigin) {
    signals.push({
      id: "DOMAIN_CREDENTIAL_CROSS_ORIGIN",
      severity: "critical",
      recommendationOnly: false,
      title: "Credential form posts off-origin",
      summary: "A password, OTP, or card field posts to another origin or registrable domain.",
    });
  }
  if (creds.present && creds.insecure) {
    signals.push({
      id: "DOMAIN_CREDENTIAL_HTTP",
      severity: "critical",
      recommendationOnly: false,
      title: "Credential form on http",
      summary: "A password, OTP, or card field is shown or posted over http.",
    });
  }

  const level = signals.some((signal) => signal.severity === "critical" && !signal.recommendationOnly)
    ? "block"
    : signals.length > 0
      ? "warn"
      : "ok";

  const assessment: SiteAssessment = {
    host: lower,
    registrableDomain: registrable,
    mixedScript,
    ipLiteral,
    suspiciousTld,
    freeHosting,
    subdomainDepth,
    credentialForm: creds.present,
    credentialCrossOrigin: creds.crossOrigin,
    credentialInsecure: creds.insecure,
    ageDays,
    level,
    signals,
  };
  if (lookalike) assessment.lookalike = lookalike;
  if (brand) assessment.brandImpersonation = { brand, withCredential: creds.present };
  return assessment;
}
