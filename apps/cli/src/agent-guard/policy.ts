import { hmacEquals, MIN_TOKEN_LENGTH, type Identity } from "./identity.js";

export const DEFAULT_BODY_CAP = 1024 * 1024;
export const DEFAULT_ROTATE_BYTES = 1024 * 1024;

export type MatchKind = "email" | "phone" | "token" | "name" | "address";
export type PolicyName = "allow" | "strip" | "block";
export type DecisionName = "allow" | "block" | "strip";

export interface HeaderLine {
  name: string;
  value: string;
}

export interface GuardRequest {
  host: string;
  path: string;
  headers: HeaderLine[];
  body: string;
}

export interface GuardDecision {
  decision: DecisionName;
  kind: string;
  policy: PolicyName;
  message: string;
  path: string;
  headers: HeaderLine[];
  body: string;
}

interface Hit {
  kind: MatchKind;
  where: "header" | "query" | "body";
  headerIndex?: number;
  queryKey?: string;
  start?: number;
  end?: number;
}

const KIND_ORDER: MatchKind[] = ["token", "email", "phone", "name", "address"];

export function parseAllowlist(text: string): Map<string, PolicyName> {
  const map = new Map<string, PolicyName>();
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;
    const parts = trimmed.split(/\s+/);
    const policy = parts[0];
    const host = parts[1];
    if ((policy !== "allow" && policy !== "strip" && policy !== "block") || !host || parts.length !== 2) {
      throw new Error("allowlist line must be allow, strip, or block and one hostname");
    }
    map.set(normalizeHost(host), policy);
  }
  return map;
}

export function policyFor(host: string, list: Map<string, PolicyName>): PolicyName {
  return list.get(normalizeHost(host)) ?? "block";
}

export function decideRequest(
  request: GuardRequest,
  identity: Identity,
  key: Buffer,
  policy: PolicyName,
  truncated: boolean,
): GuardDecision {
  const base = { policy, path: request.path, headers: request.headers, body: request.body };
  if (truncated) {
    return { ...base, decision: "block", kind: "-", message: `body was not fully visible for ${request.host}` };
  }
  const hits = collectHits(request, identity, key);
  if (policy === "allow") {
    return { ...base, decision: "allow", kind: primaryKind(hits), message: "" };
  }
  if (hits.some((hit) => hit.kind === "token")) {
    return { ...base, decision: "block", kind: "token", message: `blocked token for ${request.host}` };
  }
  if (policy === "block") {
    if (hits.length === 0) return { ...base, decision: "allow", kind: "-", message: "" };
    const kind = primaryKind(hits);
    return { ...base, decision: "block", kind, message: `blocked ${kind} for ${request.host}` };
  }
  if (hits.length === 0) return { ...base, decision: "allow", kind: "-", message: "" };
  const stripped = removeOne(request, hits[0]!);
  const residual = collectHits(stripped, identity, key);
  if (residual.length > 0) {
    const kind = primaryKind(residual);
    return { ...base, decision: "block", kind, message: `blocked ${kind} for ${request.host}` };
  }
  return {
    decision: "strip",
    kind: hits[0]!.kind,
    policy,
    message: "",
    path: stripped.path,
    headers: stripped.headers,
    body: stripped.body,
  };
}

function primaryKind(hits: Hit[]): string {
  for (const kind of KIND_ORDER) {
    if (hits.some((hit) => hit.kind === kind)) return kind;
  }
  return "-";
}

function collectHits(request: GuardRequest, identity: Identity, key: Buffer): Hit[] {
  const hits: Hit[] = [];
  request.headers.forEach((header, index) => {
    if (skipHeader(header.name)) return;
    for (const hit of hitsInText(header.value, identity, key)) {
      hits.push({ ...hit, where: "header", headerIndex: index });
    }
  });
  const queryAt = request.path.indexOf("?");
  if (queryAt >= 0) {
    for (const part of request.path.slice(queryAt + 1).split("&")) {
      if (!part) continue;
      const eq = part.indexOf("=");
      const rawKey = eq < 0 ? part : part.slice(0, eq);
      const rawValue = eq < 0 ? "" : part.slice(eq + 1);
      const value = percentDecodeOnce(rawValue);
      const found = hitsInText(value, identity, key);
      if (found.length === 0) continue;
      hits.push({ ...found[0]!, where: "query", queryKey: percentDecodeOnce(rawKey) });
    }
  }
  const pathOnly = queryAt >= 0 ? request.path.slice(0, queryAt) : request.path;
  for (const hit of hitsInText(percentDecodeOnce(pathOnly), identity, key)) {
    hits.push({ kind: hit.kind, where: "body" });
  }
  for (const hit of hitsInText(request.body, identity, key)) {
    hits.push({ ...hit, where: "body" });
  }
  for (const value of jsonStrings(request.body)) {
    for (const hit of hitsInText(value, identity, key)) {
      hits.push({ kind: hit.kind, where: "body" });
    }
  }
  return hits;
}

function removeOne(request: GuardRequest, hit: Hit): GuardRequest {
  if (hit.where === "header" && hit.headerIndex !== undefined) {
    return {
      ...request,
      headers: request.headers.filter((_header, index) => index !== hit.headerIndex),
    };
  }
  if (hit.where === "query" && hit.queryKey) {
    return { ...request, path: dropQueryKey(request.path, hit.queryKey) };
  }
  if (hit.start !== undefined && hit.end !== undefined && hit.end > hit.start) {
    return { ...request, body: `${request.body.slice(0, hit.start)}${request.body.slice(hit.end)}` };
  }
  return request;
}

function dropQueryKey(path: string, key: string): string {
  const queryAt = path.indexOf("?");
  if (queryAt < 0) return path;
  const kept = path.slice(queryAt + 1).split("&").filter((part) => {
    const eq = part.indexOf("=");
    const rawKey = eq < 0 ? part : part.slice(0, eq);
    return percentDecodeOnce(rawKey) !== key;
  });
  return kept.length === 0 ? path.slice(0, queryAt) : `${path.slice(0, queryAt)}?${kept.join("&")}`;
}

function hitsInText(text: string, identity: Identity, key: Buffer): Hit[] {
  if (!text) return [];
  const hits: Hit[] = [];
  for (const variant of textVariants(text)) {
    hits.push(...literalHits(variant.text, identity, key, variant.align));
  }
  for (const variant of plaintextVariants(text)) {
    hits.push(...nameAddressHits(variant.text, identity, variant.align));
  }
  return hits;
}

function literalHits(text: string, identity: Identity, key: Buffer, align: boolean): Hit[] {
  const hits: Hit[] = [];
  const email = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g;
  for (const match of text.matchAll(email)) {
    const value = match[0].toLowerCase();
    if (!hmacEquals(key, value, identity.emailHmac)) continue;
    const start = match.index ?? 0;
    hits.push({ kind: "email", where: "body", ...(align ? { start, end: start + match[0].length } : {}) });
  }
  for (const phone of phoneSpans(text)) {
    if (!hmacEquals(key, phone.digits, identity.phoneHmac)) continue;
    hits.push({ kind: "phone", where: "body", ...(align ? { start: phone.start, end: phone.end } : {}) });
  }
  hits.push(...tokenHits(text, identity, key, align));
  return hits;
}

function nameAddressHits(text: string, identity: Identity, align: boolean): Hit[] {
  const hits: Hit[] = [];
  const folded = text.normalize("NFKC");
  const sameLength = align && folded.length === text.length;
  for (const name of identity.names) {
    for (const span of boundedSpans(sameLength ? text : folded, name)) {
      hits.push({ kind: "name", where: "body", ...(sameLength ? span : {}) });
    }
  }
  for (const address of identity.addresses) {
    const needle = address.normalize("NFKC").toLowerCase();
    if (!needle) continue;
    const hay = folded.toLowerCase();
    let from = 0;
    while (from < hay.length) {
      const at = hay.indexOf(needle, from);
      if (at < 0) break;
      hits.push({
        kind: "address",
        where: "body",
        ...(sameLength ? { start: at, end: at + needle.length } : {}),
      });
      from = at + needle.length;
    }
  }
  return hits;
}

function textVariants(text: string): { text: string; align: boolean }[] {
  const once = percentDecodeOnce(text);
  const twice = percentDecodeOnce(once);
  const variants = [{ text, align: true }];
  if (once !== text) variants.push({ text: once, align: false });
  if (twice !== once && twice !== text) variants.push({ text: twice, align: false });
  return variants;
}

function plaintextVariants(text: string): { text: string; align: boolean }[] {
  const normalized = normalizePlaintext(text);
  const variants = [{ text, align: true }];
  if (normalized !== text) variants.push({ text: normalized, align: normalized.length === text.length });
  return variants;
}

function normalizePlaintext(text: string): string {
  let out = decodeHtmlEntities(text.normalize("NFKC"));
  out = out.replace(/\+/g, " ");
  out = percentDecodeOnce(percentDecodeOnce(out));
  out = out.replace(/\\u([0-9a-fA-F]{4})/g, (full, hex: string) => {
    const code = Number.parseInt(hex, 16);
    return Number.isInteger(code) ? String.fromCodePoint(code) : full;
  });
  return out.normalize("NFKC");
}

function decodeHtmlEntities(text: string): string {
  return text.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z]+);/g, (full, body: string) => {
    if (body.startsWith("#")) {
      const code = body[1]?.toLowerCase() === "x" ? Number.parseInt(body.slice(2), 16) : Number.parseInt(body.slice(1), 10);
      if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) return full;
      return String.fromCodePoint(code);
    }
    const named: Record<string, string> = { nbsp: " ", amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'" };
    return named[body.toLowerCase()] ?? full;
  });
}

function phoneSpans(text: string): { start: number; end: number; digits: string }[] {
  const out: { start: number; end: number; digits: string }[] = [];
  const re = /[0-9][0-9\s().+-]{8,}/g;
  for (const match of text.matchAll(re)) {
    const raw = match[0].replace(/[^\d]+$/g, "");
    const start = match.index ?? 0;
    const end = start + raw.length;
    const digits = raw.replace(/\D/g, "");
    if (digits.length < 10) continue;
    const before = start === 0 ? "" : text[start - 1] ?? "";
    const after = end >= text.length ? "" : text[end] ?? "";
    if (/[A-Za-z0-9]/.test(before) || /[A-Za-z0-9]/.test(after)) continue;
    out.push({ start, end, digits });
  }
  return out;
}

function tokenHits(text: string, identity: Identity, key: Buffer, align: boolean): Hit[] {
  if (identity.tokenHmac.length === 0 || !text) return [];
  const hits: Hit[] = [];
  const re = /[A-Za-z0-9._~+/=-]{12,}/g;
  for (const match of text.matchAll(re)) {
    const run = match[0];
    const start = match.index ?? 0;
    const found = matchTokenWindow(run, identity, key);
    if (found) {
      hits.push({
        kind: "token",
        where: "body",
        ...(align ? { start: start + found.offset, end: start + found.offset + found.length } : {}),
      });
    }
    for (const wrapped of wrappedPayloads(run)) {
      if (!matchTokenWindow(wrapped, identity, key)) continue;
      hits.push({ kind: "token", where: "body", ...(align ? { start, end: start + run.length } : {}) });
      break;
    }
  }
  return hits;
}

function matchTokenWindow(run: string, identity: Identity, key: Buffer): { offset: number; length: number } | null {
  const lengths = [...new Set(identity.tokenLengths)];
  for (const length of lengths) {
    if (length < MIN_TOKEN_LENGTH || run.length < length) continue;
    const hmacs = identity.tokenHmac.filter((_, index) => identity.tokenLengths[index] === length);
    const last = run.length - length;
    for (let offset = 0; offset <= last; offset += 1) {
      if (hmacEquals(key, run.slice(offset, offset + length), hmacs)) return { offset, length };
    }
  }
  return null;
}

function wrappedPayloads(run: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const push = (value: string | null) => {
    if (!value || value.length < MIN_TOKEN_LENGTH || seen.has(value)) return;
    seen.add(value);
    out.push(value);
  };
  const pieces = run.match(/[A-Za-z0-9+/_-]{16,}={0,2}/g) ?? [];
  for (const piece of pieces) {
    if (piece.length > 8192) continue;
    push(decodeBase64(piece));
    push(decodeBase64(piece.replace(/-/g, "+").replace(/_/g, "/")));
  }
  return out;
}

function decodeBase64(value: string): string | null {
  const compact = value.trim().replace(/=+$/g, "");
  if (compact.length < 16 || compact.length % 4 === 1) return null;
  if (!/^[A-Za-z0-9+/]+$/.test(compact)) return null;
  const padded = compact + "=".repeat((4 - (compact.length % 4)) % 4);
  const buf = Buffer.from(padded, "base64");
  if (buf.length < MIN_TOKEN_LENGTH) return null;
  if (buf.toString("base64").replace(/=+$/g, "") !== compact) return null;
  const text = buf.toString("utf8");
  if (text.includes("\uFFFD") || [...text].some((char) => isControl(char))) return null;
  return text;
}

function isControl(char: string): boolean {
  const code = char.charCodeAt(0);
  return code <= 8 || code === 11 || code === 12 || (code >= 14 && code <= 31);
}

function boundedSpans(text: string, name: string): { start: number; end: number }[] {
  const hay = text.toLowerCase();
  const needle = name.normalize("NFKC").toLowerCase();
  const spans: { start: number; end: number }[] = [];
  let from = 0;
  while (from < hay.length) {
    const at = hay.indexOf(needle, from);
    if (at < 0) break;
    const end = at + needle.length;
    const before = at === 0 ? "" : hay[at - 1] ?? "";
    const after = end >= hay.length ? "" : hay[end] ?? "";
    const edge = (char: string) => char === "" || !/[\p{L}\p{N}]/u.test(char);
    if (edge(before) && edge(after)) spans.push({ start: at, end });
    from = at + 1;
  }
  return spans;
}

function jsonStrings(body: string): string[] {
  const trimmed = body.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return [];
  try {
    return collectStrings(JSON.parse(trimmed) as unknown);
  } catch {
    return [];
  }
}

function collectStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap((item) => collectStrings(item));
  if (!value || typeof value !== "object") return [];
  return Object.values(value).flatMap((item) => collectStrings(item));
}

function percentDecodeOnce(input: string): string {
  let out = "";
  for (let i = 0; i < input.length; i += 1) {
    const hex = input.slice(i + 1, i + 3);
    if (input[i] === "%" && /^[0-9a-fA-F]{2}$/.test(hex)) {
      out += String.fromCharCode(Number.parseInt(hex, 16));
      i += 2;
      continue;
    }
    out += input[i];
  }
  return out;
}

function skipHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === "proxy-authorization" || lower === "proxy-connection";
}

function normalizeHost(host: string): string {
  return host.trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
}
