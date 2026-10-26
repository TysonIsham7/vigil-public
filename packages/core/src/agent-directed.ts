import patterns from "../data/agent-directed.json" with { type: "json" };

/** Same order of magnitude as the live response cap. A decode that grows past this keeps the prefix. */
export const AGENT_TEXT_CAP = Math.floor(1.5 * 1024 * 1024);

export const AGENT_WINDOW = patterns.window;

export type AgentSurface = "body" | "hidden" | "meta" | "robots" | "llms" | "header";

export type AgentAskKind = "credential" | "identity" | "behavior";

export interface AgentMatch {
  kind: AgentAskKind;
  surface: AgentSurface;
  evidence: string;
}

const KIND_RANK: Record<AgentAskKind, number> = {
  credential: 3,
  identity: 2,
  behavior: 1,
};

const ASK_KINDS: AgentAskKind[] = ["credential", "identity", "behavior"];

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: "\"",
  apos: "'",
  nbsp: " ",
};

export function surfaceFile(surface: AgentSurface): string {
  if (surface === "robots") return "(page:robots.txt)";
  if (surface === "llms") return "(page:llms.txt)";
  return `(page:${surface})`;
}

export function detectAgentDirected(
  text: string,
  surface: AgentSurface,
  options: { cap?: number } = {},
): AgentMatch | null {
  const cap = options.cap ?? AGENT_TEXT_CAP;
  let best: { kind: AgentAskKind; evidence: string; rank: number } | null = null;
  for (const normalized of normalizePasses(text, surface, cap)) {
    const found = matchNormalized(normalized);
    if (!found) continue;
    if (!best || found.rank > best.rank) best = found;
  }
  if (!best) return null;
  return { kind: best.kind, surface, evidence: best.evidence };
}

export interface PageSurfaces {
  body: string;
  hidden: string;
  meta: string;
}

/** Split static HTML into visible text, hidden text, and metadata. No script runs. */
export function extractPageSurfaces(html: string): PageSurfaces {
  let rest = html;
  const hidden: string[] = [];
  const meta: string[] = [];

  rest = rest.replace(/<!--([\s\S]*?)-->/g, (_full, inner: string) => {
    hidden.push(inner);
    return " ";
  });
  rest = rest.replace(/<meta\b([^>]*)>/gi, (_full, attrs: string) => {
    const name = attr(attrs, "name").toLowerCase();
    const equiv = attr(attrs, "http-equiv").toLowerCase();
    if (attr(attrs, "charset") || equiv === "charset" || name === "viewport" || name === "charset") return " ";
    const content = attr(attrs, "content");
    const property = attr(attrs, "property");
    const label = attr(attrs, "name");
    meta.push([label, property, content].filter(Boolean).join(" "));
    return " ";
  });
  rest = rest.replace(/<title\b[^>]*>([\s\S]*?)<\/title>/gi, (_full, inner: string) => {
    meta.push(inner);
    return " ";
  });
  rest = rest.replace(/<noscript\b[^>]*>([\s\S]*?)<\/noscript>/gi, (_full, inner: string) => {
    hidden.push(inner);
    return " ";
  });
  rest = rest.replace(/<template\b[^>]*>([\s\S]*?)<\/template>/gi, (_full, inner: string) => {
    hidden.push(inner);
    return " ";
  });
  rest = rest.replace(/<input\b([^>]*)>/gi, (_full, attrs: string) => {
    if (attr(attrs, "type").toLowerCase() === "hidden") hidden.push(attr(attrs, "value"));
    return " ";
  });
  rest = liftHiddenElements(rest, hidden);
  return {
    body: rest,
    hidden: hidden.join("\n"),
    meta: meta.join("\n"),
  };
}

export function inspectHtml(html: string, options: { cap?: number } = {}): AgentMatch[] {
  const surfaces = extractPageSurfaces(html);
  const matches: AgentMatch[] = [];
  const body = detectAgentDirected(surfaces.body, "body", options);
  const hidden = detectAgentDirected(surfaces.hidden, "hidden", options);
  const meta = detectAgentDirected(surfaces.meta, "meta", options);
  if (body) matches.push(body);
  if (hidden) matches.push(hidden);
  if (meta) matches.push(meta);
  return matches;
}

function normalizePasses(text: string, surface: AgentSurface, limit: number): string[] {
  let decoded = text;
  if (surface === "header" || surface === "robots") decoded = percentDecodeOnce(decoded, limit);
  decoded = decodeHtmlOnce(decoded, limit);
  if (decoded.length > limit) decoded = decoded.slice(0, limit);
  const spaced = collapse(stripTags(decoded, " "));
  const joined = collapse(stripTags(decoded, ""));
  return spaced === joined ? [spaced] : [spaced, joined];
}

function matchNormalized(normalized: string): { kind: AgentAskKind; evidence: string; rank: number } | null {
  if (!normalized) return null;
  const folded = normalized.toLowerCase();
  const addresses = spansOf(folded, patterns.addresses);
  if (addresses.length === 0) return null;
  let best: { kind: AgentAskKind; rank: number; start: number } | null = null;
  for (const kind of ASK_KINDS) {
    const phrases = patterns.asks[kind];
    for (const span of spansOf(folded, phrases)) {
      for (const address of addresses) {
        if (gap(address, span) > patterns.window) continue;
        const rank = KIND_RANK[kind];
        const start = Math.min(address.start, span.start);
        if (!best || rank > best.rank) best = { kind, rank, start };
      }
    }
  }
  if (!best) return null;
  const source = folded.length === normalized.length ? normalized : folded;
  const start = Math.max(0, best.start);
  const excerpt = source.slice(start, start + 160).trim();
  return { kind: best.kind, rank: best.rank, evidence: excerpt };
}

function spansOf(haystack: string, phrases: readonly string[]): { start: number; end: number }[] {
  const spans: { start: number; end: number }[] = [];
  for (const phrase of phrases) {
    const needle = phrase.toLowerCase();
    let from = 0;
    while (from < haystack.length) {
      const at = haystack.indexOf(needle, from);
      if (at < 0) break;
      const end = at + needle.length;
      if (bounded(haystack, at, end)) spans.push({ start: at, end });
      from = at + 1;
    }
  }
  return spans;
}

function bounded(haystack: string, start: number, end: number): boolean {
  const before = start === 0 ? "" : haystack[start - 1] ?? "";
  const after = end >= haystack.length ? "" : haystack[end] ?? "";
  return wordEdge(before) && wordEdge(after);
}

function wordEdge(char: string): boolean {
  return char === "" || !/[a-z0-9]/i.test(char);
}

function gap(left: { start: number; end: number }, right: { start: number; end: number }): number {
  if (left.end <= right.start) return right.start - left.end;
  if (right.end <= left.start) return left.start - right.end;
  return 0;
}

function collapse(input: string): string {
  return input.normalize("NFKC").replace(/\s+/g, " ").trim();
}

function stripTags(input: string, replacement: string): string {
  return input.replace(/<[^>]*>/g, replacement);
}

function decodeHtmlOnce(input: string, cap: number): string {
  let out = "";
  for (let i = 0; i < input.length && out.length < cap; i += 1) {
    if (input[i] !== "&") {
      out += input[i];
      continue;
    }
    const semi = input.indexOf(";", i + 1);
    if (semi === -1 || semi - i > 32) {
      out += "&";
      continue;
    }
    const decoded = decodeEntity(input.slice(i + 1, semi));
    if (decoded === null) {
      out += "&";
      continue;
    }
    if (out.length + decoded.length > cap) return out;
    out += decoded;
    i = semi;
  }
  return out;
}

function decodeEntity(token: string): string | null {
  const named = NAMED_ENTITIES[token.toLowerCase()];
  if (named) return named;
  if (/^#x[0-9a-f]+$/i.test(token)) {
    const code = Number.parseInt(token.slice(2), 16);
    return codePoint(code);
  }
  if (/^#\d+$/.test(token)) return codePoint(Number.parseInt(token.slice(1), 10));
  return null;
}

function codePoint(code: number): string | null {
  if (!Number.isInteger(code) || code < 0 || code > 0x10ffff) return null;
  if (code >= 0xd800 && code <= 0xdfff) return null;
  return String.fromCodePoint(code);
}

function percentDecodeOnce(input: string, cap: number): string {
  let out = "";
  for (let i = 0; i < input.length && out.length < cap; i += 1) {
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

function attr(source: string, name: string): string {
  const match = new RegExp(`\\b${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>]+))`, "i").exec(source);
  return match?.[1] ?? match?.[2] ?? match?.[3] ?? "";
}

const VOID_TAGS = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);

function liftHiddenElements(html: string, hidden: string[]): string {
  const tagRe = /<([a-zA-Z][\w:-]*)\b([^>]*)>/g;
  let out = "";
  let cursor = 0;
  let match: RegExpExecArray | null;
  while ((match = tagRe.exec(html))) {
    const name = match[1]?.toLowerCase() ?? "";
    const attrs = match[2] ?? "";
    if (!elementIsHidden(attrs)) continue;
    out += html.slice(cursor, match.index);
    const selfClosing = VOID_TAGS.has(name) || /\/\s*$/.test(attrs);
    if (selfClosing) {
      const value = attr(attrs, "value");
      if (value) hidden.push(value);
      cursor = tagRe.lastIndex;
      continue;
    }
    const closed = consumeClose(html, tagRe.lastIndex, name);
    hidden.push(closed.inner);
    cursor = closed.end;
    tagRe.lastIndex = cursor;
  }
  out += html.slice(cursor);
  return out;
}

function elementIsHidden(attrs: string): boolean {
  if (/(^|\s)hidden(\s|=|$)/i.test(attrs)) return true;
  if (/aria-hidden\s*=\s*['"]?\s*true/i.test(attrs)) return true;
  const style = attr(attrs, "style");
  return style ? hiddenStyle(style) : false;
}

function hiddenStyle(style: string): boolean {
  const compact = style.toLowerCase().replace(/\s+/g, "");
  if (compact.includes("display:none")) return true;
  if (compact.includes("visibility:hidden")) return true;
  if (/(?:^|;)opacity:0(?:\.0+)?(?:;|$)/.test(compact)) return true;
  if (/(?:^|;)font-size:0(?:px|em|rem|pt|%)?(?:;|$)/.test(compact)) return true;
  if (/(?:^|;)(?:left|top|right|bottom|text-indent):-?\d{4,}px/.test(compact)) return true;
  const color = /(?:^|;)color:([^;]+)/.exec(compact);
  const background = /(?:^|;)background(?:-color)?:([^;]+)/.exec(compact);
  if (!color?.[1] || !background?.[1]) return false;
  const left = cssColor(color[1]);
  const right = cssColor(background[1]);
  return Boolean(left && right && left === right && left !== "transparent");
}

function cssColor(value: string): string | null {
  const named: Record<string, string> = {
    white: "ffffff",
    black: "000000",
    red: "ff0000",
    blue: "0000ff",
    transparent: "transparent",
  };
  if (named[value]) return named[value];
  const hex = /^#([0-9a-f]{3}|[0-9a-f]{6})$/.exec(value);
  if (hex?.[1]) {
    const raw = hex[1];
    return raw.length === 3 ? `${raw[0]}${raw[0]}${raw[1]}${raw[1]}${raw[2]}${raw[2]}` : raw;
  }
  const rgb = /^rgb\((\d{1,3}),(\d{1,3}),(\d{1,3})\)$/.exec(value);
  if (!rgb?.[1] || !rgb[2] || !rgb[3]) return null;
  return [rgb[1], rgb[2], rgb[3]].map((part) => Number(part).toString(16).padStart(2, "0")).join("");
}

function consumeClose(html: string, from: number, name: string): { inner: string; end: number } {
  const re = new RegExp(`<(/?)${name}\\b[^>]*>`, "gi");
  re.lastIndex = from;
  let depth = 1;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html))) {
    const closing = match[1] === "/";
    if (!closing && /\/\s*>$/.test(match[0])) continue;
    depth += closing ? -1 : 1;
    if (depth === 0) return { inner: html.slice(from, match.index), end: re.lastIndex };
  }
  return { inner: html.slice(from), end: html.length };
}
