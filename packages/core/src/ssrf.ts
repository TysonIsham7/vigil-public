export class UrlRejected extends Error {
  readonly code = "url_rejected" as const;

  constructor(message: string) {
    super(message);
    this.name = "UrlRejected";
  }
}

const DENIED_HOSTS = new Set([
  "localhost",
  "localhost.localdomain",
  "ip6-localhost",
  "ip6-loopback",
  "metadata",
  "metadata.google.internal",
  "metadata.google.com",
  "metadata.goog",
  "kubernetes.default",
  "kubernetes.default.svc",
  "instance-data",
]);

export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!host) return true;
  if (DENIED_HOSTS.has(host)) return true;
  if (host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) return true;
  return false;
}

function parseOctet(part: string): number | null {
  if (/^0x[0-9a-f]+$/i.test(part)) {
    const value = Number.parseInt(part, 16);
    return value <= 255 ? value : null;
  }
  if (/^0[0-7]+$/.test(part)) {
    const value = Number.parseInt(part, 8);
    return value <= 255 ? value : null;
  }
  if (/^\d+$/.test(part)) {
    const value = Number(part);
    return value <= 255 ? value : null;
  }
  return null;
}

function partsFromInt(value: number): [number, number, number, number] {
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
}

export function parseIPv4(host: string): [number, number, number, number] | null {
  const text = host.trim().toLowerCase();
  if (/^0x[0-9a-f]+$/i.test(text)) {
    const value = Number.parseInt(text, 16);
    if (!Number.isFinite(value) || value < 0 || value > 0xffffffff) return null;
    return partsFromInt(value);
  }
  if (/^\d+$/.test(text) && text.length > 3) {
    const value = Number(text);
    if (!Number.isFinite(value) || value < 0 || value > 0xffffffff) return null;
    return partsFromInt(value);
  }
  const parts = text.split(".");
  if (parts.length !== 4) return null;
  const octets = parts.map(parseOctet);
  if (octets.some((part) => part === null)) return null;
  return octets as [number, number, number, number];
}

export function isBlockedIPv4(parts: [number, number, number, number]): boolean {
  const [a, b, c, d] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 224 && a <= 239) return true;
  if (a === 255 && b === 255 && c === 255 && d === 255) return true;
  return false;
}

function expandIPv6(input: string): string[] | null {
  const text = input.toLowerCase();
  if (text.includes(":::")) return null;
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const parseSide = (side: string): string[] => (side === "" ? [] : side.split(":"));
  if (halves.length === 1) {
    const parts = parseSide(text);
    if (parts.length !== 8 || parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
    return parts.map((part) => part.padStart(4, "0"));
  }
  const head = parseSide(halves[0] ?? "");
  const tail = parseSide(halves[1] ?? "");
  if ([...head, ...tail].some((part) => part !== "" && !/^[0-9a-f]{1,4}$/.test(part))) return null;
  if (head.length + tail.length > 7) return null;
  const missing = 8 - head.length - tail.length;
  const parts = [...head, ...Array.from({ length: missing }, () => "0"), ...tail];
  if (parts.length !== 8) return null;
  return parts.map((part) => part.padStart(4, "0"));
}

function embedDottedTail(text: string): string {
  const match = text.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (!match?.[1] || !match[2]) return text;
  const parts = parseIPv4(match[2]);
  if (!parts) return text;
  const hi = ((parts[0] << 8) | parts[1]).toString(16);
  const lo = ((parts[2] << 8) | parts[3]).toString(16);
  return `${match[1]}${hi}:${lo}`;
}

function mappedV4(hi: number, lo: number): [number, number, number, number] {
  return [(hi >> 8) & 255, hi & 255, (lo >> 8) & 255, lo & 255];
}

export function isBlockedIPv6(host: string): boolean {
  const text = embedDottedTail(host.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "");
  const mapped = text.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped?.[1]) {
    const parts = parseIPv4(mapped[1]);
    return parts ? isBlockedIPv4(parts) : false;
  }
  const mappedHex = text.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mappedHex?.[1] && mappedHex[2]) {
    return isBlockedIPv4(mappedV4(Number.parseInt(mappedHex[1], 16), Number.parseInt(mappedHex[2], 16)));
  }
  const full = expandIPv6(text);
  if (!full) return false;
  const nums = full.map((part) => Number.parseInt(part, 16));
  const first = nums[0] ?? 0;
  if (first >= 0xfe80 && first <= 0xfebf) return true;
  if (first >= 0xfc00 && first <= 0xfdff) return true;
  if (first >= 0xfec0 && first <= 0xfeff) return true;
  if (nums.every((part) => part === 0)) return true;
  if (nums.slice(0, 7).every((part) => part === 0) && nums[7] === 1) return true;
  const nat64 = full[0] === "0064"
    && full[1] === "ff9b"
    && full[2] === "0000"
    && full[3] === "0000"
    && full[4] === "0000"
    && full[5] === "0000";
  if (nat64) return true;
  if (nums[0] === 0 && nums[1] === 0 && nums[2] === 0 && nums[3] === 0 && nums[4] === 0 && nums[5] === 0xffff) {
    return isBlockedIPv4(mappedV4(nums[6] ?? 0, nums[7] ?? 0));
  }
  if (first === 0x2002) return isBlockedIPv4(mappedV4(nums[1] ?? 0, nums[2] ?? 0));
  return false;
}

export function isIpLiteral(host: string): boolean {
  const text = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  if (text.includes(":")) return expandIPv6(text.split("%")[0] ?? text) !== null || text.startsWith("::ffff:");
  return parseIPv4(text) !== null;
}

export function isBlockedIp(host: string): boolean {
  const text = host.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  const v4 = parseIPv4(text);
  if (v4) return isBlockedIPv4(v4);
  if (text.includes(":")) return isBlockedIPv6(text);
  return false;
}

/** Reject non-http(s), userinfo, localhost, metadata names, and blocked IP literals. */
export function inspectUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UrlRejected("URL is not valid");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UrlRejected(`Scheme ${url.protocol.replace(":", "")} is not allowed`);
  }
  if (url.username || url.password) {
    throw new UrlRejected("URLs with user info are not allowed");
  }
  const host = url.hostname;
  if (!host) throw new UrlRejected("URL is missing a host");
  if (isBlockedHostname(host)) throw new UrlRejected("Host is not allowed");
  if (isIpLiteral(host) && isBlockedIp(host)) throw new UrlRejected("Address is not allowed");
  return url;
}

/** Re-check a redirect target against the same policy. Relative locations resolve against the current URL. */
export function inspectRedirect(current: string, location: string): URL {
  let next: URL;
  try {
    next = new URL(location, current);
  } catch {
    throw new UrlRejected("Redirect URL is not valid");
  }
  return inspectUrl(next.toString());
}
