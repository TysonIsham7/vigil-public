import http from "node:http";
import https from "node:https";
import { lookup as dnsLookup } from "node:dns/promises";
import { DEFAULT_LIMITS, UrlRejected, inspectRedirect, inspectUrl, isBlockedHostname, isBlockedIp, isIpLiteral } from "@vigil/core";

export type AddressLookup = (host: string) => Promise<string[]>;

export interface PinnedAddress {
  address: string;
  family: 4 | 6;
}

export async function systemLookup(host: string): Promise<string[]> {
  const records = await dnsLookup(host, { all: true, verbatim: true });
  return records.map((record) => record.address);
}

/** One resolution. Every returned address must be public. Callers dial `address` and do not look the name up again. */
export async function pinAddress(host: string, lookup: AddressLookup = systemLookup): Promise<PinnedAddress> {
  const bare = host.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  if (!bare || isBlockedHostname(bare)) throw new UrlRejected("Host is not allowed");
  if (isIpLiteral(bare)) {
    if (isBlockedIp(bare)) throw new UrlRejected("Address is not allowed");
    return { address: bare, family: bare.includes(":") ? 6 : 4 };
  }
  let addresses: string[];
  try {
    addresses = await lookup(bare);
  } catch (error) {
    if (error instanceof UrlRejected) throw error;
    throw new UrlRejected("DNS lookup failed");
  }
  if (addresses.length === 0) throw new UrlRejected("DNS lookup failed");
  for (const address of addresses) {
    if (isBlockedIp(address)) throw new UrlRejected("Address is not allowed");
  }
  const address = addresses[0] ?? "";
  if (!address) throw new UrlRejected("DNS lookup failed");
  return { address, family: address.includes(":") ? 6 : 4 };
}

type DialLookup = (
  hostname: string,
  options: unknown,
  callback: (err: NodeJS.ErrnoException | null, address: string | { address: string; family: number }[], family?: number) => void,
) => void;

/** Lookup callback that returns only the address from `pinAddress`. */
export function pinnedLookup(pinned: PinnedAddress): DialLookup {
  return (_hostname, options, callback) => {
    const all = typeof options === "object" && options !== null && "all" in options && Boolean(options.all);
    if (all) {
      callback(null, [{ address: pinned.address, family: pinned.family }]);
      return;
    }
    callback(null, pinned.address, pinned.family);
  };
}

export interface SafeResponse {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
  truncated: boolean;
}

export type PinnedRequest = (
  url: URL,
  pinned: PinnedAddress,
  init: { headers: Record<string, string>; signal: AbortSignal },
) => Promise<Response>;

export async function safeFetch(
  input: string,
  options: {
    lookup?: AddressLookup;
    fetchImpl?: typeof fetch;
    requestImpl?: PinnedRequest;
    maxBytes?: number;
    maxRedirects?: number;
    timeoutMs?: number;
    headers?: Record<string, string>;
    signal?: AbortSignal;
  } = {},
): Promise<SafeResponse> {
  const lookup = options.lookup ?? systemLookup;
  const fetchImpl = options.fetchImpl;
  const requestImpl = options.requestImpl ?? nodePinnedFetch;
  const maxBytes = options.maxBytes ?? DEFAULT_LIMITS.liveResponseBytes;
  const maxRedirects = options.maxRedirects ?? 5;
  let current = inspectUrl(input);
  let pinned = await pinAddress(current.hostname, lookup);
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const signal = combinedSignal(options.timeoutMs ?? DEFAULT_LIMITS.wallClockMs, options.signal);
    const headers = { "user-agent": "vigil/2.0", ...(options.headers ?? {}) };
    const response = fetchImpl
      ? await fetchImpl(current.toString(), { redirect: "manual", headers, signal })
      : await requestImpl(current, pinned, { headers, signal });
    const location = response.headers.get("location");
    if (response.status >= 300 && response.status < 400 && location) {
      await response.body?.cancel().catch(() => undefined);
      if (hop === maxRedirects) throw new UrlRejected("Too many redirects");
      current = inspectRedirect(current.toString(), location);
      pinned = await pinAddress(current.hostname, lookup);
      continue;
    }
    const collected = await readCapped(response, maxBytes);
    return {
      url: current.toString(),
      status: response.status,
      headers: headerRecord(response.headers),
      body: collected.body,
      truncated: collected.truncated,
    };
  }
  throw new UrlRejected("Too many redirects");
}

function combinedSignal(timeoutMs: number, outer?: AbortSignal): AbortSignal {
  const signals = [AbortSignal.timeout(timeoutMs)];
  if (outer) signals.push(outer);
  return AbortSignal.any(signals);
}

function nodePinnedFetch(url: URL, pinned: PinnedAddress, init: { headers: Record<string, string>; signal: AbortSignal }): Promise<Response> {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === "https:";
    const lib = secure ? https : http;
    const hostname = url.hostname.replace(/^\[|\]$/g, "");
    const req = lib.request({
      hostname,
      port: url.port || (secure ? 443 : 80),
      path: `${url.pathname}${url.search}`,
      method: "GET",
      headers: init.headers,
      servername: isIpLiteral(hostname) ? undefined : hostname,
      lookup: pinnedLookup(pinned) as https.RequestOptions["lookup"],
      rejectUnauthorized: true,
    }, (incoming) => {
      const chunks: Buffer[] = [];
      incoming.on("data", (chunk: Buffer) => chunks.push(chunk));
      incoming.on("error", reject);
      incoming.on("end", () => {
        const headers = new Headers();
        for (const [key, value] of Object.entries(incoming.headers)) {
          if (value === undefined) continue;
          const list = Array.isArray(value) ? value : [value];
          for (const item of list) headers.append(key, item);
        }
        resolve(new Response(Buffer.concat(chunks), { status: incoming.statusCode ?? 0, headers }));
      });
    });
    const abort = () => req.destroy(init.signal.reason instanceof Error ? init.signal.reason : new DOMException("aborted", "AbortError"));
    if (init.signal.aborted) {
      abort();
      reject(init.signal.reason instanceof Error ? init.signal.reason : new DOMException("aborted", "AbortError"));
      return;
    }
    init.signal.addEventListener("abort", abort, { once: true });
    req.on("error", reject);
    req.end();
  });
}

function headerRecord(headers: Headers): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  headers.forEach((value, key) => {
    if (key === "set-cookie") return;
    out[key] = value;
  });
  const cookies = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : [];
  if (cookies.length === 1 && cookies[0]) out["set-cookie"] = cookies[0];
  else if (cookies.length > 1) out["set-cookie"] = cookies;
  else {
    const single = headers.get("set-cookie");
    if (single) out["set-cookie"] = single;
  }
  return out;
}

async function readCapped(response: Response, maxBytes: number): Promise<{ body: string; truncated: boolean }> {
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    const encoded = new TextEncoder().encode(text);
    if (encoded.byteLength <= maxBytes) return { body: text, truncated: false };
    return { body: new TextDecoder().decode(encoded.slice(0, maxBytes)), truncated: true };
  }
  const chunks: Uint8Array[] = [];
  let size = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done || !value) break;
    if (size + value.byteLength > maxBytes) {
      const room = maxBytes - size;
      if (room > 0) chunks.push(value.slice(0, room));
      size = maxBytes;
      truncated = true;
      await reader.cancel().catch(() => undefined);
      break;
    }
    chunks.push(value);
    size += value.byteLength;
  }
  const merged = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { body: new TextDecoder("utf-8", { fatal: false }).decode(merged), truncated };
}
