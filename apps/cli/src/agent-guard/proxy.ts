import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { connect as netConnect, createServer, type Server, type Socket } from "node:net";
import { dirname, join } from "node:path";
import { connect as tlsConnect, createSecureContext, TLSSocket } from "node:tls";
import { isBlockedHostname, isBlockedIp, isIpLiteral } from "@vigil/core";
import { systemLookup } from "@vigil/netcheck";
import { loadOrCreateCa, mintLeaf, type LocalCa } from "./cert.js";
import { assertPrivateMode, readIdentityFile, type Identity } from "./identity.js";
import { DecisionLog, type LogEntry } from "./log.js";
import {
  decideRequest,
  DEFAULT_BODY_CAP,
  parseAllowlist,
  policyFor,
  type GuardRequest,
  type HeaderLine,
  type PolicyName,
} from "./policy.js";

export interface GuardHandle {
  port: number;
  token: string;
  url: string;
  mode: "tunnel" | "intercept";
  certPath?: string;
  logPath: string;
  close: () => Promise<void>;
}

export interface GuardOptions {
  bind?: string;
  port?: number;
  ipv6?: boolean;
  mode?: "tunnel" | "intercept";
  token?: string;
  identifiersPath?: string;
  allowlistPath?: string;
  keyPath?: string;
  logPath?: string;
  caCertPath?: string;
  caKeyPath?: string;
  lookup?: (host: string) => Promise<string[]>;
  dial?: (info: { host: string; address: string; port: number }) => Promise<Socket>;
  bodyCap?: number;
  rotateAt?: number;
  originCa?: string | Buffer;
  now?: () => Date;
}

const HOP = new Set([
  "proxy-authorization",
  "proxy-connection",
  "connection",
  "keep-alive",
  "transfer-encoding",
  "upgrade",
  "te",
  "trailer",
  "proxy-authenticate",
  "host",
  "content-length",
]);

export function assertLoopbackBind(host: string): void {
  if (host === "127.0.0.1" || host === "::1") return;
  throw new Error(`refusing bind address ${host}`);
}

export function isLoopbackPeer(address: string | undefined): boolean {
  if (!address) return false;
  const host = address.toLowerCase().replace(/^\[|\]$/g, "").split("%")[0] ?? "";
  if (host === "::1") return true;
  const mapped = host.startsWith("::ffff:") ? host.slice("::ffff:".length) : host;
  const parts = mapped.split(".");
  if (parts.length !== 4) return false;
  const numbers = parts.map((part) => Number(part));
  return numbers.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) && numbers[0] === 127;
}

export async function defaultGuardLookup(host: string): Promise<string[]> {
  if (process.env.VITEST) throw new Error("agent-guard refused a live DNS lookup");
  return systemLookup(host);
}

export function defaultDial(info: { address: string; port: number }): Promise<Socket> {
  if (process.env.VITEST) return Promise.reject(new Error("agent-guard refused a live socket"));
  return connectTcp(info.address, info.port);
}

export async function startAgentGuard(options: GuardOptions = {}): Promise<GuardHandle> {
  const bind = options.bind ?? "127.0.0.1";
  assertLoopbackBind(bind);
  if (options.ipv6) assertLoopbackBind("::1");
  const mode = options.mode ?? "tunnel";
  if (mode !== "tunnel" && mode !== "intercept") throw new Error("mode must be tunnel or intercept");
  const token = options.token ?? randomBytes(24).toString("hex");
  if (token.length < 16) throw new Error("proxy token is too short");
  const identifiersPath = options.identifiersPath ?? join(configDir(), "identifiers");
  const keyPath = options.keyPath ?? join(dirname(identifiersPath), "identifiers.key");
  const allowlistPath = options.allowlistPath ?? join(dirname(identifiersPath), "allowlist");
  const logPath = options.logPath ?? join(dirname(identifiersPath), "agent-guard.log");
  const loaded = readIdentityFile(identifiersPath, keyPath);
  const allowlist = readAllowlist(allowlistPath);
  const log = new DecisionLog(logPath, options.rotateAt);
  let ca: LocalCa | undefined;
  let certPath: string | undefined;
  if (mode === "intercept") {
    certPath = options.caCertPath ?? join(dirname(identifiersPath), "agent-guard-ca.pem");
    const caKeyPath = options.caKeyPath ?? join(dirname(identifiersPath), "agent-guard-ca.key");
    ca = loadOrCreateCa(certPath, caKeyPath);
  }
  const lookup = options.lookup ?? defaultGuardLookup;
  const dial = options.dial ?? ((info: { host: string; address: string; port: number }) => defaultDial(info));
  const bodyCap = options.bodyCap ?? DEFAULT_BODY_CAP;
  const now = options.now ?? (() => new Date());
  const sockets = new Set<Socket>();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    if (!isLoopbackPeer(socket.remoteAddress)) {
      socket.destroy();
      return;
    }
    void handleSocket(socket).catch(() => socket.destroy());
  });
  const port = await listen(server, options.port ?? 0, bind);
  let v6: Server | undefined;
  if (options.ipv6) {
    v6 = createServer((socket) => {
      sockets.add(socket);
      socket.on("close", () => sockets.delete(socket));
      if (!isLoopbackPeer(socket.remoteAddress)) {
        socket.destroy();
        return;
      }
      void handleSocket(socket).catch(() => socket.destroy());
    });
    await listen(v6, port, "::1");
  }

  async function handleSocket(socket: Socket): Promise<void> {
    socket.setTimeout(8_000, () => socket.destroy());
    const reader = new Reader(socket);
    const head = await reader.readUntil("\r\n\r\n", 64 * 1024);
    const parsed = parseRequestHead(head);
    if (!parsed) {
      writeStatus(socket, 400, "Bad Request", "request was rejected");
      return;
    }
    const proxyAuth = headerValue(parsed.headers, "proxy-authorization");
    if (!authorized(proxyAuth, token)) {
      writeLog(log, now, { decision: "block", host: parsed.host || "-", kind: "-", policy: "block" });
      writeStatus(socket, 407, "Proxy Authentication Required", "proxy token required");
      return;
    }
    const resolved = await resolveDestination(parsed.host, lookup);
    if ("denied" in resolved) {
      writeLog(log, now, { decision: "block", host: parsed.host || "-", kind: "destination", policy: "block" });
      writeStatus(socket, 403, "Forbidden", `destination ${parsed.host} is not allowed`);
      return;
    }
    const policy = policyFor(parsed.host, allowlist);
    if (parsed.method === "CONNECT") {
      await handleConnect({
        socket,
        reader,
        host: parsed.host,
        port: parsed.port,
        address: resolved.address,
        policy,
        mode,
        dial,
        log,
        now,
        identity: loaded.identity,
        key: loaded.key,
        bodyCap,
        ca,
        originCa: options.originCa,
      });
      return;
    }
    if (hasUpgrade(parsed.headers) && policy !== "allow") {
      writeLog(log, now, { decision: "block", host: parsed.host, kind: "-", policy });
      writeStatus(socket, 403, "Forbidden", `upgrade is not tunneled for ${parsed.host}`);
      return;
    }
    if (hasUpgrade(parsed.headers) && policy === "allow") {
      writeLog(log, now, { decision: "tunnel", host: parsed.host, kind: "-", policy });
      const origin = await dial({ host: parsed.host, address: resolved.address, port: parsed.port });
      sockets.add(origin);
      origin.on("close", () => sockets.delete(origin));
      origin.on("error", () => socket.destroy());
      socket.on("error", () => origin.destroy());
      origin.write(formatUpgradeUpstream(parsed.method, parsed.path, parsed.host, parsed.headers));
      const pending = reader.detach();
      if (pending.length > 0) origin.write(pending);
      socket.pipe(origin);
      origin.pipe(socket);
      return;
    }
    const bodyResult = await readBody(reader, parsed.headers, bodyCap);
    if (bodyResult.truncated) {
      const decision = decideRequest(asRequest(parsed, ""), loaded.identity, loaded.key, policy, true);
      writeLog(log, now, { decision: "block", host: parsed.host, kind: decision.kind, policy });
      writeStatus(socket, 403, "Forbidden", decision.message);
      return;
    }
    const decision = decideRequest(asRequest(parsed, bodyResult.body), loaded.identity, loaded.key, policy, false);
    writeLog(log, now, { decision: decision.decision, host: parsed.host, kind: decision.kind, policy });
    if (decision.decision === "block") {
      writeStatus(socket, 403, "Forbidden", decision.message);
      return;
    }
    const origin = await dial({ host: parsed.host, address: resolved.address, port: parsed.port });
    sockets.add(origin);
    origin.on("close", () => sockets.delete(origin));
    origin.on("error", () => socket.destroy());
    socket.on("error", () => origin.destroy());
    origin.write(formatUpstream(parsed.method, decision.path, parsed.host, decision.headers, decision.body));
    origin.pipe(socket);
  }

  return {
    port,
    token,
    url: proxyUrl(token, bind, port),
    mode,
    ...(certPath ? { certPath } : {}),
    logPath,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await closeServer(server);
      if (v6) await closeServer(v6);
    },
  };
}

function proxyUrl(token: string, bind: string, port: number): string {
  const host = bind.includes(":") ? `[${bind}]` : bind;
  return `http://${token}@${host}:${port}`;
}

function configDir(): string {
  const home = process.env.HOME || process.env.USERPROFILE || "";
  return join(home, ".config", "vigil");
}

function readAllowlist(path: string): Map<string, PolicyName> {
  if (!existsSync(path)) return new Map();
  assertPrivateMode(path, statSync(path).mode, "allowlist");
  return parseAllowlist(readFileSync(path, "utf8"));
}

async function resolveDestination(
  host: string,
  lookup: (host: string) => Promise<string[]>,
): Promise<{ address: string } | { denied: true }> {
  const bare = host.trim().toLowerCase().replace(/\.$/, "").replace(/^\[|\]$/g, "");
  if (!bare || isBlockedHostname(bare)) return { denied: true };
  if (isIpLiteral(bare)) return isBlockedIp(bare) ? { denied: true } : { address: bare };
  let addresses: string[];
  try {
    addresses = await lookup(bare);
  } catch {
    return { denied: true };
  }
  if (addresses.length === 0 || addresses.some((address) => isBlockedIp(address))) return { denied: true };
  return { address: addresses[0] ?? "" };
}

async function handleConnect(input: {
  socket: Socket;
  reader: Reader;
  host: string;
  port: number;
  address: string;
  policy: PolicyName;
  mode: "tunnel" | "intercept";
  dial: (info: { host: string; address: string; port: number }) => Promise<Socket>;
  log: DecisionLog;
  now: () => Date;
  identity: Identity;
  key: Buffer;
  bodyCap: number;
  ca?: LocalCa;
  originCa?: string | Buffer;
}): Promise<void> {
  if (input.mode === "tunnel") {
    writeLog(input.log, input.now, { decision: "block", host: input.host, kind: "-", policy: input.policy });
    writeStatus(input.socket, 403, "Forbidden", `HTTPS to ${input.host} is not visible in tunnel mode`);
    return;
  }
  if (!input.ca) {
    writeStatus(input.socket, 403, "Forbidden", "intercept mode has no local CA");
    return;
  }
  input.socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
  const leaf = mintLeaf(input.ca, input.host);
  const pending = input.reader.detach();
  const tlsSocket = await acceptTls(input.socket, pending, leaf.certPem, leaf.keyPem);
  if (!tlsSocket || (tlsSocket.alpnProtocol && tlsSocket.alpnProtocol !== "http/1.1")) {
    writeLog(input.log, input.now, { decision: "block", host: input.host, kind: "-", policy: input.policy });
    tlsSocket?.destroy();
    input.socket.destroy();
    return;
  }
  const inner = new Reader(tlsSocket);
  const head = await inner.readUntil("\r\n\r\n", 64 * 1024);
  const parsed = parseRequestHead(head);
  if (!parsed || parsed.method === "CONNECT") {
    writeStatus(tlsSocket, 400, "Bad Request", "request was rejected");
    return;
  }
  const bodyResult = await readBody(inner, parsed.headers, input.bodyCap);
  const request = asRequest({ ...parsed, host: input.host }, bodyResult.body);
  const decision = decideRequest(request, input.identity, input.key, input.policy, bodyResult.truncated);
  writeLog(input.log, input.now, { decision: decision.decision === "allow" ? "allow" : decision.decision, host: input.host, kind: decision.kind, policy: input.policy });
  if (decision.decision === "block") {
    writeStatus(tlsSocket, 403, "Forbidden", decision.message);
    return;
  }
  try {
    const tcp = await input.dial({ host: input.host, address: input.address, port: input.port });
    const origin = tlsConnect({
      socket: tcp,
      servername: input.host,
      rejectUnauthorized: true,
      ALPNProtocols: ["http/1.1"],
      ...(input.originCa ? { ca: input.originCa } : {}),
    });
    origin.once("secureConnect", () => {
      origin.write(formatUpstream(parsed.method, decision.path, input.host, decision.headers, decision.body));
    });
    origin.once("error", () => {
      if (!tlsSocket.destroyed) writeStatus(tlsSocket, 502, "Bad Gateway", "origin certificate was rejected");
    });
    origin.pipe(tlsSocket);
    tlsSocket.on("error", () => origin.destroy());
  } catch {
    writeStatus(tlsSocket, 502, "Bad Gateway", "origin was not reachable");
  }
}

function acceptTls(socket: Socket, pending: Buffer, certPem: string, keyPem: string): Promise<TLSSocket | null> {
  if (pending.length > 0) socket.unshift(pending);
  const tlsSocket = new TLSSocket(socket, {
    isServer: true,
    secureContext: createSecureContext({ key: keyPem, cert: certPem }),
    ALPNProtocols: ["http/1.1"],
  });
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      tlsSocket.destroy();
      resolve(null);
    }, 5_000);
    tlsSocket.once("secure", () => {
      clearTimeout(timer);
      resolve(tlsSocket);
    });
    tlsSocket.once("error", () => {
      clearTimeout(timer);
      resolve(null);
    });
  });
}

function asRequest(parsed: ParsedRequest, body: string): GuardRequest {
  return { host: parsed.host, path: parsed.path, headers: parsed.headers, body };
}

function writeLog(log: DecisionLog, now: () => Date, entry: Omit<LogEntry, "time">): void {
  log.write({ time: now().toISOString(), ...entry });
}

interface ParsedRequest {
  method: string;
  path: string;
  host: string;
  port: number;
  headers: HeaderLine[];
}

function parseRequestHead(head: string): ParsedRequest | null {
  const lines = head.split("\r\n");
  const request = lines[0]?.split(" ") ?? [];
  const method = request[0] ?? "";
  const target = request[1] ?? "";
  const version = request[2] ?? "";
  if (!method || !target || !version.startsWith("HTTP/1.")) return null;
  const headers: HeaderLine[] = [];
  for (const line of lines.slice(1)) {
    if (!line) continue;
    const at = line.indexOf(":");
    if (at <= 0) return null;
    headers.push({ name: line.slice(0, at).trim(), value: line.slice(at + 1).trim() });
  }
  if (method === "CONNECT") {
    const split = splitHostPort(target);
    if (!split) return null;
    return { method, path: target, host: split.host, port: split.port, headers };
  }
  if (target.startsWith("http://") || target.startsWith("https://")) {
    let url: URL;
    try {
      url = new URL(target);
    } catch {
      return null;
    }
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    return { method, path: `${url.pathname}${url.search}`, host: url.hostname, port, headers };
  }
  const hostHeader = headerValue(headers, "host");
  if (!hostHeader) return null;
  const split = splitHostPort(hostHeader.includes(":") && !hostHeader.startsWith("[") ? hostHeader : `${hostHeader}:80`);
  return {
    method,
    path: target,
    host: split?.host || hostHeader,
    port: split?.port || 80,
    headers,
  };
}

function splitHostPort(target: string): { host: string; port: number } | null {
  if (target.startsWith("[")) {
    const end = target.indexOf("]");
    if (end < 0) return null;
    const port = Number(target.slice(end + 2));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
    return { host: target.slice(1, end), port };
  }
  const colon = target.lastIndexOf(":");
  if (colon < 0) return { host: target, port: 443 };
  const port = Number(target.slice(colon + 1));
  if (!Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { host: target.slice(0, colon), port };
}

async function readBody(reader: Reader, headers: HeaderLine[], cap: number): Promise<{ body: string; truncated: boolean }> {
  const transfer = headerValue(headers, "transfer-encoding") ?? "";
  if (/chunked/i.test(transfer)) return readChunked(reader, cap);
  const declared = headerValue(headers, "content-length");
  if (!declared) return { body: "", truncated: false };
  const length = Number(declared);
  if (!Number.isInteger(length) || length < 0) return { body: "", truncated: true };
  if (length > cap) return { body: "", truncated: true };
  const bytes = await reader.read(length);
  return { body: bytes.toString("utf8"), truncated: bytes.length < length };
}

async function readChunked(reader: Reader, cap: number): Promise<{ body: string; truncated: boolean }> {
  const parts: Buffer[] = [];
  let size = 0;
  while (true) {
    const line = await reader.readUntil("\r\n", 64);
    const length = Number.parseInt(line.trim(), 16);
    if (!Number.isInteger(length) || length < 0) return { body: "", truncated: true };
    if (length === 0) return { body: Buffer.concat(parts).toString("utf8"), truncated: false };
    if (size + length > cap) return { body: "", truncated: true };
    parts.push(await reader.read(length));
    size += length;
    await reader.read(2);
  }
}

export function formatUpstream(method: string, path: string, host: string, headers: HeaderLine[], body: string): Buffer {
  const kept = forwardHeaders(headers, false);
  const payload = Buffer.from(body);
  const lines = [
    `${method} ${path || "/"} HTTP/1.1`,
    `Host: ${host}`,
    ...kept.map((header) => `${header.name}: ${header.value}`),
    `Content-Length: ${payload.length}`,
    "Connection: close",
    "",
    "",
  ];
  return Buffer.concat([Buffer.from(`${lines.join("\r\n")}`), payload]);
}

export function formatUpgradeUpstream(method: string, path: string, host: string, headers: HeaderLine[]): Buffer {
  const kept = forwardHeaders(headers, true);
  const lines = [
    `${method} ${path || "/"} HTTP/1.1`,
    `Host: ${host}`,
    ...kept.map((header) => `${header.name}: ${header.value}`),
    "Connection: Upgrade",
    "",
    "",
  ];
  return Buffer.from(lines.join("\r\n"));
}

function forwardHeaders(headers: HeaderLine[], keepUpgrade: boolean): HeaderLine[] {
  const listed = connectionNames(headers);
  return headers.filter((header) => !isForwardHop(header.name, listed, keepUpgrade));
}

function connectionNames(headers: HeaderLine[]): Set<string> {
  const value = headerValue(headers, "connection") ?? "";
  const names = new Set<string>();
  for (const part of value.split(",")) {
    const name = part.trim().toLowerCase();
    if (name) names.add(name);
  }
  return names;
}

function isForwardHop(name: string, listed: Set<string>, keepUpgrade: boolean): boolean {
  const lower = name.toLowerCase();
  if (lower.startsWith("proxy-")) return true;
  if (keepUpgrade && lower === "upgrade") return false;
  if (HOP.has(lower)) return true;
  return listed.has(lower);
}

function headerValue(headers: HeaderLine[], name: string): string | undefined {
  return headers.find((header) => header.name.toLowerCase() === name)?.value;
}

function hasUpgrade(headers: HeaderLine[]): boolean {
  return headers.some((header) => header.name.toLowerCase() === "upgrade" && header.value.trim() !== "");
}

function authorized(header: string | undefined, token: string): boolean {
  if (!token || !header) return false;
  const match = /^Basic\s+(\S+)$/i.exec(header.trim());
  if (!match?.[1]) return false;
  const decoded = Buffer.from(match[1], "base64").toString("utf8");
  const colon = decoded.indexOf(":");
  const user = colon < 0 ? decoded : decoded.slice(0, colon);
  const pass = colon < 0 ? "" : decoded.slice(colon + 1);
  return safeEqual(user, token) || (pass.length > 0 && safeEqual(pass, token));
}

function safeEqual(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  if (a.length !== b.length) {
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}

function writeStatus(socket: Socket | TLSSocket, status: number, reason: string, message: string): void {
  const body = message.endsWith("\n") ? message : `${message}\n`;
  const head = [
    `HTTP/1.1 ${status} ${reason}`,
    "Content-Type: text/plain; charset=utf-8",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "Connection: close",
    "",
    "",
  ].join("\r\n");
  socket.end(`${head}${body}`);
}

function listen(server: Server, port: number, host: string): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, host, () => {
      const address = server.address();
      resolve(typeof address === "object" && address ? address.port : port);
    });
  });
}

function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()));
}

function connectTcp(address: string, port: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const client = netConnect({ host: address, port }, () => resolve(client));
    client.once("error", reject);
  });
}

class Reader {
  private buf = Buffer.alloc(0);
  private ended = false;
  private waiter: (() => void) | null = null;
  private onData: (chunk: Buffer) => void;
  private onEnd: () => void;
  constructor(private socket: Socket) {
    this.onData = (chunk: Buffer) => {
      this.buf = Buffer.concat([this.buf, chunk]);
      this.wake();
    };
    this.onEnd = () => {
      this.ended = true;
      this.wake();
    };
    socket.on("data", this.onData);
    socket.on("end", this.onEnd);
    socket.on("error", this.onEnd);
  }

  detach(): Buffer {
    this.socket.off("data", this.onData);
    this.socket.off("end", this.onEnd);
    this.socket.off("error", this.onEnd);
    const pending = this.buf;
    this.buf = Buffer.alloc(0);
    return pending;
  }

  async readUntil(marker: string, max: number): Promise<string> {
    const needle = Buffer.from(marker);
    while (!this.buf.includes(needle)) {
      if (this.buf.length > max) throw new Error("headers too large");
      if (this.ended) throw new Error("connection closed");
      await this.wait();
    }
    const at = this.buf.indexOf(needle);
    const head = this.buf.subarray(0, at).toString("utf8");
    this.buf = this.buf.subarray(at + needle.length);
    return head;
  }

  async read(length: number): Promise<Buffer> {
    while (this.buf.length < length && !this.ended) await this.wait();
    const size = Math.min(length, this.buf.length);
    const out = Buffer.from(this.buf.subarray(0, size));
    this.buf = this.buf.subarray(size);
    return out;
  }

  private wait(): Promise<void> {
    if (this.ended) return Promise.resolve();
    return new Promise((resolve) => {
      this.waiter = () => {
        this.waiter = null;
        resolve();
      };
    });
  }

  private wake(): void {
    this.waiter?.();
  }
}
