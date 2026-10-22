import { randomBytes, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { connect as netConnect } from "node:net";
import { VerdictTimeout, hostVerdict, verdictHost, type HostVerdict } from "./verdict.js";

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 60;
export const VERDICT_TOKEN_HEADER = "x-vigil-token";
const SQUAT_ERROR = "Another process is listening on 127.0.0.1. vigil serve will not share the port. The native host is the path.";

export async function startVerdictServer(options: {
  port?: number;
  host?: string;
  token?: string;
  verdict?: (host: string) => Promise<HostVerdict>;
} = {}): Promise<{ port: number; token: string; close: () => Promise<void> }> {
  if (options.host && options.host !== "127.0.0.1") {
    throw new Error("The verdict server listens on 127.0.0.1 only");
  }
  const requested = options.port ?? 0;
  if (requested !== 0) await assertPortFree(requested);
  const token = options.token ?? randomBytes(32).toString("hex");
  const hits: number[] = [];
  const verdict = options.verdict ?? ((host: string) => hostVerdict(host));
  let boundPort = 0;
  const server = createServer((request, response) => {
    void handle(request, response, hits, verdict, token, () => boundPort);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", (error: NodeJS.ErrnoException) => {
      reject(error.code === "EADDRINUSE" ? new Error(SQUAT_ERROR) : error);
    });
    server.listen(requested, "127.0.0.1", () => {
      const address = server.address();
      boundPort = typeof address === "object" && address ? address.port : 0;
      resolve();
    });
  });
  return {
    port: boundPort,
    token,
    close: () => new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve()))),
  };
}

function assertPortFree(port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = netConnect({ host: "127.0.0.1", port });
    const finish = (squatting: boolean) => {
      socket.destroy();
      if (squatting) reject(new Error(SQUAT_ERROR));
      else resolve();
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(300, () => finish(false));
  });
}

async function handle(
  request: IncomingMessage,
  response: ServerResponse,
  hits: number[],
  verdict: (host: string) => Promise<HostVerdict>,
  token: string,
  port: () => number,
): Promise<void> {
  try {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");
    if (request.method !== "GET" || url.pathname !== "/api/v1/verdict") {
      send(response, 404, { error: "not found" });
      return;
    }
    const bound = port();
    if (request.headers.host !== `127.0.0.1:${bound}`) {
      send(response, 403, { error: "host rejected" });
      return;
    }
    if (!tokenMatches(request.headers[VERDICT_TOKEN_HEADER], token)) {
      send(response, 401, { error: "unauthorized" });
      return;
    }
    const now = Date.now();
    while (hits.length > 0 && (hits[0] ?? 0) < now - WINDOW_MS) hits.shift();
    if (hits.length >= MAX_PER_WINDOW) {
      send(response, 429, { error: "rate limit" });
      return;
    }
    hits.push(now);
    const host = verdictHost(url.searchParams.get("host") ?? "");
    if (!host) {
      send(response, 400, { error: "host rejected" });
      return;
    }
    const result = await verdict(host);
    send(response, 200, result);
  } catch (error) {
    if (error instanceof VerdictTimeout) send(response, 504, { error: "timeout" });
    else send(response, 400, { error: "host rejected" });
  }
}

function tokenMatches(header: string | string[] | undefined, token: string): boolean {
  const value = Array.isArray(header) ? header[0] : header;
  if (!value) return false;
  const presented = Buffer.from(value);
  const expected = Buffer.from(token);
  if (presented.length !== expected.length) return false;
  return timingSafeEqual(presented, expected);
}

function send(response: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-length": Buffer.byteLength(payload),
  });
  response.end(payload);
}
