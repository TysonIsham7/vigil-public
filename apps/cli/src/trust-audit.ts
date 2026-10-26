import { execFile } from "node:child_process";
import { accessSync, constants as fsConstants } from "node:fs";
import { delimiter, join } from "node:path";
import tls from "node:tls";
import { promisify } from "node:util";
import { createFinding, type Finding } from "@vigil/core";
import { goAdvisory } from "@vigil/intel";
import incidentFile from "./trust-incidents.json" with { type: "json" };

const execFileAsync = promisify(execFile);

/** Tool deadline. The process kill is later so a tool can report its own timeout. */
export const PROBE_TIMEOUT_MS = 8_000;
const EXEC_TIMEOUT_MS = 10_000;
const PROBE_SECONDS = PROBE_TIMEOUT_MS / 1000;

/**
 * Printed for a person to review. trust-audit never executes this command.
 * It does not change a keychain, a shell profile, or a system file.
 */
export const MACOS_NEVER_TRUST_COMMAND =
  "security add-trusted-cert -r deny -k ~/Library/Keychains/login.keychain-db <pem>";

const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const PYTHON_PROBE = `
import os, re, urllib.error, urllib.request
host = os.environ.get("VIGIL_TRUST_HOST", "")
if not re.fullmatch(r"[a-z0-9.-]+", host or ""):
    raise SystemExit(2)
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None
opener = urllib.request.build_opener(NoRedirect)
req = urllib.request.Request("https://" + host + "/", method="HEAD")
try:
    with opener.open(req, timeout=${PROBE_SECONDS}) as resp:
        resp.read(0)
    print("VIGIL_EXPOSED")
except urllib.error.HTTPError:
    print("VIGIL_EXPOSED")
except Exception as exc:
    print("VIGIL_ERROR")
    print(type(exc).__name__)
    print(exc)
`.trim();

export type ProbeStatus = "blocked" | "exposed" | "unknown";
export type ToolStatus = ProbeStatus | "absent";
export type TrustMark = "never-trust" | "other" | "absent" | "unread";
export type ToolId = "node" | "curl" | "git" | "python3" | "nscurl";

export interface IncidentEndpoint {
  host: string;
  root: string;
}

export interface IncidentRoot {
  name: string;
  sha256: string | null;
}

export interface Incident {
  id: string;
  title: string;
  summary: string;
  notes: string[];
  endpoints: IncidentEndpoint[];
  roots: IncidentRoot[];
}

export interface ExecResult {
  code: number | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
}

export interface ExecRequest {
  bin: string;
  args: string[];
  env?: Record<string, string>;
  timeoutMs: number;
}

export interface TrustAuditIo {
  platform: NodeJS.Platform;
  now: Date;
  present: (bin: string) => boolean;
  exec: (request: ExecRequest) => Promise<ExecResult>;
  probeNode: (host: string) => Promise<ProbeStatus>;
  readTrust: (scope: "user" | "admin") => Promise<string | null>;
}

export interface ProbeRecord {
  host: string;
  root: string;
  status: ProbeStatus;
}

export interface ToolAudit {
  tool: ToolId;
  present: boolean;
  status: ToolStatus;
  probes: ProbeRecord[];
  advice: string[];
}

export interface RootTrust {
  name: string;
  sha256: string | null;
  user: TrustMark;
  admin: TrustMark;
}

export interface IncidentAudit {
  id: string;
  title: string;
  summary: string;
  notes: string[];
  roots: RootTrust[];
  tools: ToolAudit[];
}

export interface TrustAuditReport {
  version: 1;
  probedAt: string;
  platform: string;
  incidents: IncidentAudit[];
}

const TOOLS: ToolId[] = ["node", "curl", "git", "python3", "nscurl"];

export function formatSha256(value: string): string {
  const hex = value.replaceAll(":", "").trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hex)) throw new Error("trust-audit fingerprint was rejected");
  return (hex.match(/.{2}/g) ?? []).map((byte) => byte.toUpperCase()).join(":");
}

export function assertHost(host: string): void {
  if (!HOST_RE.test(host)) throw new Error("trust-audit host was rejected");
}

export function parseIncidents(input: unknown): Incident[] {
  if (!input || typeof input !== "object" || !Array.isArray((input as { incidents?: unknown }).incidents)) {
    throw new Error("trust incident file is missing incidents");
  }
  const incidents = (input as { incidents: unknown[] }).incidents.map((item) => parseIncident(item));
  if (incidents.length === 0) throw new Error("trust incident file has no incidents");
  return incidents;
}

export function shippedIncidents(): Incident[] {
  return parseIncidents(incidentFile);
}

function shippedHosts(): ReadonlySet<string> {
  return new Set(shippedIncidents().flatMap((incident) => incident.endpoints.map((endpoint) => endpoint.host)));
}

/** A live probe may only name a host from the shipped incident file. */
export function assertCatalogHost(host: string): void {
  assertHost(host);
  if (!shippedHosts().has(host)) throw new Error("trust-audit host was rejected");
}

export function trustSettingsArgs(scope: "user" | "admin"): string[] {
  return scope === "admin" ? ["dump-trust-settings", "-d"] : ["dump-trust-settings"];
}

/** Drop askpass and injected git config so a probe cannot send stored credentials. */
export function probeEnv(base: NodeJS.ProcessEnv, bin: string, overlay?: Record<string, string>): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...base };
  if (bin === "git") {
    for (const key of Object.keys(env)) {
      if (key === "GIT_ASKPASS" || key === "SSH_ASKPASS" || key.startsWith("GIT_CONFIG_")) delete env[key];
    }
  }
  if (bin === "python3") delete env.PYTHONSTARTUP;
  return { ...env, ...overlay };
}

export function commandFor(tool: Exclude<ToolId, "node">, host: string): ExecRequest {
  assertHost(host);
  const url = `https://${host}/`;
  switch (tool) {
    case "curl":
      return {
        bin: "curl",
        timeoutMs: EXEC_TIMEOUT_MS,
        args: [
          "-q",
          "--head",
          "--silent",
          "--show-error",
          "--max-redirs", "0",
          "--proto", "=https",
          "--http1.1",
          "--output", "/dev/null",
          "--max-time", String(PROBE_SECONDS),
          "--url", url,
        ],
      };
    case "git":
      return {
        bin: "git",
        timeoutMs: EXEC_TIMEOUT_MS,
        env: {
          GIT_TERMINAL_PROMPT: "0",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_CONFIG_SYSTEM: "/dev/null",
        },
        args: [
          "-c", "credential.helper=",
          "-c", "http.extraHeader=",
          "-c", "http.followRedirects=false",
          "ls-remote",
          "--",
          url,
        ],
      };
    case "python3":
      return {
        bin: "python3",
        timeoutMs: EXEC_TIMEOUT_MS,
        env: { VIGIL_TRUST_HOST: host, PYTHONSAFEPATH: "1", PYTHONNOUSERSITE: "1" },
        args: ["-c", PYTHON_PROBE],
      };
    case "nscurl":
      return { bin: "nscurl", timeoutMs: EXEC_TIMEOUT_MS, args: ["-v", url] };
    default: {
      const never: never = tool;
      throw new Error(`unknown tool ${never}`);
    }
  }
}

/**
 * Live exec accepts only the commands commandFor and the trust-settings read build.
 * A different binary, argument, environment entry, timeout, or host is refused.
 */
export function assertAllowedCommand(request: ExecRequest, hosts: ReadonlySet<string>): void {
  if (request.bin === "security") {
    assertDumpArgs(request.args);
    if (request.env && Object.keys(request.env).length > 0) throw new Error("trust-audit refused a command");
    if (request.timeoutMs !== PROBE_TIMEOUT_MS) throw new Error("trust-audit refused a command");
    return;
  }
  if (request.bin !== "curl" && request.bin !== "git" && request.bin !== "python3" && request.bin !== "nscurl") {
    throw new Error("trust-audit refused a command");
  }
  for (const host of hosts) {
    let expected: ExecRequest;
    try {
      expected = commandFor(request.bin, host);
    } catch {
      continue;
    }
    if (sameRequest(request, expected)) return;
  }
  throw new Error("trust-audit refused a command");
}

function sameRequest(left: ExecRequest, right: ExecRequest): boolean {
  if (left.bin !== right.bin || left.timeoutMs !== right.timeoutMs || left.args.length !== right.args.length) return false;
  for (let index = 0; index < left.args.length; index += 1) {
    if (left.args[index] !== right.args[index]) return false;
  }
  const leftEnv = left.env ?? {};
  const rightEnv = right.env ?? {};
  const leftKeys = Object.keys(leftEnv).sort();
  const rightKeys = Object.keys(rightEnv).sort();
  if (leftKeys.join("\0") !== rightKeys.join("\0")) return false;
  return leftKeys.every((key) => leftEnv[key] === rightEnv[key]);
}

export function aggregateStatus(statuses: ProbeStatus[]): ProbeStatus {
  if (statuses.some((status) => status === "exposed")) return "exposed";
  if (statuses.some((status) => status === "unknown")) return "unknown";
  if (statuses.length > 0 && statuses.every((status) => status === "blocked")) return "blocked";
  return "unknown";
}

export function classifyNodeError(error: { code?: string; message?: string }): ProbeStatus {
  const code = error.code ?? "";
  const message = error.message ?? "";
  if (code === "ETIMEDOUT" || code === "ERR_TLS_HANDSHAKE_TIMEOUT" || /timed out/i.test(message)) return "unknown";
  if (
    code.startsWith("CERT_")
    || code === "UNABLE_TO_GET_ISSUER_CERT"
    || code === "UNABLE_TO_GET_ISSUER_CERT_LOCALLY"
    || code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE"
    || code === "DEPTH_ZERO_SELF_SIGNED_CERT"
    || code === "SELF_SIGNED_CERT_IN_CHAIN"
    || code === "ERR_TLS_CERT_ALTNAME_INVALID"
    || /certificate|unable to verify|altname/i.test(message)
  ) return "blocked";
  return "unknown";
}

export function classifyCurl(result: ExecResult): ProbeStatus {
  if (result.timedOut) return "unknown";
  if (result.code === 0 || result.code === 47) return "exposed";
  const text = `${result.stderr}\n${result.stdout}`;
  if (/maximum \(\d+\) redirects/i.test(text)) return "exposed";
  if (result.code === 60 || result.code === 51 || result.code === 58) return "blocked";
  if (/certificate|ssl peer|unable to get local issuer|self[- ]signed|verify failed/i.test(text)) return "blocked";
  return "unknown";
}

export function classifyGit(result: ExecResult): ProbeStatus {
  if (result.timedOut) return "unknown";
  const text = `${result.stderr}\n${result.stdout}`;
  if (/ssl certificate|certificate verify|unable to get local issuer|server certificate verification failed/i.test(text)) return "blocked";
  if (/timed out|timeout|could not resolve|couldn't resolve|connection refused|network is unreachable|failed to connect/i.test(text)) {
    return "unknown";
  }
  if (result.code === 0) return "exposed";
  if (/requested url returned error|repository .* not found|authentication|could not read username|terminal prompts disabled/i.test(text)) {
    return "exposed";
  }
  return "unknown";
}

export function classifyPython(result: ExecResult): ProbeStatus {
  if (result.timedOut) return "unknown";
  const text = `${result.stdout}\n${result.stderr}`;
  if (text.includes("VIGIL_EXPOSED")) return "exposed";
  if (/TimeoutError|timed out/i.test(text)) return "unknown";
  if (/CERTIFICATE_VERIFY_FAILED|SSLCertVerificationError|certificate verify failed/i.test(text)) return "blocked";
  return "unknown";
}

export function classifyNscurl(result: ExecResult): ProbeStatus {
  if (result.timedOut) return "unknown";
  const text = `${result.stdout}\n${result.stderr}`;
  if (/Code=-1202|certificate for this server is invalid|errSSL|kCFStreamErrorDomainSSL|Trust evaluation failed/i.test(text)) {
    return "blocked";
  }
  if (/Code=-1001|Code=-1003|Code=-1004|Code=-1009|timed out|timeout|could not resolve|cannot find host|not connected to the internet/i.test(text)) {
    return "unknown";
  }
  if (/HTTP\/[12]/.test(text)) return "exposed";
  if (result.code === 0 && text.trim() !== "") return "exposed";
  return "unknown";
}

/** A cert block is Never Trust only when a setting says kSecTrustSettingsResultDeny. */
export function markInDump(dump: string, rootName: string): TrustMark {
  const wanted = rootName.trim().toLowerCase();
  const blocks = dump.split(/\n(?=Cert \d+:)/);
  let deny = false;
  let other = false;
  for (const block of blocks) {
    const name = /^Cert \d+:\s*(.+)$/m.exec(block)?.[1]?.trim().toLowerCase();
    if (!name || name !== wanted) continue;
    if (/kSecTrustSettingsResultDeny/.test(block)) deny = true;
    else if (/kSecTrustSettingsResult/.test(block)) other = true;
  }
  if (deny) return "never-trust";
  if (other) return "other";
  return "absent";
}

export async function runTrustAudit(io?: TrustAuditIo): Promise<TrustAuditReport> {
  const runtime = io ?? createDefaultIo();
  const incidents = shippedIncidents();
  const audited = await Promise.all(incidents.map((incident) => auditIncident(runtime, incident)));
  return {
    version: 1,
    probedAt: runtime.now.toISOString(),
    platform: runtime.platform,
    incidents: audited,
  };
}

export function formatTrustAudit(report: TrustAuditReport): string {
  const lines = [
    "trust-audit",
    "This command only reports. It does not change trust settings, shell profiles, or system files.",
    "Node stops at the TLS handshake. curl and python3 urllib send HEAD. git uses ls-remote, with prompts and redirects disabled, and does not push. No request body is sent.",
  ];
  for (const incident of report.incidents) {
    lines.push("", incident.title, incident.summary);
    for (const note of incident.notes) lines.push(note);
    lines.push("roots:");
    for (const root of incident.roots) {
      const fingerprint = root.sha256 ? ` ${root.sha256}` : "";
      if (report.platform === "darwin") {
        lines.push(`  ${root.name}${fingerprint}  user: ${root.user}  admin: ${root.admin}`);
      } else {
        lines.push(`  ${root.name}${fingerprint}`);
      }
    }
    if (report.platform !== "darwin") {
      lines.push("trust settings: read on macOS only (security dump-trust-settings, user and admin).");
    }
    for (const tool of incident.tools) {
      lines.push("", `${tool.tool}: ${tool.status}`);
      if (tool.tool === "nscurl" && tool.present) {
        lines.push("  nscurl sends its default request and no request body. It has no HEAD switch.");
      }
      for (const probe of tool.probes) lines.push(`  ${probe.host} (${probe.root}): ${probe.status}`);
      if (tool.status === "exposed") {
        for (const line of tool.advice) {
          lines.push(line === MACOS_NEVER_TRUST_COMMAND ? `  ${line}` : `  advice: ${line}`);
        }
      }
    }
    if (report.platform !== "darwin") lines.push("", "nscurl: not run (macOS only).");
  }
  return lines.join("\n");
}

export function trustAuditFindings(report: TrustAuditReport): Finding[] {
  const findings: Finding[] = [];
  for (const incident of report.incidents) {
    for (const tool of incident.tools) {
      if (tool.status === "exposed") {
        const hosts = tool.probes.filter((probe) => probe.status === "exposed").map((probe) => probe.host);
        findings.push(createFinding({
          id: "TRUST_AUDIT_EXPOSED",
          severity: "high",
          confidence: "high",
          title: `${tool.tool} still trusts a compromised test host`,
          summary: `${tool.tool} completed TLS to ${hosts.join(", ")}. A completed handshake means this tool still trusts a compromised intermediate chain.`,
          why: "These hosts are on the incident list. A TLS error is blocked. A timeout or other connection failure is unknown. It does not mean the tool rejected the chain. This finding does not change trust settings.",
          remediation: tool.advice.length > 0 ? tool.advice : ["Update the trust store this tool uses."],
          recommendationOnly: true,
          file: `(trust-audit:${tool.tool})`,
          line: 1,
          evidence: `${tool.tool} exposed ${hosts.length}`,
          agentAction: "Update the trust store this tool uses. The printed command is for a person to review. Do not change the keychain from this report.",
          category: "trust-audit",
          occurrenceId: `TRUST_AUDIT_EXPOSED:${incident.id}:${tool.tool}`,
        }));
      } else if (tool.status === "unknown") {
        const hosts = tool.probes.filter((probe) => probe.status === "unknown").map((probe) => probe.host);
        findings.push(createFinding({
          id: "TRUST_AUDIT_UNKNOWN",
          severity: "informational",
          confidence: "medium",
          title: `${tool.tool} trust probe did not finish`,
          summary: `${tool.tool} returned unknown for ${hosts.join(", ") || "a probe"}. A timeout is unknown. It does not mean the tool rejected the chain.`,
          why: "A connection failure that is not a TLS verification error does not show that the tool rejected the chain.",
          remediation: ["Run vigil trust-audit again when this tool can reach the test hosts."],
          recommendationOnly: true,
          file: `(trust-audit:${tool.tool})`,
          line: 1,
          evidence: `${tool.tool} unknown ${hosts.length}`,
          agentAction: "Re-run vigil trust-audit. Do not treat an unknown probe as a pass.",
          category: "trust-audit",
          occurrenceId: `TRUST_AUDIT_UNKNOWN:${incident.id}:${tool.tool}`,
        }));
      }
    }
  }
  return findings;
}

function parseIncident(input: unknown): Incident {
  const record = asRecord(input, "incident");
  const id = asString(record.id, "incident id");
  if (!/^[a-z0-9][a-z0-9-]{0,63}$/.test(id)) throw new Error("trust incident id was rejected");
  const endpoints = asArray(record.endpoints, "endpoints").map((item) => {
    const endpoint = asRecord(item, "endpoint");
    const host = asString(endpoint.host, "host");
    assertHost(host);
    return { host, root: asString(endpoint.root, "endpoint root") };
  });
  if (endpoints.length === 0) throw new Error("trust incident has no endpoints");
  const hosts = new Set<string>();
  for (const endpoint of endpoints) {
    if (hosts.has(endpoint.host)) throw new Error("trust incident repeats a host");
    hosts.add(endpoint.host);
  }
  const roots = asArray(record.roots, "roots").map((item) => {
    const root = asRecord(item, "root");
    const name = asString(root.name, "root name");
    if (name.includes("\n")) throw new Error("trust incident root name was rejected");
    const sha = root.sha256;
    return { name, sha256: sha === null || sha === undefined ? null : formatSha256(asString(sha, "fingerprint")) };
  });
  const rootNames = new Set(roots.map((root) => root.name));
  for (const endpoint of endpoints) {
    if (!rootNames.has(endpoint.root)) throw new Error("trust incident endpoint names an unknown root");
  }
  return {
    id,
    title: asString(record.title, "title"),
    summary: asString(record.summary, "summary"),
    notes: asArray(record.notes, "notes").map((note) => asString(note, "note")),
    endpoints,
    roots,
  };
}

function asRecord(input: unknown, label: string): Record<string, unknown> {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new Error(`trust incident ${label} was rejected`);
  return input as Record<string, unknown>;
}

function asArray(input: unknown, label: string): unknown[] {
  if (!Array.isArray(input)) throw new Error(`trust incident ${label} was rejected`);
  return input;
}

function asString(input: unknown, label: string): string {
  if (typeof input !== "string" || input.trim() === "") throw new Error(`trust incident ${label} was rejected`);
  return input.trim();
}

async function auditIncident(io: TrustAuditIo, incident: Incident): Promise<IncidentAudit> {
  const tools = TOOLS.filter((tool) => tool !== "nscurl" || io.platform === "darwin");
  const [audited, userDump, adminDump] = await Promise.all([
    Promise.all(tools.map((tool) => auditTool(io, incident, tool))),
    io.platform === "darwin" ? safeRead(io, "user") : Promise.resolve(null),
    io.platform === "darwin" ? safeRead(io, "admin") : Promise.resolve(null),
  ]);
  return {
    id: incident.id,
    title: incident.title,
    summary: incident.summary,
    notes: [...incident.notes, `Go is not probed. ${goAdvisory.remediation} vigil doctor reports an older toolchain.`],
    roots: incident.roots.map((root) => ({
      name: root.name,
      sha256: root.sha256,
      user: io.platform === "darwin" ? markFromDump(userDump, root.name) : "unread",
      admin: io.platform === "darwin" ? markFromDump(adminDump, root.name) : "unread",
    })),
    tools: audited,
  };
}

function markFromDump(dump: string | null, name: string): TrustMark {
  if (dump === null) return "unread";
  return markInDump(dump, name);
}

async function auditTool(io: TrustAuditIo, incident: Incident, tool: ToolId): Promise<ToolAudit> {
  if (tool !== "node" && !io.present(tool)) {
    return { tool, present: false, status: "absent", probes: [], advice: [] };
  }
  const probes = await mapPool(incident.endpoints, 4, async (endpoint) => ({
    host: endpoint.host,
    root: endpoint.root,
    status: await probeHost(io, tool, endpoint.host),
  }));
  const status = aggregateStatus(probes.map((probe) => probe.status));
  return {
    tool,
    present: true,
    status,
    probes,
    advice: status === "exposed" ? adviceFor(tool, incident.roots) : [],
  };
}

async function probeHost(io: TrustAuditIo, tool: ToolId, host: string): Promise<ProbeStatus> {
  assertCatalogHost(host);
  try {
    if (tool === "node") return await io.probeNode(host);
    const request = commandFor(tool, host);
    assertAllowedCommand(request, shippedHosts());
    const result = await io.exec(request);
    return classifyExec(tool, result);
  } catch {
    return "unknown";
  }
}

function classifyExec(tool: ToolId, result: ExecResult): ProbeStatus {
  switch (tool) {
    case "curl": return classifyCurl(result);
    case "git": return classifyGit(result);
    case "python3": return classifyPython(result);
    case "nscurl": return classifyNscurl(result);
    case "node": return "unknown";
    default: {
      const never: never = tool;
      throw new Error(`unknown tool ${never}`);
    }
  }
}

function adviceFor(tool: ToolId, roots: IncidentRoot[]): string[] {
  switch (tool) {
    case "node":
      return ["Update Node to 22.23.4 or newer on the 22 line, 24.22.1 or newer on the 24 line, or 26.12.1 or newer on the 26 line."];
    case "curl":
      return ["Update ca-certificates, or the CA bundle this curl uses."];
    case "git":
      return ["Update ca-certificates, or the CA bundle this git uses for HTTPS."];
    case "python3":
      return ["Update ca-certificates for this python3 urllib store. Update certifi when other Python tools use certifi."];
    case "nscurl":
      return [
        "Mark the root Never Trust. Vigil prints this command and does not run it.",
        MACOS_NEVER_TRUST_COMMAND,
        `Replace <pem> with a PEM file for the root. ${roots.map((root) => root.sha256 ? `${root.name} ${root.sha256}` : root.name).join("; ")}.`,
        "The login-keychain change applies to Security.framework clients such as nscurl. curl, git, and python3 urllib still need a ca-certificates update.",
      ];
    default: {
      const never: never = tool;
      throw new Error(`unknown tool ${never}`);
    }
  }
}

async function safeRead(io: TrustAuditIo, scope: "user" | "admin"): Promise<string | null> {
  try {
    return await io.readTrust(scope);
  } catch {
    return null;
  }
}

async function mapPool<T, R>(items: T[], limit: number, run: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    for (;;) {
      const index = next;
      next += 1;
      if (index >= items.length) return;
      const item = items[index];
      if (item === undefined) return;
      results[index] = await run(item);
    }
  });
  await Promise.all(workers);
  return results;
}

function createDefaultIo(): TrustAuditIo {
  if (process.env.VITEST) throw new Error("trust-audit probes are disabled under the test runner");
  return {
    platform: process.platform,
    now: new Date(),
    present: commandOnPath,
    exec: execLive,
    probeNode: probeNodeLive,
    readTrust: readTrustLive,
  };
}

const PATH_BINS = new Set(["curl", "git", "python3", "nscurl"]);

function commandOnPath(bin: string): boolean {
  if (!PATH_BINS.has(bin)) return false;
  const pathEnv = process.env.PATH ?? "";
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    try {
      accessSync(join(dir, bin), fsConstants.X_OK);
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

function probeNodeLive(host: string): Promise<ProbeStatus> {
  assertCatalogHost(host);
  return new Promise((resolve) => {
    let settled = false;
    const finish = (status: ProbeStatus) => {
      if (settled) return;
      settled = true;
      resolve(status);
    };
    const socket = tls.connect({
      host,
      port: 443,
      servername: host,
      rejectUnauthorized: true,
      timeout: PROBE_TIMEOUT_MS,
    });
    const done = (status: ProbeStatus) => {
      socket.destroy();
      finish(status);
    };
    socket.once("secureConnect", () => done(socket.authorized ? "exposed" : "blocked"));
    socket.once("timeout", () => done("unknown"));
    socket.once("error", (error: NodeJS.ErrnoException) => done(classifyNodeError(error)));
  });
}

async function readTrustLive(scope: "user" | "admin"): Promise<string | null> {
  const args = trustSettingsArgs(scope);
  assertDumpArgs(args);
  const result = await execLive({ bin: "security", args, timeoutMs: PROBE_TIMEOUT_MS });
  if (result.timedOut || (result.code !== 0 && result.stdout.trim() === "")) return null;
  return result.stdout;
}

function assertDumpArgs(args: readonly string[]): void {
  const allowed = args.length === 1
    ? args[0] === "dump-trust-settings"
    : args.length === 2 && args[0] === "dump-trust-settings" && args[1] === "-d";
  if (!allowed) throw new Error("trust-audit refused a trust-settings command");
}

async function execLive(request: ExecRequest): Promise<ExecResult> {
  if (request.args.some((arg) => arg.includes("add-trusted-cert"))) {
    throw new Error("trust-audit refused a trust change");
  }
  assertAllowedCommand(request, shippedHosts());
  const env = probeEnv(process.env, request.bin, request.env);
  try {
    const { stdout, stderr } = await execFileAsync(request.bin, request.args, {
      timeout: request.timeoutMs,
      killSignal: "SIGKILL",
      maxBuffer: 256 * 1024,
      env,
      encoding: "utf8",
    });
    return { code: 0, stdout, stderr, timedOut: false };
  } catch (error) {
    return exitResult(error);
  }
}

function exitResult(error: unknown): ExecResult {
  if (!error || typeof error !== "object") return { code: null, stdout: "", stderr: "", timedOut: false };
  const err = error as { code?: number | string; killed?: boolean; signal?: string; stdout?: unknown; stderr?: unknown };
  const stdout = typeof err.stdout === "string" ? err.stdout : "";
  const stderr = typeof err.stderr === "string" ? err.stderr : "";
  const timedOut = err.killed === true || err.code === "ETIMEDOUT" || err.signal === "SIGKILL" || err.signal === "SIGTERM";
  const code = typeof err.code === "number" ? err.code : null;
  return { code, stdout, stderr, timedOut };
}
