import { execFile } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { buildReport, LimitError, scanFilesWithPrompt, UrlRejected, type HostingHint, type Report } from "@vigil/core";
import { INTEL_VERSION } from "@vigil/intel";
import {
  assessToolchain,
  collectTrustBundles,
  dependencyFindings,
  imagesFromDockerfiles,
  parseDependencies,
  checkBackend,
  queryOsv,
  runNativeHost,
  scanUrl,
  startVerdictServer,
  type AddressLookup,
  type BackendHandshake,
  type BackendTransport,
  type ScanUrlOptions,
  type TrustBundle,
} from "@vigil/netcheck";
import { collectFiles, collectLockfiles } from "./files.js";
import { runGate } from "./gate.js";
import { formatHuman } from "./format.js";
import { CHROME_NATIVE_HOST_NAME, installNativeHost, uninstallNativeHost } from "./native-install.js";
import { startAgentGuard } from "./agent-guard/proxy.js";
import { formatTrustAudit, runTrustAudit, trustAuditFindings, type TrustAuditReport } from "./trust-audit.js";

const execFileAsync = promisify(execFile);
const VERSION = "2.0.0";
const COMMANDS = new Set([
  "scan",
  "gate",
  "check-url",
  "check-backend",
  "deps",
  "doctor",
  "trust-audit",
  "serve",
  "native-host",
  "install-native-host",
  "uninstall-native-host",
  "agent-guard",
]);

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export interface CliDeps {
  scanUrl?: typeof scanUrl;
  fetchImpl?: typeof fetch;
  lookup?: AddressLookup;
  cwd?: string;
  versions?: {
    node?: string | null;
    curl?: string | null;
    go?: string | null;
    nginx?: string | null;
    pip?: string | null;
    uv?: string | null;
    kernel?: string | null;
    kernelOs?: string | null;
  };
  trustBundles?: TrustBundle[];
  readFiles?: (path: string) => { name: string; content: string }[];
  now?: Date;
  nativeHost?: typeof runNativeHost;
  installNativeHost?: typeof installNativeHost;
  uninstallNativeHost?: typeof uninstallNativeHost;
  trustAudit?: TrustAuditReport;
  runTrustAudit?: () => Promise<TrustAuditReport>;
  checkBackend?: typeof checkBackend;
  backendTransport?: BackendTransport;
  backendHandshake?: BackendHandshake;
}

const HELP = `vigil ${VERSION}

  vigil scan <path|url> [--json] [--prompt [text]] [--hosting vercel|netlify|cloudflare]
                        [--allow-host name] [--sample] [--ct]
  vigil gate <npm:name@version|path.tgz|package-dir> [--json]
  vigil check-url <url> [same flags]
  vigil check-backend <url> [--json]
  vigil deps [path] [--json]
  vigil doctor [path] [--json]
  vigil trust-audit [--json]
  vigil serve [--port 8787]
  vigil native-host
  vigil install-native-host --extension-id <id>
  vigil uninstall-native-host
  vigil agent-guard [--port 0] [--mode tunnel|intercept] [--identifiers file] [--allowlist file]
                    [--proxy-token token] [--ipv6]

check-backend is a passive fingerprint of backend exposure on a site you open as a visitor.
It reads response headers, one browser-style TLS handshake, TLS 1.0 and TLS 1.1
support handshakes, time until response headers,
one GET for a missing page, and GET requests for a short list of known paths
(/.git/HEAD, /server-status, /phpinfo.php, and a few others).
It sends no request body, no crash payload, no oversized header, and no exploit.
Active probing of a host you do not own may breach that host's terms of service
or computer-misuse law. Run it only on hosts you are allowed to test.
PHP versions are read from headers and compared with 8.5.12, 8.4.27, 8.3.36,
and 8.2.35. PHP 5-7 is never patched. PHP with no version is unknown.
A fingerprint does not set block_deploy. An existing critical certificate
failure still can, including when the first GET fails the certificate check.
Exit 0 when block_deploy is false. Exit 2 when it is set.
Exit 1 is usage, SSRF, or a network error.
Details: docs/CHECK-BACKEND.md.

gate reads an npm package without installing it. Pass npm:name@version, a .tgz path, or an unpacked package directory.
It follows bin, main, and exports, including files under dist, and it reads registry lifecycle scripts.
It does not run npm, npx, or those scripts. A registry tarball is fetched with the guarded client and checked against the registry integrity hash before it is unpacked.
prepare is reported and is not treated as a registry install script.
Exit 0 when that graph was read and nothing blocking was found.
Exit 2 when install behavior is blocking, a graph file was not read, a require or import is computed, or the gate file budget is hit.
Exit 1 is usage, a network error, or a registry integrity mismatch.
scan is unchanged: it still skips dist and still uses the 40-file source cap. gate uses its own walker and budget.

scan reads files or scans a URL as the site owner. check-url scans a URL as a visitor.
check-url and an owner URL scan flag AGENT_DIRECTED_REQUEST when a page addresses an agent and asks for identity, a credential, or a behavior change. That finding is recommendationOnly. It does not hold the page and it does not block a deploy. It is not the outbound guard.
deps reads lockfiles and Dockerfiles. doctor reports the local Node, curl, Go, nginx, pip, uv, kernel (uname), trust stores, and trust-audit.
trust-audit probes local TLS clients against known-bad test hosts and prints advice. It does not change trust settings, shell profiles, or system files. A timeout is unknown. It does not mean the tool rejected the chain. Exit 0 when the audit finishes.
serve listens on 127.0.0.1 for the extension helper. It returns verdict signals for one hostname and stores no page content.
native-host speaks Chrome's stdio native-messaging protocol and returns that same verdict. It does not log.
install-native-host writes a user-level Chrome host manifest for one extension id. No sudo.
uninstall-native-host removes that manifest and its launcher.
agent-guard is a separate loopback proxy. It does not read the page check and it does not upload the identifier list.
Listen is 127.0.0.1 only, plus ::1 with --ipv6. Set both proxies to the printed URL, including the token:
  HTTP_PROXY=http://<token>@127.0.0.1:<port>
  HTTPS_PROXY=http://<token>@127.0.0.1:<port>
  NO_PROXY=localhost,127.0.0.1,::1
Do not put public hosts in NO_PROXY. Clients that omit the token are refused.
The default mode is tunnel. Plain HTTP is inspected. Every CONNECT is refused, including an allowlisted host, because the payload is not visible. The shippable guard does not open a CONNECT tunnel without inspection. There is no local CA in tunnel mode. Intercept mode decrypts every CONNECT, then applies the same checks. An allowlisted Upgrade is rebuilt without hop-by-hop or proxy headers.
curl can use those environment variables. --proxy is an alternative for one invocation. Do not pass --insecure. --cacert is only for intercept mode.
Claude Code should be started with those variables. If Node fetch ignores them, also set NODE_USE_ENV_PROXY=1. Intercept mode sets NODE_EXTRA_CA_CERTS to the printed certificate path. A shell tool that clears the proxy variables is outside the guard.
Cursor can set http.proxy to the same URL (include the token if the field accepts it), http.proxySupport to override, and http.noProxy to localhost,127.0.0.1,::1. Cursor's HTTPS calls need intercept mode. Intercept mode is a poor fit if the editor trusts only the operating system store.
Do not install the local CA in the operating system trust store. Process-scoped variables are NODE_EXTRA_CA_CERTS, SSL_CERT_FILE, REQUESTS_CA_BUNDLE, and curl --cacert. A cloud agent needs its own guard and its own identity file. Do not copy a CA key to another machine.
Allow means a matched identifier may be forwarded after inspection. Allowlist entries are exact hosts. The sample file docs/agent-guard.sample has placeholders only. See docs/AGENT-GUARD.md.
Exit 0 when the scan finishes without block_deploy. Exit 2 when block_deploy is set.
doctor exits 0 even when it reports findings. Exit 1 is a usage, SSRF, or network error.
`;

export async function main(argv: string[], io: CliIo = consoleIo(), deps: CliDeps = {}): Promise<number> {
  try {
    const flags = parseArgs(argv);
    if (flags.help) {
      io.stdout(HELP);
      return 0;
    }
    if (flags.version) {
      io.stdout(`${VERSION}\n`);
      return 0;
    }
    const command = flags.positionals[0];
    if (!command || !COMMANDS.has(command)) {
      io.stderr(HELP);
      return 1;
    }
    if (command === "check-backend") return await backendCommand(flags, io, deps);
    if (command === "gate") return await gateCommand(flags, io, deps);
    if (command === "trust-audit" && flags.positionals.length > 1) throw new LimitError("trust-audit takes no path");
    const trustAudit = command === "doctor" || command === "trust-audit" ? await loadTrustAudit(deps) : undefined;
    if (command === "trust-audit") {
      const audit = trustAudit ?? await loadTrustAudit(deps);
      io.stdout(flags.json ? `${JSON.stringify(audit, null, 2)}\n` : `${formatTrustAudit(audit)}\n`);
      return 0;
    }
    if (command === "serve") return await serve(flags, io);
    if (command === "agent-guard") return await agentGuard(flags, io);
    if (command === "native-host") return await nativeHost(deps);
    if (command === "install-native-host") return installCommand(flags, io, deps);
    if (command === "uninstall-native-host") return uninstallCommand(io, deps);
    const report = await run(command, flags, trustAudit ? { ...deps, trustAudit } : deps);
    const human = command === "doctor" && trustAudit
      ? `${formatHuman(report)}\n\n${formatTrustAudit(trustAudit)}`
      : formatHuman(report);
    io.stdout(flags.json ? `${JSON.stringify(report, null, 2)}\n` : `${human}\n`);
    if (command === "doctor") return 0;
    return report.blockDeploy ? 2 : 0;
  } catch (error) {
    const message = error instanceof UrlRejected || error instanceof LimitError
      ? error.message
      : error instanceof Error
        ? error.message
        : "Scan failed";
    io.stderr(`${message}\n`);
    return 1;
  }
}

async function agentGuard(flags: Flags, io: CliIo): Promise<number> {
  const dir = flags.configDir;
  const guard = await startAgentGuard({
    ...(flags.port !== undefined ? { port: flags.port } : {}),
    ...(flags.mode ? { mode: flags.mode } : {}),
    ...(flags.proxyToken ? { token: flags.proxyToken } : {}),
    ...(flags.ipv6 ? { ipv6: true } : {}),
    ...(dir ? {
      identifiersPath: join(dir, "identifiers"),
      allowlistPath: join(dir, "allowlist"),
      logPath: join(dir, "agent-guard.log"),
      keyPath: join(dir, "identifiers.key"),
      caCertPath: join(dir, "agent-guard-ca.pem"),
      caKeyPath: join(dir, "agent-guard-ca.key"),
    } : {}),
    ...(flags.identifiers ? { identifiersPath: flags.identifiers } : {}),
    ...(flags.allowlist ? { allowlistPath: flags.allowlist } : {}),
    ...(flags.logPath ? { logPath: flags.logPath } : {}),
  });
  io.stdout(`vigil agent-guard listening on 127.0.0.1:${guard.port}\n`);
  io.stdout(`proxy url ${guard.url}\n`);
  io.stdout(`mode ${guard.mode}\n`);
  io.stdout("Set HTTP_PROXY and HTTPS_PROXY to the proxy url.\n");
  io.stdout("Set NO_PROXY=localhost,127.0.0.1,::1\n");
  if (guard.certPath) io.stdout(`local ca certificate ${guard.certPath}\n`);
  await new Promise<void>((resolve) => {
    const stop = () => {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      void guard.close().finally(resolve);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
  return 0;
}

async function serve(flags: Flags, io: CliIo): Promise<number> {
  if (flags.port !== undefined && (!Number.isInteger(flags.port) || flags.port < 1 || flags.port > 65535)) {
    io.stderr("port must be between 1 and 65535\n");
    return 1;
  }
  const server = await startVerdictServer({ port: flags.port ?? 8787 });
  io.stdout(`vigil serve on 127.0.0.1:${server.port}\n`);
  io.stdout(`token ${server.token}\n`);
  await new Promise<void>((resolve) => {
    const stop = () => {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
      void server.close().finally(resolve);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
  return 0;
}

async function nativeHost(deps: CliDeps): Promise<number> {
  try {
    await (deps.nativeHost ?? runNativeHost)({ input: process.stdin, output: process.stdout });
    return 0;
  } catch {
    return 1;
  }
}

function installCommand(flags: Flags, io: CliIo, deps: CliDeps): number {
  if (!flags.extensionId) {
    io.stderr("install-native-host requires --extension-id\n");
    return 1;
  }
  try {
    const installed = (deps.installNativeHost ?? installNativeHost)({
      extensionId: flags.extensionId,
      nodePath: process.execPath,
      scriptPath: fileURLToPath(import.meta.url),
    });
    io.stdout(`Installed Chrome native host ${CHROME_NATIVE_HOST_NAME}\n`);
    for (const manifestPath of installed.manifestPaths) io.stdout(`${manifestPath}\n`);
    return 0;
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : "install failed"}\n`);
    return 1;
  }
}

function uninstallCommand(io: CliIo, deps: CliDeps): number {
  try {
    const removed = (deps.uninstallNativeHost ?? uninstallNativeHost)();
    io.stdout(removed.removed
      ? `Removed Chrome native host ${CHROME_NATIVE_HOST_NAME}\n`
      : `Chrome native host is not installed\n`);
    return 0;
  } catch (error) {
    io.stderr(`${error instanceof Error ? error.message : "uninstall failed"}\n`);
    return 1;
  }
}

async function gateCommand(flags: Flags, io: CliIo, deps: CliDeps): Promise<number> {
  if (flags.positionals.length > 2) throw new LimitError("gate takes one package");
  const target = flags.positionals[1];
  if (!target) throw new LimitError("gate requires npm:name@version, a .tgz path, or a package directory");
  const report = await runGate(target, {
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    ...(deps.lookup ? { lookup: deps.lookup } : {}),
    ...(deps.cwd ? { cwd: deps.cwd } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  });
  io.stdout(flags.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatHuman(report)}\n`);
  return report.blockDeploy ? 2 : 0;
}

async function backendCommand(flags: Flags, io: CliIo, deps: CliDeps): Promise<number> {
  if (flags.positionals.length > 2) throw new LimitError("check-backend takes one URL");
  const target = flags.positionals[1];
  if (!target || !isUrl(target)) throw new UrlRejected("check-backend requires an http(s) URL");
  const report = await (deps.checkBackend ?? checkBackend)(target, {
    ...(deps.backendTransport ? { transport: deps.backendTransport } : {}),
    ...(deps.backendHandshake ? { handshake: deps.backendHandshake } : {}),
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
    ...(deps.now ? { now: deps.now } : {}),
  });
  io.stdout(flags.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatHuman(report)}\n`);
  return report.blockDeploy ? 2 : 0;
}

async function run(command: string, flags: Flags, deps: CliDeps): Promise<Report> {
  const now = deps.now ?? new Date();
  if (command === "deps") return depsReport(flags, deps, now);
  if (command === "doctor") return doctorReport(flags, deps, now);
  const target = flags.sample ? sampleDir() : flags.positionals[1];
  if (!target) throw new LimitError(command === "check-url" ? "check-url requires a URL" : "scan requires a path or URL");
  if (isUrl(target)) {
    const scan = deps.scanUrl ?? scanUrl;
    const options: ScanUrlOptions = {
      audience: command === "check-url" ? "visitor" : "owner",
      allowHosts: flags.allowHost,
      ...(flags.hosting ? { hostingHint: flags.hosting } : {}),
      ...(flags.prompt !== undefined ? { prompt: flags.prompt } : {}),
      ...(flags.ct ? { ct: true } : {}),
      ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
      now,
    };
    return (await scan(target, options)).report;
  }
  if (command === "check-url") throw new UrlRejected("check-url requires an http(s) URL");
  const files = (deps.readFiles ?? collectFiles)(target);
  return (await scanFilesWithPrompt(files, {
    sourceType: flags.sample ? "sample" : "files",
    ...(flags.hosting ? { hostingHint: flags.hosting } : {}),
    ...(flags.prompt !== undefined ? { prompt: flags.prompt } : {}),
    now,
    intelVersion: INTEL_VERSION,
    ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}),
  })).report;
}

async function depsReport(flags: Flags, deps: CliDeps, now: Date): Promise<Report> {
  const target = flags.positionals[1] ?? deps.cwd ?? process.cwd();
  const files = (deps.readFiles ?? collectLockfiles)(target);
  const packages = parseDependencies(files);
  const osv = await queryOsv(packages, deps.fetchImpl ?? fetch);
  const { findings, deps: depChecks } = dependencyFindings(packages, osv);
  return buildReport({
    findings,
    sourceType: "files",
    filesAnalyzed: files.length,
    bytesAnalyzed: 0,
    checks: { deps: depChecks },
    now,
    intelVersion: INTEL_VERSION,
  });
}

async function loadTrustAudit(deps: CliDeps): Promise<TrustAuditReport> {
  if (deps.trustAudit) return deps.trustAudit;
  if (deps.runTrustAudit) return deps.runTrustAudit();
  return runTrustAudit();
}

async function doctorReport(flags: Flags, deps: CliDeps, now: Date): Promise<Report> {
  const target = flags.positionals[1] ?? deps.cwd ?? process.cwd();
  const versions = deps.versions ?? {
    node: process.version,
    curl: await commandOutput("curl", ["--version"]),
    go: await commandOutput("go", ["version"]),
    nginx: await nginxVersion(),
    pip: await commandOutput("pip", ["--version"]) ?? await commandOutput("pip3", ["--version"]),
    uv: await commandOutput("uv", ["--version"]),
    kernel: await commandOutput("uname", ["-r"]),
    kernelOs: await commandOutput("uname", ["-s"]),
  };
  const trustBundles = deps.trustBundles ?? (deps.versions ? [] : await collectTrustBundles());
  let files: { name: string; content: string }[];
  try {
    files = (deps.readFiles ?? collectLockfiles)(target).filter((file) => /dockerfile/i.test(file.name));
  } catch {
    files = [];
  }
  const findings = [
    ...assessToolchain({
      nodeVersion: versions.node,
      curlVersion: versions.curl,
      goVersion: versions.go,
      nginxVersion: versions.nginx,
      pipVersion: versions.pip,
      uvVersion: versions.uv,
      kernelRelease: versions.kernel,
      kernelOs: versions.kernelOs,
      trustBundles,
      images: imagesFromDockerfiles(files),
      recommendationOnly: true,
    }),
    ...(deps.trustAudit ? trustAuditFindings(deps.trustAudit) : []),
  ];
  return buildReport({
    findings,
    sourceType: "files",
    filesAnalyzed: files.length,
    bytesAnalyzed: 0,
    now,
    intelVersion: INTEL_VERSION,
  });
}

async function commandOutput(bin: string, args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync(bin, args, { timeout: 4000 });
    return stdout;
  } catch {
    return null;
  }
}

/** `nginx -v` writes the version to stderr and exits 0. A missing binary is skipped. */
async function nginxVersion(): Promise<string | null> {
  try {
    const { stdout, stderr } = await execFileAsync("nginx", ["-v"], { timeout: 4000 });
    const text = `${stdout}\n${stderr}`;
    return text.includes("nginx/") ? text : null;
  } catch (error) {
    const stdout = typeof error === "object" && error && "stdout" in error ? String((error as { stdout?: unknown }).stdout ?? "") : "";
    const stderr = typeof error === "object" && error && "stderr" in error ? String((error as { stderr?: unknown }).stderr ?? "") : "";
    const text = `${stdout}\n${stderr}`;
    return text.includes("nginx/") ? text : null;
  }
}

function sampleDir(): string {
  return join(dirname(fileURLToPath(import.meta.url)), "../../../fixtures/vulnerable");
}

interface Flags {
  json: boolean;
  prompt?: string;
  hosting?: HostingHint;
  allowHost: string[];
  sample: boolean;
  ct: boolean;
  help: boolean;
  version: boolean;
  port?: number;
  extensionId?: string;
  mode?: "tunnel" | "intercept";
  identifiers?: string;
  allowlist?: string;
  logPath?: string;
  proxyToken?: string;
  ipv6: boolean;
  configDir?: string;
  positionals: string[];
}

function parseArgs(argv: string[]): Flags {
  const flags: Flags = {
    json: false,
    allowHost: [],
    sample: false,
    ct: false,
    help: false,
    version: false,
    ipv6: false,
    positionals: [],
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i] ?? "";
    if (arg === "--json") flags.json = true;
    else if (arg === "--sample") flags.sample = true;
    else if (arg === "--ct") flags.ct = true;
    else if (arg === "--help" || arg === "-h") flags.help = true;
    else if (arg === "--version" || arg === "-V") flags.version = true;
    else if (arg === "--prompt") {
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        flags.prompt = next;
        i += 1;
      } else flags.prompt = "";
    } else if (arg === "--hosting") {
      const next = argv[++i];
      if (next !== "vercel" && next !== "netlify" && next !== "cloudflare") {
        throw new LimitError("--hosting must be vercel, netlify, or cloudflare");
      }
      flags.hosting = next;
    } else if (arg === "--port") {
      const next = argv[++i];
      const port = Number(next);
      if (!next || !Number.isInteger(port)) throw new LimitError("--port requires an integer");
      flags.port = port;
    } else if (arg === "--extension-id") {
      const next = argv[++i];
      if (!next || next.startsWith("--")) throw new LimitError("--extension-id requires a value");
      if (next.length > 32) throw new LimitError("extension id was rejected");
      flags.extensionId = next;
    } else if (arg === "--allow-host") {
      const next = argv[++i];
      if (!next) throw new LimitError("--allow-host requires a hostname");
      flags.allowHost.push(next);
    } else if (arg === "--mode") {
      const next = argv[++i];
      if (next !== "tunnel" && next !== "intercept") throw new LimitError("--mode must be tunnel or intercept");
      flags.mode = next;
    } else if (arg === "--identifiers") {
      const next = argv[++i];
      if (!next) throw new LimitError("--identifiers requires a path");
      flags.identifiers = next;
    } else if (arg === "--allowlist") {
      const next = argv[++i];
      if (!next) throw new LimitError("--allowlist requires a path");
      flags.allowlist = next;
    } else if (arg === "--log") {
      const next = argv[++i];
      if (!next) throw new LimitError("--log requires a path");
      flags.logPath = next;
    } else if (arg === "--proxy-token") {
      const next = argv[++i];
      if (!next) throw new LimitError("--proxy-token requires a value");
      flags.proxyToken = next;
    } else if (arg === "--config-dir") {
      const next = argv[++i];
      if (!next) throw new LimitError("--config-dir requires a path");
      flags.configDir = next;
    } else if (arg === "--ipv6") flags.ipv6 = true;
    else if (arg.startsWith("--")) throw new LimitError(`Unknown flag ${arg}`);
    else flags.positionals.push(arg);
  }
  return flags;
}

function isUrl(value: string): boolean {
  return value.startsWith("http://") || value.startsWith("https://");
}

function consoleIo(): CliIo {
  return {
    stdout: (text) => process.stdout.write(text),
    stderr: (text) => process.stderr.write(text),
  };
}

const entry = process.argv[1] ? resolve(process.argv[1]) : "";
if (entry && entry === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2))
    .then((code) => {
      process.exit(code);
    })
    .catch((error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : "Scan failed"}\n`);
      process.exit(1);
    });
}
