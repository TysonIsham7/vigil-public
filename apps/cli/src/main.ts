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
  queryOsv,
  runNativeHost,
  scanUrl,
  startVerdictServer,
  type ScanUrlOptions,
  type TrustBundle,
} from "@vigil/netcheck";
import { collectFiles, collectLockfiles } from "./files.js";
import { formatHuman } from "./format.js";
import { CHROME_NATIVE_HOST_NAME, installNativeHost, uninstallNativeHost } from "./native-install.js";

const execFileAsync = promisify(execFile);
const VERSION = "2.0.0";
const COMMANDS = new Set([
  "scan",
  "check-url",
  "deps",
  "doctor",
  "serve",
  "native-host",
  "install-native-host",
  "uninstall-native-host",
]);

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
}

export interface CliDeps {
  scanUrl?: typeof scanUrl;
  fetchImpl?: typeof fetch;
  cwd?: string;
  versions?: { node?: string | null; curl?: string | null; go?: string | null; kernel?: string | null; kernelOs?: string | null };
  trustBundles?: TrustBundle[];
  readFiles?: (path: string) => { name: string; content: string }[];
  now?: Date;
  nativeHost?: typeof runNativeHost;
  installNativeHost?: typeof installNativeHost;
  uninstallNativeHost?: typeof uninstallNativeHost;
}

const HELP = `vigil ${VERSION}

  vigil scan <path|url> [--json] [--prompt [text]] [--hosting vercel|netlify|cloudflare]
                        [--allow-host name] [--sample] [--ct]
  vigil check-url <url> [same flags]
  vigil deps [path] [--json]
  vigil doctor [path] [--json]
  vigil serve [--port 8787]
  vigil native-host
  vigil install-native-host --extension-id <id>
  vigil uninstall-native-host

scan reads files or scans a URL as the site owner. check-url scans a URL as a visitor.
deps reads lockfiles and Dockerfiles. doctor reports the local Node, curl, Go, kernel (uname), and trust stores.
serve listens on 127.0.0.1 for the extension helper. It returns verdict signals for one hostname and stores no page content.
native-host speaks Chrome's stdio native-messaging protocol and returns that same verdict. It does not log.
install-native-host writes a user-level Chrome host manifest for one extension id. No sudo.
uninstall-native-host removes that manifest and its launcher.
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
    if (command === "serve") return await serve(flags, io);
    if (command === "native-host") return await nativeHost(deps);
    if (command === "install-native-host") return installCommand(flags, io, deps);
    if (command === "uninstall-native-host") return uninstallCommand(io, deps);
    const report = await run(command, flags, deps);
    io.stdout(flags.json ? `${JSON.stringify(report, null, 2)}\n` : `${formatHuman(report)}\n`);
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

async function doctorReport(flags: Flags, deps: CliDeps, now: Date): Promise<Report> {
  const target = flags.positionals[1] ?? deps.cwd ?? process.cwd();
  const versions = deps.versions ?? {
    node: process.version,
    curl: await commandOutput("curl", ["--version"]),
    go: await commandOutput("go", ["version"]),
    kernel: await commandOutput("uname", ["-r"]),
    kernelOs: await commandOutput("uname", ["-s"]),
  };
  const trustBundles = deps.trustBundles ?? (deps.versions ? [] : await collectTrustBundles());
  let files: { name: string; content: string }[] = [];
  try {
    files = (deps.readFiles ?? collectLockfiles)(target).filter((file) => /dockerfile/i.test(file.name));
  } catch {
    files = [];
  }
  const findings = assessToolchain({
    nodeVersion: versions.node,
    curlVersion: versions.curl,
    goVersion: versions.go,
    kernelRelease: versions.kernel,
    kernelOs: versions.kernelOs,
    trustBundles,
    images: imagesFromDockerfiles(files),
    recommendationOnly: true,
  });
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
  positionals: string[];
}

function parseArgs(argv: string[]): Flags {
  const flags: Flags = { json: false, allowHost: [], sample: false, ct: false, help: false, version: false, positionals: [] };
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
    } else if (arg.startsWith("--")) throw new LimitError(`Unknown flag ${arg}`);
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
