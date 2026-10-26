import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import distrusted from "../../../packages/intel/data/distrusted-cas.json" with { type: "json" };
import { main } from "../src/main.js";
import {
  MACOS_NEVER_TRUST_COMMAND,
  aggregateStatus,
  assertHost,
  classifyCurl,
  classifyGit,
  classifyNodeError,
  classifyNscurl,
  classifyPython,
  assertAllowedCommand,
  assertCatalogHost,
  commandFor,
  formatSha256,
  probeEnv,
  formatTrustAudit,
  markInDump,
  parseIncidents,
  runTrustAudit,
  shippedIncidents,
  trustAuditFindings,
  trustSettingsArgs,
  type ExecRequest,
  type ExecResult,
  type ProbeStatus,
  type TrustAuditIo,
  type TrustAuditReport,
} from "../src/trust-audit.js";

const root = join(import.meta.dirname, "../../..");
const sentinel = "REDACTED_HOME_SEGMENT";
const emSignFingerprint = "86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B";

function io() {
  let out = "";
  let err = "";
  return {
    stdout: (text: string) => { out += text; },
    stderr: (text: string) => { err += text; },
    text: () => out,
    error: () => err,
  };
}

function result(partial: Partial<ExecResult>): ExecResult {
  return { code: partial.code ?? null, stdout: partial.stdout ?? "", stderr: partial.stderr ?? "", timedOut: partial.timedOut ?? false };
}

function harness(options: {
  platform?: NodeJS.Platform;
  present?: (bin: string) => boolean;
  node?: ProbeStatus;
  exec: (request: ExecRequest) => ExecResult;
  readTrust?: (scope: "user" | "admin") => string | null;
}) {
  const calls: ExecRequest[] = [];
  const trustScopes: ("user" | "admin")[] = [];
  const runtime: TrustAuditIo = {
    platform: options.platform ?? "linux",
    now: new Date("2026-10-22T00:00:00.000Z"),
    present: options.present ?? (() => true),
    probeNode: async (host) => {
      assertHost(host);
      return options.node ?? "blocked";
    },
    exec: async (request) => {
      calls.push(request);
      if (request.args.some((arg) => arg.includes("add-trusted-cert"))) throw new Error("mutation attempted");
      return options.exec(request);
    },
    readTrust: async (scope) => {
      trustScopes.push(scope);
      return options.readTrust ? options.readTrust(scope) : null;
    },
  };
  return { runtime, calls, trustScopes };
}

describe("trust incident file", () => {
  it("lists the DV, OV, and EV G3B and G3C hosts and both roots", () => {
    const [incident] = shippedIncidents();
    expect(incident?.id).toBe("emudhra-2026-10");
    const hosts = incident?.endpoints.map((endpoint) => endpoint.host) ?? [];
    for (const kind of ["dv", "ov", "ev"]) {
      for (const generation of ["g3b", "g3c"]) {
        expect(hosts).toContain(`${kind}-${generation}-emudhra.we-have-a-problem.com`);
        expect(hosts).toContain(`${kind}-${generation}-aaa-emudhra.we-have-a-problem.com`);
      }
    }
    expect(hosts).toHaveLength(12);
    const emSign = incident?.roots.find((item) => item.name === "emSign ECC Root CA - G3");
    const aaa = incident?.roots.find((item) => item.name === "AAA Certificate Services");
    const published = distrusted.roots.find((item) => item.name === "emSign ECC Root CA - G3");
    const publishedAaa = distrusted.roots.find((item) => item.name === "AAA Certificate Services");
    expect(emSign?.sha256).toBe(emSignFingerprint);
    expect(published?.sha256 ? formatSha256(published.sha256) : "").toBe(emSignFingerprint);
    expect(aaa?.sha256).toBe(publishedAaa?.sha256 ? formatSha256(publishedAaa.sha256) : "");
    expect(incident?.summary).toMatch(/emSign ECC Root CA - G3/);
    expect(incident?.summary).toMatch(/AAA Certificate Services/);
    expect(incident?.notes.join(" ")).toMatch(/503/);
  });

  it("rejects a host that is not a DNS name", () => {
    const [incident] = shippedIncidents();
    expect(incident).toBeDefined();
    const broken = {
      incidents: [{
        ...incident,
        endpoints: [{ host: "not a host", root: "emSign ECC Root CA - G3" }],
      }],
    };
    expect(() => parseIncidents(broken)).toThrow(/host/);
    expect(() => assertHost("evil.example/path")).toThrow(/host/);
    expect(() => parseIncidents({ incidents: [] })).toThrow(/no incidents/);
  });
});

describe("probe classification", () => {
  it("treats a TLS error as blocked and a timeout as unknown", () => {
    expect(classifyCurl(result({ code: 0 }))).toBe("exposed");
    expect(classifyCurl(result({ code: 60, stderr: "SSL certificate problem" }))).toBe("blocked");
    expect(classifyCurl(result({ code: 28, stderr: "Connection timed out" }))).toBe("unknown");
    expect(classifyCurl(result({ code: 0, timedOut: true }))).toBe("unknown");
    expect(classifyGit(result({
      code: 128,
      stderr: "fatal: unable to access 'https://example.invalid/': SSL certificate problem: unable to get local issuer certificate",
    }))).toBe("blocked");
    expect(classifyGit(result({
      code: 128,
      stderr: "fatal: unable to access 'https://example.invalid/': The requested URL returned error: 404",
    }))).toBe("exposed");
    expect(classifyGit(result({ code: 0, stdout: "refs", timedOut: true }))).toBe("unknown");
    expect(classifyPython(result({ code: 0, stdout: "VIGIL_EXPOSED\n" }))).toBe("exposed");
    expect(classifyPython(result({ code: 0, stdout: "VIGIL_ERROR\nURLError\nCERTIFICATE_VERIFY_FAILED\n" }))).toBe("blocked");
    expect(classifyPython(result({ code: 0, stdout: "VIGIL_ERROR\nTimeoutError\ntimed out\n" }))).toBe("unknown");
    expect(classifyNscurl(result({ code: 1, stderr: "NSURLErrorDomain Code=-1202 The certificate for this server is invalid" }))).toBe("blocked");
    expect(classifyNscurl(result({ code: 0, stdout: "HTTP/1.1 200 OK\nthis page talks about a certificate\n" }))).toBe("exposed");
    expect(classifyNscurl(result({ code: 0, stdout: "HTTP/1.1 200 OK\n", timedOut: true }))).toBe("unknown");
    expect(classifyNodeError({ code: "UNABLE_TO_GET_ISSUER_CERT_LOCALLY", message: "unable to get local issuer certificate" })).toBe("blocked");
    expect(classifyNodeError({ code: "ETIMEDOUT", message: "connect ETIMEDOUT" })).toBe("unknown");
    expect(classifyNodeError({ code: "ECONNREFUSED", message: "connect ECONNREFUSED" })).toBe("unknown");
    expect(aggregateStatus(["blocked", "unknown"])).toBe("unknown");
    expect(aggregateStatus(["blocked", "exposed"])).toBe("exposed");
    expect(aggregateStatus(["blocked", "blocked"])).toBe("blocked");
    expect(aggregateStatus([])).toBe("unknown");
  });

  it("builds handshake and HEAD commands and reads trust settings without changing them", () => {
    const host = "dv-g3b-emudhra.we-have-a-problem.com";
    const curl = commandFor("curl", host);
    const git = commandFor("git", host);
    const python = commandFor("python3", host);
    const nscurl = commandFor("nscurl", host);
    expect(curl.args[0]).toBe("-q");
    expect(curl.args).toContain("--head");
    expect(curl.args).toContain(`https://${host}/`);
    expect(curl.args.join(" ")).not.toMatch(/--insecure|(^|\s)-k(\s|$)|--data|\s-d\s|POST/);
    expect(git.args).toContain("ls-remote");
    expect(git.args).not.toContain("push");
    expect(git.env?.GIT_TERMINAL_PROMPT).toBe("0");
    expect(python.args[1]).toContain('method="HEAD"');
    expect(python.args[1]).toContain("read(0)");
    expect(python.args[1]).not.toContain("certifi");
    expect(python.args.join(" ")).not.toContain(host);
    expect(python.env?.VIGIL_TRUST_HOST).toBe(host);
    expect(python.env?.PYTHONSAFEPATH).toBe("1");
    const scrubbed = probeEnv(
      { PATH: "/usr/bin", GIT_ASKPASS: "secret-helper", GIT_CONFIG_COUNT: "1", PYTHONSTARTUP: "/tmp/startup.py" },
      "git",
      git.env,
    );
    expect(scrubbed.GIT_ASKPASS).toBeUndefined();
    expect(scrubbed.GIT_CONFIG_COUNT).toBeUndefined();
    expect(scrubbed.GIT_TERMINAL_PROMPT).toBe("0");
    expect(scrubbed.GIT_CONFIG_NOSYSTEM).toBe("1");
    expect(JSON.stringify(scrubbed)).not.toContain("secret-helper");
    expect(probeEnv({ PYTHONSTARTUP: "/tmp/startup.py" }, "python3", python.env).PYTHONSTARTUP).toBeUndefined();
    expect(nscurl.args).toEqual(["-v", `https://${host}/`]);
    expect(trustSettingsArgs("user")).toEqual(["dump-trust-settings"]);
    expect(trustSettingsArgs("admin")).toEqual(["dump-trust-settings", "-d"]);
    const source = readFileSync(new URL("../src/trust-audit.ts", import.meta.url), "utf8");
    expect(source).not.toMatch(/writeFile|appendFile|createWriteStream|shell:\s*true|sudo |cert\.pem|sitecustomize/);
    expect(source.split("add-trusted-cert").length - 1).toBe(2);
  });
});

describe("command allowlist", () => {
  const hosts = new Set(shippedIncidents().flatMap((incident) => incident.endpoints.map((endpoint) => endpoint.host)));
  const host = "dv-g3b-emudhra.we-have-a-problem.com";

  it("accepts the shipped probe commands and the trust-settings reads", () => {
    for (const name of hosts) {
      expect(() => assertCatalogHost(name)).not.toThrow();
      for (const tool of ["curl", "git", "python3", "nscurl"] as const) {
        expect(() => assertAllowedCommand(commandFor(tool, name), hosts)).not.toThrow();
      }
    }
    expect(() => assertAllowedCommand({ bin: "security", args: ["dump-trust-settings"], timeoutMs: 8_000 }, hosts)).not.toThrow();
    expect(() => assertAllowedCommand({ bin: "security", args: ["dump-trust-settings", "-d"], timeoutMs: 8_000 }, hosts)).not.toThrow();
  });

  it("refuses a trust change, an upload, another host, and another binary", () => {
    expect(() => assertAllowedCommand({ bin: "security", args: ["add-trusted-cert", "-r", "deny"], timeoutMs: 8_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ bin: "security", args: ["delete-certificate"], timeoutMs: 8_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ bin: "security", args: ["import"], timeoutMs: 8_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ bin: "curl", args: ["--data", "x", `https://${host}/`], timeoutMs: 10_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ bin: "git", args: ["push", `https://${host}/`], timeoutMs: 10_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ bin: "bash", args: ["-c", "true"], timeoutMs: 10_000 }, hosts)).toThrow(/refused/);
    const curl = commandFor("curl", host);
    expect(() => assertAllowedCommand({ ...curl, timeoutMs: 60_000 }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand({ ...curl, env: { VIGIL_TRUST_HOST: "other.example" } }, hosts)).toThrow(/refused/);
    expect(() => assertAllowedCommand(curl, new Set(["other.example"]))).toThrow(/refused/);
    const python = commandFor("python3", host);
    expect(python.args.join(" ")).not.toContain(host);
    expect(() => assertAllowedCommand({ ...python, args: [...python.args, host] }, hosts)).toThrow(/refused/);
    expect(() => assertCatalogHost("other.example")).toThrow(/host/);
    expect(() => assertCatalogHost("evil.example/path")).toThrow(/host/);
  });
});

describe("trust settings", () => {
  const dump = [
    `Trust Settings exported from: "/Users/${sentinel}/Library/Keychains/login.keychain-db"`,
    "Number of trusted certs = 2",
    "Cert 0: emSign ECC Root CA - G3",
    "   Number of trust settings : 1",
    "   Trust Setting 0:",
    "      Result Type           : kSecTrustSettingsResultDeny",
    "Cert 1: AAA Certificate Services",
    "   Number of trust settings : 1",
    "   Trust Setting 0:",
    "      Result Type           : kSecTrustSettingsResultTrustRoot",
  ].join("\n");

  it("reads Never Trust from the cert block and drops the keychain path", () => {
    expect(markInDump(dump, "emSign ECC Root CA - G3")).toBe("never-trust");
    expect(markInDump(dump, "AAA Certificate Services")).toBe("other");
    expect(markInDump(dump, "emSign Root TLS CA - G3")).toBe("absent");
    expect(markInDump("No Trust Settings were found.\n", "emSign ECC Root CA - G3")).toBe("absent");
    expect(dump).toContain(sentinel);
  });
});

describe("runTrustAudit", () => {
  it("reports each tool from mocked probes and does not keep tool output", async () => {
    const { runtime, calls, trustScopes } = harness({
      platform: "darwin",
      node: "blocked",
      readTrust: (scope) => scope === "user"
        ? [
          `Trust Settings exported from: "/Users/${sentinel}/Library/Keychains/login.keychain-db"`,
          "Cert 0: emSign ECC Root CA - G3",
          "   Result Type           : kSecTrustSettingsResultDeny",
        ].join("\n")
        : "No Trust Settings were found.\n",
      exec: (request) => {
        if (request.bin === "curl") return result({ code: 60, stderr: `SSL certificate problem ${sentinel}` });
        if (request.bin === "git") return result({ code: null, stderr: sentinel, timedOut: true });
        if (request.bin === "python3") return result({ code: 0, stdout: "VIGIL_ERROR\nURLError\nCERTIFICATE_VERIFY_FAILED\n" });
        if (request.bin === "nscurl") return result({ code: 0, stdout: `HTTP/1.1 200 OK\n${sentinel}\n` });
        throw new Error(`unexpected ${request.bin}`);
      },
    });
    const report = await runTrustAudit(runtime);
    const tools = Object.fromEntries((report.incidents[0]?.tools ?? []).map((tool) => [tool.tool, tool]));
    expect(tools.node?.status).toBe("blocked");
    expect(tools.curl?.status).toBe("blocked");
    expect(tools.git?.status).toBe("unknown");
    expect(tools.python3?.status).toBe("blocked");
    expect(tools.nscurl?.status).toBe("exposed");
    expect(tools.curl?.advice).toEqual([]);
    expect(tools.git?.advice).toEqual([]);
    expect(tools.nscurl?.advice).toContain(MACOS_NEVER_TRUST_COMMAND);
    expect(tools.nscurl?.advice.join(" ")).toMatch(/ca-certificates/);
    expect(report.incidents[0]?.roots.find((item) => item.name === "emSign ECC Root CA - G3")).toMatchObject({
      user: "never-trust",
      admin: "absent",
    });
    expect(report.incidents[0]?.roots.find((item) => item.name === "AAA Certificate Services")).toMatchObject({
      user: "absent",
      admin: "absent",
    });
    expect(trustScopes.sort()).toEqual(["admin", "user"]);
    expect(calls.some((call) => call.bin === "security")).toBe(false);
    expect(calls.some((call) => call.args.includes("add-trusted-cert"))).toBe(false);
    expect(calls.filter((call) => call.bin === "curl")).toHaveLength(12);
    expect(calls.filter((call) => call.bin === "git").every((call) => call.args.includes("ls-remote"))).toBe(true);
    expect(calls.filter((call) => call.bin === "curl").every((call) => call.args.includes("--head"))).toBe(true);
    const rendered = `${JSON.stringify(report)}\n${formatTrustAudit(report)}`;
    expect(rendered).not.toContain(sentinel);
    expect(rendered).toContain(MACOS_NEVER_TRUST_COMMAND);
    expect(rendered).toContain("does not change trust settings");
    expect(rendered).toContain("Go is not probed");
    const findings = trustAuditFindings(report);
    expect(findings.map((finding) => finding.id).sort()).toEqual(["TRUST_AUDIT_EXPOSED", "TRUST_AUDIT_UNKNOWN"]);
    expect(findings.every((finding) => finding.recommendationOnly)).toBe(true);
    expect(findings.find((finding) => finding.id === "TRUST_AUDIT_EXPOSED")?.agentAction).not.toContain("add-trusted-cert");
    expect(findings.find((finding) => finding.id === "TRUST_AUDIT_UNKNOWN")?.remediation.join(" ")).not.toContain("add-trusted-cert");
  });

  it("skips missing tools and does not read macOS trust settings on other platforms", async () => {
    const { runtime, calls, trustScopes } = harness({
      platform: "linux",
      present: (bin) => bin !== "git",
      node: "blocked",
      exec: (request) => {
        if (request.bin === "curl") return result({ code: 60, stderr: "SSL certificate problem" });
        if (request.bin === "python3") return result({ code: 0, stdout: "VIGIL_EXPOSED\n" });
        throw new Error(`unexpected ${request.bin}`);
      },
    });
    const report = await runTrustAudit(runtime);
    const tools = Object.fromEntries((report.incidents[0]?.tools ?? []).map((tool) => [tool.tool, tool]));
    expect(tools.git?.status).toBe("absent");
    expect(tools.python3?.status).toBe("exposed");
    expect(tools.python3?.advice[0]).toMatch(/certifi/);
    expect(tools.nscurl).toBeUndefined();
    expect(calls.some((call) => call.bin === "git" || call.bin === "nscurl" || call.bin === "security")).toBe(false);
    expect(trustScopes).toEqual([]);
    expect(report.incidents[0]?.roots.every((item) => item.user === "unread" && item.admin === "unread")).toBe(true);
    const text = formatTrustAudit(report);
    expect(text).toContain("nscurl: not run");
    expect(text).toContain("Update certifi");
    expect(text).not.toContain(MACOS_NEVER_TRUST_COMMAND);
    const blocked = formatTrustAudit({
      ...report,
      incidents: report.incidents.map((incident) => ({
        ...incident,
        tools: incident.tools.map((tool) => ({ ...tool, status: "blocked" as const, advice: [MACOS_NEVER_TRUST_COMMAND] })),
      })),
    });
    expect(blocked).not.toContain("add-trusted-cert");
    expect(blocked).not.toContain("advice:");
  });
});

describe("cli trust-audit", () => {
  const versions = {
    node: "v22.23.4",
    curl: "curl 8.23.0",
    go: "go version go1.27.3 linux/amd64",
    kernel: "6.12.113",
    kernelOs: "Linux",
  };

  async function exposedCurl(): Promise<TrustAuditReport> {
    const { runtime } = harness({
      platform: "linux",
      present: (bin) => bin === "curl",
      node: "blocked",
      exec: () => result({ code: 0 }),
    });
    return runTrustAudit(runtime);
  }

  it("does not open a live probe from the test runner", async () => {
    const output = io();
    const code = await main(["trust-audit"], output);
    expect(code).toBe(1);
    expect(output.error()).toMatch(/disabled under the test runner/);
  });

  it("prints JSON and refuses a path", async () => {
    const report = await exposedCurl();
    const output = io();
    expect(await main(["trust-audit", "--json"], output, { runTrustAudit: async () => report })).toBe(0);
    const parsed = JSON.parse(output.text()) as TrustAuditReport;
    expect(parsed.incidents[0]?.tools.find((tool) => tool.tool === "curl")?.status).toBe("exposed");
    expect(output.text()).not.toContain(sentinel);
    const extra = io();
    expect(await main(["trust-audit", "fixtures"], extra, { runTrustAudit: async () => report })).toBe(1);
    expect(extra.error()).toMatch(/no path/);
    const help = io();
    expect(await main(["--help"], help)).toBe(0);
    expect(help.text()).toContain("vigil trust-audit");
  });

  it("adds recommendation-only doctor findings and prints advice without applying it", async () => {
    const report = await exposedCurl();
    const jsonOut = io();
    const code = await main(["doctor", join(root, "fixtures/doctor"), "--json"], jsonOut, {
      versions,
      trustBundles: [],
      trustAudit: report,
    });
    expect(code).toBe(0);
    const parsed = JSON.parse(jsonOut.text()) as {
      blockDeploy: boolean;
      findings: { id: string; recommendationOnly: boolean; remediation: string[] }[];
      education: { category: string }[];
    };
    expect(parsed.blockDeploy).toBe(false);
    const finding = parsed.findings.find((item) => item.id === "TRUST_AUDIT_EXPOSED");
    expect(finding?.recommendationOnly).toBe(true);
    expect(finding?.remediation.join(" ")).toMatch(/ca-certificates/);
    expect(finding?.remediation.join(" ")).not.toContain("add-trusted-cert");
    expect(parsed.education.some((item) => item.category === "trust-audit")).toBe(true);

    const { runtime } = harness({
      platform: "darwin",
      present: (bin) => bin === "nscurl",
      node: "blocked",
      exec: () => result({ code: 0, stdout: "HTTP/1.1 200 OK\n" }),
      readTrust: () => null,
    });
    const darwin = await runTrustAudit(runtime);
    const human = io();
    expect(await main(["doctor", join(root, "fixtures/doctor")], human, {
      versions,
      trustBundles: [],
      trustAudit: darwin,
    })).toBe(0);
    expect(human.text()).toContain("verdict:");
    expect(human.text()).toContain(MACOS_NEVER_TRUST_COMMAND);
    expect(human.text()).toContain("does not change trust settings");
    expect(human.text()).toContain("user: unread");
  });
});
