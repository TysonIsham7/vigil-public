import { describe, expect, it } from "vitest";
import {
  assessKernel,
  assessKernelSharedFrag,
  classifyPhpExposure,
  curlAffected,
  evaluatePhp,
  goMissingTrustFix,
  isCompromisedAxios,
  isCompromisedLitellm,
  isVulnerableMcpSdk,
  nginxMissingSecurityRelease,
  nodeAdvisory,
  nodeMissingSecurityRelease,
  pythonMissingSecurityRelease,
  litellmImage,
  classifyPhpHeaders,
  phpAdvisory,
  phpSessionAdvisory,
  phpSessionProgressNote,
  phpSessionUnfixedLine,
  phpVulnerable,
  pipMissingCertifiFix,
  uvMissingCertifiFix,
} from "../src/index.js";

describe("advisories", () => {
  it("matches the PHP fixed lines", () => {
    expect(phpVulnerable("8.2.34")).toBe(true);
    expect(phpVulnerable("8.2.35")).toBe(false);
    expect(phpVulnerable("8.3.35")).toBe(true);
    expect(phpVulnerable("8.3.36")).toBe(false);
    expect(phpVulnerable("8.4.26")).toBe(true);
    expect(phpVulnerable("8.4.27")).toBe(false);
    expect(phpVulnerable("8.5.11")).toBe(true);
    expect(phpVulnerable("8.5.12")).toBe(false);
    expect(phpVulnerable("8.1.33")).toBe(true);
    expect(phpVulnerable("7.4.33")).toBe(true);
    expect(phpVulnerable("8.6.0")).toBe(false);
    expect(phpVulnerable("9.0.0")).toBe(false);
  });

  it("classifies advertised PHP headers without reading a body", () => {
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.2.34" } }])).toMatchObject({ status: "below-patch", version: "8.2.34" });
    expect(classifyPhpHeaders([{ headers: { server: "PHP/8.2.35" } }])).toMatchObject({ status: "patched", version: "8.2.35" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.3.35" } }])).toMatchObject({ status: "below-patch", version: "8.3.35" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.3.36" } }])).toMatchObject({ status: "patched", version: "8.3.36" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.4.26" } }])).toMatchObject({ status: "below-patch", version: "8.4.26" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.4.27" } }])).toMatchObject({ status: "patched", version: "8.4.27" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.5.11" } }])).toMatchObject({ status: "below-patch", version: "8.5.11" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.5.12" } }])).toMatchObject({ status: "patched", version: "8.5.12" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.0.30" } }])).toMatchObject({ status: "below-patch", version: "8.0.30" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.6.0" } }])).toMatchObject({ status: "patched", version: "8.6.0" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/5.6.40" } }])).toMatchObject({ status: "never-patched", version: "5.6.40" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/6.0.0" } }])).toMatchObject({ status: "never-patched", version: "6.0.0" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/7.4.33" } }])).toMatchObject({ status: "never-patched", version: "7.4.33" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.2" }, setCookies: ["PHPSESSID=1"] }])).toEqual({ status: "unknown" });
    expect(classifyPhpHeaders([{ headers: { server: "Apache" }, setCookies: ["PHPSESSID=1"] }])).toEqual({ status: "unknown" });
    expect(classifyPhpHeaders([{ headers: { server: "nginx" } }])).toEqual({ status: "not-applicable" });
    expect(classifyPhpHeaders([
      { headers: { "x-powered-by": "PHP/8.5.12" } },
      { headers: { server: "PHP/7.4.33" } },
    ])).toMatchObject({ status: "never-patched", version: "7.4.33" });
    expect(classifyPhpHeaders([{ headers: { "x-powered-by": "PHP/8.2.35", server: "PHP/8.2.34" } }])).toMatchObject({
      status: "below-patch",
      version: "8.2.34",
    });
  });

  it("blocks a confirmed PHP version for the owner and warns a visitor", () => {
    const headers = { "x-powered-by": "PHP/8.2.34" };
    const owner = evaluatePhp({ headers, audience: "owner" });
    const visitor = evaluatePhp({ headers, audience: "visitor" });
    expect(owner).toMatchObject({ status: "vulnerable", recommendationOnly: false, severity: "critical", level: "block" });
    expect(visitor).toMatchObject({ status: "vulnerable", recommendationOnly: true, severity: "high", level: "warn" });
    expect(evaluatePhp({ headers: { server: "Apache" }, setCookies: ["PHPSESSID=1"], audience: "owner" }).status).toBe("suspected");
    expect(evaluatePhp({ headers: { "x-powered-by": "PHP/8.2.35" }, audience: "owner" }).status).toBe("fixed");
    expect(evaluatePhp({
      headers: { "x-powered-by": "PHP/8.2.35", server: "PHP/8.2.34" },
      audience: "visitor",
    })).toMatchObject({ status: "vulnerable", version: "8.2.34", severity: "high" });
  });

  it("keeps CVE-2026-115560 informational until PHP publishes a fixed release", () => {
    expect(phpSessionAdvisory.fixed).toEqual([]);
    expect(phpSessionAdvisory.cves).toEqual(["CVE-2026-115560"]);
    const note = phpSessionProgressNote("8.5.12");
    expect(note.id).toBe("PHP_CVE_2026_115560");
    expect(note.summary).toMatch(/8\.5\.12/);
    expect(note.remediation[0]).toMatch(/session\.upload_progress\.enabled=0/);
    expect(note.remediation[0]).toMatch(/does not block a deploy or hold a page/);
    expect(phpSessionUnfixedLine()).toMatch(/CVE-2026-115560/);
    expect(phpSessionUnfixedLine()).not.toMatch(/does not block a deploy or hold a page/);
  });

  it("classifies PHP2Shell from X-Powered-By and Server only", () => {
    expect(phpAdvisory.fixed).toEqual([
      { major: 8, minor: 2, patch: 35 },
      { major: 8, minor: 3, patch: 36 },
      { major: 8, minor: 4, patch: 27 },
      { major: 8, minor: 5, patch: 12 },
    ]);
    expect(phpAdvisory.exposure.eolUnpatchedAtOrBelow).toEqual({ major: 8, minor: 1 });
    expect(phpAdvisory.knownExploited).toMatch(/26 October 2026/);
    expect(phpAdvisory.knownExploited).toMatch(/2026\.10\.26/);
    expect(phpAdvisory.kevAction).toMatch(/take the PHP system offline/);
    expect(classifyPhpExposure({ "X-Powered-By": "PHP/8.2.34" }).summary).toMatch(/Known Exploited Vulnerabilities/);
    expect(classifyPhpExposure({ "X-Powered-By": "PHP/8.5.12" }).summary).not.toMatch(/Known Exploited Vulnerabilities/);
    for (const line of phpAdvisory.fixed) {
      const below = `${line.major}.${line.minor}.${line.patch - 1}`;
      const at = `${line.major}.${line.minor}.${line.patch}`;
      expect(classifyPhpExposure({ "X-Powered-By": `PHP/${below}` }).status).toBe("exposed");
      expect(classifyPhpExposure({ Server: `Apache PHP/${at}` }).status).toBe("patched");
    }
    expect(classifyPhpExposure({ "x-powered-by": "PHP/8.1.33" }).status).toBe("exposed");
    expect(classifyPhpExposure({ server: "PHP/7.4.33" }).status).toBe("exposed");
    expect(classifyPhpExposure({ "x-powered-by": "PHP/8.6.1" }).status).toBe("patched");
    expect(classifyPhpExposure({ "x-powered-by": "PHP/9.0.0" }).status).toBe("patched");
    expect(classifyPhpExposure({ "x-powered-by": "PHP/8.2" }).status).toBe("hidden");
    expect(classifyPhpExposure({ "x-powered-by": "PHP" }).status).toBe("hidden");
    expect(classifyPhpExposure({ server: "nginx", "x-powered-by": "Express" }).status).toBe("not-PHP");
    expect(classifyPhpExposure({}).status).toBe("not-PHP");
    expect(classifyPhpExposure({ "x-powered-by": "PHP/8.3.36", server: "PHP/8.1.2" }).status).toBe("exposed");
    expect(classifyPhpExposure({ "set-cookie": "PHPSESSID=1" }).status).toBe("not-PHP");
  });

  it("uses the curl patched branches instead of every build before 8.23.0", () => {
    expect(curlAffected("8.5.0")).toBe(false);
    expect(curlAffected("8.11.1")).toBe(false);
    expect(curlAffected("8.12.0")).toBe(true);
    expect(curlAffected("8.14.2")).toBe(true);
    expect(curlAffected("8.14.3")).toBe(false);
    expect(curlAffected("8.16.1")).toBe(true);
    expect(curlAffected("8.16.2")).toBe(false);
    expect(curlAffected("8.20.1")).toBe(true);
    expect(curlAffected("8.20.2")).toBe(false);
    expect(curlAffected("8.22.0")).toBe(true);
    expect(curlAffected("8.23.0")).toBe(false);
  });

  it("flags Node builds below the October 2026 security release", () => {
    expect(nodeMissingSecurityRelease("v22.23.3")).toBe(true);
    expect(nodeMissingSecurityRelease("22.23.4")).toBe(false);
    expect(nodeMissingSecurityRelease("22.24.0")).toBe(false);
    expect(nodeMissingSecurityRelease("v24.22.0")).toBe(true);
    expect(nodeMissingSecurityRelease("24.22.1")).toBe(false);
    expect(nodeMissingSecurityRelease("v26.12.0")).toBe(true);
    expect(nodeMissingSecurityRelease("26.12.1")).toBe(false);
    expect(nodeMissingSecurityRelease("26.13.0")).toBe(false);
    expect(nodeMissingSecurityRelease("23.11.0")).toBe(true);
    expect(nodeMissingSecurityRelease("25.0.0")).toBe(true);
    expect(nodeMissingSecurityRelease("20.19.0")).toBe(true);
    expect(nodeMissingSecurityRelease("27.0.0")).toBe(false);
    expect(nodeAdvisory.knownExploited).toMatch(/27 October 2026/);
    expect(nodeAdvisory.knownExploited).toMatch(/2026\.10\.27/);
    expect(nodeAdvisory.knownExploited).toMatch(/CVE-2026-111497/);
    expect(nodeAdvisory.kevAction).toMatch(/21 October 2026/);
  });

  it("flags nginx builds below the 14 October 2026 security release", () => {
    expect(nginxMissingSecurityRelease("1.31.6")).toBe(true);
    expect(nginxMissingSecurityRelease("nginx/1.31.7")).toBe(false);
    expect(nginxMissingSecurityRelease("1.31.8")).toBe(false);
    expect(nginxMissingSecurityRelease("1.31.0")).toBe(true);
    expect(nginxMissingSecurityRelease("1.31")).toBe(false);
    expect(nginxMissingSecurityRelease("1.31-alpine3.24")).toBe(false);
    expect(nginxMissingSecurityRelease("1.30.5")).toBe(true);
    expect(nginxMissingSecurityRelease("1.30.6")).toBe(false);
    expect(nginxMissingSecurityRelease("1.30")).toBe(false);
    expect(nginxMissingSecurityRelease("1.30-alpine")).toBe(false);
    expect(nginxMissingSecurityRelease("1.29")).toBe(true);
    expect(nginxMissingSecurityRelease("1.28")).toBe(true);
    expect(nginxMissingSecurityRelease("1.29.4")).toBe(true);
    expect(nginxMissingSecurityRelease("1.31.6-alpine3.21")).toBe(true);
    expect(nginxMissingSecurityRelease("1.32.0")).toBe(false);
    expect(nginxMissingSecurityRelease("0.1.28")).toBe(false);
    expect(nginxMissingSecurityRelease("0.1.29")).toBe(true);
  });

  it("flags CPython below the 26 October 2026 floors without padding or swallowing a pre-release", () => {
    expect(pythonMissingSecurityRelease("Python 3.15.1")).toBe(true);
    expect(pythonMissingSecurityRelease("3.15.2")).toBe(false);
    expect(pythonMissingSecurityRelease("3.14.9")).toBe(true);
    expect(pythonMissingSecurityRelease("3.14.10")).toBe(false);
    expect(pythonMissingSecurityRelease("3.13.17")).toBe(true);
    expect(pythonMissingSecurityRelease("3.13.18")).toBe(false);
    expect(pythonMissingSecurityRelease("3.12.15")).toBe(true);
    expect(pythonMissingSecurityRelease("3.12.16")).toBe(false);
    expect(pythonMissingSecurityRelease("3.11.17")).toBe(true);
    expect(pythonMissingSecurityRelease("3.11.18")).toBe(false);
    expect(pythonMissingSecurityRelease("3.10.14")).toBe(true);
    expect(pythonMissingSecurityRelease("3.10")).toBe(true);
    expect(pythonMissingSecurityRelease("3.10-alpine")).toBe(true);
    expect(pythonMissingSecurityRelease("3.16.0")).toBe(false);
    expect(pythonMissingSecurityRelease("3.16")).toBe(false);
    expect(pythonMissingSecurityRelease("2.7.18")).toBe(false);
    expect(pythonMissingSecurityRelease("3.12")).toBe(false);
    expect(pythonMissingSecurityRelease("3.12-slim")).toBe(false);
    expect(pythonMissingSecurityRelease("3.11")).toBe(false);
    expect(pythonMissingSecurityRelease("3.13")).toBe(false);
    expect(pythonMissingSecurityRelease("3.14")).toBe(false);
    expect(pythonMissingSecurityRelease("3.15")).toBe(false);
    expect(pythonMissingSecurityRelease("3.12.0")).toBe(true);
    expect(pythonMissingSecurityRelease("Python 3.12.16rc1")).toBe(true);
    expect(pythonMissingSecurityRelease("3.15.2a1")).toBe(true);
    expect(pythonMissingSecurityRelease("3.12.16b1")).toBe(true);
    expect(pythonMissingSecurityRelease("3.12.16.dev1")).toBe(true);
    expect(pythonMissingSecurityRelease("3.12.16+")).toBe(false);
    expect(pythonMissingSecurityRelease("3.12.16+local")).toBe(false);
    expect(pythonMissingSecurityRelease("3.14.0a1")).toBe(true);
  });

  it("flags pip and uv from before the eMudhra certifi update", () => {
    expect(pipMissingCertifiFix("26.2.1")).toBe(true);
    expect(pipMissingCertifiFix("24.0.0")).toBe(true);
    expect(pipMissingCertifiFix("26.2.2")).toBe(false);
    expect(pipMissingCertifiFix("26.3.0")).toBe(false);
    expect(uvMissingCertifiFix("0.13.3")).toBe(true);
    expect(uvMissingCertifiFix("0.12.0")).toBe(true);
    expect(uvMissingCertifiFix("0.13.4")).toBe(false);
    expect(uvMissingCertifiFix("0.14.0")).toBe(false);
  });

  it("flags Go builds that are missing the eMudhra trust filter", () => {
    expect(goMissingTrustFix("go1.22.2")).toBe(true);
    expect(goMissingTrustFix("1.26.9")).toBe(true);
    expect(goMissingTrustFix("1.26.10")).toBe(false);
    expect(goMissingTrustFix("1.27.2")).toBe(true);
    expect(goMissingTrustFix("1.27.3")).toBe(false);
    expect(goMissingTrustFix("1.28.0")).toBe(false);
  });

  it("compares a kernel release to the PwnEscape stable fixes", () => {
    expect(assessKernel("6.12.94+")?.affected).toBe(true);
    expect(assessKernel("6.12.112")?.fixedIn).toBe("6.12.113");
    expect(assessKernel("6.12.113")?.affected).toBe(false);
    expect(assessKernel("6.12.113-1-generic")?.affected).toBe(false);
    expect(assessKernel("5.10.271")?.affected).toBe(true);
    expect(assessKernel("5.10.272")?.affected).toBe(false);
    expect(assessKernel("5.15.222")?.affected).toBe(true);
    expect(assessKernel("5.15.223")?.affected).toBe(false);
    expect(assessKernel("6.1.189")?.affected).toBe(true);
    expect(assessKernel("6.1.190")?.affected).toBe(false);
    expect(assessKernel("6.6.158")?.affected).toBe(true);
    expect(assessKernel("6.6.159")?.affected).toBe(false);
    expect(assessKernel("6.18.56")?.affected).toBe(true);
    expect(assessKernel("6.18.57")?.affected).toBe(false);
    expect(assessKernel("7.2.10")?.affected).toBe(true);
    expect(assessKernel("7.2.11")?.affected).toBe(false);
    expect(assessKernel("7.3.0")?.affected).toBe(false);
    expect(assessKernel("7.4.1")?.affected).toBe(false);
    expect(assessKernel("6.8.0-45-generic")?.affected).toBe(true);
    expect(assessKernel("6.8.0-45-generic")?.fixedIn).toBeUndefined();
    expect(assessKernel("2.6.26")?.affected).toBe(false);
    expect(assessKernel("Linux secret-host 6.12.94+ #1")?.version).toBe("6.12.94");
  });

  it("compares a kernel release to the CVE-2026-46300 stable fixes", () => {
    expect(assessKernelSharedFrag("6.12.90")?.affected).toBe(true);
    expect(assessKernelSharedFrag("6.12.90")?.fixedIn).toBe("6.12.91");
    expect(assessKernelSharedFrag("6.12.91")?.affected).toBe(false);
    expect(assessKernelSharedFrag("6.12.94+")?.affected).toBe(false);
    expect(assessKernelSharedFrag("5.10.256")?.affected).toBe(true);
    expect(assessKernelSharedFrag("5.10.257")?.affected).toBe(false);
    expect(assessKernelSharedFrag("5.15.207")?.affected).toBe(true);
    expect(assessKernelSharedFrag("5.15.208")?.affected).toBe(false);
    expect(assessKernelSharedFrag("6.1.173")?.affected).toBe(true);
    expect(assessKernelSharedFrag("6.1.174")?.affected).toBe(false);
    expect(assessKernelSharedFrag("6.6.140")?.affected).toBe(true);
    expect(assessKernelSharedFrag("6.6.141")?.affected).toBe(false);
    expect(assessKernelSharedFrag("6.18.32")?.affected).toBe(true);
    expect(assessKernelSharedFrag("6.18.33")?.affected).toBe(false);
    expect(assessKernelSharedFrag("7.0.9")?.affected).toBe(true);
    expect(assessKernelSharedFrag("7.0.9")?.fixedIn).toBe("7.0.10");
    expect(assessKernelSharedFrag("7.0.10")?.affected).toBe(false);
    expect(assessKernelSharedFrag("7.1.0")?.affected).toBe(false);
    expect(assessKernelSharedFrag("7.2.0")?.affected).toBe(false);
    expect(assessKernelSharedFrag("6.8.0-45-generic")?.affected).toBe(true);
    expect(assessKernelSharedFrag("6.8.0-45-generic")?.fixedIn).toBeUndefined();
    expect(assessKernelSharedFrag("3.8.0")?.affected).toBe(false);
    expect(assessKernelSharedFrag("3.9.0")?.affected).toBe(true);
  });

  it("matches the malicious axios releases and MCP SDK versions below 1.32.0 exactly", () => {
    expect(isCompromisedAxios("axios", "1.14.1")).toBe(true);
    expect(isCompromisedAxios("axios", "0.30.4")).toBe(true);
    expect(isCompromisedAxios("axios", "1.14.0")).toBe(false);
    expect(isCompromisedAxios("axios", "0.30.3")).toBe(false);
    expect(isCompromisedAxios("plain-crypto-js", "4.2.1")).toBe(true);
    expect(isCompromisedAxios("plain-crypto-js", "4.2.0")).toBe(true);
    expect(isCompromisedAxios("plain-crypto-js", "4.2.2")).toBe(false);
    expect(isVulnerableMcpSdk("@modelcontextprotocol/sdk", "1.31.0")).toBe(true);
    expect(isVulnerableMcpSdk("@modelcontextprotocol/sdk", "1.3.0")).toBe(true);
    expect(isVulnerableMcpSdk("@modelcontextprotocol/sdk", "1.32.0")).toBe(false);
    expect(isVulnerableMcpSdk("@modelcontextprotocol/sdk", "1.32.2")).toBe(false);
    expect(isVulnerableMcpSdk("@modelcontextprotocol/sdk", "^1.0.0")).toBe(false);
    expect(isVulnerableMcpSdk("axios", "1.14.1")).toBe(false);
  });

  it("matches LiteLLM 1.107.0 exactly", () => {
    expect(isCompromisedLitellm("litellm", "1.107.0")).toBe(true);
    expect(isCompromisedLitellm("litellm", "v1.107.0")).toBe(true);
    expect(isCompromisedLitellm("ghcr.io/berriai/litellm", "1.107.0")).toBe(true);
    expect(isCompromisedLitellm("litellm", "1.106.2")).toBe(false);
    expect(isCompromisedLitellm("litellm", "latest")).toBe(false);
    expect(litellmImage("ghcr.io/berriai/litellm:1.107.0")).toBe(true);
    expect(litellmImage("ghcr.io/berriai/litellm:latest")).toBe(false);
  });
});
