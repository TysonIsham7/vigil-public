import { describe, expect, it } from "vitest";
import {
  assessKernel,
  curlAffected,
  evaluatePhp,
  goMissingTrustFix,
  isCompromisedLitellm,
  nodeMissingSecurityRelease,
  litellmImage,
  phpVulnerable,
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

  it("blocks a confirmed PHP version for the owner and warns a visitor", () => {
    const headers = { "x-powered-by": "PHP/8.2.34" };
    const owner = evaluatePhp({ headers, audience: "owner" });
    const visitor = evaluatePhp({ headers, audience: "visitor" });
    expect(owner).toMatchObject({ status: "vulnerable", recommendationOnly: false, severity: "critical", level: "block" });
    expect(visitor).toMatchObject({ status: "vulnerable", recommendationOnly: true, severity: "high", level: "warn" });
    expect(evaluatePhp({ headers: { server: "Apache" }, setCookies: ["PHPSESSID=1"], audience: "owner" }).status).toBe("suspected");
    expect(evaluatePhp({ headers: { "x-powered-by": "PHP/8.2.35" }, audience: "owner" }).status).toBe("fixed");
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
