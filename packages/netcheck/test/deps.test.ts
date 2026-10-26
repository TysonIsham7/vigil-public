import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { buildReport } from "@vigil/core";
import { intermediatePems } from "@vigil/intel";
import { assessToolchain, dependencyFindings, gateDependencyReport, kernelFinding, manifestDependencies, parseDependencies, parseDockerImages, queryOsv, sharedHostFinding, trustStoreFindings, versionToken } from "../src/index.js";
import { ageInDays, registrationDate, selectRdapServer } from "../src/index.js";

const depsDir = join(import.meta.dirname, "../../../fixtures/deps");

describe("lockfiles and OSV", () => {
  const files = readdirSync(depsDir).map((name) => ({ name, content: readFileSync(join(depsDir, name), "utf8") }));
  const packages = parseDependencies(files);

  it("reads npm, PyPI, Go, Packagist, and the LiteLLM image pin", () => {
    expect(packages).toEqual(expect.arrayContaining([
      expect.objectContaining({ ecosystem: "npm", name: "left-pad", version: "1.3.0" }),
      expect.objectContaining({ ecosystem: "npm", name: "@scope/pkg", version: "2.0.1" }),
      expect.objectContaining({ ecosystem: "PyPI", name: "litellm", version: "1.107.0" }),
      expect.objectContaining({ ecosystem: "PyPI", name: "requests", version: "2.32.3" }),
      expect.objectContaining({ ecosystem: "PyPI", name: "litellm", version: "1.106.2" }),
      expect.objectContaining({ ecosystem: "Go", name: "golang.org/x/crypto", version: "v0.31.0" }),
      expect.objectContaining({ ecosystem: "Packagist", name: "vendor/pkg", version: "1.2.3" }),
    ]));
    expect(packages.some((pkg) => pkg.version.includes("go.mod"))).toBe(false);
  });

  it("blocks exact axios and MCP SDK pins", () => {
    const { findings } = dependencyFindings([
      { ecosystem: "npm", name: "axios", version: "1.14.1", source: "package-lock.json" },
      { ecosystem: "npm", name: "axios", version: "1.14.0", source: "package-lock.json" },
      { ecosystem: "npm", name: "@modelcontextprotocol/sdk", version: "1.31.0", source: "package-lock.json" },
      { ecosystem: "npm", name: "@modelcontextprotocol/sdk", version: "1.32.0", source: "package-lock.json" },
      { ecosystem: "npm", name: "litellm", version: "1.107.0", source: "requirements.txt" },
    ], { hits: [] });
    expect(findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED" && finding.evidence === "axios@1.14.1")).toBe(true);
    expect(findings.some((finding) => finding.evidence === "axios@1.14.0")).toBe(false);
    expect(findings.some((finding) => finding.id === "DEP_MCP_SDK" && finding.evidence === "@modelcontextprotocol/sdk@1.31.0")).toBe(true);
    expect(findings.some((finding) => finding.evidence === "@modelcontextprotocol/sdk@1.32.0")).toBe(false);
    expect(findings.some((finding) => finding.id === "DEP_LITELLM_COMPROMISED")).toBe(true);
  });

  it("blocks the exact LiteLLM pin and keeps OSV as a recommendation", () => {
    const { findings } = dependencyFindings(packages, {
      hits: [{ pkg: packages.find((pkg) => pkg.name === "requests")!, ids: ["PYSEC-1"], high: true }],
    });
    const litellm = findings.filter((finding) => finding.id === "DEP_LITELLM_COMPROMISED");
    expect(litellm.length).toBeGreaterThan(0);
    expect(litellm.every((finding) => finding.severity === "critical" && !finding.recommendationOnly)).toBe(true);
    expect(litellm[0]?.taxonomy.domain).toBe("emerging-tech");
    const osv = findings.find((finding) => finding.id === "DEP_OSV");
    expect(osv?.recommendationOnly).toBe(true);
    expect(osv?.severity).toBe("high");
  });

  it("fails open when OSV is down and still reports the local advisory", async () => {
    const fetchImpl: typeof fetch = async () => { throw new Error("down"); };
    const osv = await queryOsv(packages, fetchImpl);
    expect(osv.error).toMatch(/down/);
    const { findings, deps } = dependencyFindings(packages, osv);
    expect(findings.some((finding) => finding.id === "DEP_LITELLM_COMPROMISED")).toBe(true);
    expect(deps.some((dep) => dep.level === "unknown")).toBe(true);
  });

  it("keeps an exact version on an npm: alias", () => {
    const deps = manifestDependencies({
      name: "package.json",
      content: JSON.stringify({
        dependencies: {
          request: "npm:axios@1.14.1",
          old: "npm:axios@0.30.4",
          dropper: "npm:plain-crypto-js@4.2.0",
          ranged: "npm:axios@^1.14.0",
          scoped: "npm:@modelcontextprotocol/sdk@1.31.0",
        },
      }),
    });
    expect(deps).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "axios", version: "1.14.1", spec: "npm:axios@1.14.1" }),
      expect.objectContaining({ name: "axios", version: "0.30.4" }),
      expect.objectContaining({ name: "plain-crypto-js", version: "4.2.0" }),
      expect.objectContaining({ name: "axios", spec: "npm:axios@^1.14.0", version: null }),
      expect.objectContaining({ name: "@modelcontextprotocol/sdk", version: "1.31.0" }),
    ]));
    const report = gateDependencyReport({
      name: "package.json",
      content: JSON.stringify({ dependencies: { request: "npm:axios@1.14.1" } }),
    }, []);
    expect(report.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED" && finding.evidence === "axios@1.14.1")).toBe(true);
    expect(report.findings.some((finding) => finding.id === "DEP_RANGE")).toBe(false);
  });

  it("reads a lockfileVersion 1 tree and strips pnpm peer suffixes", () => {
    const v1 = parseDependencies([{
      name: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 1,
        dependencies: {
          left: {
            version: "1.0.0",
            dependencies: { axios: { version: "0.30.4" } },
          },
        },
      }),
    }]);
    expect(v1).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "left", version: "1.0.0" }),
      expect.objectContaining({ name: "axios", version: "0.30.4" }),
    ]));
    const pnpm = parseDependencies([{
      name: "pnpm-lock.yaml",
      content: [
        "lockfileVersion: '9.0'",
        "",
        "packages:",
        "",
        "  axios@1.14.1(react@18.2.0):",
        "    resolution: {integrity: sha}",
        "",
        "  'axios@0.30.4(react@18.2.0(react-dom@18.2.0))':",
        "    resolution: {integrity: sha}",
        "",
      ].join("\n"),
    }]);
    expect(pnpm).toEqual(expect.arrayContaining([
      expect.objectContaining({ name: "axios", version: "1.14.1" }),
      expect.objectContaining({ name: "axios", version: "0.30.4" }),
    ]));
    expect(pnpm.some((pkg) => pkg.version.includes("("))).toBe(false);
    const report = gateDependencyReport(null, [{
      name: "pnpm-lock.yaml",
      content: "lockfileVersion: '9.0'\n\npackages:\n\n  axios@1.14.1(react@18.2.0):\n    resolution: {integrity: sha}\n",
    }]);
    expect(report.findings.some((finding) => finding.id === "DEP_AXIOS_COMPROMISED" && finding.evidence === "axios@1.14.1")).toBe(true);
  });

  it("chunks are not required to call the network for an empty set", async () => {
    let called = false;
    const osv = await queryOsv([], async () => { called = true; return new Response("{}"); });
    expect(called).toBe(false);
    expect(osv.hits).toEqual([]);
  });
});

describe("RDAP dates", () => {
  it("selects the longest matching zone and reads the registration event", () => {
    const base = selectRdapServer("example.co.uk", {
      services: [
        [["uk"], ["https://rdap.example/uk/"]],
        [["co.uk"], ["https://rdap.example/couk/"]],
      ],
    });
    expect(base).toBe("https://rdap.example/couk/");
    const registeredAt = registrationDate({ events: [{ eventAction: "registration", eventDate: "2026-10-01T00:00:00Z" }] });
    expect(ageInDays(registeredAt ?? "", new Date("2026-10-21T00:00:00Z"))).toBe(20);
  });
});

describe("doctor toolchain", () => {
  it("reports local curl and Go without a deploy block", () => {
    const findings = assessToolchain({
      curlVersion: "curl 8.5.0 (x86_64-pc-linux-gnu)",
      goVersion: "go version go1.22.2 linux/amd64",
      images: [
        { image: "golang:1.22.2", tag: "1.22.2", source: "Dockerfile", line: 1 },
        { image: "curlimages/curl:8.12.0", tag: "8.12.0", source: "Dockerfile", line: 2 },
      ],
    });
    expect(findings.some((finding) => finding.id === "TOOLCHAIN_CURL")).toBe(false);
    expect(findings.some((finding) => finding.id === "TOOLCHAIN_GO" && finding.recommendationOnly)).toBe(true);
    expect(findings.filter((finding) => finding.id === "TOOLCHAIN_IMAGE")).toHaveLength(2);
    expect(findings.every((finding) => finding.recommendationOnly)).toBe(true);
    expect(versionToken("8.12")).toBe("8.12.0");
    const nodeOld = assessToolchain({ nodeVersion: "v22.23.3" });
    const nodeOk = assessToolchain({ nodeVersion: "v22.23.4" });
    expect(nodeOld.some((finding) => finding.id === "TOOLCHAIN_NODE" && finding.recommendationOnly)).toBe(true);
    expect(nodeOld.find((finding) => finding.id === "TOOLCHAIN_NODE")?.evidence).toBe("22.23.3");
    expect(nodeOk.some((finding) => finding.id === "TOOLCHAIN_NODE")).toBe(false);
    expect(assessToolchain({ nodeVersion: "v24.22.0" }).some((finding) => finding.id === "TOOLCHAIN_NODE")).toBe(true);
    expect(assessToolchain({ nodeVersion: "v26.12.1" }).some((finding) => finding.id === "TOOLCHAIN_NODE")).toBe(false);
    const nginxOld = assessToolchain({ nginxVersion: "nginx version: nginx/1.31.6" });
    const nginxStable = assessToolchain({ nginxVersion: "nginx version: nginx/1.30.6" });
    expect(nginxOld.find((finding) => finding.id === "TOOLCHAIN_NGINX")?.recommendationOnly).toBe(true);
    expect(nginxOld.find((finding) => finding.id === "TOOLCHAIN_NGINX")?.evidence).toBe("1.31.6");
    expect(nginxStable.some((finding) => finding.id === "TOOLCHAIN_NGINX")).toBe(false);
  });

  it("reports nginx image tags without padding the floating 1.31 and 1.30 lines", () => {
    const parsed = parseDockerImages("Dockerfile", [
      "FROM nginx:1.31",
      "FROM nginx:1.31-alpine3.24",
      "FROM nginx:1.30",
      "FROM nginx:1.30-alpine",
      "FROM nginx:1.29",
      "FROM nginx:1.28",
      "FROM nginx:1.31.6-alpine3.21",
      "FROM localhost:5000/nginx:1.31.6",
      "FROM nginx:1.31.6@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "FROM nginx:1.31.7-alpine",
      "FROM nginxinc/nginx-prometheus-exporter:1.0.0",
      "FROM nginxinc/nginx-unprivileged:1.30.5",
    ].join("\n"));
    expect(parsed.find((image) => image.image.startsWith("localhost:"))?.tag).toBe("1.31.6");
    expect(parsed.find((image) => image.image.includes("@sha256"))?.tag).toBe("1.31.6");
    const flagged = assessToolchain({ images: parsed }).filter((finding) => finding.id === "TOOLCHAIN_IMAGE");
    expect(flagged.map((finding) => finding.evidence).sort()).toEqual([
      "localhost:5000/nginx:1.31.6",
      "nginx:1.28",
      "nginx:1.29",
      "nginx:1.31.6-alpine3.21",
      "nginx:1.31.6@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "nginxinc/nginx-unprivileged:1.30.5",
    ]);
    expect(flagged.every((finding) => finding.recommendationOnly)).toBe(true);
  });

  it("reports an affected uname and a trust store that still has an eMudhra key", () => {
    const pem = intermediatePems()[0]?.pem ?? "";
    const findings = assessToolchain({
      kernelRelease: "Linux secret-host 6.12.94+ #1 SMP",
      kernelOs: "Linux",
      goVersion: "go version go1.27.3 linux/amd64",
      trustBundles: [{ label: "ca-certificates", pem }, { label: "node", pem: "not a certificate" }],
    });
    const kernel = findings.find((finding) => finding.id === "KERNEL_CVE_2026_99999");
    const trust = findings.find((finding) => finding.id === "TRUSTSTORE_EMUDHRA");
    expect(kernel?.recommendationOnly).toBe(true);
    expect(kernel?.evidence).toBe("6.12.94");
    expect(kernel?.taxonomy.domain).toBe("endpoint-device");
    expect(JSON.stringify(kernel)).not.toContain("secret-host");
    expect(trust?.file).toBe("(trust:ca-certificates)");
    expect(trust?.recommendationOnly).toBe(true);
    expect(JSON.stringify(trust)).not.toContain("BEGIN CERTIFICATE");
    expect(findings.some((finding) => finding.id === "TOOLCHAIN_GO")).toBe(false);
    expect(assessToolchain({ kernelRelease: "6.12.113", kernelOs: "Linux" }).some((finding) => finding.id === "KERNEL_CVE_2026_99999")).toBe(false);
    const oldPip = assessToolchain({ pipVersion: "pip 24.0 from /usr/lib/python3/dist-packages/pip (python 3.12)", uvVersion: "uv 0.13.3" });
    expect(oldPip.find((finding) => finding.id === "TOOLCHAIN_PIP")).toMatchObject({ recommendationOnly: true, evidence: "24.0.0" });
    expect(oldPip.find((finding) => finding.id === "TOOLCHAIN_UV")).toMatchObject({ recommendationOnly: true, evidence: "0.13.3" });
    expect(JSON.stringify(oldPip)).not.toContain("/usr/lib");
    const currentPip = assessToolchain({ pipVersion: "pip 26.2.2 from /opt/pip", uvVersion: "uv 0.13.4" });
    expect(currentPip.some((finding) => finding.id === "TOOLCHAIN_PIP" || finding.id === "TOOLCHAIN_UV")).toBe(false);
    expect(assessToolchain({ kernelRelease: "24.6.0", kernelOs: "Darwin" }).some((finding) => finding.id === "KERNEL_CVE_2026_99999")).toBe(false);
    expect(trustStoreFindings([{ label: "certifi", pem: "" }])).toEqual([]);
    expect(kernelFinding("7.2.11")).toBeUndefined();
  });

  it("keeps the shared-host note informational", () => {
    const finding = sharedHostFinding();
    expect(finding.severity).toBe("informational");
    expect(finding.recommendationOnly).toBe(true);
    expect(finding.taxonomy.domain).toBe("cloud-hybrid");
    expect(finding.taxonomy.cis).toBeNull();
    const report = buildReport({
      findings: [finding],
      sourceType: "url",
      filesAnalyzed: 1,
      bytesAnalyzed: 1,
      intelVersion: "test",
    });
    expect(report.blockDeploy).toBe(false);
    expect(report.verdict).toBe("allow");
  });
});
