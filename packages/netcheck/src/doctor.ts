import { assessKernel, assessKernelSharedFrag, curlAdvisory, curlAffected, goAdvisory, goMissingTrustFix, kernelAdvisory, kernelSharedFragAdvisory, litellmAdvisory, nginxAdvisory, nginxMissingSecurityRelease, nodeAdvisory, nodeMissingSecurityRelease, pipAdvisory, pipMissingCertifiFix, pythonAdvisory, pythonMissingSecurityRelease, pythonVersionEvidence, uvMissingCertifiFix } from "@vigil/intel";
import type { Finding } from "@vigil/core";
import { dockerImageName, parseDockerImages, type ImageRef } from "./deps.js";
import { netFinding } from "./finding.js";
import { distrustedInBundle, type TrustBundle } from "./truststore.js";

export function versionToken(text: string): string | undefined {
  const match = /(\d+\.\d+(?:\.\d+)?)/.exec(text);
  if (!match?.[1]) return undefined;
  return match[1].split(".").length === 2 ? `${match[1]}.0` : match[1];
}

export function assessToolchain(input: {
  nodeVersion?: string | null;
  curlVersion?: string | null;
  goVersion?: string | null;
  nginxVersion?: string | null;
  pipVersion?: string | null;
  uvVersion?: string | null;
  pythonVersion?: string | null;
  kernelRelease?: string | null;
  kernelOs?: string | null;
  trustBundles?: TrustBundle[];
  images?: ImageRef[];
  recommendationOnly?: boolean;
}): Finding[] {
  const findings: Finding[] = [];
  const reportOnly = input.recommendationOnly !== false;
  const node = input.nodeVersion ? versionToken(input.nodeVersion) : undefined;
  if (node && nodeMissingSecurityRelease(node)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_NODE",
      severity: "high",
      title: "Local Node is below the October 2026 security release",
      summary: `Node ${node} is not one of the patched releases. Use Node 22.23.4 or newer on the 22 line, 24.22.1 or newer on the 24 line, or 26.12.1 or newer on the 26 line.`,
      why: `The page fetch uses this Node process, including its Brotli decoder. ${nodeAdvisory.knownExploited} This is a report about the machine running vigil doctor. It does not block a deploy.`,
      remediation: [nodeAdvisory.remediation, nodeAdvisory.kevAction],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: node,
    }));
  }
  const curl = input.curlVersion ? versionToken(input.curlVersion) : undefined;
  if (curl && curlAffected(curl)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_CURL",
      severity: "high",
      title: "Local curl is in the CVE-2026-92392 range",
      summary: `curl ${curl} is inside ${curlAdvisory.introduced} through the release before ${curlAdvisory.fixed}, and it is not one of the patched branches.`,
      why: "This is a report about the machine running vigil doctor. It does not block a deploy.",
      remediation: [curlAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: curl,
    }));
  }
  const nginxRaw = input.nginxVersion ?? "";
  const nginx = nginxRaw ? versionToken(nginxRaw) : undefined;
  if (nginxRaw && nginxMissingSecurityRelease(nginxRaw)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_NGINX",
      severity: "high",
      title: "Local nginx is below the 14 October 2026 security release",
      summary: `nginx ${nginx ?? nginxRaw} is inside the range fixed by 1.31.7 on the mainline and 1.30.6 on the 1.30 line.`,
      why: "Those releases fix five medium worker issues, including a buffer overflow, HTTP/3 request-body injection, and TLS session-ticket forgery. This is a report about the machine running vigil doctor. It does not probe a remote server and it does not block a deploy.",
      remediation: [nginxAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: nginx ?? nginxRaw,
    }));
  }
  const go = input.goVersion ? versionToken(input.goVersion) : undefined;
  if (go && goMissingTrustFix(go)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_GO",
      severity: "high",
      title: "Local Go is missing the eMudhra trust filter",
      summary: `Go ${go} is older than the 1.27.3 fix and is not on a patched 1.26.10 line.`,
      why: "Programs built with this toolchain still trust the compromised intermediate keys until they are rebuilt.",
      remediation: [goAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: go,
    }));
  }
  const pip = input.pipVersion ? versionToken(input.pipVersion) : undefined;
  if (pip && pipMissingCertifiFix(pip)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_PIP",
      severity: "high",
      title: "Local pip still vendors a pre-eMudhra certifi",
      summary: `pip ${pip} is older than ${pipAdvisory.pipFixed}. It keeps trusting the compromised intermediates from its own certifi copy.`,
      why: "pip loads that vendored bundle in addition to the system trust store. Removing the keys from ca-certificates does not update it. This is a report about the machine running vigil doctor. It does not block a deploy.",
      remediation: [pipAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: pip,
    }));
  }
  const uv = input.uvVersion ? versionToken(input.uvVersion) : undefined;
  if (uv && uvMissingCertifiFix(uv)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_UV",
      severity: "high",
      title: "Local uv is below the eMudhra certifi update",
      summary: `uv ${uv} is older than ${pipAdvisory.uvFixed}.`,
      why: "That release is the one that picked up certifi 2026.10.19. This is a report about the machine running vigil doctor. It does not block a deploy.",
      remediation: [pipAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: uv,
    }));
  }
  const python = input.pythonVersion ? pythonVersionEvidence(input.pythonVersion) : undefined;
  if (input.pythonVersion && python && pythonMissingSecurityRelease(input.pythonVersion)) {
    findings.push(netFinding({
      id: "TOOLCHAIN_PYTHON",
      severity: "high",
      title: "Local Python is below the 26 October 2026 security release",
      summary: `Python ${python} is not a fixed build. Use 3.15.2, 3.14.10, 3.13.18, 3.12.16, or 3.11.18, or a newer build on that line. A 3.10 or older install has no release on its line that includes this fix.`,
      why: "Those releases distrust the compromised eMudhra intermediates in the ssl module (CVE-2026-115557) and reject a tarfile link that replaces the destination (CVE-2026-114583). A tag with no patch on 3.11 through 3.15 is left alone. An explicit patch, including 0, is compared with that floor. A pre-release of the floor is still below it. A distributor may have backported the fix without changing this version string. This is a report about the machine running vigil doctor. It does not block a deploy.",
      remediation: [pythonAdvisory.remediation],
      recommendationOnly: true,
      category: "toolchain",
      file: "(local)",
      evidence: python,
    }));
  }
  if (input.kernelRelease && isLinux(input.kernelOs)) {
    const kernel = kernelFinding(input.kernelRelease);
    if (kernel) findings.push(kernel);
    const sharedFrag = kernelSharedFragFinding(input.kernelRelease);
    if (sharedFrag) findings.push(sharedFrag);
  }
  findings.push(...trustStoreFindings(input.trustBundles ?? []));
  for (const image of input.images ?? []) {
    const tag = versionToken(image.tag) ?? image.tag;
    const curlImage = /curl/i.test(image.image) && tag && curlAffected(tag);
    const goImage = /golang|^go(?::|\/)/i.test(image.image) && tag && goMissingTrustFix(tag);
    const nginxImage = isNginxImage(image.image) && nginxMissingSecurityRelease(image.tag);
    const pythonImage = dockerImageName(image.image) === "python" && image.tag !== "" && pythonMissingSecurityRelease(image.tag);
    if (curlImage || goImage || nginxImage) {
      const kind = curlImage ? "a curl" : goImage ? "a Go" : "an nginx";
      findings.push(netFinding({
        id: "TOOLCHAIN_IMAGE",
        severity: "high",
        title: "Container base image is missing a toolchain fix",
        summary: `${image.image} matches ${kind} advisory range.`,
        why: "Doctor reports the image. It does not build or run it.",
        remediation: [curlImage ? curlAdvisory.remediation : goImage ? goAdvisory.remediation : nginxAdvisory.remediation],
        recommendationOnly: true,
        category: "toolchain",
        file: image.source,
        line: image.line,
        evidence: image.image,
      }));
    }
    if (pythonImage) {
      findings.push(netFinding({
        id: "TOOLCHAIN_IMAGE",
        severity: "high",
        title: "Container base image is missing a toolchain fix",
        summary: `${image.image} is below the 26 October 2026 CPython security release.`,
        why: "Doctor reports the image. It does not build or run it. A tag that names no patch on 3.11 through 3.15 is left alone. An explicit patch, including 0, is compared with the advisory floor.",
        remediation: [pythonAdvisory.remediation],
        recommendationOnly: true,
        category: "toolchain",
        file: image.source,
        line: image.line,
        evidence: image.image,
      }));
    }
    if (/litellm/i.test(image.image) && isExactLitellm(image.tag)) {
      findings.push(netFinding({
        id: "DEP_LITELLM_COMPROMISED",
        severity: "critical",
        title: "Dockerfile pins compromised LiteLLM 1.107.0",
        summary: `${image.source} uses ${image.image}.`,
        why: reportOnly
          ? "vigil doctor reports this image and does not set a deploy block. vigil deps blocks on the same pin."
          : "That image tag matches the compromised LiteLLM release.",
        remediation: [litellmAdvisory.remediation],
        recommendationOnly: reportOnly,
        category: "dependency",
        file: image.source,
        line: image.line,
        evidence: image.image,
      }));
    }
  }
  return findings;
}

export function imagesFromDockerfiles(files: { name: string; content: string }[]): ImageRef[] {
  return files.flatMap((file) => parseDockerImages(file.name, file.content));
}

function kernelSummary(version: string, fixedIn: string | undefined): string {
  return fixedIn
    ? `uname reports ${version}. Upstream ${fixedIn.split(".").slice(0, 2).join(".")} is fixed in ${fixedIn}. A distributor may have backported that fix without changing this version string.`
    : `uname reports ${version}. The advisory lists no stable fix for this major.minor. Treat it as affected unless the distributor confirms a backport. uname cannot show that.`;
}

export function kernelFinding(text: string): Finding | undefined {
  const assessment = assessKernel(text);
  if (!assessment?.affected) return undefined;
  return netFinding({
    id: "KERNEL_CVE_2026_99999",
    severity: "high",
    title: "Local kernel is in the PwnEscape range",
    summary: kernelSummary(assessment.version, assessment.fixedIn),
    why: `${kernelAdvisory.name} (${kernelAdvisory.cve}) is a Linux IPv4 checksum_start bug with a virtio guest-to-host impact, CVSS ${kernelAdvisory.cvss}. This is the local version only. It does not block a deploy.`,
    remediation: [kernelAdvisory.remediation],
    recommendationOnly: true,
    category: "kernel",
    file: "(local)",
    evidence: assessment.version,
  });
}

export function kernelSharedFragFinding(text: string): Finding | undefined {
  const assessment = assessKernelSharedFrag(text);
  if (!assessment?.affected) return undefined;
  return netFinding({
    id: "KERNEL_CVE_2026_46300",
    severity: "high",
    title: "Local kernel is in the CVE-2026-46300 range",
    summary: kernelSummary(assessment.version, assessment.fixedIn),
    why: `${kernelSharedFragAdvisory.name} (${kernelSharedFragAdvisory.cve}) is in the CISA Known Exploited Vulnerabilities catalog, added 2026-10-28, due 2026-10-31. Forensic triage is required. Ransomware use is unknown. This is the local version only. It does not block a deploy.`,
    remediation: [kernelSharedFragAdvisory.remediation],
    recommendationOnly: true,
    category: "kernel",
    file: "(local)",
    evidence: assessment.version,
  });
}

/** Informational note for a URL scan. It does not claim the remote host is vulnerable. */
export function sharedHostFinding(): Finding {
  return netFinding({
    id: "KERNEL_SHARED_HOST",
    severity: "informational",
    title: "Shared-host kernel risk is not visible from here",
    summary: `${kernelAdvisory.name} (${kernelAdvisory.cve}) is a Linux host-kernel bug. This scan cannot see the host kernel, so it does not say whether that host is affected. The same limit applies to CVE-2026-46300.`,
    why: "A page, certificate, and set of headers do not include the kernel of the machine that served them. Shared hosting and a VM whose host is still in the affected range are outside what a site scan can measure.",
    remediation: ["Run vigil doctor on the host that serves this site. A remote scan is not a kernel check."],
    recommendationOnly: true,
    category: "kernel",
    file: "(site)",
    evidence: kernelAdvisory.cve,
  });
}

export function trustStoreFindings(bundles: TrustBundle[]): Finding[] {
  const findings: Finding[] = [];
  for (const bundle of bundles) {
    const hits = distrustedInBundle(bundle.label, bundle.pem);
    if (hits.length === 0) continue;
    findings.push(netFinding({
      id: "TRUSTSTORE_EMUDHRA",
      severity: "high",
      title: `${bundle.label} still trusts an eMudhra key`,
      summary: `${bundle.label} contains ${hits.map((hit) => hit.name).join(", ")}.`,
      why: "These are the compromised eMudhra intermediates or emSign ECC Root CA - G3. Clients that use this store can still accept a certificate those keys sign. Record-only roots are not reported. Go applies its own filter only in 1.27.3 or newer, and in 1.26.10 or newer on the 1.26 line. ca-certificates, certifi, and Node do not get that filter from a Go upgrade. This read does not see the certifi copy vendored inside an older pip.",
      remediation: [
        "Update this trust store so the distrusted keys are gone.",
        goAdvisory.remediation,
      ],
      recommendationOnly: true,
      category: "truststore",
      file: `(trust:${bundle.label})`,
      evidence: hits.map((hit) => `${hit.name} ${hit.spkiSha256.slice(0, 12)}`).join("; "),
    }));
  }
  return findings;
}

function isNginxImage(image: string): boolean {
  const name = dockerImageName(image);
  return name === "nginx" || name === "nginx-unprivileged";
}

function isLinux(kernelOs: string | null | undefined): boolean {
  if (kernelOs === undefined || kernelOs === null || kernelOs.trim() === "") return true;
  return /^linux$/i.test(kernelOs.trim());
}

function isExactLitellm(tag: string): boolean {
  const normalized = tag.trim().replace(/^v/, "");
  return litellmAdvisory.dockerTags.some((item) => item.replace(/^v/, "") === normalized) || normalized === litellmAdvisory.version;
}
