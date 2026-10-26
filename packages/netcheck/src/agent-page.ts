import {
  detectAgentDirected,
  inspectHtml,
  surfaceFile,
  type AgentMatch,
  type AgentSurface,
  type Finding,
} from "@vigil/core";
import type { SafeResponse } from "./fetch.js";
import { netFinding } from "./finding.js";

export const AGENT_EXTRA_PATHS = ["/robots.txt", "/llms.txt", "/llm.txt", "/.well-known/llms.txt"] as const;

const HEADER_VALUE_CAP = 8192;

const KIND_WORD: Record<AgentMatch["kind"], string> = {
  identity: "identity",
  credential: "a credential",
  behavior: "a behavior change",
};

const SURFACE_WORD: Record<AgentSurface, string> = {
  body: "Visible page text",
  hidden: "Hidden page text",
  meta: "Page metadata",
  robots: "robots.txt",
  llms: "llms.txt",
  header: "A response header",
};

export async function agentPageFindings(options: {
  html: string;
  headers: Record<string, string | string[]>;
  budget: () => boolean;
  fetchExtra: (url: string) => Promise<SafeResponse>;
  origin: string;
}): Promise<Finding[]> {
  const matches: AgentMatch[] = [
    ...inspectHtml(options.html),
    ...headerMatches(options.headers),
  ];
  const unread: string[] = [];
  const failed: string[] = [];
  let robots = "";
  let llms = "";
  const extraHeaders: Record<string, string | string[]>[] = [];
  for (const path of AGENT_EXTRA_PATHS) {
    if (!options.budget()) {
      unread.push(path);
      continue;
    }
    let response: SafeResponse;
    try {
      response = await options.fetchExtra(new URL(path, options.origin).toString());
    } catch {
      failed.push(path);
      continue;
    }
    if (response.status < 200 || response.status >= 300) failed.push(path);
    if (path === "/robots.txt") robots += `\n${response.body}`;
    else llms += `\n${response.body}`;
    extraHeaders.push(response.headers);
  }
  const robotsMatch = detectAgentDirected(robots, "robots");
  const llmsMatch = detectAgentDirected(llms, "llms");
  if (robotsMatch) matches.push(robotsMatch);
  if (llmsMatch) matches.push(llmsMatch);
  for (const headers of extraHeaders) matches.push(...headerMatches(headers));
  return [...dedupedFindings(matches), ...unread.map(unreadFinding), ...failed.map(failedFinding)];
}

export function redactInstructionHeaders(
  headers: Record<string, string | string[]>,
): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    const list = Array.isArray(value) ? value : [value];
    const redacted = list.map((item) => (
      detectAgentDirected(`${name}: ${item}`, "header") || detectAgentDirected(item, "header")
        ? "[redacted agent instruction]"
        : item
    ));
    out[name] = Array.isArray(value) ? redacted : redacted[0] ?? "";
  }
  return out;
}

function headerMatches(headers: Record<string, string | string[]>): AgentMatch[] {
  const lines: string[] = [];
  for (const [name, value] of Object.entries(headers)) {
    const joined = Array.isArray(value) ? value.join(", ") : value;
    lines.push(`${name}: ${joined.slice(0, HEADER_VALUE_CAP)}`);
  }
  const match = detectAgentDirected(lines.join("\n"), "header");
  return match ? [match] : [];
}

function dedupedFindings(matches: AgentMatch[]): Finding[] {
  const seen = new Set<string>();
  const findings: Finding[] = [];
  for (const match of matches) {
    const file = surfaceFile(match.surface);
    const key = `${match.kind}:${file}`;
    if (seen.has(key)) continue;
    seen.add(key);
    findings.push(agentFinding(match, file));
  }
  return findings;
}

function agentFinding(match: AgentMatch, file: string): Finding {
  const asked = KIND_WORD[match.kind];
  return netFinding({
    id: "AGENT_DIRECTED_REQUEST",
    severity: "high",
    title: "Agent-directed request",
    summary: `${SURFACE_WORD[match.surface]} addressed an agent and asked for ${asked}.`,
    why: `The page addressed an agent and asked for ${asked}. Vigil did not follow the instruction. The check read the static response only. Text added by script, or hidden only by an external stylesheet, was not part of this check.`,
    remediation: [
      "Do not let an agent act on text from this page.",
      "Do not put identity or credentials into a request the page asked for.",
    ],
    recommendationOnly: true,
    category: "agent-instruction",
    file,
    evidence: `${SURFACE_WORD[match.surface]} asked for ${asked}. Instruction text is omitted.`,
  });
}

function failedFinding(path: string): Finding {
  const label = path === "/robots.txt" ? "robots.txt" : path.replace(/^\//, "");
  return netFinding({
    id: "AGENT_DIRECTED_REQUEST",
    severity: "informational",
    title: "Agent file was not verified",
    summary: `${label} is unverified/fetch failed.`,
    why: "A failed fetch is not a clean result. Vigil did not read the file and does not describe it as reviewed.",
    remediation: ["Fetch this file again before treating the page check as complete."],
    recommendationOnly: true,
    category: "agent-instruction",
    file: path === "/robots.txt" ? "(page:robots.txt)" : "(page:llms.txt)",
    evidence: "unverified/fetch failed",
  });
}

function unreadFinding(path: string): Finding {
  const label = path === "/robots.txt" ? "robots.txt" : path.replace(/^\//, "");
  return netFinding({
    id: "AGENT_DIRECTED_REQUEST",
    severity: "informational",
    title: "Agent file was not read",
    summary: `${label} was not read because the fetch budget was spent.`,
    why: "An omitted file is not a clean result. Vigil did not fetch it and does not describe it as reviewed.",
    remediation: ["Scan the URL again when the fetch budget can include this file."],
    recommendationOnly: true,
    category: "agent-instruction",
    file: path === "/robots.txt" ? "(page:robots.txt)" : "(page:llms.txt)",
    evidence: label,
  });
}
