import { createFinding, type Finding, type Severity } from "@vigil/core";

export function netFinding(input: {
  id: string;
  severity: Severity;
  title: string;
  summary: string;
  why: string;
  remediation: string[];
  recommendationOnly: boolean;
  category: string;
  evidence?: string;
  file?: string;
  line?: number;
  confidence?: Finding["confidence"];
}): Finding {
  const file = input.file ?? "(network)";
  const line = input.line ?? 1;
  return createFinding({
    id: input.id,
    severity: input.severity,
    confidence: input.confidence ?? "high",
    title: input.title,
    summary: input.summary,
    why: input.why,
    remediation: input.remediation,
    file,
    line,
    evidence: input.evidence ?? input.title,
    agentAction: input.remediation[0] ?? input.title,
    category: input.category,
    recommendationOnly: input.recommendationOnly,
  });
}
