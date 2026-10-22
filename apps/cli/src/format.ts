import { DISCLAIMER, type Report } from "@vigil/core";

export function formatHuman(report: Report): string {
  const lines = [
    `verdict: ${report.verdict}`,
    `block_deploy: ${report.blockDeploy ? "true" : "false"}`,
    `intel: ${report.intelVersion}`,
    "domains:",
  ];
  for (const row of report.summary.byDomain) {
    if (row.total === 0) continue;
    const parts = (["critical", "high", "medium", "low", "informational"] as const)
      .filter((severity) => row[severity] > 0)
      .map((severity) => `${row[severity]} ${severity}`);
    lines.push(`  ${row.label}: ${parts.join(", ")}`);
  }
  if (report.summary.byDomain.every((row) => row.total === 0)) lines.push("  (none)");
  lines.push("findings:");
  if (report.findings.length === 0) lines.push("  (none)");
  for (const finding of report.findings) {
    const flag = finding.recommendationOnly ? "recommendation" : finding.severity;
    lines.push(`  [${flag}] ${finding.id} ${finding.file}:${finding.line} ${finding.title} (${finding.taxonomy.domain})`);
  }
  lines.push(`expires: ${report.expiresAt}`);
  lines.push(DISCLAIMER);
  return lines.join("\n");
}
