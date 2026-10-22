const SECRET_PATTERNS: { pattern: RegExp; replace: (match: string) => string }[] = [
  {
    pattern: /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/g,
    replace: () => "[redacted private key]",
  },
  {
    pattern: /AKIA[0-9A-Z]{16}/g,
    replace: (match) => `${match.slice(0, 4)}${"*".repeat(match.length - 4)}`,
  },
  {
    pattern: /sk_live_[A-Za-z0-9]+/g,
    replace: (match) => `sk_live_${"*".repeat(Math.max(4, match.length - "sk_live_".length))}`,
  },
  {
    pattern: /sk-[A-Za-z0-9_-]{20,}/g,
    replace: (match) => `${match.slice(0, 3)}${"*".repeat(match.length - 3)}`,
  },
  {
    pattern: /ghp_[A-Za-z0-9]+/g,
    replace: (match) => `ghp_${"*".repeat(Math.max(4, match.length - 4))}`,
  },
];

export function redactEvidence(line: string): string {
  let out = line.trim();
  for (const rule of SECRET_PATTERNS) {
    out = out.replace(rule.pattern, (match) => rule.replace(match));
  }
  out = out.replace(
    /((?:api_key|secret_key|auth_token|bearer)\s*[:=]\s*['"])[^'"]{8,}(['"])/gi,
    (_all, prefix: string, suffix: string) => `${prefix}${"*".repeat(8)}${suffix}`,
  );
  if (out.length > 180) out = `${out.slice(0, 177)}...`;
  return out;
}
