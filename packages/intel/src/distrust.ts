import distrusted from "../data/distrusted-cas.json" with { type: "json" };

export interface DistrustHit {
  name: string;
  spkiSha256: string;
  sha256?: string;
}

interface Intermediate {
  name: string;
  action: string;
  sha256: string;
  spkiSha256: string;
  pem?: string;
  crossSigns?: { sha256: string; spkiSha256: string }[];
}

interface Root {
  name: string;
  action: string;
  sha256: string | null;
  spkiSha256: string | null;
}

const data = distrusted as {
  version: string;
  testHost: string;
  sources: { title: string; url: string }[];
  intermediates: Intermediate[];
  roots: Root[];
};

function blockedRecords(): { name: string; sha256?: string; spkiSha256: string }[] {
  const rows: { name: string; sha256?: string; spkiSha256: string }[] = [];
  for (const item of data.intermediates) {
    if (item.action !== "block") continue;
    rows.push({ name: item.name, sha256: item.sha256.toLowerCase(), spkiSha256: item.spkiSha256.toLowerCase() });
    for (const cross of item.crossSigns ?? []) {
      rows.push({ name: item.name, sha256: cross.sha256.toLowerCase(), spkiSha256: cross.spkiSha256.toLowerCase() });
    }
  }
  for (const root of data.roots) {
    if (root.action !== "block" || !root.spkiSha256) continue;
    rows.push({
      name: root.name,
      ...(root.sha256 ? { sha256: root.sha256.toLowerCase() } : {}),
      spkiSha256: root.spkiSha256.toLowerCase(),
    });
  }
  return rows;
}

const BLOCKED = blockedRecords();

export function distrustVersion(): string {
  return data.version;
}

export function distrustTestHost(): string {
  return data.testHost;
}

export function distrustSources(): { title: string; url: string }[] {
  return data.sources;
}

export function blockedSpkiHashes(): string[] {
  return [...new Set(BLOCKED.map((row) => row.spkiSha256))];
}

export function intermediatePems(): { name: string; pem: string; spkiSha256: string; sha256: string }[] {
  return data.intermediates
    .filter((item) => item.action === "block" && item.pem)
    .map((item) => ({
      name: item.name,
      pem: item.pem ?? "",
      spkiSha256: item.spkiSha256.toLowerCase(),
      sha256: item.sha256.toLowerCase(),
    }));
}

export function matchDistrust(input: { spkiSha256?: string; sha256?: string }): DistrustHit | undefined {
  const spki = input.spkiSha256?.toLowerCase();
  const sha = input.sha256?.toLowerCase();
  const hit = BLOCKED.find((row) => (spki && row.spkiSha256 === spki) || (sha && row.sha256 === sha));
  if (!hit) return undefined;
  return { name: hit.name, spkiSha256: hit.spkiSha256, ...(hit.sha256 ? { sha256: hit.sha256 } : {}) };
}

export interface ReputationResult {
  provider: string;
  status: "not-configured" | "clean" | "flagged" | "unknown";
  detail?: string;
}

export interface ReputationProvider {
  readonly name: string;
  check(input: { host: string; registrableDomain: string }): Promise<ReputationResult>;
}

/** Reputation lookups stay off unless a later build wires a licensed provider. Nothing is sent. */
export function disabledReputation(name = "safe-browsing"): ReputationProvider {
  return {
    name,
    async check() {
      return { provider: name, status: "not-configured", detail: "Reputation lookups are disabled." };
    },
  };
}
