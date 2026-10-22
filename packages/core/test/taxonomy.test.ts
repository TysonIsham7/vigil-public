import { describe, expect, it } from "vitest";
import {
  TAXONOMY_DOMAIN_IDS,
  catalogRuleIds,
  createFinding,
  summarize,
  taxonomyDomains,
  taxonomyFor,
} from "../src/index.js";

describe("taxonomy catalog", () => {
  it("resolves every rule into one of the eleven domains", () => {
    expect(taxonomyDomains().map((domain) => domain.id)).toEqual([...TAXONOMY_DOMAIN_IDS]);
    const ids = catalogRuleIds();
    expect(ids.length).toBeGreaterThan(40);
    for (const id of ids) {
      const taxonomy = taxonomyFor(id);
      expect(TAXONOMY_DOMAIN_IDS).toContain(taxonomy.domain);
      expect(taxonomy.nistCsf.category.startsWith(taxonomy.nistCsf.function)).toBe(true);
      if (taxonomy.cis) expect(taxonomy.cis.version).toBe("8.1");
    }
  });

  it("summarizes every domain, including zeroes", () => {
    const finding = createFinding({
      id: "FETCH_TRUNCATED",
      severity: "medium",
      confidence: "high",
      title: "truncated",
      summary: "truncated",
      why: "policy",
      remediation: ["scan files"],
      file: "(network)",
      line: 1,
      evidence: "cap",
      agentAction: "scan files",
      category: "limits",
      recommendationOnly: true,
    });
    const summary = summarize([finding]);
    expect(summary.byDomain).toHaveLength(11);
    expect(summary.byDomain.find((row) => row.id === "grc")).toMatchObject({ medium: 1, total: 1 });
    expect(summary.byDomain.filter((row) => row.total === 0)).toHaveLength(10);
  });

  it("rejects a rule id that is not in the catalog", () => {
    expect(() => taxonomyFor("NOT_A_RULE")).toThrow(/no taxonomy entry/);
  });
});
