import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { PHASE1_BLOCKERS, PHASE1_RECOMMENDATIONS, ruleCatalog, scanSource } from "../src/index.js";

const vulnerable = join(import.meta.dirname, "../../../fixtures/vulnerable");

describe("phase 1 rules", () => {
  it("flags every blocker on the vulnerable fixture and skips comments", () => {
    const findings = readdirSync(vulnerable).flatMap((name) => scanSource(name, readFileSync(join(vulnerable, name), "utf8")));
    const ids = new Set(findings.map((finding) => finding.id));
    for (const id of PHASE1_BLOCKERS) expect(ids.has(id), id).toBe(true);
    expect(findings.some((finding) => finding.evidence.includes("eval(\"nope\")") || finding.evidence.includes("eval(\"hidden\")"))).toBe(false);
    expect(findings.every((finding) => finding.taxonomy.domain.length > 0)).toBe(true);
  });

  it("does not execute an eval string", () => {
    const findings = scanSource("sample.js", 'eval("throw new Error(\'executed\')")');
    expect(findings.map((finding) => finding.id)).toContain("XSS_EVAL");
  });

  it("allows a clean static page", () => {
    const html = readFileSync(join(import.meta.dirname, "../../../fixtures/clean/index.html"), "utf8");
    expect(scanSource("index.html", html)).toEqual([]);
  });

  it("drops CSP_MISSING when a live CSP header is known", () => {
    const html = readFileSync(join(vulnerable, "index.html"), "utf8");
    expect(scanSource("index.html", html, { liveCsp: true }).some((finding) => finding.id === "CSP_MISSING")).toBe(false);
  });

  it("tags the phase 1 catalog from the rule data", () => {
    const ids = new Set(ruleCatalog().map((rule) => rule.id));
    for (const id of [...PHASE1_BLOCKERS, ...PHASE1_RECOMMENDATIONS]) expect(ids.has(id), id).toBe(true);
    const sink = ruleCatalog().find((rule) => rule.id === "XSS_UNSAFE_SINK");
    expect(sink?.taxonomy.domain).toBe("application-software");
    expect(sink?.taxonomy.nistCsf.function).toBe("PR");
    expect(sink?.recommendationOnly).toBe(false);
  });
});
