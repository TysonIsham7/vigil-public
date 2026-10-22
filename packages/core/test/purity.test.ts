import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("core purity", () => {
  it("does not import node or the DOM", () => {
    const dir = join(import.meta.dirname, "../src");
    const files = readdirSync(dir).filter((name) => name.endsWith(".ts"));
    expect(files.length).toBeGreaterThan(5);
    for (const name of files) {
      const source = readFileSync(join(dir, name), "utf8");
      expect(source, name).not.toMatch(/from ["']node:/);
      expect(source, name).not.toMatch(/from ["'](?:fs|path|crypto|tls|dns)["']/);
    }
  });
});
