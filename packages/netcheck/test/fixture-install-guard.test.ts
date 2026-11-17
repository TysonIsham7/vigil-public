import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { fixtureInstallsInFile, fixtureRequirementInstalls, scanFixtureInstalls } from "../../../scripts/fixture-install-guard.mjs";

const root = join(import.meta.dirname, "../../..");

function line(...parts: string[]): string {
  return parts.join(" ");
}

describe("fixture requirement install guard", () => {
  it("flags an installer pointed at the fixture requirements file", () => {
    const req = ["fixtures", "deps", "requirements.txt"].join("/");
    expect(fixtureRequirementInstalls(line("pip", "install", "-r", req))).not.toEqual([]);
    expect(fixtureRequirementInstalls(line("python3", "-m", "pip", "install", "--requirement", req))).not.toEqual([]);
    expect(fixtureRequirementInstalls(line("uv", "pip", "install", "-r", `./${req}`))).not.toEqual([]);
    expect(fixtureRequirementInstalls(`${line("pip", "install", "-r")} \\\n ${req}\n`)).not.toEqual([]);
    const pin = ["litellm", "==", "1.107.0"].join("");
    expect(fixtureRequirementInstalls(line("pip", "install", pin))).not.toEqual([]);
    const other = ["requests", "==", "2.32.3"].join("");
    expect(fixtureRequirementInstalls(line("pip", "install", other))).not.toEqual([]);
  });

  it("flags a directory change into fixtures followed by an installer", () => {
    const move = line("cd", "fixtures/deps");
    const install = line("pip", "install", "-r", "requirements.txt");
    expect(fixtureRequirementInstalls(`${move}\n${install}\n`)).not.toEqual([]);
    const workdir = line("WORKDIR", "fixtures/deps");
    const run = line("RUN", "pip", "install", "-r", "requirements.txt");
    expect(fixtureRequirementInstalls(`${workdir}\n${run}\n`)).not.toEqual([]);
    const step = line("working-directory:", "fixtures/deps");
    const action = line("run:", "pip", "install", "-r", "requirements.txt");
    expect(fixtureRequirementInstalls(`${step}\n${action}\n`)).not.toEqual([]);
  });

  it("leaves detection samples and ordinary installs alone", () => {
    expect(fixtureRequirementInstalls("FROM ghcr.io/berriai/litellm:1.107.0\n")).toEqual([]);
    expect(fixtureRequirementInstalls("litellm==1.107.0\nrequests==2.32.3\n")).toEqual([]);
    expect(fixtureRequirementInstalls("pnpm install --frozen-lockfile\n")).toEqual([]);
    expect(fixtureRequirementInstalls(line("pip", "install", "-r", "requirements.txt"))).toEqual([]);
    const note = readFileSync(join(root, "fixtures/README.md"), "utf8");
    expect(note).toMatch(/MAL-2026-2144/);
    expect(note).toMatch(/deps\/requirements\.txt/);
    expect(fixtureRequirementInstalls(note)).toEqual([]);
    expect(readFileSync(join(root, "fixtures/deps/requirements.txt"), "utf8")).toBe("litellm==1.107.0\nrequests==2.32.3\n");
  });

  it("flags an installer inside the fixture tree and a clean checkout", () => {
    const rel = ["fixtures", "deps", "Dockerfile"].join("/");
    const run = line("RUN", "pip", "install", "-r", "requirements.txt");
    expect(fixtureInstallsInFile(rel, `${run}\n`)).not.toEqual([]);
    expect(fixtureInstallsInFile(rel, "FROM ghcr.io/berriai/litellm:1.107.0\n")).toEqual([]);
    expect(scanFixtureInstalls(root)).toEqual([]);
  });

  it("keeps the guard ahead of CI installs", () => {
    const ci = readFileSync(join(root, ".github/workflows/ci.yml"), "utf8");
    expect(ci.split("scripts/fixture-install-guard.mjs").length - 1).toBe(ci.split("actions/checkout@").length - 1);
    const checkJob = ci.slice(0, ci.indexOf("ios-swift:"));
    expect(checkJob.indexOf("scripts/fixture-install-guard.mjs")).toBeGreaterThan(-1);
    expect(checkJob.indexOf("scripts/fixture-install-guard.mjs")).toBeLessThan(checkJob.indexOf("pnpm install --frozen-lockfile"));
  });
});
