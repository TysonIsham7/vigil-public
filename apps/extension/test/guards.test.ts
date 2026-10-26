import { describe, expect, it } from "vitest";
import { DEFAULT_GUARDS, omitPhpExposure, readGuards } from "../src/guard-settings.js";
import { enabledGuardScripts } from "../src/page-guards.js";

describe("page guard settings", () => {
  it("defaults every guard on and ignores non-booleans", () => {
    expect(readGuards(undefined)).toEqual(DEFAULT_GUARDS);
    expect(readGuards({ clickfix: false, seedPhrase: "no", wallet: true }, DEFAULT_GUARDS)).toEqual({
      phpExposure: true,
      clickfix: false,
      seedPhrase: true,
      wallet: true,
    });
  });

  it("drops the PHP class only when that guard is off", () => {
    const signals = [{ id: "PHP2SHELL_EXPOSURE" }, { id: "HEADER_CSP" }];
    expect(omitPhpExposure(signals, true)).toEqual(signals);
    expect(omitPhpExposure(signals, false).map((signal) => signal.id)).toEqual(["HEADER_CSP"]);
  });

  it("registers a main-world script only for an enabled page guard", () => {
    const all = enabledGuardScripts(DEFAULT_GUARDS);
    expect(all.map((script) => script.js[0])).toEqual(["clickfix-guard.js", "seed-guard.js", "wallet-guard.js"]);
    expect(all.every((script) => script.world === "MAIN" && script.runAt === "document_start")).toBe(true);
    expect(enabledGuardScripts({ ...DEFAULT_GUARDS, clickfix: false, wallet: false }).map((script) => script.id)).toEqual(["vigil-seed-guard"]);
    expect(enabledGuardScripts({ ...DEFAULT_GUARDS, phpExposure: false })).toHaveLength(3);
  });
});