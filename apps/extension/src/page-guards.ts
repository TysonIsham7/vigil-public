import { pageMatches } from "./blank-guard.js";
import type { GuardSettings } from "./guard-settings.js";

export const GUARD_SCRIPT_IDS = ["vigil-clickfix-guard", "vigil-seed-guard", "vigil-wallet-guard"] as const;

const FILES = {
  clickfix: { id: "vigil-clickfix-guard", file: "clickfix-guard.js" },
  seedPhrase: { id: "vigil-seed-guard", file: "seed-guard.js" },
  wallet: { id: "vigil-wallet-guard", file: "wallet-guard.js" },
} as const;

export interface GuardRegistration {
  id: string;
  js: [string];
  matches: string[];
  runAt: "document_start";
  world: "MAIN";
  allFrames: true;
  persistAcrossSessions: true;
}

/**
 * Main-world hooks for the guards that are on. PHP classification does not inject a script.
 * Turning a guard off unregisters it for documents opened later. A page that already ran the hook keeps that hook until it reloads.
 */
export function enabledGuardScripts(settings: GuardSettings): GuardRegistration[] {
  const keys = ["clickfix", "seedPhrase", "wallet"] as const;
  return keys.flatMap((key) => {
    if (!settings[key]) return [];
    const item = FILES[key];
    return [{
      id: item.id,
      js: [item.file] as [string],
      matches: pageMatches(),
      runAt: "document_start" as const,
      world: "MAIN" as const,
      allFrames: true as const,
      persistAcrossSessions: true as const,
    }];
  });
}
