export const PHP_EXPOSURE_ID = "PHP2SHELL_EXPOSURE";

export interface GuardSettings {
  phpExposure: boolean;
  clickfix: boolean;
  seedPhrase: boolean;
  wallet: boolean;
}

export const DEFAULT_GUARDS: GuardSettings = {
  phpExposure: true,
  clickfix: true,
  seedPhrase: true,
  wallet: true,
};

export function readGuards(value: unknown, base: GuardSettings = DEFAULT_GUARDS): GuardSettings {
  const record = value && typeof value === "object" ? value as Record<string, unknown> : {};
  return {
    phpExposure: bool(record.phpExposure, base.phpExposure),
    clickfix: bool(record.clickfix, base.clickfix),
    seedPhrase: bool(record.seedPhrase, base.seedPhrase),
    wallet: bool(record.wallet, base.wallet),
  };
}

export function omitPhpExposure<T extends { id: string }>(signals: readonly T[], include: boolean): T[] {
  if (include) return [...signals];
  return signals.filter((signal) => signal.id !== PHP_EXPOSURE_ID);
}

function bool(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}
