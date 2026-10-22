import { REPORT_TTL_MS, type LightweightReport, type Report } from "./types.js";
import { toLightweight } from "./report.js";

/**
 * In-process stand-in for the 15-minute report retention rule.
 * The full report is dropped when the clock passes `expiresAt`. A saved
 * lightweight list can outlive it and never includes evidence or source.
 */
export class EphemeralReports {
  private readonly full = new Map<string, { report: Report; expiresAtMs: number }>();
  private readonly saved = new Map<string, LightweightReport>();

  constructor(
    private readonly ttlMs = REPORT_TTL_MS,
    private readonly now = () => Date.now(),
  ) {}

  put(report: Report): void {
    this.full.set(report.id, { report, expiresAtMs: this.now() + this.ttlMs });
  }

  get(id: string): Report | undefined {
    const row = this.full.get(id);
    if (!row) return undefined;
    if (this.now() >= row.expiresAtMs) {
      this.full.delete(id);
      return undefined;
    }
    return row.report;
  }

  saveLightweight(report: Report): LightweightReport {
    const light = toLightweight(report);
    this.saved.set(report.id, light);
    return light;
  }

  getSaved(id: string): LightweightReport | undefined {
    return this.saved.get(id);
  }
}
