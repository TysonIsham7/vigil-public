import { chmodSync, existsSync, mkdirSync, renameSync, rmSync, statSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";
import { assertPrivateMode } from "./identity.js";
import { DEFAULT_ROTATE_BYTES } from "./policy.js";

export interface LogEntry {
  time: string;
  decision: "allow" | "block" | "strip" | "tunnel";
  host: string;
  kind: string;
  policy: "allow" | "strip" | "block";
}

export class DecisionLog {
  constructor(
    private readonly path: string,
    private readonly rotateAt = DEFAULT_ROTATE_BYTES,
  ) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    if (existsSync(path)) assertPrivateMode(path, statSync(path).mode, "decision log");
  }

  write(entry: LogEntry): void {
    const line = `${entry.time}\t${entry.decision}\t${entry.host}\t${entry.kind || "-"}\t${entry.policy}\n`;
    this.rotate(Buffer.byteLength(line));
    appendFileSync(this.path, line, { mode: 0o600 });
    chmodSync(this.path, 0o600);
  }

  private rotate(incoming: number): void {
    if (!existsSync(this.path)) return;
    if (statSync(this.path).size + incoming <= this.rotateAt) return;
    const older = `${this.path}.2`;
    const mid = `${this.path}.1`;
    if (existsSync(older)) rmSync(older);
    if (existsSync(mid)) renameSync(mid, older);
    renameSync(this.path, mid);
  }
}
