/** Local classifier for shell and Run-dialog commands a page may write to the clipboard. */

export const CLICKFIX_KINDS = [
  "powershell",
  "mshta",
  "cmd",
  "base64-shell",
  "pipe-shell",
  "certutil",
  "bitsadmin",
  "rundll32",
  "regsvr32",
  "msiexec",
  "script-host",
  "base64-blob",
] as const;

export type ClickFixKind = (typeof CLICKFIX_KINDS)[number];

export interface ClickFixResult {
  risky: boolean;
  kind: ClickFixKind | null;
}

const RULES: readonly { kind: ClickFixKind; pattern: RegExp }[] = [
  { kind: "powershell", pattern: /\b(?:powershell|pwsh|conhost)(?:\.exe)?\b[^\n]{0,400}(?:-nop(?:rofile)?\b|-w(?:indowstyle)?\s+hidden\b|-c(?:ommand)?\b|-e(?:nc|ncodedcommand)?\b|\biex\b|\biwr\b|invoke-expression|invoke-webrequest|downloadstring|frombase64string|executionpolicy\s+bypass)/i },
  { kind: "powershell", pattern: /\b(?:iex|invoke-expression)\s*\(/i },
  { kind: "mshta", pattern: /\bmshta(?:\.exe)?\b[^\n]{0,160}(?:https?:|vbscript:|javascript:|\.hta\b)/i },
  { kind: "cmd", pattern: /\bcmd(?:\.exe)?\s+\/[cCkK]\b/i },
  { kind: "base64-shell", pattern: /\bbase64\b[^\n|]{0,40}(?:-d|--decode)\b[^\n]{0,120}\|\s*(?:sh|bash|zsh|dash|ksh|pwsh|powershell)(?:\.exe)?\b/i },
  { kind: "pipe-shell", pattern: /\|\s*(?:sh|bash|zsh|dash|ksh|pwsh|powershell)(?:\.exe)?\b/i },
  { kind: "pipe-shell", pattern: /\b(?:bash|sh|zsh|dash)\s+-c\b/i },
  { kind: "certutil", pattern: /\bcertutil(?:\.exe)?\b[^\n]{0,160}-(?:urlcache|decode|decodehex|encode)\b/i },
  { kind: "bitsadmin", pattern: /\bbitsadmin(?:\.exe)?\b[^\n]{0,80}\/transfer\b/i },
  { kind: "rundll32", pattern: /\brundll32(?:\.exe)?\b[^\n]{0,160}(?:javascript:|https?:|shell32\.dll)/i },
  { kind: "regsvr32", pattern: /\bregsvr32(?:\.exe)?\b[^\n]{0,160}(?:scrobj\.dll|\/i:https?:)/i },
  { kind: "msiexec", pattern: /\bmsiexec(?:\.exe)?\b[^\n]{0,80}\/i\s+https?:/i },
  { kind: "script-host", pattern: /\b(?:wscript|cscript)(?:\.exe)?\b[^\n]{0,120}(?:https?:|\.js\b|\/\/e:jscript)/i },
];

const KIND_TEXT: Record<ClickFixKind, string> = {
  powershell: "a PowerShell command",
  mshta: "an mshta command",
  cmd: "a Windows command",
  "base64-shell": "a base64 blob piped into a shell",
  "pipe-shell": "a command piped into a shell",
  certutil: "a certutil command",
  bitsadmin: "a bitsadmin download",
  rundll32: "a rundll32 command",
  regsvr32: "a regsvr32 command",
  msiexec: "an msiexec install from a URL",
  "script-host": "a Windows script host command",
  "base64-blob": "a base64 blob that decodes to a shell command",
};

export function classifyClickFix(input: string): ClickFixResult {
  return classifySample(input, true);
}

export function clickFixCopy(kind: ClickFixKind): { title: string; body: string } {
  return {
    title: "Clipboard command held",
    body: `This page tried to copy ${KIND_TEXT[kind]}. Pasting it into a terminal or the Run dialog can run it on this computer. Vigil did not keep a copy.`,
  };
}

function classifySample(input: string, decode: boolean): ClickFixResult {
  const sample = input.length > 16000 ? input.slice(0, 16000) : input;
  for (const rule of RULES) {
    if (rule.pattern.test(sample)) return { risky: true, kind: rule.kind };
  }
  if (!decode) return { risky: false, kind: null };
  const decoded = decodeCommand(sample);
  if (!decoded) return { risky: false, kind: null };
  const inner = classifySample(decoded, false);
  if (!inner.risky) return { risky: false, kind: null };
  return { risky: true, kind: "base64-blob" };
}

function decodeCommand(input: string): string | null {
  const compact = input.replace(/\s+/g, "");
  if (compact.length < 32 || compact.length > 16000 || compact.length % 4 !== 0) return null;
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(compact)) return null;
  const bytes = decodeBase64(compact);
  if (!bytes || bytes.length < 8) return null;
  const text = bytesToText(bytes);
  bytes.fill(0);
  return text;
}

function decodeBase64(input: string): Uint8Array | null {
  const table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const pad = input.endsWith("==") ? 2 : input.endsWith("=") ? 1 : 0;
  const out = new Uint8Array((input.length / 4) * 3 - pad);
  let at = 0;
  for (let i = 0; i < input.length; i += 4) {
    const a = table.indexOf(input[i] ?? "");
    const b = table.indexOf(input[i + 1] ?? "");
    const c = input[i + 2] === "=" ? 0 : table.indexOf(input[i + 2] ?? "");
    const d = input[i + 3] === "=" ? 0 : table.indexOf(input[i + 3] ?? "");
    if (a < 0 || b < 0 || c < 0 || d < 0) return null;
    const value = (a << 18) | (b << 12) | (c << 6) | d;
    if (at < out.length) out[at] = (value >> 16) & 255;
    at += 1;
    if (at < out.length) out[at] = (value >> 8) & 255;
    at += 1;
    if (at < out.length) out[at] = value & 255;
    at += 1;
  }
  return out;
}

function bytesToText(bytes: Uint8Array): string {
  let zeros = 0;
  for (const byte of bytes) if (byte === 0) zeros += 1;
  const utf16 = bytes.length >= 4 && zeros * 2 >= bytes.length;
  let text = "";
  if (utf16) {
    for (let i = 0; i + 1 < bytes.length; i += 2) {
      const code = (bytes[i] ?? 0) | ((bytes[i + 1] ?? 0) << 8);
      if (code !== 0) text += String.fromCharCode(code);
    }
    return text;
  }
  for (const byte of bytes) text += String.fromCharCode(byte);
  return text;
}
