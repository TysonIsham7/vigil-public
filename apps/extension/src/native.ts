import type { GateSignal } from "@vigil/core";

/** Containing-app bundle ids. The native message is delivered to that app's extension handler. */
export const NATIVE_APP_MAC = "com.example.vigil.macos";
export const NATIVE_APP_IOS = "com.example.vigil.ios";

/**
 * The handler's URLSession budget is 1.6s. This wait is longer so a finished
 * native failure can still fall back to the loopback helper inside the 2s limit.
 */
export const NATIVE_ATTEMPT_MS = 1700;

export interface NativeRuntime {
  sendNativeMessage?(application: string, message: { url: string }): Promise<unknown>;
  getPlatformInfo?(): Promise<{ os?: string }>;
}

export type NativeResult =
  | { status: "ok"; signals: GateSignal[] }
  | { status: "unavailable" }
  | { status: "timeout" }
  | { status: "disconnected" };

export function nativeAppId(os: string | undefined): string {
  const name = os?.toLowerCase();
  if (name === "ios" || name === "ipados") return NATIVE_APP_IOS;
  return NATIVE_APP_MAC;
}

/** Safari's manifest lists loopback explicitly. Chrome's sendNativeMessage is a different host API. */
export function nativeMessagingEnabled(
  manifest: { host_permissions?: readonly string[] } | undefined,
  runtime: { sendNativeMessage?: unknown } | undefined,
): boolean {
  return typeof runtime?.sendNativeMessage === "function"
    && manifest?.host_permissions?.includes("http://127.0.0.1/*") === true;
}

export function nativeMessage(host: string): { url: string } | null {
  const normalized = httpsHost(host);
  if (!normalized) return null;
  const scheme = "https:";
  return { url: `${scheme}//${normalized}/` };
}

export function httpsHost(value: string): string | null {
  const host = value.toLowerCase().replace(/\.$/, "");
  if (!isDnsHost(host)) return null;
  return host;
}

export function parseNativeVerdict(host: string, value: unknown): { signals: GateSignal[] } | null {
  if (!value || typeof value !== "object") return null;
  const body = value as Record<string, unknown>;
  if ("error" in body) return null;
  if (body.host !== host || body.coverage !== "full" || typeof body.intelVersion !== "string" || body.intelVersion.length === 0) {
    return null;
  }
  if (!Array.isArray(body.signals) || body.signals.some((item) => !isGateSignal(item))) return null;
  return { signals: body.signals.filter(isGateSignal) };
}

export function isGateSignal(value: unknown): value is GateSignal {
  if (!value || typeof value !== "object") return false;
  const signal = value as Partial<GateSignal>;
  return typeof signal.id === "string"
    && typeof signal.title === "string"
    && typeof signal.summary === "string"
    && typeof signal.recommendationOnly === "boolean"
    && (signal.severity === "critical" || signal.severity === "high" || signal.severity === "medium" || signal.severity === "low" || signal.severity === "informational");
}

export async function requestNativeVerdict(input: {
  host: string;
  runtime: NativeRuntime | undefined;
  timeoutMs: number;
}): Promise<NativeResult> {
  const send = input.runtime?.sendNativeMessage;
  if (!send) return { status: "unavailable" };
  const message = nativeMessage(input.host);
  if (!message || input.timeoutMs <= 0) return input.timeoutMs <= 0 ? { status: "timeout" } : { status: "unavailable" };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const response = await Promise.race([
      (async () => {
        const os = input.runtime?.getPlatformInfo ? (await input.runtime.getPlatformInfo()).os : undefined;
        return send(nativeAppId(os), message);
      })(),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { name: "AbortError" })), input.timeoutMs);
      }),
    ]);
    const parsed = parseNativeVerdict(input.host, response);
    if (!parsed) return { status: "unavailable" };
    return { status: "ok", signals: parsed.signals };
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    if (name === "AbortError" || name === "TimeoutError") return { status: "timeout" };
    return { status: "unavailable" };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function isDnsHost(host: string): boolean {
  if (host.length === 0 || host.length > 253) return false;
  const labels = host.split(".");
  if (labels.length < 2) return false;
  if (labels.every((label) => label.length > 0 && [...label].every((char) => char >= "0" && char <= "9"))) return false;
  return labels.every((label) => {
    if (label.length === 0 || label.length > 63) return false;
    if (label.startsWith("-") || label.endsWith("-")) return false;
    return [...label].every((char) => (char >= "a" && char <= "z") || (char >= "0" && char <= "9") || char === "-");
  });
}
