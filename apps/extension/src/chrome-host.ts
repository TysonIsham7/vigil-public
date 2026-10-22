import { parseNativeVerdict, type NativeResult } from "./native.js";

/** Must match the host manifest installed by `vigil install-native-host`. */
export const CHROME_NATIVE_HOST = "com.example.vigil";

export interface ChromeNativePort {
  postMessage(message: { host: string }): void;
  disconnect(): void;
  onMessage: { addListener(handler: (message: unknown) => void): void };
  onDisconnect: { addListener(handler: () => void): void };
}

export interface ChromeNativeRuntime {
  connectNative?(hostName: string): ChromeNativePort;
  sendNativeMessage?(hostName: string, message: { host: string }): Promise<unknown>;
  /** Set by Chrome on the runtime while a port disconnect listener runs. */
  lastError?: { message?: string } | null;
}

/**
 * A missing or forbidden host may fall through to the loopback helper.
 * Any other disconnect, including a host that exited, stays fail-closed.
 */
export function nativeDisconnectStatus(message: string | undefined): "unavailable" | "disconnected" {
  if (message && /not found|forbidden/i.test(message)) return "unavailable";
  return "disconnected";
}

export function chromeNativeMessage(host: string): { host: string } | null {
  if (host.length === 0 || host.length > 253 || /[/\\@\s?#]/.test(host)) return null;
  return { host };
}

/**
 * Chrome's native host is the stdio helper. Safari is recognized by its explicit loopback
 * host permission and keeps the containing-app certificate check instead.
 */
export function chromeNativeEnabled(
  manifest: { permissions?: readonly string[]; host_permissions?: readonly string[] } | undefined,
  runtime: { connectNative?: unknown; sendNativeMessage?: unknown } | undefined,
): boolean {
  if (manifest?.host_permissions?.includes("http://127.0.0.1/*")) return false;
  if (manifest?.permissions?.includes("nativeMessaging") !== true) return false;
  return typeof runtime?.connectNative === "function" || typeof runtime?.sendNativeMessage === "function";
}

export async function requestChromeNativeVerdict(input: {
  host: string;
  runtime: ChromeNativeRuntime | undefined;
  timeoutMs: number;
}): Promise<NativeResult> {
  if (!input.runtime) return { status: "unavailable" };
  if (input.timeoutMs <= 0) return { status: "timeout" };
  const message = chromeNativeMessage(input.host);
  if (!message) return { status: "unavailable" };
  if (input.runtime.connectNative) {
    try {
      const port = input.runtime.connectNative(CHROME_NATIVE_HOST);
      return await requestOnPort(port, message, input.host, input.timeoutMs, () => input.runtime?.lastError?.message);
    } catch {
      return { status: "unavailable" };
    }
  }
  const send = input.runtime.sendNativeMessage;
  if (!send) return { status: "unavailable" };
  return requestBySend(send, message, input.host, input.timeoutMs);
}

function classify(host: string, response: unknown): NativeResult {
  if (response && typeof response === "object" && "error" in response) {
    return (response as { error?: unknown }).error === "timeout" ? { status: "timeout" } : { status: "unavailable" };
  }
  const parsed = parseNativeVerdict(host, response);
  if (!parsed) return { status: "unavailable" };
  return { status: "ok", signals: parsed.signals };
}

function requestOnPort(
  port: ChromeNativePort,
  message: { host: string },
  host: string,
  timeoutMs: number,
  readError: () => string | undefined,
): Promise<NativeResult> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (result: NativeResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        port.disconnect();
      } catch {
        /* The port may already be closed. */
      }
      resolve(result);
    };
    const timer = setTimeout(() => finish({ status: "timeout" }), timeoutMs);
    port.onMessage.addListener((response) => finish(classify(host, response)));
    port.onDisconnect.addListener(() => finish({ status: nativeDisconnectStatus(readError()) }));
    try {
      port.postMessage(message);
    } catch {
      finish({ status: "disconnected" });
    }
  });
}

async function requestBySend(
  send: (hostName: string, message: { host: string }) => Promise<unknown>,
  message: { host: string },
  host: string,
  timeoutMs: number,
): Promise<NativeResult> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const response = await Promise.race([
      send(CHROME_NATIVE_HOST, message),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(Object.assign(new Error("timeout"), { name: "AbortError" })), timeoutMs);
      }),
    ]);
    return classify(host, response);
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    if (name === "AbortError" || name === "TimeoutError") return { status: "timeout" };
    return { status: nativeDisconnectStatus(error instanceof Error ? error.message : undefined) };
  } finally {
    if (timer) clearTimeout(timer);
  }
}
