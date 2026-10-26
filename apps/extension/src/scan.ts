import {
  NAV_HARD_TIMEOUT_MS,
  helperInstallToken,
  loopbackHelperOrigin,
  planAfter,
  type GateSignal,
  type NavDecision,
  type SecurityMode,
} from "@vigil/core";
import { assessSite } from "@vigil/intel/lookalike";
import { INTEL_VERSION } from "@vigil/intel/version";
import { omitPhpExposure } from "./guard-settings.js";
import { requestChromeNativeVerdict, type ChromeNativeRuntime } from "./chrome-host.js";
import { NATIVE_ATTEMPT_MS, isGateSignal, requestNativeVerdict, type NativeRuntime } from "./native.js";

export function localSignals(host: string): GateSignal[] {
  return assessSite({ host, html: "" }).signals.map((signal) => ({
    id: signal.id,
    severity: signal.severity,
    recommendationOnly: signal.recommendationOnly,
    title: signal.title,
    summary: signal.summary,
    confidence: signal.severity === "critical" ? "high" as const : "medium" as const,
  }));
}

/**
 * A configured helper that failed with a network error is down. A timeout still
 * means High Security must fail closed, so the helper stays in use.
 */
export function helperReachable(input: { configured: boolean; coverage: "local" | "full" | null; timedOut: boolean }): boolean {
  if (!input.configured) return false;
  if (input.timedOut) return true;
  return input.coverage !== "local";
}

export async function runHoldScan(input: {
  host: string;
  mode: SecurityMode;
  helperOrigin: string | null;
  helperToken?: string | null;
  now: number;
  startedAt?: number;
  fetchImpl?: typeof fetch;
  hardTimeoutMs?: number;
  nativeRuntime?: NativeRuntime;
  chromeNative?: ChromeNativeRuntime;
  includePhpExposure?: boolean;
}): Promise<NavDecision> {
  const seen = (signals: GateSignal[]) => omitPhpExposure(signals, input.includePhpExposure !== false);
  const local = localSignals(input.host);
  const origin = input.helperOrigin ? loopbackHelperOrigin(input.helperOrigin) : null;
  const token = input.helperToken ? helperInstallToken(input.helperToken) : null;
  const base = {
    mode: input.mode,
    host: input.host,
    now: input.now,
    intelVersion: INTEL_VERSION,
  };
  const hardTimeoutMs = input.hardTimeoutMs ?? NAV_HARD_TIMEOUT_MS;
  const started = input.startedAt ?? Date.now();
  const remaining = () => hardTimeoutMs - (Date.now() - started);
  if (remaining() <= 0) {
    return planAfter({ ...base, signals: seen(local), timedOut: true, coverage: "full" });
  }
  let nativeStatus: "unavailable" | "timeout" = "unavailable";
  if (input.chromeNative) {
    const chrome = await requestChromeNativeVerdict({
      host: input.host,
      runtime: input.chromeNative,
      timeoutMs: Math.max(0, remaining()),
    });
    if (chrome.status === "ok") {
      return planAfter({ ...base, signals: seen(merge(chrome.signals, local)), timedOut: false, coverage: "full" });
    }
    if (chrome.status === "disconnected") return helperDisconnected(input.mode, local);
    nativeStatus = chrome.status;
  }
  if (input.nativeRuntime && remaining() > 0 && nativeStatus !== "timeout") {
    const nativeBudget = origin ? Math.min(NATIVE_ATTEMPT_MS, Math.max(0, remaining())) : Math.max(0, remaining());
    const native = await requestNativeVerdict({
      host: input.host,
      runtime: input.nativeRuntime,
      timeoutMs: nativeBudget,
    });
    if (native.status === "ok") {
      return planAfter({ ...base, signals: seen(merge(native.signals, local)), timedOut: false, coverage: "full" });
    }
    if (native.status === "timeout") nativeStatus = "timeout";
  }
  const left = remaining();
  if (left <= 0 || (nativeStatus === "timeout" && !origin)) {
    return planAfter({ ...base, signals: seen(local), timedOut: true, coverage: "full" });
  }
  if (!origin) {
    return planAfter({ ...base, signals: seen(local), timedOut: false, coverage: "local" });
  }
  if (!token) {
    return { ...planAfter({ ...base, signals: seen(local), timedOut: true, coverage: "full" }), helper: "up" };
  }
  return helperVerdict({
    base,
    origin,
    local,
    token,
    timeoutMs: left,
    includePhpExposure: input.includePhpExposure !== false,
    ...(input.fetchImpl ? { fetchImpl: input.fetchImpl } : {}),
  });
}

function helperDisconnected(mode: SecurityMode, local: GateSignal[]): NavDecision {
  const popup: GateSignal[] = [
    {
      id: "HELPER_UNAVAILABLE",
      severity: "high",
      recommendationOnly: true,
      title: "Helper unavailable",
      summary: "The native helper disconnected before the check finished, so this page stays held.",
      confidence: "high",
    },
    ...local,
  ];
  if (mode !== "high") {
    return { intercept: false, action: "warn", badge: "unknown", reason: "unavailable", gating: [], popup };
  }
  return { intercept: true, action: "hold", badge: "unknown", reason: "unavailable", gating: [], popup };
}

function holdOnHelper(base: { mode: SecurityMode; host: string; now: number; intelVersion: string }, local: GateSignal[], helper: "up" | "down"): NavDecision {
  return { ...planAfter({ ...base, signals: local, timedOut: true, coverage: "full" }), helper };
}

async function helperVerdict(input: {
  base: { mode: SecurityMode; host: string; now: number; intelVersion: string };
  origin: string;
  local: GateSignal[];
  token: string;
  timeoutMs: number;
  includePhpExposure: boolean;
  fetchImpl?: typeof fetch;
}): Promise<NavDecision> {
  const controller = new AbortController();
  const fetchImpl = input.fetchImpl ?? fetch;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new DOMException("The operation was aborted.", "AbortError"));
    }, input.timeoutMs);
  });
  try {
    const response = await Promise.race([
      fetchImpl(
        `${input.origin}/api/v1/verdict?host=${encodeURIComponent(input.base.host)}`,
        {
          signal: controller.signal,
          redirect: "error",
          headers: { "x-vigil-token": input.token },
          cache: "no-store",
        } as RequestInit & { cache: "no-store" },
      ),
      deadline,
    ]);
    if (response.status !== 200) return holdOnHelper(input.base, input.local, "up");
    const body = await response.json() as { host?: unknown; signals?: unknown };
    if (body.host !== input.base.host || !Array.isArray(body.signals)) return holdOnHelper(input.base, input.local, "up");
    const remote = body.signals.filter(isGateSignal);
    return { ...planAfter({ ...input.base, signals: omitPhpExposure(merge(remote, input.local), input.includePhpExposure), timedOut: false, coverage: "full" }), helper: "up" };
  } catch (error) {
    const name = error instanceof Error ? error.name : "";
    const timedOut = name === "AbortError" || name === "TimeoutError";
    return holdOnHelper(input.base, input.local, timedOut ? "up" : "down");
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function merge(remote: GateSignal[], local: GateSignal[]): GateSignal[] {
  const seen = new Set<string>();
  const out: GateSignal[] = [];
  for (const signal of [...remote, ...local]) {
    if (seen.has(signal.id)) continue;
    seen.add(signal.id);
    out.push(signal);
  }
  return out;
}
