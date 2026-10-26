import { classifyWalletRequest, walletGuardCopy } from "@vigil/core/wallet-request";
import { chooseGuard, claimGuard } from "./guard-panel.js";

/**
 * Wraps EIP-1193 request on a provider that actually exists.
 * Spenders remembered here stay in this document only. A page cannot write the set.
 */
export function installWalletGuard(scope: Window): void {
  if (!claimGuard(scope, "vigilWallet")) return;
  const wrapped = new WeakSet<object>();
  const allowed = new Set<string>();
  const arm = (provider: unknown) => {
    if (!provider || typeof provider !== "object") return;
    if (wrapped.has(provider)) return;
    const target = provider as { request?: (args: unknown) => Promise<unknown> };
    const current = target.request;
    if (typeof current !== "function") return;
    const orig = current.bind(target);
    const wrappedRequest = (args: unknown) => {
      const risk = classifyWalletRequest(args, [...allowed]);
      if (!risk.risky) return orig(args);
      const copy = walletGuardCopy(risk);
      return chooseGuard({
        title: copy.title,
        body: copy.body,
        allowLabel: "Continue",
        blockLabel: "Reject",
        ...(copy.rememberLabel ? { rememberLabel: copy.rememberLabel } : {}),
      }).then((choice) => {
        if (!choice.ok) return Promise.reject(rejected());
        if (choice.remember && risk.spender) allowed.add(risk.spender);
        return orig(args);
      });
    };
    try {
      target.request = wrappedRequest;
    } catch {
      return;
    }
    if (target.request !== wrappedRequest) return;
    wrapped.add(provider);
  };

  const ethereum = () => (scope as { ethereum?: unknown }).ethereum;
  arm(ethereum());
  const timer = scope.setInterval(() => arm(ethereum()), 500);
  scope.setTimeout(() => scope.clearInterval(timer), 8000);
  scope.addEventListener("eip6963:announceProvider", (event: Event) => {
    const detail = (event as CustomEvent<{ provider?: unknown }>).detail;
    if (detail) arm(detail.provider);
  });
  try {
    scope.dispatchEvent(new Event("eip6963:requestProvider"));
  } catch {
    /* A provider can still appear on the short poll. */
  }
}

function rejected(): Error {
  const error = new Error("Vigil rejected the wallet request");
  (error as { code?: number }).code = 4001;
  return error;
}
