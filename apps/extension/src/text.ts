const BIDI_AND_INVISIBLE = /[\u202A-\u202E\u2066-\u2069\u200B-\u200F\uFEFF]/g;

/** Hold and popup text. Bidirectional overrides and non-ASCII are dropped so a signal cannot spoof the destination. */
/** Status line on the hold page. A dead helper and a sealed blank window must not look like a certificate failure. */
export function holdStatusText(input: { reason?: string; ids?: readonly string[] }): string {
  const ids = new Set(input.ids ?? []);
  if (input.reason === "unavailable" || ids.has("HELPER_UNAVAILABLE")) {
    return "helper unavailable. The native helper disconnected, so this page stays held.";
  }
  if (ids.has("BLANK_WINDOW")) {
    return "This blank window was held before script could run.";
  }
  if (input.reason === "timeout") {
    return "High Security did not finish within 2 seconds, so this page stays held.";
  }
  return "The check found a certificate, phishing, or advisory signal. Missing headers are not why this page is held.";
}

export function safeSignalText(value: string, max = 160): string {
  const cleaned = value.replace(BIDI_AND_INVISIBLE, "").replace(/[^\t\n\r\x20-\x7E]/g, "");
  const flat = cleaned.replace(/\s+/g, " ").trim();
  if (flat.length <= max) return flat;
  return `${flat.slice(0, Math.max(0, max - 1))}…`;
}
