export type ExtensionPage = "popup" | "hold" | "other";

/** Popup settings and hold-page overrides must come from those extension pages. */
export function extensionMessagePage(url: string | undefined): ExtensionPage {
  if (!url) return "other";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "other";
  }
  if (parsed.protocol !== "chrome-extension:" && parsed.protocol !== "safari-web-extension:") return "other";
  const path = parsed.pathname.replace(/^\//, "");
  if (path === "popup.html") return "popup";
  if (path === "hold.html") return "hold";
  return "other";
}
