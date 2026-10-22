import { registrableDomain } from "@vigil/intel";
import { safeFetch, type AddressLookup } from "./fetch.js";

export interface RdapBootstrap {
  services: [string[], string[]][];
}

const BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json";

export function selectRdapServer(domain: string, bootstrap: RdapBootstrap): string | undefined {
  let best: { length: number; base: string } | undefined;
  for (const [zones, urls] of bootstrap.services) {
    for (const zone of zones) {
      const normalized = zone.toLowerCase().replace(/^\.+/, "");
      if (domain !== normalized && !domain.endsWith(`.${normalized}`)) continue;
      const base = urls[0];
      if (base && (!best || normalized.length > best.length)) best = { length: normalized.length, base };
    }
  }
  return best?.base;
}

export function registrationDate(document: unknown): string | undefined {
  if (!document || typeof document !== "object") return undefined;
  const events = (document as { events?: { eventAction?: string; eventDate?: string }[] }).events ?? [];
  return events.find((event) => event.eventAction === "registration" && event.eventDate)?.eventDate;
}

export function ageInDays(registeredAt: string, now: Date): number | null {
  const time = Date.parse(registeredAt);
  if (Number.isNaN(time)) return null;
  return Math.floor((now.getTime() - time) / 86_400_000);
}

export async function lookupDomainAge(
  host: string,
  options: { fetchImpl?: typeof fetch; lookup?: AddressLookup; now?: Date; bootstrapUrl?: string; signal?: AbortSignal } = {},
): Promise<{ ageDays: number | null; registeredAt?: string; error?: string }> {
  const now = options.now ?? new Date();
  const domain = registrableDomain(host.toLowerCase());
  const shared = {
    ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.lookup ? { lookup: options.lookup } : {}),
    ...(options.signal ? { signal: options.signal } : {}),
    timeoutMs: 5_000,
  };
  try {
    const bootstrap = await safeFetch(options.bootstrapUrl ?? BOOTSTRAP_URL, shared);
    if (bootstrap.status < 200 || bootstrap.status >= 300) throw new Error("RDAP bootstrap failed");
    const document = JSON.parse(bootstrap.body) as RdapBootstrap;
    const base = selectRdapServer(domain, document);
    if (!base) throw new Error("No RDAP server for this domain");
    const root = base.endsWith("/") ? base : `${base}/`;
    const query = new URL(`domain/${encodeURIComponent(domain)}`, root).toString();
    const response = await safeFetch(query, shared);
    if (response.status < 200 || response.status >= 300) throw new Error(`RDAP status ${response.status}`);
    const registeredAt = registrationDate(JSON.parse(response.body));
    if (!registeredAt) throw new Error("RDAP response has no registration date");
    const ageDays = ageInDays(registeredAt, now);
    return ageDays === null ? { ageDays: null, registeredAt, error: "RDAP registration date is not valid" } : { ageDays, registeredAt };
  } catch (error) {
    return { ageDays: null, error: error instanceof Error ? error.message : "RDAP lookup failed" };
  }
}

export async function crtShEarliest(
  registrable: string,
  fetchImpl: typeof fetch,
): Promise<{ earliest?: string; error?: string }> {
  try {
    const response = await fetchImpl(`https://crt.sh/?q=${encodeURIComponent(registrable)}&output=json`);
    if (!response.ok) throw new Error(`crt.sh status ${response.status}`);
    const rows = (await response.json()) as { not_before?: string }[];
    const times = rows.map((row) => Date.parse(row.not_before ?? "")).filter((time) => !Number.isNaN(time));
    if (times.length === 0) return {};
    return { earliest: new Date(Math.min(...times)).toISOString() };
  } catch (error) {
    return { error: error instanceof Error ? error.message : "crt.sh failed" };
  }
}
