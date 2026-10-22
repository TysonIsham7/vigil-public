import { readFileSync } from "node:fs";
import { join } from "node:path";
import { domainToASCII } from "node:url";
import { describe, expect, it } from "vitest";
import { assessSite, decodeHostname, registrableDomain, skeleton } from "../src/index.js";

const login = readFileSync(join(import.meta.dirname, "../../../fixtures/phishing/login.html"), "utf8");

describe("lookalikes", () => {
  it("decodes punycode and maps a cyrillic google lookalike", () => {
    const unicode = `g${"\u043e".repeat(2)}gle.com`;
    const ascii = domainToASCII(unicode);
    expect(ascii.startsWith("xn--")).toBe(true);
    expect(skeleton(decodeHostname(ascii).split(".")[0] ?? "")).toBe("google");
    const site = assessSite({ host: ascii });
    expect(site.signals.some((signal) => signal.id === "DOMAIN_LOOKALIKE" && !signal.recommendationOnly)).toBe(true);
    const apple = assessSite({ host: "www.xn--80ak6aa92e.com" });
    expect(apple.signals.some((signal) => signal.id === "DOMAIN_LOOKALIKE" && !signal.recommendationOnly)).toBe(true);
  });

  it("flags paypal.github.io, paypa1, and an allowlisted exception", () => {
    expect(registrableDomain("paypal.github.io")).toBe("paypal.github.io");
    expect(assessSite({ host: "paypal.github.io" }).lookalike?.confidence).toBe("high");
    expect(assessSite({ host: "paypa1.com" }).signals.some((signal) => signal.id === "DOMAIN_LOOKALIKE")).toBe(true);
    expect(assessSite({ host: "paypa1.com" }).level).toBe("block");
    const allowed = assessSite({ host: "paypal.github.io", allowlist: ["paypal.github.io"] });
    expect(allowed.lookalike).toBeUndefined();
  });

  it("blocks a new domain with a login and warns a domain younger than 30 days", () => {
    const fresh = assessSite({ host: "brand-new.example", ageDays: 3, html: login, pageUrl: "https://brand-new.example/login" });
    expect(fresh.signals.some((signal) => signal.id === "DOMAIN_NEW_LOGIN" && !signal.recommendationOnly)).toBe(true);
    const month = assessSite({ host: "brand-new.example", ageDays: 12 });
    expect(month.signals.some((signal) => signal.id === "DOMAIN_NEW")).toBe(true);
    expect(assessSite({ host: "brand-new.example", ageDays: 40 }).signals.some((signal) => signal.id.startsWith("DOMAIN_NEW"))).toBe(false);
  });

  it("treats brand text plus a credential form as impersonation", () => {
    const site = assessSite({ host: "accounts-secure.example", html: login, pageUrl: "https://accounts-secure.example/" });
    expect(site.brandImpersonation).toEqual({ brand: "paypal", withCredential: true });
    expect(site.credentialCrossOrigin).toBe(true);
    expect(site.signals.some((signal) => signal.id === "DOMAIN_BRAND_IMPERSONATION" && !signal.recommendationOnly)).toBe(true);
    expect(site.signals.some((signal) => signal.id === "DOMAIN_CREDENTIAL_CROSS_ORIGIN")).toBe(true);
  });

  it("flags mixed script, suspicious tlds, free hosting, depth, and IP logins", () => {
    expect(assessSite({ host: `pay${"\u0440"}al.com` }).mixedScript).toBe(true);
    expect(assessSite({ host: "example.xyz" }).suspiciousTld).toBe(true);
    expect(assessSite({ host: "demo.pages.dev" }).signals.some((signal) => signal.id === "DOMAIN_FREE_HOSTING")).toBe(true);
    expect(assessSite({ host: "a.b.c.example.com" }).subdomainDepth).toBe(3);
    const ip = assessSite({
      host: "203.0.113.10",
      html: `<form><input type="password"></form>`,
      pageUrl: "http://203.0.113.10/",
    });
    expect(ip.signals.some((signal) => signal.id === "DOMAIN_IP_LOGIN")).toBe(true);
    expect(ip.signals.some((signal) => signal.id === "DOMAIN_CREDENTIAL_HTTP")).toBe(true);
  });
});
