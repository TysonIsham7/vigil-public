import { describe, expect, it } from "vitest";
import { headerFindings, inspectRedirect, tlsRecommendation } from "../src/index.js";

describe("redirects and headers", () => {
  it("re-checks redirect targets", () => {
    expect(inspectRedirect("https://example.com/a", "/next").href).toBe("https://example.com/next");
    expect(() => inspectRedirect("https://example.com/a", "http://169.254.169.254/")).toThrow(/not allowed/);
    expect(() => inspectRedirect("https://example.com/a", "http://127.0.0.1/")).toThrow(/not allowed/);
  });

  it("keeps header findings as recommendations and skips HSTS on http", () => {
    const https = headerFindings("https://example.com/", {});
    expect(https.findings.every((finding) => finding.recommendationOnly)).toBe(true);
    expect(https.findings.some((finding) => finding.id === "HEADER_HSTS")).toBe(true);
    expect(https.findings.find((finding) => finding.id === "COOKIE_FLAGS")).toBeUndefined();
    const http = headerFindings("http://example.com/", { "set-cookie": "sid=1" });
    expect(http.findings.some((finding) => finding.id === "HEADER_HSTS")).toBe(false);
    expect(http.findings.some((finding) => finding.id === "TLS_HTTP_ONLY")).toBe(true);
    expect(http.findings.some((finding) => finding.id === "COOKIE_FLAGS")).toBe(true);
    expect(http.cookies[0]?.secure).toBe(false);
  });

  it("records an unauthorized certificate as a recommendation", () => {
    expect(tlsRecommendation({ scheme: "https:", authorized: false }).map((finding) => finding.id)).toEqual(["TLS_INVALID"]);
    expect(tlsRecommendation({ scheme: "https:", authorized: null })).toEqual([]);
    expect(tlsRecommendation({ scheme: "http:", authorized: false })).toEqual([]);
  });
});
