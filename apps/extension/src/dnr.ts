export interface SessionRule {
  id: number;
  priority: number;
  action: { type: "redirect"; redirect: { extensionPath: string } } | { type: "block" };
  condition: {
    urlFilter?: string;
    requestDomains?: string[];
    excludedRequestDomains?: string[];
    resourceTypes: Array<"main_frame" | "sub_frame">;
  };
}

/**
 * High Security holds http(s) main frames before page script and blocks subframes.
 * Allowlisted, one-time, and cached allow/warn hosts are excluded. Other schemes are not matched here.
 */
export function highSecurityRules(excludedDomains: readonly string[]): SessionRule[] {
  const excluded = [...new Set(excludedDomains.map((host) => host.toLowerCase().replace(/\.$/, "")).filter(Boolean))].slice(0, 1000);
  const exclusion = excluded.length > 0 ? { excludedRequestDomains: excluded } : {};
  return [
    {
      id: 1,
      priority: 1,
      action: { type: "redirect", redirect: { extensionPath: "/hold.html" } },
      condition: { urlFilter: "|http", resourceTypes: ["main_frame"], ...exclusion },
    },
    {
      id: 2,
      priority: 1,
      action: { type: "block" },
      condition: { urlFilter: "|http", resourceTypes: ["sub_frame"], ...exclusion },
    },
  ];
}
