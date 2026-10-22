import { describe, expect, it } from "vitest";
import type { SessionRule } from "../src/dnr.js";
import {
  applySessionRules,
  createSessionArea,
  detectCapabilities,
  readEphemeral,
  setBadge,
  writeEphemeral,
  type StorageAreaLike,
} from "../src/platform.js";

function memory(): StorageAreaLike & { dump(): Record<string, unknown> } {
  const data: Record<string, unknown> = {};
  return {
    dump: () => ({ ...data }),
    async get(keys) {
      if (keys == null) return { ...data };
      const list = typeof keys === "string" ? [keys] : keys;
      const out: Record<string, unknown> = {};
      for (const key of list) {
        if (Object.prototype.hasOwnProperty.call(data, key)) out[key] = data[key];
      }
      return out;
    },
    async set(items) {
      Object.assign(data, items);
    },
    async remove(keys) {
      const list = typeof keys === "string" ? [keys] : keys;
      for (const key of list) delete data[key];
    },
  };
}

const rule: SessionRule = {
  id: 1000,
  priority: 2,
  action: { type: "redirect", redirect: { extensionPath: "/hold.html" } },
  condition: { requestDomains: ["paypa1.com"], resourceTypes: ["main_frame"] },
};

describe("browser layer", () => {
  it("keeps a native session area off local storage", async () => {
    const local = memory();
    const session = memory();
    const area = createSessionArea(local, session);
    await area.set({ "url:1": { host: "example.com" } });
    expect(await area.get("url:1")).toEqual({ "url:1": { host: "example.com" } });
    expect(local.dump()).toEqual({});
  });

  it("stores session keys in a local bag when session storage is missing", async () => {
    const local = memory();
    const area = createSessionArea(local);
    await area.set({ "url:4": { url: "https://example.com/", host: "example.com" }, "decision:4": { badge: "warn" } });
    expect(await area.get(["url:4", "missing"])).toEqual({
      "url:4": { url: "https://example.com/", host: "example.com" },
    });
    await area.remove("decision:4");
    expect(await area.get(null)).toEqual({
      "url:4": { url: "https://example.com/", host: "example.com" },
    });
    await local.set({ "vigil-session": ["not-a-bag"] });
    expect(await area.get(null)).toEqual({});
  });

  it("restores a missing helper as up and an explicit false as down", async () => {
    const area = memory();
    expect(await readEphemeral(area)).toEqual({ once: [], helperUp: true });
    await writeEphemeral(area, { once: ["paypa1.com", ""], helperUp: false });
    expect(await readEphemeral(area)).toEqual({ once: ["paypa1.com"], helperUp: false });
    await area.set({ "vigil-once": ["ok.example", 3, ""], "vigil-helper-up": true });
    expect(await readEphemeral(area)).toEqual({ once: ["ok.example"], helperUp: true });
  });

  it("skips session rules when the API is missing or rejects the update", async () => {
    expect(await applySessionRules(undefined, [rule])).toEqual({
      applied: false,
      reason: "declarativeNetRequest session rules are not available",
    });
    const partial = { getSessionRules: () => Promise.resolve([]) };
    expect(await applySessionRules(partial as never, [rule])).toMatchObject({ applied: false });
    const rejected = {
      async getSessionRules() {
        return [{ id: 1000 }, { id: 1001 }];
      },
      async updateSessionRules() {
        throw new Error("extensionPath redirect is not supported");
      },
    };
    expect(await applySessionRules(rejected, [rule])).toEqual({
      applied: false,
      reason: "extensionPath redirect is not supported",
    });
  });

  it("replaces the current session rules when the browser accepts them", async () => {
    let removed: number[] = [];
    let added: SessionRule[] = [];
    const dnr = {
      async getSessionRules() {
        return [{ id: 7 }];
      },
      async updateSessionRules(options: { removeRuleIds?: number[]; addRules?: SessionRule[] }) {
        removed = options.removeRuleIds ?? [];
        added = options.addRules ?? [];
      },
    };
    expect(await applySessionRules(dnr, [rule])).toEqual({ applied: true });
    expect(removed).toEqual([7]);
    expect(added).toEqual([rule]);
  });

  it("reports a missing or throwing badge API without failing the hold", async () => {
    expect(await setBadge(undefined, 3, "!", "#8f1d1d")).toBe(false);
    expect(await setBadge({ setBadgeText: async () => undefined }, 3, "!", "#8f1d1d")).toBe(false);
    const calls: string[] = [];
    expect(await setBadge({
      async setBadgeText() {
        calls.push("text");
        throw new Error("no toolbar badge");
      },
      async setBadgeBackgroundColor() {
        calls.push("color");
      },
    }, 3, "!", "#8f1d1d")).toBe(false);
    expect(calls).toEqual(["text"]);
    const painted: { text?: string; color?: string; tabId?: number } = {};
    expect(await setBadge({
      async setBadgeText(details) {
        painted.text = details.text;
        painted.tabId = details.tabId;
      },
      async setBadgeBackgroundColor(details) {
        painted.color = details.color;
      },
    }, 9, "?", "#3e4c5a")).toBe(true);
    expect(painted).toEqual({ text: "?", color: "#3e4c5a", tabId: 9 });
  });

  it("detects the APIs this extension uses", () => {
    expect(detectCapabilities({})).toEqual({
      sessionStorage: false,
      declarativeNetRequest: false,
      webNavigation: false,
      toolbarBadge: false,
    });
    expect(detectCapabilities({
      storage: { session: {} },
      declarativeNetRequest: {
        getSessionRules() {
          return Promise.resolve([]);
        },
        updateSessionRules() {
          return Promise.resolve();
        },
      },
      webNavigation: { onBeforeNavigate: {} },
      action: { setBadgeText: async () => undefined },
    })).toEqual({
      sessionStorage: true,
      declarativeNetRequest: true,
      webNavigation: true,
      toolbarBadge: true,
    });
  });
});
