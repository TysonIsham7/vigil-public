import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  acceptOpenerBlank,
  blankGuardScript,
  blankHoldDecision,
  installBlankGuard,
  isScriptlessBlank,
  openerTargetNeedsSeal,
  pageMatches,
  type GuardWindow,
  type OpenedWindow,
  type ScriptBlockDocument,
} from "../src/blank-guard.js";
import { holdStatusText } from "../src/text.js";

const BEACON = "<script>navigator.sendBeacon('http://127.0.0.1:9/beacon')</script>";

interface CountingDocument extends ScriptBlockDocument {
  beacons: number;
}

function makeRealm(): { proto: ScriptBlockDocument; create: () => CountingDocument } {
  const proto: ScriptBlockDocument = {
    write(this: CountingDocument, html: unknown) {
      if (String(html).includes("beacon")) this.beacons += 1;
    },
    writeln(this: CountingDocument, html: unknown) {
      if (String(html).includes("beacon")) this.beacons += 1;
    },
    open(this: CountingDocument) {
      this.beacons += 1;
    },
  };
  return {
    proto,
    create() {
      const doc = Object.create(proto) as CountingDocument;
      doc.beacons = 0;
      return doc;
    },
  };
}

function opener(open: GuardWindow["open"], document: ScriptBlockDocument): GuardWindow {
  return { document, open };
}

describe("opener blank windows", () => {
  it("seals about:blank so document.write and the prototype cannot fire a beacon", () => {
    const childRealm = makeRealm();
    const openerRealm = makeRealm();
    const openerDoc = openerRealm.create();
    const events: string[] = [];
    openerDoc.dispatchEvent = (event) => {
      events.push(event.type);
    };
    const opened: unknown[] = [];
    let childDoc: CountingDocument | undefined;
    const win = opener((url, target, features) => {
      opened.push([url, target, features]);
      childDoc = childRealm.create();
      return { document: childDoc, location: { protocol: "about:", href: "about:blank" } };
    }, openerDoc);
    installBlankGuard(win);
    installBlankGuard(win);

    const child = win.open("about:blank");
    child?.document.write(BEACON);
    child?.document.writeln(BEACON);
    child?.document.open();
    childRealm.proto.write.call(child?.document, BEACON);
    openerRealm.proto.write.call(child?.document, BEACON);
    openerDoc.write(BEACON);

    expect(opened).toEqual([["about:blank", "_blank", undefined]]);
    expect(childDoc?.beacons).toBe(0);
    expect(openerDoc.beacons).toBe(1);
    expect(events).toEqual(["vigil-opener-blank"]);
    expect(child?.document).not.toBe(openerDoc);
  });

  it("never hands javascript, data, blob, or userinfo urls to the browser open", () => {
    const childRealm = makeRealm();
    const opened: unknown[] = [];
    const win = opener((url, target) => {
      opened.push([url, target]);
      return { document: childRealm.create(), location: { protocol: "about:", href: "about:blank" } };
    }, makeRealm().create());
    installBlankGuard(win);
    for (const url of ["javascript:beacon=1", "data:text/html,beacon", "blob:https://example.com/11111111-1111-1111-1111-111111111111", "https://user:secret@example.com/", "", null, undefined]) {
      const child = win.open(url);
      child?.document.write(BEACON);
      (Object.getPrototypeOf(child?.document) as ScriptBlockDocument).write.call(child?.document, BEACON);
    }
    expect(opened.every((entry) => Array.isArray(entry) && entry[0] === "about:blank" && entry[1] === "_blank")).toBe(true);
    expect(opened).toHaveLength(7);
  });

  it("leaves an existing http page and a normal popup writable", () => {
    const siteRealm = makeRealm();
    const site = siteRealm.create();
    const opened: unknown[] = [];
    const win = opener((url, target, features) => {
      opened.push([url, target, features]);
      return { document: site, location: { protocol: "https:", href: "https://example.com/path" } };
    }, makeRealm().create());
    installBlankGuard(win);
    const child = win.open("https://example.com/path", "popup", "width=10");
    child?.document.write(BEACON);
    expect(opened).toEqual([["https://example.com/path", "popup", "width=10"]]);
    expect(site.beacons).toBe(1);

    const reused = win.open("about:blank");
    reused?.document.write(BEACON);
    expect(opened[1]).toEqual(["about:blank", "_blank", undefined]);
    expect(site.beacons).toBe(2);
  });

  it("does not seal the opener when open returns its own document", () => {
    const realm = makeRealm();
    const doc = realm.create();
    const win = opener(() => ({ document: doc, location: { protocol: "about:", href: "about:blank" } }), doc);
    installBlankGuard(win);
    win.open();
    doc.write(BEACON);
    expect(doc.beacons).toBe(1);
  });

  it("blocks script elements inserted into the sealed window", () => {
    const tags: string[] = [];
    const appended: unknown[] = [];
    const proto: ScriptBlockDocument = {
      write() {},
      writeln() {},
      open() {},
      createElement(tag: string) {
        tags.push(tag);
        return { nodeName: String(tag).toUpperCase(), setAttribute() {} };
      },
      appendChild(node: unknown) {
        appended.push(node);
        return node;
      },
      insertBefore(node: unknown) {
        appended.push(node);
        return node;
      },
      replaceChild(node: unknown) {
        appended.push(node);
        return node;
      },
    };
    const doc = Object.create(proto) as ScriptBlockDocument & { head: { appendChild: (node: unknown) => void } };
    doc.head = { appendChild() {} };
    const win = opener(() => ({ document: doc, location: { href: "about:blank", protocol: "about:" } }), makeRealm().create());
    installBlankGuard(win);
    const child = win.open("about:blank") as OpenedWindow;
    const created = child.document.createElement?.("script");
    child.document.appendChild?.({ nodeName: "SCRIPT" });
    expect(tags).not.toContain("script");
    expect(created && typeof created === "object" ? (created as { nodeName?: string }).nodeName : "").toBe("META");
    expect(appended).toEqual([]);
  });

  it("decides which opens to seal and which senders may ask for a hold", () => {
    expect(openerTargetNeedsSeal(null)).toBe(true);
    expect(openerTargetNeedsSeal(undefined)).toBe(true);
    expect(openerTargetNeedsSeal("")).toBe(true);
    expect(openerTargetNeedsSeal("about:blank")).toBe(true);
    expect(openerTargetNeedsSeal("about:srcdoc")).toBe(true);
    expect(isScriptlessBlank("https://user:secret@example.com/")).toBe(false);
    expect(openerTargetNeedsSeal("https://user:secret@example.com/")).toBe(true);
    expect(openerTargetNeedsSeal("https://example.com/")).toBe(false);
    expect(openerTargetNeedsSeal("/local-path")).toBe(false);
    expect(acceptOpenerBlank({ highMode: true, senderUrl: "https://example.com/app", tabId: 4 })).toBe(true);
    expect(acceptOpenerBlank({ highMode: false, senderUrl: "https://example.com/app", tabId: 4 })).toBe(false);
    expect(acceptOpenerBlank({ highMode: true, senderUrl: "chrome-extension://abc/popup.html", tabId: 4 })).toBe(false);
    expect(acceptOpenerBlank({ highMode: true, senderUrl: "https://example.com/app" })).toBe(false);
    expect(pageMatches()).toEqual(["http://*/*", "https://*/*"]);
    const script = blankGuardScript();
    expect(script.world).toBe("MAIN");
    expect(script.runAt).toBe("document_start");
    expect(script.allFrames).toBe(true);
    expect(script.persistAcrossSessions).toBe(true);
    expect(script.js).toEqual(["blank-guard.js"]);
    const held = blankHoldDecision();
    expect(held.intercept).toBe(true);
    expect(held.action).toBe("hold");
    expect(held.popup[0]?.id).toBe("BLANK_WINDOW");
    expect(holdStatusText({ reason: held.reason, ids: [held.popup[0].id] })).toContain("blank window");
    expect(holdStatusText({ reason: held.reason, ids: [held.popup[0].id] })).not.toContain("certificate");
    const relay = readFileSync(new URL("../src/blank-relay.ts", import.meta.url), "utf8");
    expect(relay).toContain("OPENER_BLANK_MESSAGE");
    expect(relay).not.toMatch(/innerHTML|querySelector|document\.body|document\.cookie/);
  });
});
