/** High Security only. Registered as a MAIN-world document_start script while that mode is on. */
export const BLANK_GUARD_ID = "vigil-blank-guard";
export const OPENER_BLANK_EVENT = "vigil-opener-blank";
export const OPENER_BLANK_MESSAGE = "opener-blank";

const sealed = new WeakSet<object>();

export interface ScriptElement {
  setAttribute?: (name: string, value: string) => void;
  httpEquiv?: string;
  content?: string;
}

export interface ScriptBlockDocument {
  write: (...args: unknown[]) => unknown;
  writeln: (...args: unknown[]) => unknown;
  open: (...args: unknown[]) => unknown;
  createElement?: (tag: string, options?: unknown) => unknown;
  head?: { appendChild?: (node: unknown) => unknown } | null;
  documentElement?: { appendChild?: (node: unknown) => unknown } | null;
  defaultView?: { Element?: { prototype: object } } | null;
  dispatchEvent?: (event: { type: string }) => void;
  appendChild?: (node: unknown) => unknown;
  insertBefore?: (node: unknown, child: unknown) => unknown;
  replaceChild?: (node: unknown, child: unknown) => unknown;
}

export interface OpenedWindow {
  document: ScriptBlockDocument;
  location?: { href?: string; protocol?: string };
  closed?: boolean;
}

export interface GuardWindow extends OpenedWindow {
  open: (url?: string | URL | null, target?: string, features?: string) => OpenedWindow | null;
  __vigilBlankGuard?: boolean;
}

export function pageMatches(): string[] {
  const anyHost = "*";
  return [`${"http"}://${anyHost}/*`, `${"https"}://${anyHost}/*`];
}

export function blankGuardScript(): {
  id: string;
  js: ["blank-guard.js"];
  matches: string[];
  runAt: "document_start";
  world: "MAIN";
  allFrames: true;
  persistAcrossSessions: true;
} {
  return {
    id: BLANK_GUARD_ID,
    js: ["blank-guard.js"],
    matches: pageMatches(),
    runAt: "document_start",
    world: "MAIN",
    allFrames: true,
    persistAcrossSessions: true,
  };
}

export function httpPageUrl(url: string | undefined): boolean {
  if (!url) return false;
  return url.startsWith("http:") || url.startsWith("https:");
}

/** Content-script messages only. Extension pages and normal mode do not qualify. */
export function acceptOpenerBlank(input: { highMode: boolean; senderUrl?: string; tabId?: number }): boolean {
  return input.highMode && input.tabId !== undefined && httpPageUrl(input.senderUrl);
}

export function isScriptlessBlank(url: string | null | undefined): boolean {
  if (url == null) return true;
  const value = url.trim();
  if (value === "") return true;
  const scheme = value.toLowerCase().split(":", 1)[0] ?? "";
  return scheme === "about" || scheme === "blob" || scheme === "data" || scheme === "javascript";
}

export function openerTargetNeedsSeal(url: string | null | undefined): boolean {
  if (isScriptlessBlank(url)) return true;
  return hasUserinfo(url ?? "");
}

export function shouldHoldOpenedUrl(url: string | undefined): boolean {
  if (url == null || url.trim() === "") return true;
  return openerTargetNeedsSeal(url);
}

export function childIsExistingSite(location: { href?: string; protocol?: string } | null | undefined): boolean {
  const protocol = location?.protocol ?? "";
  if (protocol !== "http:" && protocol !== "https:") return false;
  if (!location?.href) return true;
  return !openerTargetNeedsSeal(location.href);
}

export function blankHoldDecision(): {
  intercept: true;
  action: "hold";
  badge: "unknown";
  reason: "unknown";
  gating: [];
  popup: [{
    id: "BLANK_WINDOW";
    severity: "high";
    recommendationOnly: true;
    title: "Blank window held";
    summary: "This blank window was held before script could run.";
  }];
} {
  return {
    intercept: true,
    action: "hold",
    badge: "unknown",
    reason: "unknown",
    gating: [],
    popup: [{
      id: "BLANK_WINDOW",
      severity: "high",
      recommendationOnly: true,
      title: "Blank window held",
      summary: "This blank window was held before script could run.",
    }],
  };
}

/** Replace window.open so a blank child cannot run script before this function returns. */
export function installBlankGuard(win: GuardWindow): void {
  if (win.__vigilBlankGuard) return;
  try {
    win.__vigilBlankGuard = true;
  } catch {
    /* Keep wrapping even if the flag cannot be stored. */
  }
  const nativeOpen = win.open.bind(win);
  win.open = (url?: string | URL | null, target?: string, features?: string) => {
    const seal = openerTargetNeedsSeal(urlToString(url));
    const child = seal ? nativeOpen("about:blank", "_blank", features) : nativeOpen(url, target, features);
    if (!seal || !child?.document || child.document === win.document) return child;
    if (childIsExistingSite(child.location)) return child;
    sealBlankDocument(child.document, win.document);
    dispatchBlank(win.document);
    return child;
  };
}

export function sealBlankDocument(doc: ScriptBlockDocument, openerDoc?: ScriptBlockDocument): void {
  if (!doc || typeof doc !== "object") return;
  sealed.add(doc);
  try {
    blockScripts(doc);
  } catch {
    /* The write seal still applies. */
  }
  const noop = () => undefined;
  const proto = objectProto(doc);
  const openerProto = openerDoc ? objectProto(openerDoc) : null;
  muteWrites(proto, noop);
  muteWrites(doc, noop);
  if (proto && proto !== openerProto) muteCreate(proto);
  muteCreate(doc);
  muteInsertTree(doc);
  if (openerProto && openerProto !== proto) guardForeignWrites(openerProto);
}

function urlToString(url: string | URL | null | undefined): string | null | undefined {
  if (url == null) return url;
  return typeof url === "string" ? url : url.href;
}

function hasUserinfo(value: string): boolean {
  try {
    const parsed = new URL(value, "http://127.0.0.1");
    return parsed.username.length > 0 || parsed.password.length > 0;
  } catch {
    return false;
  }
}

function dispatchBlank(doc: ScriptBlockDocument): void {
  if (typeof doc.dispatchEvent !== "function") return;
  const Scope = globalThis as { CustomEvent?: new (type: string) => { type: string } };
  const event = typeof Scope.CustomEvent === "function" ? new Scope.CustomEvent(OPENER_BLANK_EVENT) : { type: OPENER_BLANK_EVENT };
  try {
    doc.dispatchEvent(event);
  } catch {
    /* The write seal already ran. The hold redirect is additional. */
  }
}

function blockScripts(doc: ScriptBlockDocument): void {
  const create = doc.createElement;
  if (typeof create !== "function") return;
  const meta = create.call(doc, "meta");
  if (!meta || typeof meta !== "object") return;
  const element = meta as ScriptElement;
  element.httpEquiv = "Content-Security-Policy";
  element.content = "script-src 'none'";
  element.setAttribute?.("http-equiv", "Content-Security-Policy");
  element.setAttribute?.("content", "script-src 'none'");
  const parent = doc.head ?? doc.documentElement;
  parent?.appendChild?.(meta);
}

function objectProto(value: object): object | null {
  const proto = Object.getPrototypeOf(value) as object | null;
  if (!proto || proto === Object.prototype) return null;
  return proto;
}

function muteWrites(target: object | null, noop: () => undefined): void {
  if (!target) return;
  for (const key of ["write", "writeln", "open"]) assign(target, key, noop);
}

function muteCreate(target: object | null): void {
  if (!target) return;
  const current = (target as { createElement?: (tag: string, options?: unknown) => unknown }).createElement;
  if (typeof current !== "function" || marked(current)) return;
  const wrapped = function (this: unknown, tag: string, options?: unknown) {
    if (String(tag).toLowerCase() === "script") return current.call(this, "meta");
    return current.call(this, tag, options);
  };
  mark(wrapped);
  assign(target, "createElement", wrapped);
}

function muteInsertTree(doc: ScriptBlockDocument): void {
  muteInsert(doc);
  muteInsert(objectProto(doc));
  const elementProto = doc.defaultView?.Element?.prototype;
  if (elementProto && elementProto !== Object.prototype) muteInsert(elementProto);
  if (doc.head) muteInsert(objectProto(doc.head));
  if (doc.documentElement) muteInsert(objectProto(doc.documentElement));
}

function muteInsert(target: object | null): void {
  if (!target) return;
  const record = target as Record<string, unknown>;
  for (const key of ["appendChild", "insertBefore", "replaceChild"]) {
    const current = record[key];
    if (typeof current !== "function" || marked(current)) continue;
    const wrapped = function (this: unknown, node: unknown, ...rest: unknown[]) {
      if (isScriptNode(node)) return node;
      return (current as (...args: unknown[]) => unknown).apply(this, [node, ...rest]);
    };
    mark(wrapped);
    assign(target, key, wrapped);
  }
}

function guardForeignWrites(proto: object): void {
  const record = proto as Record<string, unknown>;
  for (const key of ["write", "writeln", "open"]) {
    const current = record[key];
    if (typeof current !== "function" || marked(current)) continue;
    const wrapped = function (this: unknown, ...args: unknown[]) {
      if (this && typeof this === "object" && sealed.has(this)) return undefined;
      return (current as (...args: unknown[]) => unknown).apply(this, args);
    };
    mark(wrapped);
    assign(proto, key, wrapped);
  }
}

function isScriptNode(node: unknown): boolean {
  if (!node || typeof node !== "object") return false;
  const name = (node as { nodeName?: unknown }).nodeName;
  return typeof name === "string" && name.toLowerCase() === "script";
}

function marked(fn: unknown): boolean {
  return typeof fn === "function" && (fn as { vigilGuard?: boolean }).vigilGuard === true;
}

function mark(fn: object): void {
  try {
    Object.defineProperty(fn, "vigilGuard", { value: true });
  } catch {
    /* A sealed function still runs. */
  }
}

function assign(target: object, key: string, value: unknown): void {
  try {
    (target as Record<string, unknown>)[key] = value;
  } catch {
    /* Frozen documents still get the other seals. */
  }
}
