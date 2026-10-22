/**
 * Sandboxed Chrome-for-Testing pass for the unpacked MV3 extension.
 * Branded Chrome ignores --load-extension, so this script refuses that binary.
 *
 *   CHROME_PATH=... xvfb-run -a node scripts/e2e-extension.mjs
 *
 * Screenshots and the JSON report go to /opt/cursor/artifacts. Nothing here is committed.
 */
/* global chrome, document, location */
import { spawn } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { clearTimeout, setTimeout } from "node:timers";
import { setTimeout as sleep } from "node:timers/promises";
import puppeteer from "puppeteer-core";

const ARTIFACTS = process.env.VIGIL_ARTIFACTS || "/opt/cursor/artifacts/screenshots";
const REPORT = process.env.VIGIL_E2E_REPORT || "/opt/cursor/artifacts/e2e-extension-report.json";
const EXT = resolve("apps/extension/dist");
const EMUDHRA = "https://dv-g3b-emudhra.we-have-a-problem.com/";
const EXAMPLE = "https://example.com/";
const IDN = "https://www.xn--80ak6aa92e.com/";
const LOOKALIKE = "https://paypa1.com/";
const PORT = Number(process.env.VIGIL_SERVE_PORT || 8877);

const results = [];

function chromeExecutable() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  return "/tmp/puppeteer-browsers/chrome/linux-156.0.8078.47/chrome-linux64/chrome";
}

function record(step, pass, ms, detail, screenshot) {
  results.push({ step, pass, ms, detail, screenshot });
  const mark = pass ? "PASS" : "FAIL";
  console.log(`${mark}\t${String(ms).padStart(5)}ms\t${step}\t${detail}`);
}

async function shot(page, name) {
  const file = join(ARTIFACTS, name);
  await page.screenshot({ path: file, fullPage: false }).catch(() => undefined);
  return file;
}

function startServe(port) {
  const child = spawn(process.execPath, ["apps/cli/dist/vigil.js", "serve", "--port", String(port)], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  let log = "";
  child.stdout.on("data", (chunk) => {
    log += chunk.toString();
  });
  child.stderr.on("data", (chunk) => {
    log += chunk.toString();
  });
  const ready = new Promise((resolveReady, rejectReady) => {
    const timer = setTimeout(() => rejectReady(new Error(`vigil serve did not listen\n${log}`)), 10000);
    const check = () => {
      const token = log.match(/^token ([A-Za-z0-9_-]{16,128})$/m)?.[1];
      if (log.includes("vigil serve") && token) {
        clearTimeout(timer);
        resolveReady(token);
      }
    };
    child.stdout.on("data", check);
    child.on("exit", (code) => {
      clearTimeout(timer);
      rejectReady(new Error(`vigil serve exited ${code}\n${log}`));
    });
  });
  return { child, ready, stop: () => child.kill("SIGTERM") };
}

function hangServer() {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => undefined);
  });
  return new Promise((resolveReady) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      resolveReady({
        port,
        close: () => new Promise((done) => {
          for (const socket of sockets) socket.destroy();
          server.close(() => done());
        }),
      });
    });
  });
}

async function startSession() {
  const launched = await launchBrowser();
  const control = await openControl(launched.browser, await extensionId(launched.browser));
  const page = await launched.browser.newPage();
  await page.goto("about:blank");
  return {
    browser: launched.browser,
    control,
    page,
    close: async () => {
      await launched.browser.close().catch(() => undefined);
      rmSync(launched.userDataDir, { recursive: true, force: true });
    },
  };
}

async function launchBrowser() {
  const executablePath = chromeExecutable();
  if (executablePath.includes("google-chrome") && !executablePath.includes("chrome-linux64")) {
    throw new Error("Refusing branded Chrome; it ignores --load-extension");
  }
  const userDataDir = join(tmpdir(), `vigil-e2e-${process.pid}`);
  rmSync(userDataDir, { recursive: true, force: true });
  mkdirSync(userDataDir, { recursive: true });
  const browser = await puppeteer.launch({
    executablePath,
    headless: false,
    enableExtensions: true,
    userDataDir,
    protocolTimeout: 20000,
    defaultViewport: { width: 1280, height: 800 },
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      `--disable-extensions-except=${EXT}`,
      `--load-extension=${EXT}`,
      "--disable-features=DisableLoadExtensionCommandLineSwitch",
      "--no-first-run",
      "--window-size=1280,800",
      "--host-resolver-rules=MAP paypa1.com ~NOTFOUND",
    ],
  });
  return { browser, userDataDir };
}

async function extensionId(browser) {
  const target = await browser.waitForTarget(
    (candidate) => candidate.type() === "service_worker" && candidate.url().includes("background.js"),
    { timeout: 15000 },
  );
  return new URL(target.url()).host;
}

async function openControl(browser, id) {
  const { targetId } = await browser._connection.send("Target.createTarget", {
    url: `chrome-extension://${id}/popup.html`,
  });
  const target = await browser.waitForTarget((candidate) => candidate._targetId === targetId, { timeout: 10000 });
  const control = await target.page();
  if (!control) throw new Error("Extension page did not open");
  const info = await control.evaluate(() => ({
    href: location.href,
    title: document.title,
    hasStorage: typeof chrome !== "undefined" && Boolean(chrome.storage),
    text: (document.body?.innerText || "").slice(0, 180),
  })).catch((error) => ({ href: "", title: "", hasStorage: false, text: String(error) }));
  console.log(`control ${info.href} storage=${info.hasStorage}`);
  if (!info.hasStorage) throw new Error(`Extension page has no chrome.storage (${info.href})`);
  return control;
}

let installToken = "";

async function configure(control, state) {
  const next = { ...state, helperToken: state.helperToken || installToken };
  return control.evaluate(async (payload) => {
    await chrome.storage.local.set({
      vigil: {
        mode: payload.mode,
        helperOrigin: payload.helperOrigin,
        helperToken: payload.helperToken,
        allowlist: payload.allowlist,
        cache: payload.cache,
      },
    });
    await chrome.storage.session.clear();
    await chrome.runtime.sendMessage({ type: "set-mode", mode: payload.mode });
    await chrome.runtime.sendMessage({
      type: "set-helper",
      helperOrigin: payload.helperOrigin || "",
      helperToken: payload.helperToken || "",
    });
    await chrome.storage.local.set({
      vigil: {
        mode: payload.mode,
        helperOrigin: payload.helperOrigin,
        helperToken: payload.helperToken,
        allowlist: payload.allowlist,
        cache: payload.cache,
      },
    });
    await chrome.runtime.sendMessage({ type: "set-mode", mode: payload.mode });
    const value = await chrome.storage.local.get("vigil");
    return value.vigil;
  }, next);
}

async function tabState(control) {
  return control.evaluate(async () => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find((item) => item.url?.includes("hold.html"))
      || tabs.find((item) => item.url?.startsWith("http://") || item.url?.startsWith("https://"))
      || tabs.find((item) => item.url?.startsWith("chrome-error:"))
      || null;
    if (!tab?.id) return { url: "", badge: "", decision: null };
    const key = `decision:${tab.id}`;
    const stored = await chrome.storage.session.get(key);
    const badge = await chrome.action.getBadgeText({ tabId: tab.id });
    return { url: tab.url ?? "", badge, decision: stored[key] ?? null };
  });
}

async function visit(page, url) {
  const host = new URL(url).hostname;
  const stamp = `v${Date.now()}${Math.random().toString(16).slice(2)}`;
  await page.evaluate((value) => {
    document.documentElement.dataset.vigilStamp = value;
  }, stamp).catch(() => undefined);
  const started = Date.now();
  const navigation = page.goto(url, { waitUntil: "domcontentloaded", timeout: 20000 }).catch((error) => error);
  try {
  await page.waitForFunction((mark, expected) => {
    if (document.documentElement.dataset.vigilStamp === mark) return false;
    const href = location.href;
    if (href.includes("hold.html")) {
      const title = document.querySelector("#title")?.textContent || "";
      return title.startsWith("Vigil ");
    }
    if (location.hostname === expected) return document.readyState !== "loading";
    if (href.startsWith("chrome-error:")) return true;
    return false;
  }, { timeout: 20000 }, stamp, host);
  } catch (error) {
    const info = await page.evaluate(() => ({
      href: location.href,
      title: document.querySelector("#title")?.textContent || document.title || "",
      status: document.querySelector("#status")?.textContent || "",
      reasons: [...document.querySelectorAll("#reasons .id")].map((node) => node.textContent || ""),
      text: (document.body?.innerText || "").slice(0, 400),
    })).catch(() => null);
    console.log(`visit timeout ${url} currently ${info?.href ?? "unavailable"}`);
    if (info?.href.startsWith("chrome-error:")) return { ms: Date.now() - started, ...info };
    throw error;
  }
  const ms = Date.now() - started;
  await navigation;
  await sleep(150);
  const pageInfo = await page.evaluate(() => ({
    href: location.href,
    title: document.querySelector("#title")?.textContent || document.title || "",
    status: document.querySelector("#status")?.textContent || "",
    reasons: [...document.querySelectorAll("#reasons .id")].map((node) => node.textContent || ""),
    text: (document.body?.innerText || "").slice(0, 400),
  }));
  return { ms, ...pageInfo };
}

async function leaveHold(page) {
  const started = Date.now();
  await page.waitForFunction(() => !location.href.includes("hold.html"), { timeout: 15000 });
  await sleep(200);
  const info = await page.evaluate(() => ({
    href: location.href,
    title: document.title || "",
    text: (document.body?.innerText || "").slice(0, 240),
  }));
  return { ms: Date.now() - started, ...info };
}

async function openPopup(browser, control, site, name) {
  await site.bringToFront();
  const controlId = control.target()._targetId;
  const before = new Set(browser.targets().map((target) => target._targetId));
  const opened = await control.evaluate(async () => {
    try {
      await chrome.action.openPopup();
      return "opened";
    } catch (error) {
      return error instanceof Error ? error.message : "open failed";
    }
  }).catch((error) => String(error));
  const target = await browser.waitForTarget(
    (candidate) => candidate.url().includes("/popup.html") && !before.has(candidate._targetId),
    { timeout: 2500 },
  ).catch(() => null);
  if (!target) return { ok: false, note: opened, file: "" };
  const popup = await target.asPage();
  await popup.waitForSelector("#findings", { timeout: 3000 }).catch(() => undefined);
  const file = await shot(popup, name);
  const text = await popup.evaluate(() => document.body?.innerText || "").catch(() => "");
  if (target._targetId !== controlId) await popup.close().catch(() => undefined);
  return { ok: true, note: text.slice(0, 300), file };
}

function idsOf(decision) {
  const gating = decision?.gating?.map((item) => item.id) ?? [];
  const popup = decision?.popup?.map((item) => item.id) ?? [];
  return { gating, popup };
}

async function main() {
  mkdirSync(ARTIFACTS, { recursive: true });
  const executablePath = chromeExecutable();
  const serve = startServe(PORT);
  installToken = await serve.ready;
  const helper = `http://127.0.0.1:${PORT}`;
  let session = await startSession();
  let { browser, control, page } = session;
  try {
    console.log("browser launched");
    let stored = await configure(control, {
      mode: "high",
      helperOrigin: helper,
      allowlist: [],
      cache: [],
    });
    console.log(`extension mode=${stored?.mode} helper=${stored?.helperOrigin}`);

    const emudhra = await visit(page, EMUDHRA);
    const emudhraShot = await shot(page, "01-high-emudhra-block.png");
    record(
      "high + helper: eMudhra blocks",
      emudhra.href.includes("hold.html")
        && emudhra.title === "Vigil blocked this site"
        && emudhra.reasons.includes("CERT_DISTRUSTED_CA"),
      emudhra.ms,
      `${emudhra.title}; ${emudhra.reasons.join(",") || emudhra.status}`,
      emudhraShot,
    );

    const example = await visit(page, EXAMPLE);
    const exampleShot = await shot(page, "02-high-example-release.png");
    const exampleState = await tabState(control);
    const exampleIds = idsOf(exampleState.decision);
    const popup = await openPopup(browser, control, page, "02b-high-example-popup.png");
    const headerOnly = exampleIds.popup.some((id) => id.startsWith("HEADER_"))
      && exampleIds.gating.length === 0
      && !example.href.includes("hold.html")
      && /example/i.test(example.text + example.title);
    record(
      "high + helper: example.com releases, headers only in popup",
      headerOnly,
      example.ms,
      `url=${example.href} badge=${exampleState.badge} popup=${exampleIds.popup.join(",") || "(none)"} gating=${exampleIds.gating.join(",") || "(none)"} popup-ui=${popup.ok ? "open" : popup.note}`,
      popup.file || exampleShot,
    );

    const idn = await visit(page, IDN);
    const idnShot = await shot(page, "03-high-idn-hold.png");
    const idnHeld = idn.href.includes("hold.html") && (idn.title === "Vigil blocked this site" || idn.title === "Vigil held this site");
    record(
      "high + helper: punycode homograph holds",
      idnHeld && (idn.reasons.includes("DOMAIN_LOOKALIKE") || idn.reasons.includes("DOMAIN_MIXED_SCRIPT")),
      idn.ms,
      `${idn.title}; ${idn.reasons.join(",") || idn.status}`,
      idnShot,
    );

    await page.click("#once");
    const onceLeft = await leaveHold(page);
    const onceShot = await shot(page, "04-proceed-once.png");
    record(
      "Proceed this time leaves the hold page",
      !onceLeft.href.includes("hold.html"),
      onceLeft.ms,
      onceLeft.href,
      onceShot,
    );

    const idnAgain = await visit(page, IDN);
    const againShot = await shot(page, "05-proceed-once-consumed.png");
    record(
      "Proceed this time is single-use",
      idnAgain.href.includes("hold.html") && idnAgain.title.startsWith("Vigil "),
      idnAgain.ms,
      `${idnAgain.title}; ${idnAgain.reasons.join(",")}`,
      againShot,
    );

    await page.click("#always");
    const alwaysLeft = await leaveHold(page);
    const alwaysShot = await shot(page, "06-always-allow.png");
    record(
      "Always allow leaves the hold page",
      !alwaysLeft.href.includes("hold.html"),
      alwaysLeft.ms,
      alwaysLeft.href,
      alwaysShot,
    );

    const idnAllowed = await visit(page, IDN);
    const allowedShot = await shot(page, "07-always-allow-again.png");
    record(
      "Always allow skips the next visit",
      !idnAllowed.href.includes("hold.html"),
      idnAllowed.ms,
      idnAllowed.href,
      allowedShot,
    );

    serve.stop();
    await session.close();
    session = await startSession();
    ({ browser, control, page } = session);
    stored = await configure(control, {
      mode: "high",
      helperOrigin: helper,
      allowlist: [],
      cache: [],
    });
    const downExample = await visit(page, EXAMPLE);
    const downExampleShot = await shot(page, "08-helper-down-example.png");
    const downExampleState = await tabState(control);
    record(
      "helper stopped: example.com stays held",
      downExample.href.includes("hold.html") && !downExample.reasons.includes("CERT_DISTRUSTED_CA"),
      downExample.ms,
      `url=${downExample.href} badge=${downExampleState.badge}`,
      downExampleShot,
    );

    const downLook = await visit(page, LOOKALIKE);
    const downLookShot = await shot(page, "09-helper-down-lookalike.png");
    record(
      "helper stopped: hostname lookalike still holds",
      downLook.href.includes("hold.html") && downLook.reasons.includes("DOMAIN_LOOKALIKE"),
      downLook.ms,
      `${downLook.title}; ${downLook.reasons.join(",")}`,
      downLookShot,
    );

    const downCert = await visit(page, EMUDHRA);
    const downCertShot = await shot(page, "10-helper-down-emudhra.png");
    record(
      "helper stopped: eMudhra stays held without a certificate verdict",
      downCert.href.includes("hold.html") && !downCert.reasons.includes("CERT_DISTRUSTED_CA"),
      downCert.ms,
      `url=${downCert.href} title=${downCert.title}`,
      downCertShot,
    );

    const hung = await hangServer();
    stored = await configure(control, {
      mode: "high",
      helperOrigin: `http://127.0.0.1:${hung.port}`,
      allowlist: [],
      cache: [],
    });
    const hungFirst = await visit(page, EXAMPLE);
    const hungShot = await shot(page, "11-helper-hung-timeout.png");
    record(
      "helper hung: example.com stays held after 2s",
      hungFirst.href.includes("hold.html")
        && hungFirst.ms >= 1900
        && hungFirst.status.includes("2 seconds"),
      hungFirst.ms,
      `${hungFirst.title}; ${hungFirst.status}`,
      hungShot,
    );
    const hungSecond = await visit(page, EXAMPLE);
    const hungSecondShot = await shot(page, "12-helper-hung-second.png");
    record(
      "helper hung: timeout is not cached as allow",
      hungSecond.href.includes("hold.html") && hungSecond.ms >= 1900 && hungSecond.status.includes("2 seconds"),
      hungSecond.ms,
      `${hungSecond.title}; ${hungSecond.status}`,
      hungSecondShot,
    );
    await hung.close();

    stored = await configure(control, {
      mode: "normal",
      helperOrigin: null,
      allowlist: [],
      cache: [],
    });
    const normalExample = await visit(page, EXAMPLE);
    const normalExampleShot = await shot(page, "13-normal-example.png");
    const normalExampleState = await tabState(control);
    record(
      "normal mode: example.com is not held",
      !normalExample.href.includes("hold.html") && normalExampleState.decision?.intercept !== true,
      normalExample.ms,
      `url=${normalExample.href} badge=${JSON.stringify(normalExampleState.badge)}`,
      normalExampleShot,
    );

    const normalLook = await visit(page, IDN);
    const normalLookShot = await shot(page, "14-normal-lookalike-badge.png");
    let normalLookState = await tabState(control);
    for (let attempt = 0; attempt < 10 && normalLookState.badge !== "!"; attempt += 1) {
      await sleep(100);
      normalLookState = await tabState(control);
    }
    record(
      "normal mode: lookalike is badge only",
      !normalLook.href.includes("hold.html")
        && normalLookState.badge === "!"
        && normalLookState.decision?.intercept === false
        && normalLookState.decision?.badge === "block",
      normalLook.ms,
      `url=${normalLook.href} badge=${JSON.stringify(normalLookState.badge)} action=${normalLookState.decision?.action ?? ""}`,
      normalLookShot,
    );

    const normalCert = await visit(page, EMUDHRA);
    const normalCertShot = await shot(page, "15-normal-emudhra.png");
    record(
      "normal mode: eMudhra is not redirected to the hold page",
      !normalCert.href.includes("hold.html"),
      normalCert.ms,
      `url=${normalCert.href} title=${normalCert.title}`,
      normalCertShot,
    );

  } finally {
    const passed = results.filter((item) => item.pass).length;
    mkdirSync(ARTIFACTS, { recursive: true });
    writeFileSync(REPORT, `${JSON.stringify({
      browser: executablePath,
      extension: EXT,
      passed,
      failed: results.length - passed,
      results,
    }, null, 2)}\n`);
    console.log(`report ${REPORT}`);
    console.log(`${passed}/${results.length} passed`);
    if (results.length === 0 || passed !== results.length) process.exitCode = 1;
    serve.stop();
    await session.close();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 1;
});
