import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { checkIosExtension } from "../scripts/check-ios-extension.mjs";

const safariRoot = fileURLToPath(new URL("..", import.meta.url));
const repoRoot = fileURLToPath(new URL("../../..", import.meta.url));

function read(path: string): string {
  return readFileSync(join(safariRoot, path), "utf8");
}

function walk(dir: string, skip: (rel: string) => boolean): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    const rel = relative(safariRoot, full);
    if (skip(rel)) continue;
    if (entry.isDirectory()) out.push(...walk(full, skip));
    else if (entry.isFile()) out.push(rel);
  }
  return out;
}

describe("Safari container", () => {
  it("ships a private MV3 manifest that can call loopback", () => {
    const manifest = JSON.parse(read("manifest.json")) as {
      manifest_version: number;
      permissions: string[];
      host_permissions: string[];
      content_security_policy: { extension_pages: string };
      update_url?: string;
      externally_connectable?: unknown;
      browser_specific_settings?: unknown;
      background: { service_worker: string; type: string };
    };
    expect(manifest.manifest_version).toBe(3);
    expect(manifest.permissions.sort()).toEqual(["declarativeNetRequest", "storage", "tabs", "webNavigation"]);
    expect(manifest.host_permissions).toEqual(["http://*/*", "https://*/*", "http://127.0.0.1/*"]);
    expect(manifest.content_security_policy.extension_pages).toContain("script-src 'self'");
    expect(manifest.update_url).toBeUndefined();
    expect(manifest.externally_connectable).toBeUndefined();
    expect(manifest.browser_specific_settings).toBeUndefined();
    expect(manifest.background).toEqual({ service_worker: "background.js", type: "module" });
  });

  it("uses placeholder signing and the converter target shape", () => {
    const project = read("Vigil.xcodeproj/project.pbxproj");
    const teams = project.match(/DEVELOPMENT_TEAM = [^;]+;/g) ?? [];
    expect(teams.length).toBeGreaterThan(0);
    expect(new Set(teams)).toEqual(new Set(["DEVELOPMENT_TEAM = XXXXXXXXXX;"]));
    for (const id of [
      "com.example.vigil.macos;",
      "com.example.vigil.macos.extension;",
    ]) {
      expect(project).toContain(`PRODUCT_BUNDLE_IDENTIFIER = ${id}`);
    }
    expect(project).not.toContain("com.example.vigil.ios");
    expect(project).toContain("com.apple.product-type.app-extension");
    expect(project).toContain("dstSubfolderSpec = 13;");
    expect(project).toContain('name = "Vigil macOS";');
    expect(project).toContain('name = "Vigil macOS Extension";');
    expect(project).toContain('name = "Vigil macOS Tests";');
    expect(project).not.toContain('name = "Vigil iOS"');
    expect(project).toContain("PRODUCT_BUNDLE_IDENTIFIER = com.example.vigil.macos.tests;");
    expect(project).toContain("generate-blocklist.py");
    expect(project).toContain("com.apple.product-type.bundle.unit-test");
    expect(project).toContain("GENERATE_INFOPLIST_FILE = NO;");
    expect(project).not.toContain("PRODUCT_NAME = VigilIOS");
    expect(project).toContain("PRODUCT_NAME = VigilMacExtension;");
    expect(project).not.toContain("VigilIOS");
    expect(project).toContain("path = VigilMacExtension.appex;");
    expect(project).not.toContain("VigilExtension.appex");
    expect(project).not.toContain("Vigil Extension.appex");
    expect(project).not.toContain("CONTENTS_FOLDER_PATH");
    expect(project).not.toContain("INFOPLIST_PATH");
    expect(project).not.toContain("WRAPPER_EXTENSION");
    expect(project).not.toContain("WRAPPER_NAME");
    expect(project).not.toContain("TARGETED_DEVICE_FAMILY");
    expect(project).not.toContain("iphoneos");
    expect(project).not.toContain("DEVELOPMENT_TEAM = \"\"");
    expect(read("Vigil.xcodeproj/xcshareddata/xcschemes/Vigil macOS.xcscheme")).toContain("A10000000000000000000050");
    expect(existsSync(join(safariRoot, "Vigil.xcodeproj/xcshareddata/xcschemes/Vigil iOS.xcscheme"))).toBe(false);
    expect(existsSync(join(safariRoot, "iOS (App)"))).toBe(false);
    expect(existsSync(join(safariRoot, "iOS (Extension)"))).toBe(false);
  });

  it("keeps the macOS appex name in one token and the extension plist keys complete", () => {
    expect(checkIosExtension()).toEqual([]);
    const run = spawnSync(process.execPath, ["apps/safari/scripts/check-ios-extension.mjs"], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    expect(run.status, run.stderr).toBe(0);
    expect(run.stderr).toBe("");
  });

  it("allows loopback in every container and extension plist and sandboxes the Mac extension", () => {
    const plists = [
      "macOS (App)/Info.plist",
      "macOS (Extension)/Info.plist",
    ].map((path) => read(path));
    for (const plist of plists) {
      expect(plist).toContain("<key>NSAllowsLocalNetworking</key>");
      expect(plist).not.toContain("NSAllowsArbitraryLoads");
    }
    const extensionPlists = [plists[1]];
    for (const plist of extensionPlists) {
      expect(plist).toContain("<string>com.apple.Safari.web-extension</string>");
      expect(plist).toContain("$(PRODUCT_MODULE_NAME).SafariWebExtensionHandler");
    }
    for (const path of ["macOS (App)/Vigil.entitlements", "macOS (Extension)/Vigil.entitlements"]) {
      const text = read(path);
      expect(text).toContain("com.apple.security.app-sandbox");
      expect(text).toContain("com.apple.security.network.client");
      expect(text).not.toContain("application-groups");
    }
  });

  it("keeps the native handler from logging or echoing the message", () => {
    const handler = read("Shared (Extension)/SafariWebExtensionHandler.swift");
    const checker = read("Shared (Extension)/NativeCertCheck.swift");
    expect(handler).toContain("NativeCertCheck.respond");
    expect(handler).not.toMatch(/\bprint\s*\(|NSLog|os\.log|Logger\(/);
    expect(checker).not.toMatch(/\bprint\s*\(|NSLog|os\.log|Logger\(/);
    expect(handler).not.toContain("SFExtensionMessageKey: message");
    expect(checker).toContain("SecTrustSetNetworkFetchAllowed");
    expect(checker).toContain('return ["error": "rejected"]');
  });

  it("keeps machine names, real team ids, and non-loopback addresses out of the container", () => {
    const files = walk(safariRoot, (rel) => rel.startsWith("test") || rel.includes(`${join("Shared (Extension)", "Resources")}`) || rel.includes(`${join("Shared (Extension)", "Generated")}`) || rel.endsWith(".png"));
    expect(files.length).toBeGreaterThan(5);
    const gitignore = readFileSync(join(repoRoot, ".gitignore"), "utf8");
    expect(gitignore).toContain("apps/safari/Shared (Extension)/Resources/*");
    expect(gitignore).toContain("apps/safari/Shared (Extension)/Generated/*");
    expect(statSync(join(safariRoot, "Shared (Extension)", "Resources", ".gitkeep")).isFile()).toBe(true);
    const extra = ["docs/SAFARI-TESTING.md", "README.md"].map((rel) => join(repoRoot, rel));
    for (const file of [...files.map((rel) => join(safariRoot, rel)), ...extra]) {
      const text = readFileSync(file, "utf8");
      expect(text, file).not.toMatch(/\/Users\/|\/home\/[A-Za-z0-9]/);
      expect(text, file).not.toMatch(/MacBook|iPhone\s?\d|iPad\s?(Pro|Air|mini|\d)/i);
      const ips = text.match(/\b\d{1,3}(?:\.\d{1,3}){3}\b/g) ?? [];
      for (const ip of ips) expect(ip, file).toBe("127.0.0.1");
    }
  });

  it("wires Safari gaps through the shared browser layer", () => {
    const background = readFileSync(join(repoRoot, "apps/extension/src/background.ts"), "utf8");
    expect(background).toContain("onCommitted?.addListener");
    expect(background).toContain("onUpdated?.addListener");
    expect(background).toContain("applySessionRules");
    expect(background).toContain("readEphemeral");
    expect(background).toContain("writeEphemeral");
    expect(background).toContain("hasNativeSession");
    expect(background).toContain("remove(SESSION_BAG)");
    expect(readFileSync(join(repoRoot, "apps/extension/src/platform.ts"), "utf8")).toContain('SESSION_BAG = "vigil-session"');
    const build = readFileSync(join(repoRoot, "scripts/build.mjs"), "utf8");
    expect(build).toContain('copyFileSync("apps/safari/manifest.json"');
  });
});
