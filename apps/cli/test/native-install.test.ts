import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { main } from "../src/main.js";
import {
  CHROME_NATIVE_HOST_NAME,
  installNativeHost,
  nativeHostLocations,
  nativeHostWrapper,
  uninstallNativeHost,
  windowsRegistryKey,
} from "../src/native-install.js";

const EXTENSION_ID = "hldpadjbahmnkhfchiikihdofpelfjne";

function io() {
  let out = "";
  let err = "";
  return {
    stdout: (text: string) => { out += text; },
    stderr: (text: string) => { err += text; },
    text: () => out,
    error: () => err,
  };
}

describe("chrome native host install", () => {
  it("writes a user-level macOS manifest pinned to one extension id", () => {
    const home = mkdtempSync(join(tmpdir(), "vigil-host-"));
    const installed = installNativeHost({
      extensionId: EXTENSION_ID,
      platform: "darwin",
      home,
      nodePath: "/usr/local/bin/node",
      scriptPath: "/opt/vigil/vigil.js",
    });
    expect(installed.manifestPaths).toEqual([
      join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", `${CHROME_NATIVE_HOST_NAME}.json`),
    ]);
    const manifest = JSON.parse(readFileSync(installed.manifestPaths[0] ?? "", "utf8")) as {
      name: string;
      path: string;
      type: string;
      allowed_origins: string[];
    };
    expect(manifest).toMatchObject({
      name: CHROME_NATIVE_HOST_NAME,
      type: "stdio",
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    });
    expect(manifest.path).toBe(join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts", `${CHROME_NATIVE_HOST_NAME}.sh`));
    expect(readFileSync(manifest.path, "utf8")).toBe("#!/bin/sh\nexec '/usr/local/bin/node' '/opt/vigil/vigil.js' native-host\n");
    expect(statSync(manifest.path).mode & 0o777).toBe(0o755);
    expect(uninstallNativeHost({ platform: "darwin", home }).removed).toBe(true);
    expect(uninstallNativeHost({ platform: "darwin", home }).removed).toBe(false);
  });

  it("writes the Linux Chrome and Chromium directories and the Windows HKCU launcher", () => {
    expect(nativeHostLocations("linux", "/home/example").map((location) => location.manifestPath)).toEqual([
      "/home/example/.config/google-chrome/NativeMessagingHosts/com.example.vigil.json",
      "/home/example/.config/chromium/NativeMessagingHosts/com.example.vigil.json",
    ]);
    expect(nativeHostLocations("darwin", "/Users/example")[0]?.manifestPath).toBe(
      "/Users/example/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.example.vigil.json",
    );
    expect(nativeHostLocations("win32", "C:\\Users\\example", "C:\\Users\\example\\AppData\\Local")[0]?.manifestPath).toBe(
      "C:\\Users\\example\\AppData\\Local\\Google\\Chrome\\NativeMessagingHosts\\com.example.vigil.json",
    );
    const root = mkdtempSync(join(tmpdir(), "vigil-win-"));
    const location = {
      manifestPath: join(root, "com.example.vigil.json"),
      wrapperPath: join(root, "com.example.vigil.cmd"),
    };
    const registered: string[] = [];
    installNativeHost({
      extensionId: EXTENSION_ID,
      platform: "win32",
      home: "C:\\Users\\example",
      nodePath: "C:\\Program Files\\nodejs\\node.exe",
      scriptPath: "C:\\vigil\\vigil.js",
      locations: [location],
      registerWindowsHost(manifestPath) {
        registered.push(manifestPath);
      },
    });
    expect(registered).toEqual([location.manifestPath]);
    expect(readFileSync(location.wrapperPath, "utf8")).toBe(
      "@echo off\r\n\"C:\\Program Files\\nodejs\\node.exe\" \"C:\\vigil\\vigil.js\" native-host\r\n",
    );
    expect(windowsRegistryKey()).toBe("HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\com.example.vigil");
    expect(nativeHostWrapper("darwin", "/tmp/a'b", "/opt/vigil/vigil.js")).toBeNull();
    expect(() => installNativeHost({
      extensionId: "NOT-AN-ID",
      platform: "darwin",
      home: root,
      nodePath: "/usr/local/bin/node",
      scriptPath: "/opt/vigil/vigil.js",
    })).toThrow("extension id was rejected");
  });

  it("runs install, uninstall, and native-host without printing a rejected id or a host error", async () => {
    const installed = io();
    let seen = "";
    expect(await main(["install-native-host", "--extension-id", EXTENSION_ID], installed, {
      installNativeHost: (options) => {
        seen = options.extensionId;
        return { manifestPaths: ["/tmp/com.example.vigil.json"] };
      },
    })).toBe(0);
    expect(seen).toBe(EXTENSION_ID);
    expect(installed.text()).toContain("Installed Chrome native host com.example.vigil");
    expect(installed.error()).toBe("");

    const missing = io();
    expect(await main(["install-native-host"], missing)).toBe(1);
    expect(missing.error()).toContain("--extension-id");

    const rejected = io();
    expect(await main(["install-native-host", "--extension-id", "ZZ"], rejected)).toBe(1);
    expect(rejected.error()).toBe("extension id was rejected\n");
    expect(rejected.error()).not.toContain("ZZ");

    const removed = io();
    expect(await main(["uninstall-native-host"], removed, {
      uninstallNativeHost: () => ({ removed: false }),
    })).toBe(0);
    expect(removed.text()).toContain("not installed");

    const host = io();
    expect(await main(["native-host"], host, {
      nativeHost: async () => {
        throw new Error("certificate for example.com failed");
      },
    })).toBe(1);
    expect(host.text()).toBe("");
    expect(host.error()).toBe("");
  });
});
