import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

/** Chrome native-messaging host name. The manifest file and `connectNative` use this same string. */
export const CHROME_NATIVE_HOST_NAME = "com.example.vigil";

export function chromeExtensionId(value: string): string | null {
  if (value.length !== 32 || !/^[a-p]+$/.test(value)) return null;
  return value;
}

export interface NativeHostLocation {
  manifestPath: string;
  wrapperPath: string;
}

/** User-level Chrome native-messaging directories. No system path and no sudo. */
export function nativeHostLocations(platform: NodeJS.Platform, home: string, localAppData?: string): NativeHostLocation[] {
  if (!home || home.includes("\0")) return [];
  if (platform === "darwin") {
    return [hostFiles(path.join(home, "Library", "Application Support", "Google", "Chrome", "NativeMessagingHosts"), "sh")];
  }
  if (platform === "linux") {
    return [
      hostFiles(path.join(home, ".config", "google-chrome", "NativeMessagingHosts"), "sh"),
      hostFiles(path.join(home, ".config", "chromium", "NativeMessagingHosts"), "sh"),
    ];
  }
  if (platform === "win32") {
    const base = localAppData && !localAppData.includes("\0") ? localAppData : path.win32.join(home, "AppData", "Local");
    return [hostFiles(path.win32.join(base, "Google", "Chrome", "NativeMessagingHosts"), "cmd", path.win32)];
  }
  return [];
}

export function nativeHostWrapper(platform: NodeJS.Platform, nodePath: string, scriptPath: string): string | null {
  const node = quoteExecutable(platform, nodePath);
  const script = quoteExecutable(platform, scriptPath);
  if (!node || !script) return null;
  if (platform === "win32") return `@echo off\r\n${node} ${script} native-host\r\n`;
  if (platform === "darwin" || platform === "linux") return `#!/bin/sh\nexec ${node} ${script} native-host\n`;
  return null;
}

export function installNativeHost(options: {
  extensionId: string;
  platform?: NodeJS.Platform;
  home?: string;
  localAppData?: string;
  nodePath: string;
  scriptPath: string;
  locations?: NativeHostLocation[];
  registerWindowsHost?: (manifestPath: string) => void;
}): { manifestPaths: string[] } {
  const extensionId = chromeExtensionId(options.extensionId);
  if (!extensionId) throw new Error("extension id was rejected");
  const platform = options.platform ?? process.platform;
  const home = options.home ?? homedir();
  const locations = options.locations ?? nativeHostLocations(platform, home, options.localAppData);
  if (locations.length === 0) throw new Error("This operating system has no Chrome native host path");
  const wrapper = nativeHostWrapper(platform, options.nodePath, options.scriptPath);
  if (!wrapper) throw new Error("native host path was rejected");
  const manifestPaths: string[] = [];
  const dir = platform === "win32" ? path.win32 : path;
  try {
    for (const location of locations) {
      mkdirSync(dir.dirname(location.manifestPath), { recursive: true });
      writeFileAtomic(location.wrapperPath, wrapper, 0o755);
      const manifest = nativeHostManifest(extensionId, location.wrapperPath);
      writeFileAtomic(location.manifestPath, manifest, 0o644);
      manifestPaths.push(location.manifestPath);
    }
  } catch {
    throw new Error("Chrome native host could not be installed");
  }
  if (platform === "win32") {
    const manifestPath = manifestPaths[0];
    if (!manifestPath) throw new Error("Chrome native host could not be installed");
    try {
      (options.registerWindowsHost ?? registerWindowsHost)(manifestPath);
    } catch {
      throw new Error("Chrome native host registry update failed");
    }
  }
  return { manifestPaths };
}

export function uninstallNativeHost(options: {
  platform?: NodeJS.Platform;
  home?: string;
  localAppData?: string;
  locations?: NativeHostLocation[];
  unregisterWindowsHost?: () => void;
} = {}): { removed: boolean } {
  const platform = options.platform ?? process.platform;
  const home = options.home ?? homedir();
  const locations = options.locations ?? nativeHostLocations(platform, home, options.localAppData);
  if (locations.length === 0) throw new Error("This operating system has no Chrome native host path");
  let removed = false;
  for (const location of locations) {
    for (const file of [location.manifestPath, location.wrapperPath, `${location.manifestPath}.tmp`, `${location.wrapperPath}.tmp`]) {
      if (removeFile(file)) removed = true;
    }
  }
  if (platform === "win32") {
    (options.unregisterWindowsHost ?? unregisterWindowsHost)();
  }
  return { removed };
}

export function windowsRegistryKey(): string {
  return `HKCU\\Software\\Google\\Chrome\\NativeMessagingHosts\\${CHROME_NATIVE_HOST_NAME}`;
}

function nativeHostManifest(extensionId: string, wrapperPath: string): string {
  return `${JSON.stringify({
    name: CHROME_NATIVE_HOST_NAME,
    description: "Vigil local verdict helper",
    path: wrapperPath,
    type: "stdio",
    allowed_origins: [`chrome-extension://${extensionId}/`],
  }, null, 2)}\n`;
}

function hostFiles(dir: string, extension: "sh" | "cmd", lib: path.PlatformPath = path): NativeHostLocation {
  return {
    manifestPath: lib.join(dir, `${CHROME_NATIVE_HOST_NAME}.json`),
    wrapperPath: lib.join(dir, `${CHROME_NATIVE_HOST_NAME}.${extension}`),
  };
}

function quoteExecutable(platform: NodeJS.Platform, value: string): string | null {
  const lib = platform === "win32" ? path.win32 : path.posix;
  const resolved = lib.resolve(value);
  if (platform === "win32") {
    if (!/^[A-Za-z]:\\/.test(resolved)) return null;
    if (/[\0\r\n"%]/.test(resolved)) return null;
    return `"${resolved}"`;
  }
  if (!resolved.startsWith("/")) return null;
  if (/[\0\r\n'"]/.test(resolved)) return null;
  return `'${resolved}'`;
}

function writeFileAtomic(file: string, contents: string, mode: number): void {
  const temporary = `${file}.tmp`;
  writeFileSync(temporary, contents, { mode });
  chmodSync(temporary, mode);
  renameSync(temporary, file);
}

function removeFile(file: string): boolean {
  if (!existsSync(file)) return false;
  if (!statSync(file).isFile()) return false;
  rmSync(file);
  return true;
}

function registerWindowsHost(manifestPath: string): void {
  const result = spawnSync("reg", ["add", windowsRegistryKey(), "/ve", "/d", manifestPath, "/f"], {
    stdio: "ignore",
    windowsHide: true,
  });
  if (result.status !== 0) throw new Error("Chrome native host registry update failed");
}

function unregisterWindowsHost(): void {
  spawnSync("reg", ["delete", windowsRegistryKey(), "/f"], { stdio: "ignore", windowsHide: true });
}
