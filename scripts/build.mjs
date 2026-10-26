import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { deflateSync, crc32 } from "node:zlib";
import { build } from "esbuild";

const outfile = "apps/cli/dist/vigil.js";
mkdirSync(dirname(outfile), { recursive: true });
await build({
  entryPoints: ["apps/cli/src/main.ts"],
  bundle: true,
  platform: "node",
  target: "node22",
  format: "esm",
  outfile,
  banner: { js: "#!/usr/bin/env node" },
  legalComments: "none",
  logLevel: "info",
});
copyFileSync("packages/netcheck/certs/mozilla-cacert.pem", join(dirname(outfile), "mozilla-cacert.pem"));
chmodSync(outfile, 0o755);

const extensionDir = "apps/extension/dist";
mkdirSync(extensionDir, { recursive: true });
await build({
  entryPoints: {
    background: "apps/extension/src/background.ts",
    hold: "apps/extension/src/hold.ts",
    popup: "apps/extension/src/popup.ts",
  },
  bundle: true,
  platform: "browser",
  target: "chrome120",
  format: "esm",
  outdir: extensionDir,
  legalComments: "none",
  logLevel: "info",
});
await build({
  entryPoints: {
    "blank-guard": "apps/extension/src/blank-guard-main.ts",
    "blank-relay": "apps/extension/src/blank-relay.ts",
    "clickfix-guard": "apps/extension/src/clickfix-guard-main.ts",
    "seed-guard": "apps/extension/src/seed-guard-main.ts",
    "wallet-guard": "apps/extension/src/wallet-guard-main.ts",
  },
  bundle: true,
  platform: "browser",
  target: "chrome120",
  format: "iife",
  outdir: extensionDir,
  legalComments: "none",
  logLevel: "info",
});
copyFileSync("apps/extension/manifest.json", join(extensionDir, "manifest.json"));
copyFileSync("apps/extension/hold.html", join(extensionDir, "hold.html"));
copyFileSync("apps/extension/popup.html", join(extensionDir, "popup.html"));
writeFileSync(join(extensionDir, "icon16.png"), png(16, 120, 178, 214));
writeFileSync(join(extensionDir, "icon48.png"), png(48, 120, 178, 214));
writeFileSync(join(extensionDir, "icon128.png"), png(128, 120, 178, 214));

const safariResources = "apps/safari/Shared (Extension)/Resources";
mkdirSync(safariResources, { recursive: true });
for (const name of ["background.js", "hold.js", "popup.js", "hold.html", "popup.html", "icon16.png", "icon48.png", "icon128.png"]) {
  copyFileSync(join(extensionDir, name), join(safariResources, name));
}
copyFileSync("apps/safari/manifest.json", join(safariResources, "manifest.json"));

const blocklist = spawnSync("python3", ["apps/safari/scripts/generate-blocklist.py"], { stdio: "inherit" });
if (blocklist.status !== 0) process.exit(blocklist.status ?? 1);

function png(size, r, g, b) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 2;
  const raw = Buffer.alloc((size * 3 + 1) * size);
  for (let y = 0; y < size; y += 1) {
    const row = y * (size * 3 + 1);
    raw[row] = 0;
    for (let x = 0; x < size; x += 1) {
      const dx = x - size / 2;
      const dy = y - size / 2;
      const inside = dx * dx + dy * dy < (size * 0.38) ** 2;
      const offset = row + 1 + x * 3;
      raw[offset] = inside ? r : 14;
      raw[offset + 1] = inside ? g : 22;
      raw[offset + 2] = inside ? b : 34;
    }
  }
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
  return Buffer.concat([signature, chunk("IHDR", ihdr), chunk("IDAT", deflateSync(raw)), chunk("IEND", Buffer.alloc(0))]);
}

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body) >>> 0);
  return Buffer.concat([length, body, crc]);
}
