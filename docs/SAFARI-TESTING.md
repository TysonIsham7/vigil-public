# Safari testing

Safari uses the same extension scripts as Chrome: `apps/extension/src`. Safari-only behavior sits in `apps/extension/src/platform.ts`, `apps/safari/manifest.json`, and the Xcode container. The unit tests in this repo exercise that shared logic and lint the manifest, plists, and project file. They do not launch Safari or Xcode. A green `pnpm check` is not a Safari pass. Run the steps below on a Mac.

iOS, including Safari on iPhone, is an upcoming release. This tree does not include an iOS app, an iOS extension, or an iOS scheme.

The container is a local build. Do not archive it for distribution, and do not upload it to App Store Connect or TestFlight.

## Build the extension resources

From the repo root:

```text
pnpm install
pnpm build
```

`pnpm build` writes the Chrome package to `apps/extension/dist` and copies `background.js`, `hold.js`, `popup.js`, `hold.html`, `popup.html`, the icons, and `apps/safari/manifest.json` into `apps/safari/Shared (Extension)/Resources`. It also writes `DistrustedCAs.swift` from `packages/intel/data/distrusted-cas.json`. Those generated files stay out of git. Open the Xcode project after this build so the Resources folder contains a manifest. The Xcode targets run the same generator before compiling, so a later `xcodebuild` refreshes the blocklist from the intel file.

## Xcode container

`apps/safari/Vigil.xcodeproj` follows the layout `safari-web-extension-converter` produces:

| Group | Target |
|---|---|
| macOS (App) | Vigil macOS |
| macOS (Extension) | Vigil macOS Extension, embedded in the app |
| Shared (App) | SwiftUI container UI, compiled into the macOS app |
| Shared (Extension) | `SafariWebExtensionHandler.swift`, `NativeCertCheck.swift`, the generated blocklist, and the Resources folder |
| Vigil macOS Tests | XCTest target compiled by the Vigil macOS scheme |

The shared scheme is **Vigil macOS**. The deployment target is macOS 14.0 so the project opens on a current Xcode. There is no asset catalog and no storyboard. `GENERATE_INFOPLIST_FILE` is NO. The extension point is `com.apple.Safari.web-extension`, and the principal class is `$(PRODUCT_MODULE_NAME).SafariWebExtensionHandler`.

The app product is `VigilMac.app`. The extension product is `VigilMacExtension.appex`. Target names stay **Vigil macOS**, **Vigil macOS Extension**, and **Vigil macOS Tests**. Each product file reference uses `explicitFileType` `wrapper.application` or `wrapper.app-extension` and `sourceTree` `BUILT_PRODUCTS_DIR`. The macOS app embeds `VigilMacExtension.appex`.

`CONTENTS_FOLDER_PATH`, `INFOPLIST_PATH`, `EXECUTABLE_PATH`, `EXECUTABLE_FOLDER_PATH`, `WRAPPER_EXTENSION`, and `WRAPPER_NAME` stay unset. The product type supplies those paths inside the wrapper. Setting them in the project writes `Info.plist` and `Contents` into the products directory, and Xcode then reports that multiple commands produce the same file. `apps/safari/project.yml` is the same target list for XcodeGen. The checked-in `Vigil.xcodeproj` is the project the command below builds. `CFBundleExecutable` is `$(EXECUTABLE_NAME)`. The extension bundle id is `com.example.vigil.macos.extension`, prefixed by `com.example.vigil.macos`. `GENERATE_INFOPLIST_FILE` is NO.

`pnpm check` runs this check. You can run it on its own from the repo root:

```text
node apps/safari/scripts/check-ios-extension.mjs
```

The committed `DEVELOPMENT_TEAM` is the placeholder `XXXXXXXXXX`. Bundle ids are `com.example.vigil.macos`, `com.example.vigil.macos.extension`, and `com.example.vigil.macos.tests`. In Xcode, select each target, open Signing & Capabilities, and choose your development team. Leave the committed project on the placeholder. Do not commit a real team id, a machine name, a username, or a device name.

Product → Run is the path that loads the extension in Safari. That run has to be signed, so select a team first. Signing fails until a team is selected locally.

This repository's checks do not run Xcode. On the Mac, this command is the compile check. Run it from the repo root after `pnpm build`:

```text
xcodebuild -project apps/safari/Vigil.xcodeproj -scheme "Vigil macOS" -destination "platform=macOS" CODE_SIGNING_ALLOWED=NO build
```

The macOS build writes `Debug/VigilMac.app/Contents/PlugIns/VigilMacExtension.appex`, with the plist at `Contents/Info.plist`.

Wrapper path overrides (`CONTENTS_FOLDER_PATH`, `INFOPLIST_PATH`, and the related path settings) stay unset. Those settings are relative to the products directory, so setting them makes Xcode report `Multiple commands produce` for `Info.plist` and `Contents`. Product names stay unique.

The macOS scheme **Vigil macOS** built with Xcode 27.1 and `CODE_SIGNING_ALLOWED=NO`. `CODE_SIGNING_ALLOWED=NO` compiles without a real team. It does not produce a build Safari will load. Product → Run, with a team selected and that change left uncommitted, is the signed run. The macOS scheme also builds the `Vigil macOS Tests` bundle. The extension target generates `DistrustedCAs.swift`, and the test bundle depends on that target so the file has one producer. To execute those tests:

```text
xcodebuild -project apps/safari/Vigil.xcodeproj -scheme "Vigil macOS" -destination "platform=macOS" test
```

Run that `test` action after a development team is selected locally. Leave the committed team placeholder unchanged. An unsigned test bundle can compile and still refuse to load.

## Mac

1. Open `apps/safari/Vigil.xcodeproj`.
2. Scheme: **Vigil macOS**. Destination: My Mac.
3. Product → Run. The container window opens.
4. If the system blocks the app, allow it from System Settings → Privacy & Security.
5. Quit Safari if it is open, then open Safari again.
6. Safari → Settings → Extensions. Enable Vigil.
7. For this test, set Vigil's website access to all websites. Safari otherwise asks once per site.
8. Click the Vigil toolbar button. The popup is the same page as the Chrome extension.
9. Switch the mode to High Security. Leave the helper blank for the first pass. The certificate check runs in the app.

The fallback helper is still `pnpm vigil serve` from the repo root. It listens on `127.0.0.1:8787` only and prints a token once. Put `http://127.0.0.1:8787` and that token in the popup when you want that fallback. `localhost` and `https://127.0.0.1` are rejected. The accepted origin is `http://127.0.0.1:<port>` with an empty path. The native host stays the default and does not use the token.

## Upcoming iOS release

Safari on iPhone is not in this release. There is no iOS scheme to run, and these steps do not cover a phone.

## Manual checks

Use High Security on the Mac. The native certificate check is the first path. `vigil serve` runs only when that call fails.

High Security, native handler available:

| Visit | Expected |
|---|---|
| `https://dv-g3b-emudhra.we-have-a-problem.com/` | Hold page, then a block. Title starts with "Vigil blocked". The signal includes `CERT_DISTRUSTED_CA`. |
| `https://example.com/` | The site loads when the system trusts the chain and Vigil's blocklist does not hit. Header notes such as `HEADER_CSP` appear when the native call failed and the loopback helper answered. A successful native check does not fetch the page, so those notes are absent. |
| `https://www.xn--80ak6aa92e.com/` | Hold. The signal includes `DOMAIN_LOOKALIKE`. |
| Proceed this time on that hold | The site loads once. The next visit holds again. |
| Always allow this site | The site loads, and a later visit skips the hold. |

Native call failed, helper blank:

| Visit | Expected |
|---|---|
| `https://example.com/` | Hostname check only. The site loads. It is not held for headers. |
| The punycode host above | Still held. Lookalikes do not need a certificate check. |
| The eMudhra host above | The real page can load. There is no certificate block without the native handler or the helper. |

Native call failed, helper running at `http://127.0.0.1:8787`:

| Visit | Expected |
|---|---|
| The eMudhra host | Block, with `CERT_DISTRUSTED_CA`, from the helper. |
| `https://example.com/` | The site loads. The popup can list header notes. |

Native call failed, helper hung (a process accepts TCP on `127.0.0.1:8787` and writes nothing):

| Visit | Expected |
|---|---|
| `https://example.com/` | The hold page stays up after 2 seconds and says High Security did not finish within 2 seconds. That timeout is not saved as an allow. |

A native check that does not return before the budget ends, with no helper configured, uses that same 2 second fail-closed hold. When a helper is configured, a fast native failure leaves the rest of the 2 seconds for the helper. A native success does not call the helper.

Normal mode:

| Visit | Expected |
|---|---|
| Any of the hosts above | The browser stays on the site. macOS may show `!` or `?` on the toolbar. The popup has the decision. The page is not redirected to the hold page. |

Also confirm the popup rejects a helper value of `http://localhost:8787` and `https://127.0.0.1:8787`.

## Browser differences

These are the Chrome APIs Safari is known to lack or to handle differently, and what Vigil does about each one.

### declarativeNetRequest session rules

Chrome installs session rules that redirect a cached hold or block host to `hold.html` before the service worker wakes. Safari's `declarativeNetRequest` support is narrower: session rules may be missing, `extensionPath` redirects may be rejected, and the dynamic-rule quota is a poor place for a temporary hold. Persistent dynamic rules are not used, because a leftover redirect would keep holding a site after a switch back to normal mode if the worker never cleared it.

`applySessionRules` calls `getSessionRules` and `updateSessionRules`. A missing method or a thrown rejection returns `{ applied: false }` and the navigation continues. The rule list is still capped at 100 hosts. `webNavigation` remains the gate, so a rejected rule does not leave the site open in High Security.

The Safari manifest does not request `declarativeNetRequestWithHostAccess`. An unknown permission can make Safari refuse the extension.

### webNavigation

`onBeforeNavigate` is the gate for a top-level http(s) navigation. Some Safari transitions, including back-forward cache restores, can skip that event and only deliver `onCommitted`. The commit listener calls the same `noteNavigation` path. An armed key of tab id plus URL means the first event wins, so a browser that fires both events does not redirect twice.

If Safari also omits `onCommitted`, the listener is skipped (`onCommitted?.addListener`) and the extension still loads. A navigation that never produces `onBeforeNavigate` would not be held. That is the gap to watch on the device: a hold that appears only after a short paint means the before-event was skipped and the commit event caught it.

`tabs.onUpdated` is optional for the same reason. It only reapplies the badge.

### Service-worker storage

Chrome keeps `chrome.storage.session` for the browser session, and it drops the in-memory once-set and helper-down flag when the worker stops. Safari stops the worker aggressively and may omit `storage.session`.

The once-set ("Proceed this time") and the helper-down flag are written through `readEphemeral` / `writeEphemeral` on every change. The tab stash and the popup decision already live in the session area (`url:<tabId>`, `decision:<tabId>`). `createSessionArea` uses `chrome.storage.session` when it exists. Otherwise it stores those keys in `chrome.storage.local` under `vigil-session`.

`runtime.onStartup`, when it exists and session storage does not, deletes that bag so a browser restart clears "Proceed this time". If Safari never fires `onStartup`, the bag can outlive a Safari restart until extension storage is cleared. "Always allow" is stored with the normal extension state and is meant to persist. A timeout still does not write an allow entry.

### Toolbar badge

`setBadge` no-ops when `setBadgeText` or `setBadgeBackgroundColor` is missing or throws. The hold page and the popup still show the decision. macOS Safari can show a badge. The badge is applied again on commit and on a completed tab update, because a badge set before the document commits can be cleared.

### Localhost fetch

`http://*/*` does not reliably include loopback on Safari. The Safari manifest adds `http://127.0.0.1/*`. The accepted helper origin is still only `http://127.0.0.1:<port>`.

Each app and extension Info.plist sets `NSAppTransportSecurity` → `NSAllowsLocalNetworking`. `NSAllowsArbitraryLoads` is not set. The macOS app and the macOS extension entitlements enable the app sandbox and `com.apple.security.network.client`. There is no app group.

### On-device certificate check

Safari calls `runtime.sendNativeMessage` with the containing app id (`com.example.vigil.macos`) and one field, `url`, set to `https://<host>/`. The handler treats that dictionary as untrusted input. It accepts an https URL whose host is a DNS name, with no userinfo, no path, no query, no fragment, and no port other than 443. It opens that host on port 443, copies the server certificate chain from the `URLSession` server-trust challenge, and cancels the transfer so the page body is not downloaded. Redirects are cancelled. `SecTrustSetNetworkFetchAllowed` is false, so trust evaluation does not make a second request. The handler does not log the message or the reply.

The chain is judged with `SecTrust` and with Vigil's blocklist. The blocklist is generated at build time from `packages/intel/data/distrusted-cas.json`. A block-listed SPKI or certificate fingerprint, including the emSign and eMudhra entries, is `CERT_DISTRUSTED_CA` even when the system still trusts the chain. Expired leaves, a name that does not match, a self-signed leaf, and a system trust failure are returned as `CERT_EXPIRED`, `CERT_HOSTNAME_MISMATCH`, `CERT_SELF_SIGNED`, and `TLS_INVALID`. The JSON shape matches `vigil serve`: `host`, `intelVersion`, `coverage: "full"`, and `signals`. Record-only roots stay out of the block set.

A rejected message or a transport failure is `{ "error": "rejected" }` or `{ "error": "unavailable" }`. The extension then uses `vigil serve` when the popup has a loopback origin. Chrome does not call this Safari handler. Chrome's own host is `com.example.vigil`, and the shared script still tells the browsers apart by the explicit `http://127.0.0.1/*` permission, which only the Safari manifest has.

## What a green unit run means

`pnpm check` lints, typechecks, bundles, and runs the unit tests, including `apps/extension/test/platform.test.ts` and `apps/safari/test/scaffold.test.ts`. Record the Mac results from the tables above separately. Those results are the Safari pass.
