# Chrome extension

Unpacked load only. Do not upload this to the Chrome Web Store.

```text
pnpm install
pnpm build
```

In Chrome, open `chrome://extensions`, turn on Developer mode, and choose **Load unpacked**. Select `apps/extension/dist`.

The popup starts in normal mode: the badge can show a warning, and the page is not held. High Security Mode holds a site that is not allowlisted and has no fresh verdict. The hold page runs the check and sends the tab back when the result does not gate navigation.

Chrome launches the helper itself. High Security calls `runtime.connectNative` (`sendNativeMessage` when that API is missing) with host name `com.example.vigil` and one field, `{ "host": "<hostname>" }`. The host returns the same verdict as `vigil serve`: distrusted CA, invalid TLS, domain age, headers, and a confirmed PHP advisory. A slow registry lookup is capped so it cannot drop a certificate result that already finished. Header notes stay in the popup.

If that call fails, the extension uses `vigil serve` when the popup has `http://127.0.0.1:<port>`. `localhost` and `https://127.0.0.1` are rejected. If the loopback helper is blank or down, the extension judges the hostname locally (lookalikes, mixed script, IP literals) and does not call any other server. The whole sequence stays inside the 2 second fail-closed budget. A native host that never answers holds the page. A port that disconnects, or a host that exits during the check, also holds the page and shows helper unavailable. That result is not cached as an allow, and it does not fall through to the local hostname check. A missing host still does fall through.

The unpacked extension id is fixed by the public `key` in `apps/extension/manifest.json`. The private key is not in this repo. The id is `hldpadjbahmnkhfchiikihdofpelfjne`.

On a Mac, from the repo root:

```text
pnpm install
pnpm build
```

In Chrome, remove any previously loaded Vigil unpacked extension, then load `apps/extension/dist` again. Confirm the id is `hldpadjbahmnkhfchiikihdofpelfjne`. Then:

```text
pnpm vigil install-native-host --extension-id hldpadjbahmnkhfchiikihdofpelfjne
```

Quit Chrome completely and open it again so it reads the new host. High Security can leave the helper blank. `vigil uninstall-native-host` removes the host. The install writes only the current user's Chrome directory. It does not use sudo.

| System | Manifest |
|---|---|
| macOS | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.example.vigil.json` |
| Linux Chrome | `~/.config/google-chrome/NativeMessagingHosts/com.example.vigil.json` |
| Linux Chromium | `~/.config/chromium/NativeMessagingHosts/com.example.vigil.json` |
| Windows | `%LOCALAPPDATA%\Google\Chrome\NativeMessagingHosts\com.example.vigil.json` and `HKCU\Software\Google\Chrome\NativeMessagingHosts\com.example.vigil` |

`vigil serve` is still the fallback. It listens on `127.0.0.1:8787`, checks the `Host` header, and prints a token once. Put `http://127.0.0.1:8787` and that token in the popup only when the native host is not installed. The native host does not use the token. A process already bound to the port stops `vigil serve` from starting.

## What may hold a page

High Security keeps the hold page up only for:

- Certificate problems: `CERT_DISTRUSTED_CA`, `CERT_EXPIRED`, `CERT_HOSTNAME_MISMATCH`, `CERT_SELF_SIGNED`, `TLS_INVALID`.
- Fake-site signals: lookalike, similar name, mixed script, new domain, brand impersonation, IP literal, credential-form risk.
- Confirmed advisories: PHP `CVE-2026-109618` when a version is present, and exact LiteLLM `1.107.0`.

Missing headers, `KERNEL_SHARED_HOST`, SCT absence, expiring or SHA-1 certificates, suspicious TLDs, free-hosting suffixes, and a PHP fingerprint with no version stay in the popup. They do not keep the hold page up.

A check that does not finish within 2 seconds fails closed in High Security. The hold page says so and still offers an override. A missing native host, or a loopback helper that is not running (connection refused), falls back to the next check and does not send the tab back to the hold page on the next request. Saving the helper address again retries the loopback helper. A native host or loopback helper that accepts the connection and never answers stays held, and that timeout is not cached as an allow. A native port that disconnects or a host process that exits mid-check stays held with helper unavailable, including when the hostname itself looks clean. A helper response for a different host is treated as a failed check and stays held.

While High Security is on, a main-world script wraps `window.open` before page script runs. `about:blank`, `blob:`, `data:`, `javascript:`, and userinfo targets are opened as `about:blank` and sealed, so `document.write` cannot run a script. The new tab is then sent to the hold page. Normal mode does not install that script. Turning High Security on also injects it into tabs that are already open. A page that kept its own copy of `window.open` before that injection can still use the copy until it reloads.

Normal mode never redirects. The badge is set again when the navigation commits, because Chrome drops a badge that was set before the document committed.

## Red-team checklist

| Case | Expected | Covered by |
|---|---|---|
| Redirect chain | Each hop uses its own host. A cached allow for the first host does not allow the next. | `hopHosts` / `planBefore` in `packages/core/test/navigate.test.ts` |
| Open redirect via the hold page | The return URL must be the stashed http(s) URL for that tab. `javascript:`, `data:`, extension pages, userinfo, and a different host are rejected. | `returnHostMatches` |
| Unicode / IDN | The cache key is the punycode hostname from the URL parser, so a lookalike does not reuse the real brand's allow entry. | `canonicalHost` |
| Cache poisoning | An allow entry is rejected when it still lists a gating id, when its expiry is longer than the TTL, when the intel version differs, or when a local-only allow is reused after the helper is turned on. A page cannot write `chrome.storage`. | `readCache` |
| Timeout | High Security holds and does not write an allow. The override buttons remain. | `planAfter` and `runHoldScan` |
| Helper down vs helper hung | A connection failure, a non-200 answer, and a 2 second abort all hold. None of those write an allow. A 429 keeps the helper marked up. | `runHoldScan` in `apps/extension/test/gate.test.ts` |
| Native host missing vs hung vs killed | A missing host falls through to the loopback helper, then to the local hostname check. A host that never answers holds at 2 seconds. A port that disconnects, or a host that exits mid-check, stays held with helper unavailable and is not cached as an allow. | `apps/extension/test/chrome-native.test.ts` |
| Opener-created blank window | High Security seals `about:blank`, `blob:`, `data:`, `javascript:`, and userinfo windows a page opens, so `document.write` cannot run a script, then redirects that tab to the hold page. Normal mode does not install the seal. | `apps/extension/test/blank-guard.test.ts` |
| Headers and `KERNEL_SHARED_HOST` | Popup only. | `planAfter` and `runHoldScan` |
| Distrusted CA from the helper | Block, including when the machine trust store still accepts the chain. The helper uses Vigil's blocklist. | `hostVerdict` in `packages/netcheck/test/verdict.test.ts` |
| Known-bad shortcut | While High Security is on, session rules redirect every http(s) main frame to `hold.html` and block subframes, except allowlisted, one-time, and cached allow/warn hosts. `about:`, `blob:`, and userinfo URLs are held from the navigation handler without waiting on storage. Safari may reject the rules. The handler still holds the page. | `highSecurityRules` and `applySessionRules` |
| Remote code | Manifest CSP is `script-src 'self'`. No update URL, no external messaging, no telemetry. | manifest assertion in `gate.test.ts` |

Permissions are `storage`, `webNavigation`, `tabs`, `declarativeNetRequest`, `nativeMessaging`, and `scripting`, plus `http` and `https` host access so High Security can see top-level navigations. The only always-on content script is an isolated relay. It listens for one event from the blank-window guard and does not read the page. The guard itself is a main-world script registered only while High Security is on. The native host and the loopback helper each fetch the public URL themselves and drop the body before they answer. The native host does not log the request.

Safari loads the same scripts from `apps/safari` and asks the containing app for the certificate chain. It does not use this Chrome host. The browser differences, the native handler, and the Xcode steps are in `docs/SAFARI-TESTING.md`.
