# Independent test report, 2026-10-22

## Retest of `3be8f9c`

PR #7 moved to `3be8f9cd3aca685d876e0851a90988cccd015486` ("Fail closed when the native host dies and seal opener-created blank windows") on `cursor/vigil-publish-prep-8561`. The same Chrome for Testing setup was run again from a detached worktree. Nothing was pushed to that branch, and this retest does not merge it.

The two failures from `328b2d8` now pass. Normal mode still does not hold pages. The export is still one noreply commit.

| Check | Result | Notes |
|---|---|---|
| Native host killed mid-check | Pass | The host wrapper was `sleep`. During a High Security visit to `https://example.org/`, that process was sent `SIGKILL` after it started. The tab stayed on `hold.html`. Status: "helper unavailable. The native helper disconnected, so this page stays held." Reason `HELPER_UNAVAILABLE`. It did not load `example.org`. Two runs, at 1292ms and 1090ms, each still held a second later. On `328b2d8` this same kill released the site in 128ms. |
| `window.open("about:blank")` then `document.write` | Pass | High Security, allowlisted `http://parent.vigil.test:8765/parent`, trusted click. `window.__vigilBlankGuard` was set. `document.write` of a script that fetches `/blank-ran` returned without throwing. The beacon was not received. The new tab became `hold.html`, not `about:blank`. Status: "This blank window was held before script could run." |
| Normal mode, ordinary site | Pass | Popup mode `normal`, zero session rules. `https://example.com/` loaded "Example Domain" and never went to `hold.html`. |
| Normal mode, expired certificate | Pass | `https://expired.badssl.com/` ended on Chrome's own privacy error (`chrome-error://chromewebdata/`). Vigil did not redirect it to `hold.html`. |
| Normal mode, `window.open("about:blank")` | Pass | After leaving High Security and loading the parent page again, the blank guard was absent. `document.write` ran, `/normal-blank-ran` was received, and the child stayed on `about:blank`. |
| Sleeping native host, 2 second hold | Pass | A host that stays up and never replies still holds `https://example.com/` at 2049ms with "High Security did not finish within 2 seconds, so this page stays held." The tab was still `hold.html` afterward. A row in the longer script read an older hold page for `beacon.vigil.test` and is not this measurement. A fresh tab made the 2 second result above. |
| Distrusted-CA page is held | Pass | `https://dv-g3b-emudhra.we-have-a-problem.com/` stayed held. Title "Vigil blocked this site". Reasons `CERT_DISTRUSTED_CA`, `TLS_INVALID`, `DOMAIN_NEW`. |
| Expired certificate is held | Pass | `https://expired.badssl.com/` in High Security. Reasons `CERT_EXPIRED` and `TLS_INVALID`. |
| Young domain is held | Pass | `https://greenwam.com/` held with `DOMAIN_NEW` and `DOMAIN_BRAND_IMPERSONATION`. |
| Normal site passes in High Security | Pass | `https://example.com/` was held, then released. Title "Example Domain". |
| `chrome.tabs.create({ url: "about:blank" })` | Pass | Ended on `hold.html`. |
| `blob:` is held | Pass | The blob tab became `hold.html`. Its fetch beacon did not run. |
| Userinfo URL is held | Pass | A URL with embedded username and password ended on `hold.html` and did not continue to the host. Session storage contained that userinfo. The hold page's target line was empty on this run. |
| Subframes are blocked | Pass | Allowlisted `parent.vigil.test` loaded. `child.vigil.test` never hit the server. The iframe's client height was 0. |
| RT-01 hold before script | Pass | For `http://beacon.vigil.test:8765/beacon`, the hold page was up at 50ms and the server had received nothing. `/beacon`, `/ran`, and `/favicon.ico` arrived at 88ms, 98ms, and 101ms, after the local check released the name. |
| RT-02 helper HTTP 500 is not cached as allow | Pass | Native host manifest removed from the throwaway profile. Popup pointed at `http://127.0.0.1:8794` with a token. That server returned 500. `example.org` was held on the first visit and again on the second. |
| `vigil serve` token, Host, and taken port | Pass | Raw HTTP on `127.0.0.1:8791`, so the `Host` header was actually sent. Missing token: 401. `Host: rebinding.example:8791`: 403 with and without the token. Wrong token: 401. Matching token and `Host: 127.0.0.1:8791`: 200. A listener already bound to `127.0.0.1:8792` made `vigil serve --port 8792` exit 1 with "vigil serve will not share the port." Node's `fetch` cannot set `Host`; a first attempt that used `fetch` was discarded. |
| `node publish/export.mjs /tmp/out` | Pass | One commit, `c67d590a35857cc7f3440ab662649977831566e8`. Author and committer were `Vigil <vigil@users.noreply.github.com>`. `docs/HANDOFF.md` and `publish/` were omitted. The new blank-guard sources are in the snapshot. Grep found no personal name. The only `/Users/` and `/home/` hits are `/Users/example` and `/home/example`. Every `DEVELOPMENT_TEAM` is `XXXXXXXXXX`. The `AKIA`, `sk_live_`, `sk-`, `ghp_`, and `BEGIN PRIVATE KEY` hits are the vulnerable-fixture placeholders and the scanner patterns that look for them. No unexpected email addresses. |

`pnpm install && pnpm check` was not run again. RT-03 was not run again. This commit does not change the address denylist. The only edit in `packages/core/src/navigate.ts` is adding `"unavailable"` to the decision reason union.

Chrome for Testing was 156.0.8078.47, headful, with a throwaway `--user-data-dir`. The extension id was `hldpadjbahmnkhfchiikihdofpelfjne`. The native-host manifest was copied into that profile, because Chrome reads `NativeMessagingHosts` from the user-data directory. The host was uninstalled afterward, and the `vigil.test` line was removed from `/etc/hosts`.

## Earlier run at `328b2d8`

Tested `328b2d8bb68fedf645827c95fd33bef76853fc8c` ("Hold pages before script runs and fail closed on helper and DNS tricks"). That was the PR head at the time. The tree was checked out in a separate worktree. Nothing was pushed to that branch.

Two checks failed. Both are covered by the retest above.

- Killing the native host fail-opens. A host that stays connected and never replies holds the page at about 2 seconds. Killing that process released `https://example.org/` in 128ms.
- `window.open("about:blank")` followed by `document.write` still runs the written script. The tab stays on `about:blank`. A top-level navigation to `about:blank` that Chrome reports to the extension is held.

| Check | Result | Notes |
|---|---|---|
| `pnpm install && pnpm check` on Node 22.23.4 | Pass | Lint, typecheck, build, and 127 tests passed. The VM's default `node` is 22.23.3 at `/exec-daemon/node`, which `package.json` rejects, so the run put `~/.nvm/versions/node/v22.23.4/bin` first on `PATH`. pnpm warned that esbuild's install scripts were ignored. The bundle and the tests still ran. |
| `pnpm install && pnpm check` on Node 24.22.1 | Pass | Clean `node_modules`, then the same check. 24 files, 127 tests, exit 0. Same esbuild install-script warning. |
| Distrusted-CA page is held | Pass | High Security, native host installed. `https://dv-g3b-emudhra.we-have-a-problem.com/` stayed on the hold page: "Vigil blocked this site", reasons `CERT_DISTRUSTED_CA`, `TLS_INVALID`, and `DOMAIN_NEW`. OpenSSL showed the live intermediate `EM DV TLS CA - G3B` with SPKI `ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105`, which is the block-listed certificate. The registrable domain is also younger than 30 days, so the young-domain signal is present beside the certificate block. |
| Expired certificate is held | Pass | `https://expired.badssl.com/` stayed held. Reasons `CERT_EXPIRED` and `TLS_INVALID`. The leaf's `notAfter` is 12 Apr 2015. |
| Young domain is held | Pass | `https://greenwam.com/` was held with `DOMAIN_NEW`. Verisign RDAP says the domain was registered `2026-10-20T00:56:36Z`, two days before this run. The page also produced `DOMAIN_BRAND_IMPERSONATION`. The certificate was valid through Jan 2027, so the hold was not a certificate failure. |
| Normal site passes | Pass | `https://example.com/` was sent to the hold page and then released. The loaded title was "Example Domain". The native host's verdict for that host was header findings only. |
| `about:blank` is held | Fail | `chrome.tabs.create({ url: "about:blank" })` from the extension page ended on `hold.html`. `window.open("about:blank")` from an allowlisted page, followed by `document.write` of a script, did not. The script's request to the local beacon was received, and the new tab was still `about:blank` one second later. |
| `blob:` is held | Pass | A top-level `blob:` URL created in the extension page was replaced with `hold.html`. The blob's fetch beacon did not run. |
| Userinfo URL is held | Pass | A URL with embedded username and password ended on the hold page. Session state still contained that userinfo. |
| Subframes are blocked | Pass | With `parent.vigil.test` allowlisted, `http://parent.vigil.test:8765/parent` loaded and its full-window iframe of `child.vigil.test` did not. The child path never hit the server. The iframe's client height was 0. |
| 2s fail-closed when the helper is killed | Fail | Replacing the native-host wrapper with `sleep`, then visiting `https://example.com/`, held the tab at 2064ms with "High Security did not finish within 2 seconds, so this page stays held." Killing that process during a visit to `https://example.org/` released the site in 128ms. The extension treats a closed native port as an unavailable host and falls through to the local name check. A normal name is then allowed. |
| `vigil serve` token, Host, and taken port | Pass | On `127.0.0.1:8791`, a missing token returned 401 `unauthorized`. `Host: rebinding.example:8791` returned 403 `host rejected` with and without the token. A wrong token returned 401. The matching token and `Host: 127.0.0.1:8791` returned 200 for `example.com`. A listener already bound to `127.0.0.1:8792` made `vigil serve --port 8792` exit 1 with "vigil serve will not share the port." |
| RT-01 https hold-before-script | Pass | For `http://beacon.vigil.test:8765/beacon`, the hold page was up at 15ms and the server had received nothing yet. The document, its script beacon, and the favicon arrived only after that, at 96ms, 115ms, and 116ms, when the local check released the name. |
| RT-01 `about:blank` document.write | Fail | Same result as the `about:blank` row. The repro in `docs/redteam-2026-10-21.md` on PR #8 still runs the written script. |
| RT-02 unauthenticated helper and bad Host | Pass | The old repro, `GET /api/v1/verdict?host=example.com` with `Host: rebinding.example:8787`, no longer returns 200. A helper that returns HTTP 500, with the native host removed and the popup pointed at that helper, held `example.org` on the first visit and again on the second. The failure was not cached as an allow. |
| RT-03 private addresses are not dialed | Pass | `inspectUrl` rejected `64:ff9b::7f00:1`, `64:ff9b::127.0.0.1`, `2002:7f00:1::`, `fec0::1`, `224.0.0.1`, `255.255.255.255`, `::ffff:127.0.0.1`, `127.0.0.1`, `2130706433`, and `0x7f000001`. `127.0.0.1.nip.io` resolves to `127.0.0.1` on this VM. `pinAddress` and `hostVerdict` both threw `UrlRejected: Address is not allowed`. A root listener on `127.0.0.1:443` saw no connection while that verdict ran. |
| `node publish/export.mjs /tmp/out` | Pass | One commit, `7bd0ec2e444922118a0d1dd4463a995ea84a2c0e`. Author and committer were `Vigil <vigil@users.noreply.github.com>`. `docs/HANDOFF.md` and `publish/` were omitted. Grep found no personal name. The only `/Users/` and `/home/` hits are `/Users/example` and `/home/example` in the native-host path test. Every `DEVELOPMENT_TEAM` is `XXXXXXXXXX`. The `AKIA`, `sk_live_`, `sk-`, `ghp_`, and `BEGIN PRIVATE KEY` hits are the vulnerable-fixture placeholders and the scanner patterns that look for them. No other email addresses. |

## How the browser was run

Branded Google Chrome 156.0.8078.47 refuses `--load-extension` ("--load-extension is not allowed in Google Chrome, ignoring."). The unpacked extension was loaded in Chrome for Testing 156.0.8078.47, in a throwaway `--user-data-dir`, with a fresh profile each launch.

`vigil install-native-host --extension-id hldpadjbahmnkhfchiikihdofpelfjne` wrote the user-level manifests for Google Chrome and Chromium. The loaded extension id matched that id. Chrome's user native-messaging directory is the profile's user-data directory plus `NativeMessagingHosts`. A custom `--user-data-dir` therefore does not read `~/.config/google-chrome/NativeMessagingHosts`. The test copied the manifest the installer had just written into the throwaway profile. The wrapper path inside that manifest was the installer's wrapper. The host was removed with `vigil uninstall-native-host` after the run.

High Security was turned on from the extension popup. The session rules were a main-frame redirect to `hold.html` and a subframe block.
