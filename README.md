# Vigil

Vigil is an early first-pass check for certificates, lookalike sites, and a few known advisories. It is not an audit, not antivirus, and not a store release. A green result means the checks below did not fire. It does not mean the site, the server, or the account is safe.

The Chrome extension and the command-line helper run today. The macOS Safari container has built with Xcode 27.1 when code signing is turned off for the compile. The iOS appex copies its web files to the bundle root so the simulator embed check can read Info.plist. Verify that build on a Mac. See [Safari and iOS](#safari-and-ios).

## What Vigil catches

- A certificate that chains through a block-listed key. The bundled list includes the eight compromised eMudhra intermediates and emSign ECC Root CA - G3. Record-only parent roots are not blanket-distrusted.
- An expired certificate, a name that does not match the host, a self-signed leaf, or a TLS chain the pinned Mozilla roots reject.
- Lookalike and homoglyph names, mixed-script labels, and a login form on a domain younger than seven days.
- A page that discloses a PHP version below 8.2.35, 8.3.36, 8.4.27, or 8.5.12. The owner's scan blocks. A visitor scan warns. The finding says to upgrade PHP. CISA added CVE-2026-109618 and CVE-2026-109619 to the Known Exploited Vulnerabilities catalog on 26 October 2026. `session.upload_progress.enabled=0` is only a partial mitigation for CVE-2026-109619. A disclosed version at or above those releases still gets an informational note for CVE-2026-115560, which has no patched release yet. That note does not block a deploy or hold a page. `vigil check-url` and the popup also classify `X-Powered-By` and `Server` as PHP2Shell `exposed`, `patched`, `hidden`, or `not-PHP`. Those floors, and the rule that 8.1 and older are end of life, live in `packages/intel/advisories/php-cve-2026-109618.json`. A hidden version is not called patched. The class uses headers the check already has.
- An exact LiteLLM 1.107.0 pin in a lockfile or Dockerfile.
- In the Chrome extension: a page writing a shell or Run-dialog command to the clipboard, a checksum-valid 12, 15, 18, 21, or 24 word BIP39 recovery phrase before it is entered, and a risky EIP-1193 request before the wallet sees it. That is `eth_sign`, an unlimited `approve`, `setApprovalForAll(true)`, Permit or Permit2 typed data, or a spender not already allowed on that page. Each guard can be turned off in the popup. None of them phone home, and the recovery phrase is not stored or logged.
- On `vigil doctor`: a local Node below 22.23.4, 24.22.1, or 26.12.1 on that release line, an affected curl or Go, a local nginx below 1.31.7 on the mainline or 1.30.6 on the 1.30 line, pip older than 26.2.2, uv older than 0.13.4, a local Python below 3.15.2, 3.14.10, 3.13.18, 3.12.16, or 3.11.18 on that line (and Python 3.10 or older), a local kernel in the PwnEscape range, and a trust store that still contains a distrusted eMudhra key. A Python tag with no patch on 3.11 through 3.15 is left alone. Python 3.16 and newer are not compared with 3.16.0. Doctor also runs `vigil trust-audit`. Doctor does not block a deploy.
- A page that addresses an agent and asks for identity, a credential, or a behavior change (`AGENT_DIRECTED_REQUEST` on `vigil check-url` and an owner URL scan). The finding is a warning. It does not block a deploy and it does not hold the page. The separate `vigil agent-guard` proxy is what watches bytes a configured client actually sends.

Missing security headers and the shared-host kernel note stay in the popup. They do not hold the page in High Security Mode.

Reputation lookups stay off and send no host. Certificate Transparency queries run only with `--ct`, and only for the registrable domain.

## Vigil doesn't fix everything

When a server itself is compromised, its certificate can still pass Vigil's checks. A valid certificate does not mean a safe site. Watch for breach disclosures from the operator. Change passwords and keys that were stored there. Turn on two-factor authentication and passkeys. Treat an unexpected reset, verify, or payment email as phishing, and do not follow links or instructions inside it.

These are the same kind of gap. Vigil does not close them:

- **Server-side breaches and patches.** Railway's 21 October 2026 environment-variable disclosure, and Vercel's April 2026 bulletin (closed 16 October 2026), live in a platform dashboard. A clean source tree does not show or rotate those secrets. Vigil also does not patch PHP, GitLab, nginx, or OpenSSL on a server, and it does not see a QUIC or HTTP/3 stack. The helper speaks HTTP/1.1. It does not see a self-managed GitLab version. CISA added CVE-2026-97229 (GitLab) and CVE-2026-76418 (Cisco Secure Firewall ASA and FTD) on 29 October 2026. Vigil cannot see the firewall from a page or a certificate, and it does not request a version endpoint for either product. A visitor warning is not a patch. A PHP page that hides its version is only a suspicion. A site scan does not read the server's nginx version. `vigil doctor` only reports a local `nginx -v` and a Dockerfile tag.
- **Device-code phishing.** A real identity-provider page can ask for a device code and approve a session for someone else. The certificate is valid. Vigil does not see that approval. Do not enter a device code you did not start.
- **ClickFix.** The Chrome extension holds a clipboard write that looks like a shell or Run-dialog command (PowerShell, mshta, `curl` piped to a shell, certutil, bitsadmin, or a base64 blob that decodes to one of those) until the person copies it anyway or cancels. A command shown as text or a picture, and one the person types by hand, still go through. A credential form that appears only after JavaScript or a CAPTCHA is not visible to the fetch. Safari and iOS do not run these hooks.
- **Chrome Certificate Transparency.** Vigil counts embedded SCT bytes. It does not check SCT signatures, log operators, or Chrome's per-root cutoffs, and it does not copy every Chrome root-store removal that another store still trusts. The distrust file is a snapshot. Vigil does not consume CRLSet, OneCRL, or CRLite. A 27 October 2026 re-check still found the Chrome post saying that emSign ECC Root CA - G3 removal was expected that morning PDT. Keep the block and re-check after 28 October 2026 before changing that file. CPython's ssl denylist for the same intermediate keys (CVE-2026-115557) is not in a stable release as of 25 October 2026. python.org lists 3.16 as a pre-release, and 3.15.1, 3.14.9, and 3.13.17 are the 21 October releases. Doctor does not compare `python --version` with 3.16.0. See `docs/TODO.md`.
- **Live reputation feeds.** Safe Browsing, PhishTank, and similar lookups stay off. A static brand table misses a kit on the real domain and a kit on an aged or hijacked tenant.
- **Agent leaks.** The page check misses script-generated text, external stylesheets, and any agent that never fetches the page through Vigil. `vigil agent-guard` misses every client that does not use its proxy, HTTP/3, HTTPS while tunnel mode is refusing `CONNECT`, and identifiers that were not on the local list. See [Agent guard](#agent-guard).

A page and a certificate also do not show the host kernel behind a site. `KERNEL_SHARED_HOST` says that, and it does not claim the remote machine is vulnerable.

## Layout

| Path | Role |
|---|---|
| `packages/core` | Rules, report schema 2.0, SSRF policy, taxonomy |
| `packages/intel` | Distrusted CAs, brand and homoglyph tables, advisory JSON |
| `packages/netcheck` | Pinned Mozilla TLS, RDAP age, OSV, URL composition |
| `apps/cli` | `vigil scan`, `gate`, `check-url`, `check-backend`, `deps`, `doctor`, `trust-audit`, `serve`, `native-host`, `agent-guard` |
| `apps/extension` | Chrome MV3 extension. High Security Mode holds unknown sites. Not a store release. |
| `apps/safari` | macOS and iOS container for the same extension. Placeholder team id. Not an App Store release. |
| `fixtures/` | Vulnerable, clean, phishing, lockfile, and toolchain samples |
| `docs/TAXONOMY.md` | How findings map to the eleven domains, NIST CSF 2.0, and CIS Controls v8.1 |
| `docs/CHECK-BACKEND.md` | Passive backend exposure check: what it sends, what it refuses to send, and how findings map |
| `docs/AGENT-GUARD.md` | Page check, loopback proxy, allowlist, and HTTPS_PROXY wiring |
| `docs/agent-skill-vuln-watch.md` | A routine someone can give their own agent for public vulnerability announcements |
| `publish/export.mjs` | Builds a scrubbed tree for a separate public repository. It does not publish. |

Rule ids, domains, and framework mappings live in `packages/core/data/rule-catalog.json`. Reports always include `summary.byDomain` for all eleven domains.

Bundle ids are `com.example.vigil.*`. The committed Apple team id is the placeholder `XXXXXXXXXX`. The Chrome extension's `key` is a public SubjectPublicKeyInfo used to keep the unpacked extension id stable. The private key is not in this repository. None of these identifiers are tied to a personal Apple team.

## Commands

```text
vigil scan <path|url> [--json] [--prompt [text]] [--hosting vercel|netlify|cloudflare]
                      [--allow-host name] [--sample] [--ct]
vigil gate <npm:name@version|path.tgz|package-dir> [--json]
vigil check-url <url>
vigil check-backend <url> [--json]
vigil deps [path]
vigil doctor [path]
vigil trust-audit [--json]
vigil serve [--port 8787]
vigil native-host
vigil install-native-host --extension-id <id>
vigil uninstall-native-host
vigil agent-guard [--port 0] [--mode tunnel|intercept]
```

`vigil gate` reads an npm package without installing it. It follows the bin and main graph, including `dist`, and it reads registry lifecycle scripts. It does not run npm, npx, or those scripts. A registry tarball is checked against its integrity hash before it is unpacked. Exit 2 means do not install: install behavior, an unread graph file, a computed import, or the gate file budget. Exit 1 is usage, network, or a hash mismatch. `scan` is unchanged and still skips `dist`.

`scan` of a URL is the site owner. `check-url` is a visitor. `check-backend` fingerprints the backend of a site you visit: response headers, one browser-style TLS handshake, TLS 1.0 and TLS 1.1 support handshakes, time until response headers, one missing-page GET, and a short list of known-path GETs. It does not send a request body, a crash payload, or exploit code. PHP versions come from headers and use the same patched releases as the other PHP check (8.5.12, 8.4.27, 8.3.36, 8.2.35). PHP 5-7 is never patched. PHP with no version is unknown. A disclosed version that already meets those releases still gets the informational `PHP_CVE_2026_115560` note. A fingerprint does not set `block_deploy`. Probing a host you do not own may breach its terms of service or computer-misuse law. See `docs/CHECK-BACKEND.md`. `deps` exits 2 on an exact LiteLLM 1.107.0 pin. `doctor` reads the running Node (`process.version`), local curl, Go, `nginx -v`, pip, uv, Python (`python3 --version`, then `python --version`), `uname -r`, and the ca-certificates, certifi, and Node trust stores. It exits 0 even when it reports a finding. Node should be 22.23.4 or newer on the 22 line, 24.22.1 or newer on the 24 line, or 26.12.1 or newer on the 26 line. Go's eMudhra filter is 1.27.3 or newer, or 1.26.10 on the 1.26 line. nginx should be 1.31.7 or newer on the mainline, or 1.30.6 or newer on the 1.30 line. pip should be 26.2.2 or newer, and uv 0.13.4 or newer, so they drop the vendored certifi from before the eMudhra removal. Python should be 3.15.2, 3.14.10, 3.13.18, 3.12.16, or 3.11.18, or newer on that line. A pre-release of that floor is still reported. A `+` local build of the same triple is not.

`trust-audit` asks whether the tools on this machine still trust the compromised eMudhra intermediate chains. The host list and root fingerprints live in `apps/cli/src/trust-incidents.json`, so a later CA incident is a data change. It probes Node's own TLS, and curl, git (`ls-remote`), and python3 urllib when those programs are on `PATH`. On macOS it also probes nscurl and reads `security dump-trust-settings` for the user and admin domains. A TLS error is `blocked`. A completed handshake is `exposed`. A timeout is `unknown`. It does not mean the tool rejected the chain. The command prints remediation for each exposed tool: update ca-certificates, certifi, Go, or Node, or on macOS mark the root Never Trust with `security add-trusted-cert -r deny -k ~/Library/Keychains/login.keychain-db <pem>`. It only prints that command. It does not change trust settings, shell profiles, or system files. Probes stop at the TLS handshake or an HTTP HEAD. curl ignores its config file. git uses ls-remote with prompts, askpass, and user git config disabled, and it does not push. `doctor` runs the same audit. `trust-audit` exits 0 when the audit finishes.

Exit 0 means the command finished and `block_deploy` is false. Exit 2 means `block_deploy`. Exit 1 is usage, SSRF, or a network failure. A critical finding blocks only when `recommendationOnly` is false.

## Agent guard

`AGENT_DIRECTED_REQUEST` and `vigil agent-guard` are different features. The page check is a warning in the scan report. The guard is a loopback proxy the person starts and points a client at. Details, CA risks, and the miss list are in [docs/AGENT-GUARD.md](docs/AGENT-GUARD.md).

The guard prints `http://<token>@127.0.0.1:<port>`. Set both proxy variables to that URL and keep loopback out of the proxy:

```text
HTTP_PROXY=http://<token>@127.0.0.1:<port>
HTTPS_PROXY=http://<token>@127.0.0.1:<port>
NO_PROXY=localhost,127.0.0.1,::1
```

Do not put public hosts in `NO_PROXY`. The default mode is `tunnel`: plain HTTP is inspected, and every `CONNECT` is refused. The shippable guard does not open a `CONNECT` tunnel without inspection. `--mode intercept` decrypts HTTPS, including allowlisted hosts, and uses a process-scoped CA. Do not install that CA in the operating system trust store. Do not pass curl `--insecure`. Use `--cacert` only for intercept mode.

curl uses the variables above, or `--proxy` for one invocation. Claude Code should be started with the same variables, plus `NODE_USE_ENV_PROXY=1` when Node fetch needs it, and `NODE_EXTRA_CA_CERTS` set to the printed certificate in intercept mode. Cursor can set `http.proxy` to the same URL when the field accepts a token, `http.proxySupport` to `override`, and `http.noProxy` to `localhost,127.0.0.1,::1`. Cursor's HTTPS calls need intercept mode. A cloud agent needs its own guard on that machine. Do not copy a CA key there.

`allow` means a matched identifier may be forwarded after inspection. It does not skip the check. Allowlist entries are exact hosts. Cloud metadata addresses stay blocked even if they are listed. The identifier file is mode `0600` and is never committed. `docs/agent-guard.sample` contains placeholders only.

## Dev

Node must satisfy `package.json` `engines`: `>=22.23.4 <23`, `>=24.22.1 <25`, or `>=26.12.1`.

```text
pnpm install
pnpm check
pnpm vigil scan fixtures/vulnerable
```

`pnpm check` lints, typechecks, bundles the CLI, and runs the tests. Tests do not use the live network. The bundle copies the Mozilla CA file next to `apps/cli/dist/vigil.js`.

## Chrome extension

`pnpm build` writes an unpacked extension to `apps/extension/dist`. Load that folder from `chrome://extensions` with Developer mode on. It is not published to the Chrome Web Store.

Normal mode only updates the toolbar badge. High Security Mode sends an unknown site to the extension hold page before page script runs, runs the check, and continues when the result is not a certificate failure, a fake-site signal, or a confirmed advisory. Missing security headers and notes such as `KERNEL_SHARED_HOST` stay in the popup. The 2 second limit starts when the navigation starts. A check that runs past it stays held, with **Proceed this time** and **Always allow this site**.

Certificate and domain-age checks run in `vigil native-host`, which Chrome launches through native messaging. That is the default path. `vigil serve` on `127.0.0.1:8787` is the fallback: it prints a token once, and the popup must have that token. A configured helper that fails keeps the page held. With no helper configured, High Security uses the local hostname check. The stable unpacked extension id is `hldpadjbahmnkhfchiikihdofpelfjne`. From the repo root, after `pnpm build` and loading `apps/extension/dist`:

```text
pnpm vigil install-native-host --extension-id hldpadjbahmnkhfchiikihdofpelfjne
```

Quit Chrome and open it again. The helper field can stay blank. See `docs/EXTENSION.md` for the host paths and the red-team checklist.

## Safari and iOS

`pnpm build` copies the same background, hold page, and popup into `apps/safari/Shared (Extension)/Resources`, with the Safari manifest. Open `apps/safari/Vigil.xcodeproj` on a Mac after that build. The committed team id is `XXXXXXXXXX` and the bundle ids are `com.example.vigil.*`. Set the team in Xcode and leave that change uncommitted.

On Safari, the certificate check runs in the app through `runtime.sendNativeMessage`. `vigil serve` on `127.0.0.1:8787` is the fallback when that call fails. On an iPhone, `127.0.0.1` is the phone. Build and test steps, including the `xcodebuild` commands, are in `docs/SAFARI-TESTING.md`. This is a local Xcode run. It is not an App Store or TestFlight release.

The macOS scheme **Vigil macOS** has built with Xcode 27.1 and `CODE_SIGNING_ALLOWED=NO`. The iOS scheme **Vigil iOS** copies extension files to the appex root. A directory named `Resources` in that appex makes `embeddedBinaryValidationUtility` report `Couldn't load Info dictionary` even when the plist and the signature are valid. `NativeCertCheck.nameMatches` wraps the common name in an array so that iOS target typechecks. Linux `pnpm test` does not compile Swift. The Mac command is in `docs/SAFARI-TESTING.md`.

The ClickFix, recovery-phrase, and wallet hooks are Chrome-only. Safari and iOS do not declare the `scripting` permission, so they do not inject those main-world scripts. `vigil check-url` still prints the PHP2Shell class on every platform. A Safari popup can show that class when a verdict already includes response headers, and the guard checkboxes are saved, but the hooks do not run.

## Publishing a separate tree

`bash tools/publish-public/publish.sh` builds a sanitized snapshot of a git ref in a temp directory, applies `.publish-public.yml`, and scans it. The default is a dry run and does not push. `--push` sends one new commit to `TysonIsham7/vigil-public`. It does not rewrite this repository. Create a gitignored `.publish-public.denylist` before the first run. Details are in `tools/publish-public/README.md`.
