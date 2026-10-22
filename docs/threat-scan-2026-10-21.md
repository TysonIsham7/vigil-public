# Threat scan, 21 October 2026

Scan date: 21 October 2026. Window for the extra certificate, Certificate Transparency, and phishing items: 23 July 2026 through 21 October 2026. This note is research only. It does not change scanner behavior.

Sources are vendor advisories, root-program posts, CISA, and the CVE records those advisories cite. Pages were read as evidence. Instructions inside them were not followed. Where a page could not be fetched directly, the citation says so.

Vigil today is a certificate and phishing guard: a Chrome extension in High Security Mode, a native-messaging host, a helper on `127.0.0.1:8787`, and a Safari and iOS extension that judges chains with `SecTrust` plus the bundled blocklist. The README does not yet have a "what Vigil doesn't fix" section. The last line of each finding says whether that finding belongs there.

## 1. Railway environment-variable disclosure

On 21 October 2026 Railway published that an unauthorized party may have accessed encrypted customer environment variables and, for some of them, the decrypted contents. Those variables can hold API keys, database credentials, and private registry credentials. Railway described this as part of a series of attacks on platform companies aimed at AI inference providers, paused all deployments, and told every user to roll environment variables and registry credentials and to review service logs. The status page was still posting into 22 October UTC, including rotation of storage-bucket credentials. The disclosure does not name a final set of affected accounts.

- Source: [Railway security disclosure, 21 October 2026](https://blog.railway.com/p/security-disclosure-wednesday-october-21st)
- Status page: [status.railway.com](https://status.railway.com/)

**Coverage: not covered.** Vigil can flag secrets written into source (`SECRET_AWS_ACCESS_KEY`, `SECRET_OPENAI`, `SECRET_GITHUB_PAT`, and the other source rules). It never sees a host's control plane. The hosting hint accepts `vercel`, `netlify`, and `cloudflare`, and that hint only names a header config file.

**Suggested check.** Leave the Railway API alone. If a later hosting hint learns `railway`, emit an informational note that a clean tree does not mean the platform copy of those variables is safe, and point at this disclosure. That note should not block a deploy.

**README.** Belongs in "what Vigil doesn't fix." A source scan does not detect or rotate secrets stolen from a platform.

## 2. eMudhra intermediate compromise and distrust

On 17 October 2026 Chrome and Mozilla received reports that eight eMudhra intermediate private keys were generated with weak entropy, so the keys can be recovered from the public certificates. The certificates date from the April 2025 ceremony. Chrome blocked the SPKI hashes by CRLSet the same day. Mozilla pushed OneCRL the same day and, on 20 October, shipped Firefox 158.0.1, ESR 115.43.1, and ESR 153.5.1, and removed the signing root from NSS 3.131.1. Chrome is removing emSign ECC Root CA - G3 from the Chrome Root Store, expected for Chrome Root Store clients on the morning of 27 October 2026 PDT, sooner on Canary and Beta. Chrome says no TLS certificates chaining to the six TLS intermediates were in Certificate Transparency logs before the block, and that CT logs were updated to reject certificates chaining to the compromised CAs. Chrome also says it checked the rest of its root stores and found no other key with the same entropy failure, and that it is still reviewing eMudhra's remaining roots. Go 1.27.3 and 1.26.10 add the same SPKI filter (CVE-2026-111943).

The Mozilla article URL returned 403 to the fetcher. The publication, the date, and the OneCRL / Firefox / NSS actions are taken from the Mozilla security blog index and the public excerpt of that post, and they match Chrome's account of the same keys.

- Source: [Chrome Root Program, 20 October 2026](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- Source: [Mozilla Security Blog, 20 October 2026](https://blog.mozilla.org/security/2026/10/20/protecting-firefox-users-following-the-compromise-of-emudhra-intermediate-certificates/)
- Source: [oss-security report](https://www.openwall.com/lists/oss-security/2026/10/20/1)
- Go: [oss-security CVE-2026-111943](https://www.openwall.com/lists/oss-security/2026/10/20/29)

**Coverage: covered for TLS impersonation by these keys.** `packages/intel/data/distrusted-cas.json` (version `2026.10.21`) block-lists the eight intermediates by SPKI, including the Sectigo cross-signs, and block-lists emSign ECC Root CA - G3. emSign Root TLS CA - G3, emSign Root CS CA - G3, and AAA Certificate Services stay record-only, which matches the "do not blanket-distrust the parent" guidance. Chrome, the native host, and `vigil serve` all treat a block-listed SPKI as `CERT_DISTRUSTED_CA` and High Security holds. Safari and iOS add the same blocklist on top of `SecTrust`. `vigil doctor` reports the keys if they remain in ca-certificates, certifi, or Node's bundled roots (`TRUSTSTORE_EMUDHRA`), and it reports a local Go older than 1.27.3 or 1.26.10 (`TOOLCHAIN_GO`).

**Suggested check.** No new visitor block before publish. Two maintenance items:

- Re-read the Chrome root-program post after the 27 October root-store removal, and again if Chrome later distrusts any remaining eMudhra root. The JSON will not move on its own.
- The two code-signing intermediates are in the blocklist, so a TLS chain that contains them is blocked. Vigil does not inspect signed binaries.

**README.** One sentence belongs in "what Vigil doesn't fix": the blocklist is a snapshot. Vigil does not consume CRLSet, OneCRL, or CRLite, and a later distrust is invisible until that file is updated. The eight keys themselves do not belong there.

## 3. Critical PHP remote code execution

On 21 October 2026 PHP released 8.5.12, 8.4.27, 8.3.36, and 8.2.35 for two unauthenticated remote code execution bugs, each scored CVSS 4.0 at 9.2 by the PHP project. CVE-2026-109618 is out-of-memory handling that can leave request data half-initialized. CVE-2026-109619 is request state that can survive after its memory is freed and be reused by a later request on the same worker. PHP says the risk is highest for mod_php, that every SAPI serving web requests is affected (PHP-FPM, Apache, php-cgi, FrankenPHP, LiteSpeed), and that updating is the only complete fix. `session.upload_progress.enabled=0` blocks the confirmed session paths of CVE-2026-109619 and does not close the other variants or CVE-2026-109618. PHP 8.1 and older are out of project support; PHP published minimal source backports for 7.4, 8.0, and 8.1. CISA's same-day alert says it had not observed exploitation at publication time and tells operators who cannot patch to take PHP systems offline. These CVEs were not in the KEV additions announced on 20 October.

- Source: [PHP security advisory, 21 October 2026](https://www.php.net/archive/2026.php#2026-10-21-5)
- Source: [CISA alert, 21 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching)
- CVE records: [CVE-2026-109618](https://www.cve.org/CVERecord?id=CVE-2026-109618), [CVE-2026-109619](https://www.cve.org/CVERecord?id=CVE-2026-109619)
- NVD: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/CVE-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)

**Coverage: partial.** A disclosed `PHP/x.y.z` in `X-Powered-By` or `Server` is compared with 8.2.35, 8.3.36, 8.4.27, and 8.5.12. The owner scan blocks (`recommendationOnly: false`). The visitor scan warns, and High Security holds only when that version is disclosed (`confidence: high`). A PHP-looking cookie, `.php` URL, or body string with no version is a recommendation and does not hold. The stored summary calls both CVEs a use-after-free in `session.upload_progress`, and the remediation string leads with `session.upload_progress.enabled=0`. That setting is one partial mitigation for CVE-2026-109619. PHP's advisory says it is not a complete fix.

**Suggested check.** Keep the version gate. Change the finding text so the required action is the upgrade, and label `session.upload_progress.enabled=0` as a partial mitigation for one path of CVE-2026-109619. Leave hidden-version hits as warnings. A visitor hold cannot patch the server, and CISA's "take it offline" advice is for the operator.

**README.** Belongs in "what Vigil doesn't fix." Vigil does not patch PHP. A page that hides its version is only a suspicion. A warning in the popup is not remediation.

## 4. QUIC denial of service

Two different bugs are in circulation. Both are server availability bugs. Vigil's certificate probe speaks TLS with ALPN `http/1.1` only.

**In the 90-day window.** OpenSSL 3.5.9, 3.6.5, and 4.0.3 (29 September 2026) fix a cluster of QUIC denial-of-service bugs. The one described as CPU exhaustion is CVE-2026-42772: after a handshake, a peer can force quadratic work in QUIC STREAM reassembly. OpenSSL rates it Low. The same release fixes related QUIC resource bugs: CVE-2026-54873 (STREAM fragment metadata kept too long), CVE-2026-84784 (unbounded `RETIRE_CONNECTION_ID` backlog), CVE-2026-75804 (connection-level flow control not applied to streams), and CVE-2026-35191 (unvalidated amplification credit counted high when address validation is off). The High issue in that OpenSSL release is CVE-2026-84782, a DTLS bug, separate from QUIC. nginx 1.31.6 (15 September 2026) fixes CVE-2026-90439, a heap buffer overflow in `ngx_http_v3_module` when HTTP/3 is used with OpenSSL 3.5.0 or earlier.

**Older, and the major worker-crash bug.** nginx 1.31.2 (17 June 2026) fixes CVE-2026-42530. A crafted QUIC session can use-after-free a worker. nginx rates it major. That date is outside the 90-day window. It is included so it is not confused with the September OpenSSL bugs.

- Source: [OpenSSL 3.5 vulnerabilities](https://www.openssl-library.org/news/vulnerabilities-3.5/)
- Source: [OpenSSL 3.5.9 release notes](https://www.openssl-library.org/news/openssl-3.5-notes/)
- Source: [nginx security advisories](https://nginx.org/en/security_advisories.html)
- NVD: [CVE-2026-42772](https://nvd.nist.gov/vuln/detail/CVE-2026-42772), [CVE-2026-42530](https://nvd.nist.gov/vuln/detail/CVE-2026-42530)

**Coverage: not covered.** Nothing in the scanner reads a QUIC stack or an nginx version. `vigil doctor` reports curl, Go, the kernel, and trust bundles. It does not report the local OpenSSL or nginx version.

**Suggested check.** Do not probe remote HTTP/3. A page fetch cannot show whether the server's QUIC stack is patched, and a probe would be the wrong shape for this product. The publish action is local: run the helper on a Node build that vendors a fixed OpenSSL (see finding 5; the 22.x and 24.x security releases move OpenSSL to 3.5.9). A later `vigil doctor` entry for a local `openssl version` or `nginx -v` can follow the curl report. It should stay recommendation-only.

**README.** Belongs in "what Vigil doesn't fix." Vigil does not see or patch a server's QUIC or HTTP/3 stack.

## 5. Node.js security releases, 21 October 2026

Node.js shipped 22.23.4, 24.22.1, and 26.12.1 on 21 October 2026. The project rates the highest issue in each line High. The release also refreshes the bundled CA store for the eMudhra compromise (NSS 3.131.1 on the 24.22.1 line) and updates c-ares on all three lines. OpenSSL is listed for 24.x and 22.x, SQLite for 22.x, and undici for all three.

| CVE | Severity | Lines | What the project named |
|---|---|---|---|
| CVE-2026-111497 | high | 26, 24, 22 | Brotli decoder out-of-bounds write; the project says this permits remote code execution |
| CVE-2026-105483 | high | 26, 24 | TLS hostname bypass when an IP is written with fullwidth digits |
| CVE-2026-106069 | high | 26, 24, 22 | TLS hostname bypass when the host loosely resolves to an IP address |
| CVE-2026-105482 | high | 26, 24, 22 | `dns.resolve` truncates a name at a NUL |
| CVE-2026-105481 | medium | 26, 24, 22 | A keep-alive socket can process a response written before the request was sent |
| CVE-2026-106072 | medium | 26, 24, 22 | A non-canonical IPv4 hostname can be authenticated by a DNS SAN |
| CVE-2026-106074 | medium | 26, 24, 22 | `randomUUID()` and `randomInt()` caches are saved into startup snapshots and single executable applications |
| CVE-2026-106070 | low | 26 | ZipFile returns attacker-controlled prefix bytes after a failed ZIP header check |
| CVE-2026-106071 | low | 26 | Permission Model over-grant via wildcard radix lookup |
| CVE-2026-106073 | low | 26, 24, 22 | Permission Model bypass with `fs.realpathSync` |

- Source: [Node.js security releases, 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- Release notes: [v22.23.4](https://nodejs.org/en/blog/release/v22.23.4), [v24.22.1](https://nodejs.org/en/blog/release/v24.22.1), [v26.12.1](https://nodejs.org/en/blog/release/v26.12.1)
- NVD: [CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497), [CVE-2026-106069](https://nvd.nist.gov/vuln/detail/CVE-2026-106069)

**Coverage: partial, and the gap is the helper itself.** `package.json` allows `node >= 22`, which includes builds from before these releases. `vigil doctor` hashes Node's bundled roots and reports eMudhra keys that are still present. It does not compare `process.version` with 22.23.4, 24.22.1, or 26.12.1.

The certificate verdict does not use Node's hostname verifier. `tls.connect` is called with `rejectUnauthorized: false`, and `nameMatches` compares the host with DNS and IP SANs itself. A fullwidth or loosely parsed IP that fools Node's checker does not, by that path, become a Vigil allow. The page fetch is different: `fetch` does verify TLS inside Node, and Node will decode a Brotli body. CVE-2026-111497 and CVE-2026-105481 are reasons to start the helper on a patched runtime before it fetches untrusted sites.

`nameMatches` still has a smaller cousin of CVE-2026-106072. `parseIPv4` understands hex, octal, and a single integer, and it requires four dotted parts otherwise, so a short form such as `127.1` is not treated as an IP. For an IP-shaped host, a DNS SAN can still satisfy `nameMatches`. Fullwidth digits are not folded to ASCII.

**Suggested check.** Before publish, teach `vigil doctor` to report the running Node version against 22.23.4, 24.22.1, and 26.12.1, and tighten `engines` so a vulnerable 22, 24, or 26 build is not accepted. When the host is an IP, require a canonical iPAddress SAN and ignore DNS SANs. Reject fullwidth digits in a host before name matching. Leave snapshot and Permission Model bugs out of the visitor path. Vigil is not shipped as a single executable today.

**README.** One sentence belongs in "what Vigil doesn't fix": Vigil does not upgrade Node. The helper is only as safe as the runtime that starts it.

## 6. GitLab critical patch, 21 October 2026

GitLab released 19.5.1, 19.4.3, 19.3.6, 19.2.9, 19.1.9, 19.0.10, and 18.11.13 on 21 October 2026. The critical issue is CVE-2026-110264, CVSS 3.1 10.0: an unauthenticated user can execute code on the server by compiling a crafted regular expression (integer overflow). Affected ranges start at 7.0 and run through each listed line before its patch. GitLab.com is already patched. GitLab Dedicated tenants on 19.3.5-internal0 or 19.4.2-internal0, or later, already include the fix. The same release fixes CVE-2026-15723 (OmniAuth-to-LDAP account takeover, CVSS 8.2) and CVE-2026-112212 (OAuth/OIDC discovery cache poisoning, CVSS 7.5). GitLab keeps the issue detail private for 90 days after the patch.

This is a different bug from the 12 October 2026 critical patch, CVE-2026-97229, an integer overflow in the CI/CD regular-expression compiler fixed in 19.4.2, 19.3.5, and 19.2.8.

- Source: [GitLab 19.5.1 patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/)
- Earlier critical patch: [GitLab 19.4.2](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-4-2-released/)
- NVD: [CVE-2026-110264](https://nvd.nist.gov/vuln/detail/CVE-2026-110264)

**Coverage: not covered.** Vigil does not fingerprint a self-managed GitLab version. OSV results apply to packages in a lockfile, which is a different artifact from an installed GitLab Omnibus or chart.

**Suggested check.** Do not request version endpoints on a host the user did not ask to audit. No visitor block. An owner-scan note is optional and should stay informational: a page that looks like a GitLab sign-in is not evidence of a version.

**README.** Belongs in "what Vigil doesn't fix." Vigil does not audit or patch self-managed GitLab.

## 7. Vercel April 2026 security bulletin

Vercel closed this incident on 16 October 2026 at 10:19 AM PST. Unauthorized access to internal systems began with a compromised Context.ai OAuth app used by an employee, then that employee's Google Workspace account, then Vercel systems. The attacker enumerated and decrypted non-sensitive environment variables (values that decrypt to plaintext) for a limited set of customers, and a later review found a small number of additional accounts. Vercel says a separate handful of customer compromises did not originate on Vercel. Vercel, with GitHub, Microsoft, npm, and Socket, says no Vercel npm package was tampered with. Published IOC for Workspace administrators: OAuth client `110671459871-30f1spbu0hptbs60cb4vsmv79i7bbvqj.apps.googleusercontent.com`. Vercel's customer advice is to rotate variables that were not marked sensitive, turn sensitive variables on, review the activity log and unexpected deployments, and rotate Deployment Protection tokens.

- Source: [Vercel April 2026 security incident](https://vercel.com/kb/bulletin/vercel-april-2026-security-incident)

**Coverage: not covered.** `--hosting vercel` adds an informational header-config note. The source secret rules see tokens committed in the tree. They do not see the dashboard copy, and they do not know whether a value was marked sensitive.

**Suggested check.** When the hosting hint is `vercel`, add an informational note that points at this bulletin and says a clean tree is silent about platform variables. Do not call the Vercel API. Do not treat the OAuth client id as a website block rule. It is an IOC for a Workspace admin, not a malicious hostname.

**README.** Belongs in "what Vigil doesn't fix," together with the Railway item. A clean scan does not mean hosted environment variables were safe.

## 8. Other certificate-authority and Certificate Transparency changes

Chrome's 20 October post is the only new CA compromise found in this window. Chrome says no other key in its root stores shares the weak-entropy failure. Mozilla's CA-program blog in the window does not announce another distrust of that kind. The Mozilla article index does show an unrelated 10 August 2026 change of the GPG subkey used to sign some Firefox and Thunderbird release files. That is release signing, outside this product.

### Chrome SCT cutoff for one Firmaprofesional root

Bug 2054448 records a phase-out, not a key compromise. Publicly trusted TLS issuance from `AC Firmaprofesional - Secure Web 2025` is disabled. Chrome Root Store version 42 carries `sct_not_after_sec` 1785999664 (6 August 2026, 07:01:04 UTC) for the trust anchor `57DE0583EFD2B26E0361DA99DA9DF4648DEF7EE8441C3B728AFA9BCDE0F9B26A`, applied from Chrome 153.0.8010.0. Chrome told the CA on 12 October that the Stable rollout was expected on 17 October. That date is the CA's verification target, not a Chrome deployment guarantee.

- Source: [Mozilla bug 2054448](https://bugzilla.mozilla.org/show_bug.cgi?id=2054448)
- Policy: [Chrome Certificate Transparency policy](https://googlechrome.github.io/CertificateTransparency/ct_policy.html)

**Coverage: not covered.** Embedded SCTs are counted. Signatures are not checked (`signaturesVerified: false`). Vigil does not know log operators, log state, or a per-root `sctNotAfter`. Chrome's current policy wants two embedded SCTs from distinct logs for a lifetime of 180 days or less, and three above that, with two operators. TLS-delivered SCTs are not read. `--ct` asks crt.sh for the earliest `not_before` of the registrable domain and can mark that row `clean` when a date comes back. It does not prove the leaf was logged, and the extension does not pass `--ct`.

**Suggested check.** Before publish, state in the certificate result that a missing SCT list is a byte check, which the code already says in the finding text. Verifying SCT signatures needs a log list and is a later feature. A Firmaprofesional `sctNotAfter` warning is optional and should be recommendation-only, aimed at the site owner.

**README.** Belongs in "what Vigil doesn't fix." Vigil does not enforce Chrome CT policy.

### Just outside the window

On 1 July 2026 Chrome removed DigiCert Assured ID Root G2, DigiCert Assured ID Root G3, and DigiCert Trusted Root G4 because they are not dedicated TLS hierarchies. DigiCert says certificates issued from those hierarchies before that date stay trusted until they expire. That removal is 112 days before this scan, so it is not a 90-day item. Vigil's pinned Mozilla anchors can still treat those roots as trusted. A Chrome-divergence note for a site owner would be new work. It should not block a visitor whose certificate was issued before the deadline and is still inside its lifetime.

- Source: [DigiCert notice of the Chrome root removal](https://knowledge.digicert.com/alerts/google-chrome-root-removal-trusted-root-g4-assured-id-g2-id-g3)

**README.** A short Chrome-versus-Mozilla sentence belongs in "what Vigil doesn't fix." Vigil follows the pinned Mozilla bundle plus its own distrust file. It does not mirror every Chrome root-store removal.

### CT logs and the eMudhra keys

Chrome says the logs were updated to reject certificates chaining to the compromised CAs, and that none chaining to the six TLS intermediates were logged before the block. Vigil's SPKI block is the check that matters for a chain presented to the helper. `--ct` cannot reproduce Chrome's "nothing was logged" statement for a leaf.

## 9. Phishing techniques in the last 90 days

Safe Browsing and PhishTank providers exist in the tree and are disabled. The README already says reputation lookups stay off and send no host. The bundled checks are homoglyphs, a short brand list, mixed-script labels, young domains, free-hosting suffixes, suspicious TLDs, IP literals, and credential forms that post cross-origin or over HTTP. High Security holds the strong fake-site signals. Suspicious TLD, free hosting, and deep subdomains stay in the popup.

### Device-code phishing

Microsoft's 22 September 2026 report on EvilTokens describes device-code phishing: the victim types a code into a real Microsoft sign-in page and authorizes the attacker's session. Tokens are stolen without a lookalike certificate. The 14 October report says Storm-2990 kits also use this flow. The page the browser shows can be the real identity provider, with a normal public certificate.

- Source: [Microsoft, EvilTokens, 22 September 2026](https://www.microsoft.com/en-us/security/blog/2026/09/22/unmasking-eviltokens-getting-to-the-root-of-device-code-phishing/)

**Coverage: not covered.** A hold on `login.microsoftonline.com` would be a false block. The brand table already contains Microsoft's real domains, so a lookalike of those names can still hold.

**Suggested check.** None in the extension. Document it.

**README.** Belongs in "what Vigil doesn't fix." Vigil does not see an OAuth device-code approval on the real identity provider.

### Kits that impersonate brands, and that hide from a simple fetch

Microsoft's 14 October 2026 report describes the YAM Store (Storm-3119) and the CoGUI, Haozi, and Iron Man System kits (Storm-2990). Since January 2026 those kits have been tied to a large volume of phishing mail and SMS. Templates impersonate government, tolls, postal services, healthcare, finance, and retail, including brands this table does not list. The kits geofence, show a fake CAPTCHA, and filter researcher IPs. Some hosting is an aged or hijacked Microsoft 365 or Google tenant, so domain age and the certificate can both look ordinary. One example in the report is a newly registered `.org` used to prop up a fake organization. Young-domain-plus-login already covers that shape when the credential form is in the HTML Vigil fetches.

CISA's ATT&CK page for T1204.004, last modified 12 May 2026, is the definition of ClickFix: a page tells the user to paste a command into a terminal or the Run dialog. That page is outside the 90-day window as a publication. The October kits' fake CAPTCHA is the in-window behavior that matches it. Vigil does not execute page script, by design, so a form that appears only after JavaScript or a CAPTCHA is invisible to the fetch.

- Source: [Microsoft, phishing-kit ecosystem, 14 October 2026](https://www.microsoft.com/en-us/security/blog/2026/10/14/the-hidden-network-inside-the-phishing-infrastructure-ecosystem-powering-global-cybercrime/)
- Definition: [CISA, T1204.004 Malicious Copy and Paste](https://www.cisa.gov/eviction-strategies-tool/info-attack/T1204.004)

**Coverage: partial.** Lookalikes, homoglyphs, mixed script, a login on a domain younger than seven days, and credential forms posted to another origin or to HTTP are already hold signals. The brand list is sixteen marks (Google, Apple, Microsoft, Amazon, PayPal, Facebook, Instagram, Netflix, GitHub, Coinbase, Binance, Dropbox, Adobe, LinkedIn, Chase, Wells Fargo). Toll, postal, healthcare, and local-government lures from the October report are absent. An aged hijacked tenant will not trip the age check. A kit that withholds the form unless script runs will not trip the credential check.

**Suggested check.** Extend the brand table with stable registrable domains for the lure categories named in the 14 October report. Keep TLD, free-hosting, and subdomain-depth signals in the popup. Do not add a ClickFix command parser, and do not execute the page to get past a CAPTCHA. An adversary-in-the-middle kit on a lookalike host is already in range of the certificate and lookalike checks. A kit on the real domain is the device-code case above.

**README.** These sentences belong in "what Vigil doesn't fix":

- Reputation feeds are off. A static brand table misses kits on the real domain and kits on an aged or hijacked tenant.
- Vigil does not run page script. A credential form that appears only after JavaScript or a CAPTCHA is not visible.
- Vigil does not stop a person from pasting a command into the operating system.

## 10. CISA KEV around this date

CISA's 20 October KEV additions are CVE-2026-96652, CVE-2026-96654, CVE-2026-96655, and CVE-2026-96656 (Plex Media Server), CVE-2026-106931 (SiteGuard Server Edition), and CVE-2026-110936 (Siemens Software Center). The PHP bugs are not in that batch, and CISA said it had not seen them exploited. Earlier October KEV entries (PAN-OS, Cisco Secure Email Gateway, Ahsay, Ivanti, Fortinet, and others) are appliance and product bugs. None of them is a certificate presented to a browser or a hostname pattern Vigil can judge.

- Source: [CISA KEV additions, 20 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/20/cisa-adds-six-known-exploited-vulnerabilities-catalog)
- Catalog: [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

**Coverage: not covered, and a remote page scan should stay that way.**

**Suggested check.** None for these products.

**README.** One sentence belongs in "what Vigil doesn't fix." KEV entries for appliances, mail gateways, and local agents are outside a page and certificate check.

## Already in the tree from this month

These are in the 90-day window and already have a check. No new feature from this scan.

- LiteLLM 1.107.0 (21 October 2026). `vigil deps` blocks an exact pin. `vigil doctor` reports the matching image tag. High Security holds `DEP_LITELLM_COMPROMISED`. This is the supply-chain half of the same week as the Railway disclosure, and it is a different layer.
- curl CVE-2026-92392, fixed in 8.23.0. `TOOLCHAIN_CURL` on `vigil doctor`.
- Linux kernel CVE-2026-99999 (PwnEscape). `vigil doctor` reports the local `uname`. A URL scan adds `KERNEL_SHARED_HOST` and does not claim the remote kernel is vulnerable. That note already says what a site scan cannot see.

## What belongs in the README

Add a "what Vigil doesn't fix" section. These items belong in it:

1. Platform copies of environment variables, including the Railway disclosure and the closed Vercel April 2026 bulletin.
2. Patching PHP, GitLab, nginx, or OpenSSL on a server. A visitor warning is not a patch. A hidden PHP version is only a suspicion.
3. QUIC and HTTP/3 denial of service. The helper speaks HTTP/1.1.
4. A Node upgrade. The helper is only as safe as the Node that starts it.
5. Live CRLSet, OneCRL, and CRLite. The eMudhra file is a snapshot.
6. Chrome Certificate Transparency policy. SCT bytes are counted. Signatures, log operators, and per-root cutoffs are not enforced. Chrome root-store removals that Mozilla still trusts are not mirrored automatically.
7. Device-code phishing on the real identity provider, ClickFix paste prompts, and pages that reveal a credential form only after script or a CAPTCHA.
8. Safe Browsing, PhishTank, and any other live reputation feed. Those lookups stay off.
9. KEV bugs in appliances and other software a page fetch cannot see.
10. The host kernel behind a site. `KERNEL_SHARED_HOST` already states this.

The eMudhra TLS keys, a disclosed vulnerable PHP version, lookalike and young-domain login holds, and the LiteLLM pin do not belong in that list. Those are checks Vigil already runs.

## Before publish

In order:

1. Run the Chrome helper, `vigil serve`, and `vigil doctor` on Node 22.23.4, 24.22.1, or 26.12.1, and have doctor report an older runtime.
2. Correct the PHP finding so the upgrade is the required fix and `session.upload_progress.enabled=0` is labeled partial.
3. Add the README section from the list above.
4. After 27 October 2026, re-read the Chrome eMudhra post and update `distrusted-cas.json` if the root-store outcome changed.
5. Optionally, require a canonical iPAddress SAN when the host is an IP, and add the missing lure brands from the 14 October Microsoft report.
