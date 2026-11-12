# Threat scan, 3 November 2026

This note records what changed after the 2 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The cve.now lead pass for this run is in `docs/threat-scan-2026-11-03-leads.md`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## 3 November oss-security index

The 3 November oss-security index has one message. It is a reply on CVE-2026-98432. It does not name a new unaffected kernel line. No doctor check was added. No remote probe was added.

Source: [oss-security, 3 November 2026](https://www.openwall.com/lists/oss-security/2026/11/03/)

## CVE-2026-98432

The reply is from Sultan Alsawaf, dated 2 November 2026 at 20:46 -0800. It says `init_on_free=1` does not mitigate CVE-2026-98432. The parameter only zeroes memory when it is freed. The reply says the leak it discusses uses data in a live object after the freed slot is reused, so zeroing on free does not cover that read. It says dropping inbound TCP that carries IP options stops the object from being allocated, and that traffic between containers on the same host can bypass that filter. It says disabling MPTCP alone is not enough, because the bug is in plain IPv4 TCP.

The reply names no unaffected kernel version. The NVD unaffected lines already recorded in `docs/TODO.md` were not changed. No boot-parameter check was added. No IP-options filter was added. No MPTCP check was added. No Go version comparison was added. A site scan must not probe a remote kernel.

Source: [oss-security, 3 November 2026](https://www.openwall.com/lists/oss-security/2026/11/03/1)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## Already on main

The 2 November notes record C-Kermit before 11.1.515, Arrow Rust CVE-2026-111959, JClouds CVE-2026-119724, Oozie CVE-2026-119641, Furl CVE-2026-65059, libexpat 2.10.0, and the five Apache Syncope CVEs. They were not copied.

CVE-2026-116366 (ClickHouse), CVE-2026-119706 (LMDeploy), CVE-2026-110447 (Collabora Online built-in CODE Server), CVE-2026-48356 (Adobe Commerce and Magento), CVE-2026-111497 (Brotli), and CVE-2026-120338 (prefab-ui) are already recorded under `packages/intel/advisories/`. Those files were not copied.

## Left unchanged

The CISA catalog is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. No entry is dated 1, 2, or 3 November. The alerts HTML page returned HTTP 403 on this run, so this note does not describe that index.

CVE-2026-111357 (Ivanti Connect Secure) reached its 2 November 2026 due date. Vigil still cannot see Connect Secure from a page or a certificate. No remote probe was added.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published advisory date is still 14 October 2026. The vulnerability table still lists 8.23.0 as the newest release row, and CVE-2026-107929 is the first column, published 14 October 2026. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80).

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
