# Threat scan, 30 October 2026

This note records what changed after the 29 October scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Each item below was confirmed on `www.cisa.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, or `www.openwall.com`. NVD pages for the new kernel CVE and the two new KEV entries did not load. Unfixed follow-ups are in `docs/TODO.md`.

## CISA catalog 2026.10.29

The catalog version is `2026.10.29`, released 29 October 2026 at 19:09:34 UTC. Two entries were added that day. Both are due 1 November 2026. Ransomware use is unknown for both.

- CVE-2026-97229, GitLab Community Edition and Enterprise Edition. CISA describes an integer overflow in regular-expression handling that could let an unauthenticated user run code on the server through a CI/CD configuration. Forensic triage is required. CISA says other products can be affected by the same Ruby issue and points at the GitLab 19.4.2 patch note. This is the same CVE the 21 October threat scan already recorded as fixed in 19.4.2, 19.3.5, and 19.2.8, and as something Vigil does not fingerprint.
- CVE-2026-76418, Cisco Secure Firewall ASA and FTD. CISA describes an unchecked return that can let an unauthenticated remote attacker reload the device. Forensic triage is not required.

Source: [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), catalog JSON `2026.10.29`. Alert: [29 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/29/cisa-adds-two-known-exploited-vulnerabilities-catalog).

**Coverage: not covered, and that stays.** A page and a certificate do not show a GitLab version or a firewall version. The 21 October scan already said not to request a GitLab version endpoint and not to treat a sign-in page as a version. No doctor check was added. No visitor block was added. Both entries are in `docs/TODO.md`.

## CVE-2026-98432

On 30 October 2026 oss-security forwarded a Go security note about CVE-2026-98432, a Linux kernel IPv4 TCP use-after-free. The note says the fix is a patched kernel. It says a demonstrated path used a Multipath TCP listener, and that the bug may not be limited to that path. It says Go 1.24 and newer turn Multipath TCP on by default for Linux listen sockets, that a per-program change is a fragile mitigation, and that it is premature to change Go. The note does not name an unaffected kernel line.

Source: [oss-security, 30 October 2026](https://www.openwall.com/lists/oss-security/2026/10/30/1)

**Coverage: not covered yet.** `vigil doctor` already reports the local kernel for the separate PwnEscape advisory. It does not know CVE-2026-98432's fixed lines, because this scan did not get them from an allowlisted page. Comparing `go version` would not apply the kernel fix. No check was added. The follow-up is in `docs/TODO.md`.

## Left out on purpose

Chrome's desktop stable note on 29 October 2026 updates the channel to 156.0.8078.79/.80 and lists 21 browser security fixes. The critical entry on that note is CVE-2026-76024. Vigil does not read the browser version. No doctor check and no remote probe were added.

Source: [Chrome stable channel update, 29 October 2026](https://chromereleases.googleblog.com/)

The same day's Chrome OS note and the 30 October Dev channel note (159.0.8130.0) are browser builds. They are the same kind of gap.

The emSign ECC Root CA - G3 block was not changed. The 29 October re-check still stands. The next re-check is after 5 November 2026.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026.

The 30 October oss-security index also names Suricata before 8.0.8, two Apache Fineract SQL injection notes, dhcpcd, and Perl modules Spreadsheet::XLSX, DateTime::Lite, CallBackery, and HTTP::Parser::XS. None of those is a page, a certificate, or a toolchain `vigil doctor` already reads. A separate post reports that Claude Code for VS Code extension 2.1.313 on Open VSX was compromised. That report was not confirmed on an allowlisted vendor host, so it did not become a check.

The Python `TOOLCHAIN_PYTHON` check stays on draft pull request 4. The PHP KEV sentence stays on pull request 5. The Node Brotli sentence stays on draft pull request 6. The CVE-2026-46300 kernel check stays on draft pull request 7. None of those were copied.
