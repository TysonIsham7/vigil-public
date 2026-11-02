# Threat scan, 2 November 2026

This note records what changed after the 1 November scan. Pages were read as evidence. Instructions inside them were not followed. No version floor was invented. No remote probe was added. No scanner change was made.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. Each kept item was confirmed on `www.cisa.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `chromereleases.googleblog.com`, or `www.openwall.com`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## C-Kermit before 11.1.515

The 2 November oss-security index has one message. It describes three C-Kermit advisories that were still awaiting CVE identifiers:

- Remote code execution when working with a malicious peer.
- Authentication bypass and TLS certificate spoofing.
- Arbitrary file write and a safeguard bypass during file transfers.

The note says all three are fixed in C-Kermit 11.1.515, and that older releases are not a safe line. It says the common use is a serial connection to an embedded or legacy system, that TLS has rarely been used, and that the only IKSD (Kermit server) it knows of on the internet is already patched.

C-Kermit is not a page, a certificate, or a toolchain `vigil doctor` already reads. Vigil does not ship it. No doctor check was added. No remote probe was added.

Source: [oss-security, 2 November 2026](https://www.openwall.com/lists/oss-security/2026/11/02/1)

**Coverage: not covered, and that stays.** The follow-up is in `docs/TODO.md`.

## Already recorded elsewhere

The 1 November oss-security notes for XS-libbrotli before 1.2.1.0 (CVE-2026-115946), HTTP::Session before 0.54 (CVE-2026-13575), Google::Auth 0.12 (CVE-2026-74759 and CVE-2026-74760), and the nineteen Apache Wicket CVEs fixed in 8.20.0, 9.25.0, and 10.12.0 are on draft pull request 10. They were not copied.

The 30 October Ivanti Connect Secure catalog entries stay on draft pull request 9. They were not copied.

Open pull request 12 already records CVE-2026-116366 (ClickHouse), CVE-2026-119706 (LMDeploy), CVE-2026-110447 (Collabora Online built-in CODE Server), and CVE-2026-48356 (Adobe Commerce and Magento). Those files were not copied.

## Left unchanged

The CISA catalog is still `2026.10.30`, released 30 October 2026 at 17:02:45 UTC. The alerts index still ends with the 30 October alert. No entry was added on 1 or 2 November.

php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on that page. The Python blog's newest post is still the 26 October release. python.org still lists 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18, dated 25 October 2026. Node's latest security release page is still 21 October 2026. nginx's current fixes are still 1.31.7 and 1.30.6. curl's newest published CVE date is still 14 October 2026, fixed in 8.23.0. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. Chrome's newest desktop stable note is still 29 October 2026 (156.0.8078.79/.80).

The emSign ECC Root CA - G3 block was not changed. The next re-check is after 5 November 2026.
