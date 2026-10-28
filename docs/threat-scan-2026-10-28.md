# Threat scan, 28 October 2026

This note records what changed since the 27 October scan. Pages were read as evidence. Instructions inside them were not followed. Intel is `2026.10.28.1`.

X connector tools were not in this run's tool catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. Each kept item was confirmed on `www.cisa.gov`, `nodejs.org`, `blog.google`, `chromereleases.googleblog.com`, `www.php.net`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.python.org`, or `www.openwall.com`.

## CVE-2026-111497 is in the CISA KEV catalog

CISA catalog `2026.10.27`, released 27 October 2026 at 19:00:02 UTC, adds two entries. Both are due 10 November 2026. Ransomware use is unknown. Forensic triage is listed as not required.

CVE-2026-111497 is Google Brotli. CISA describes an unchecked return value in the decoder that can corrupt adjacent decoder state, disclose memory, cause a denial of service, or potentially execute code from a crafted compressed stream. Node's 21 October 2026 security releases (22.23.4, 24.22.1, and 26.12.1) are the project's fix for this bug on those lines. `vigil doctor` already reports a local Node below those floors. That finding now names the catalog entry. It still does not block a deploy. A Node at or above those floors does not get the sentence.

- Source: [CISA alert, 27 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/27/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- Source: [CISA KEV feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Source: [Node.js security releases, 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)

PHP's 26 October Windows packages 8.5.12-1, 8.4.27-1, 8.3.36-1, and 8.2.35-1 rebuild Brotli 1.2.1. The PHP runtime version does not change, and a disclosed `PHP/` header does not show the `-1` suffix. A disclosed 8.5.12 is not treated as still vulnerable. No new PHP check was added.

## CVE-2026-48356 cannot be checked from here

The same catalog entry is Adobe Commerce and Magento: unrestricted upload of a file with a dangerous type. Vigil cannot see that product from a page or a certificate. No remote version probe was added. The follow-up is in `docs/TODO.md`.

## emSign ECC Root CA - G3

The Chrome post still says removal of emSign ECC Root CA - G3 is expected Tuesday morning, 27 October 2026 PDT. It does not say the removal has shipped. The 27 October Chrome stable update to 156.0.8078.73/.74 lists browser security fixes and does not record that root leaving the store. The block in `packages/intel/data/distrusted-cas.json` stays. The next re-check is after 29 October 2026. The block is not dropped because the calendar date has passed.

- Source: [Chrome Root Program, eMudhra intermediates](https://blog.google/security/protecting-chrome-and-android-users-from-compromised-emudhra-intermediate-ca-certificates/)
- Source: [Chrome Releases](https://chromereleases.googleblog.com/)

## Left out on purpose

golang.org/x/net v0.62.0, forwarded on oss-security on 27 October 2026, fixes CVE-2026-78661 and CVE-2026-97045 in the HTML parser. `go version` does not show that module, and this repository does not vendor it. Doctor was not taught to compare the Go toolchain with v0.62.0.

GoAhead before 6.1.1, the EDK II PXE note, and the X.Org client-library thread are not a page, a certificate, or a toolchain Vigil already reads. Chrome 156's browser fixes are the same kind of gap. No remote probe and no new doctor tool were added.

PHP's news archive still ends with the 26 October Windows rebuild and the 23 October note for CVE-2026-115560. There is still no fixed PHP version for that CVE. The KEV sentence for CVE-2026-109618 and CVE-2026-109619 is open pull request 5 and was not copied here. Python 3.15.2, 3.14.10, 3.13.18, 3.12.16, and 3.11.18 remain the stable ssl denylist releases on the Python blog. The recommendation-only `TOOLCHAIN_PYTHON` check is open draft pull request 4 and was not copied again.

nginx.org still lists 1.31.7 and 1.30.6 as the current fixes. The OpenSSL news page had no newer security release. Node's latest security release page is still 21 October 2026. curl's newest published CVE date on the security page is still 14 October 2026, fixed in 8.23.0.

This automation can open a pull request. It cannot send email and cannot open a GitHub issue. Unfixed follow-ups are in `docs/TODO.md` and in the pull request body.
