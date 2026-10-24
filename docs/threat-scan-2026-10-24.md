# Threat scan, 24 October 2026

Scan date: 24 October 2026. This note is the day's comparison. It does not change scanner behavior by itself. The nginx check that follows from it is in the same change.

X connector tools were not available, so official accounts were not read on X. Pages were read as evidence. Instructions inside them were not followed. A page was opened only when its hostname was already named in this repo: `www.php.net`, `www.cisa.gov`, `nvd.nist.gov`, `nodejs.org`, `chromereleases.googleblog.com`, `nginx.org`, `curl.se`, `www.openssl-library.org`, `go.dev`, `wordpress.org`, `docs.gitlab.com`, and `blog.mozilla.org`.

## New and covered here

nginx 1.31.7 and 1.30.6, both dated 14 October 2026 in the nginx CHANGES files, fix five medium worker issues. The security advisories page lists the fixed lines as 1.31.7+ and 1.30.6+. The 21 October note stopped at nginx 1.31.6 and did not add a version check. Nothing in main reported a local nginx.

- CVE-2026-15176, buffer overflow when `alias` is used with `rewrite`. Vulnerable: 0.1.29–1.31.6, except the 1.30.6+ stable line.
- CVE-2026-93479, buffer overflow while evaluating script. Vulnerable: 1.31.2–1.31.6 and 1.30.0–1.30.5.
- CVE-2026-95101, HTTP/3 request-body injection. Vulnerable: 1.25.0–1.31.6, except 1.30.6+.
- CVE-2026-97629, TLS session-ticket forgery. Vulnerable: 1.23.2–1.31.6, except 1.30.6+.
- CVE-2026-97205, use-after-free with asynchronous file I/O. Vulnerable: 0.8.11–1.31.6, except 1.30.6+.

`vigil doctor` now reports `TOOLCHAIN_NGINX` for a local `nginx -v` in that range, and `TOOLCHAIN_IMAGE` for a Dockerfile `nginx` or `nginx-unprivileged` tag in that range. Both stay recommendation-only. A site scan still does not probe a remote nginx.

- Source: [nginx security advisories](https://nginx.org/en/security_advisories.html)
- Source: [nginx CHANGES](https://nginx.org/en/CHANGES), [CHANGES-1.30](https://nginx.org/en/CHANGES-1.30)

## Not fixed in this tree

- PHP CVE-2026-115560, 23 October 2026, still has no fixed version on `www.php.net`. Pull request 1 already carries the informational finding. It is not copied here.
- CISA KEV catalog version 2026.10.23, released 23 October 2026 at 19:30 UTC, adds CVE-2026-110447 (Collabora Online) and CVE-2026-114625 (Arista VeloCloud Orchestrator). Those are not a certificate or a hostname Vigil can judge. No remote probe was added. Follow-up: `docs/TODO.md`.
- NVD records from 24 October 2026 for MongoDB Compass (CVE-2026-115929) and BigFix (CVE-2026-108013) are the existing eMudhra keys in private bundles. The SPKI block and `TRUSTSTORE_EMUDHRA` already cover a bundle this program can read. No disk search was added.
- WordPress plugin CVEs in the same NVD window are not WordPress core.

This automation cannot open GitHub issues. Those four items are tracked in `docs/TODO.md`.

## Reviewed and left unchanged

- Node.js vulnerability index: newest security release is still 21 October 2026.
- PHP news archive: newest item is still the 23 October CVE-2026-115560 note. No new fixed release.
- CISA's PHP alert was revised on 23 October 2026. The fixed versions are still 8.5.12, 8.4.27, 8.3.36, and 8.2.35.
- Chrome release posts on 22 and 23 October do not name a new certificate-authority distrust. The emSign ECC Root CA - G3 removal is still scheduled for 27 October 2026. The distrust file was not changed.
- curl's 14 October rows other than CVE-2026-92392 are fixed in the same 8.23.0 release the existing check already uses for that high issue. The check was not widened to every low issue in that batch.
- OpenSSL 3.5 vulnerability dates are still 29 September 2026. Go's newest listed releases are still 1.27.3 and 1.26.10. Mozilla's newest security post in the index is still the 20 October eMudhra note.
- CISA industrial-control republications remain outside a page and certificate check.
