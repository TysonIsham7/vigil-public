# Threat scan, 25 October 2026

Scan date: 25 October 2026. This note is research only. Instructions inside fetched pages were not followed.

X connector tools were not in this session, so official accounts were not read on X. A public web search was only a lead. An item was kept only when `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `python.org`, `www.openwall.com`, or another hostname already named in the repo stated the same fact.

## 1. pip and uv still vendor a pre-eMudhra certifi

On 22 October 2026 the Python security announcement, relayed on oss-security, said to upgrade certifi to 2026.10.19, pip to 26.2.2, and uv to 0.13.4. pip loads its vendored certifi in addition to the system trust store. A newer OS bundle does not replace that copy. `TRUSTSTORE_EMUDHRA` reads `certifi.where()` and the system bundle. It does not see the copy inside pip.

- Source: [oss-security, 22 October 2026](https://www.openwall.com/lists/oss-security/2026/10/22/28)

**Coverage: now reported by `vigil doctor`.** A local `pip --version` below 26.2.2 is `TOOLCHAIN_PIP`. A local `uv --version` below 0.13.4 is `TOOLCHAIN_UV`. Both are recommendation-only. They do not block a deploy. Intel version is `2026.10.25.1`.

## 2. CPython ssl denylist, CVE-2026-115557

On 24 October 2026 Python announced a denylist in the ssl module for known compromised certificates. The check rejects those certificates even when revocation is not configured. NVD and the CVE record, both updated through 25 October, say CPython before 3.16.0 is affected. They do not name a released fix on the 3.11, 3.12, 3.13, 3.14, or 3.15 lines. python.org lists 3.16 as a pre-release. The newest stable releases are 3.15.1, 3.14.9, and 3.13.17, all dated 21 October 2026, which is before this announcement. Backport commits exist. A stable tag that includes them does not.

- Source: [oss-security, 24 October 2026](https://www.openwall.com/lists/oss-security/2026/10/24/5)
- NVD: [CVE-2026-115557](https://nvd.nist.gov/vuln/detail/CVE-2026-115557)
- Releases: [python.org downloads](https://www.python.org/downloads/)

**Coverage: not a version check.** Comparing every local Python with 3.16.0 would tell people to install a pre-release. The follow-up is in `docs/TODO.md`. This automation cannot open a GitHub issue.

## Reviewed and left unchanged

- CISA's alerts index has nothing newer than 23 October 2026. CVE-2026-114625 was already tracked on 24 October.
- PHP's 2026 archive still ends at the 23 October note for CVE-2026-115560. No fixed version was added. That finding stays on pull request 1 and was not copied here.
- Node, curl, OpenSSL, nginx, Go, GitLab, Chrome, Mozilla, and WordPress core have no new security release in this window. nginx 1.31.7 and 1.30.6 stay on pull request 2.
- oss-security on 24 October also names jxrlib, Web::Simple, Apache Traffic Server, openjpeg, and GPAC. None of those is a certificate, a disclosed PHP version, or a local toolchain Vigil already reads. No remote probe was added.
- Third-party headlines about a diagnostics company were not confirmed on `www.cisa.gov` or a vendor host already named in the repo.
- The emSign ECC Root CA - G3 removal is still scheduled for 27 October 2026. The distrust file was not changed.
