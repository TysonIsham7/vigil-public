# Threat scan, 26 October 2026

This note records three advisories that landed together on private main as intel `2026.10.26.2`. Private main was already at `2026.10.26.1` (vigil gate and the PHP2Shell header class). Pages were read as evidence. Instructions inside them were not followed.

## CVE-2026-115560

On 23 October 2026 PHP published an informational advisory. There is no patched release. PHP says `session.upload_progress.enabled=0` protects an unlikely remote-code-execution vector until the next regular bugfix release, and that the 21 October releases (8.5.12, 8.4.27, 8.3.36, 8.2.35) do not close this issue.

- Source: [PHP news archive, 23 October 2026](https://www.php.net/archive/2026.php)

A disclosed PHP version below those releases still blocks the owner scan for CVE-2026-109618 and CVE-2026-109619. That upgrade finding names CVE-2026-115560. It does not carry the sentence that says the note does not block a deploy or hold a page. That sentence is only on `PHP_CVE_2026_115560`, which is informational, `recommendationOnly`, and emitted when the disclosed version already meets the 21 October floors. `fixed` in the advisory file stays empty. High Security does not hold for it. Vigil still cannot see `php.ini`.

## nginx 1.31.7 and 1.30.6

nginx 1.31.7 and 1.30.6, both dated 14 October 2026, fix five medium worker issues: CVE-2026-15176, CVE-2026-93479, CVE-2026-95101, CVE-2026-97629, and CVE-2026-97205. The fixed lines are 1.31.7+ and 1.30.6+.

- Source: [nginx security advisories](https://nginx.org/en/security_advisories.html)
- Source: [nginx CHANGES](https://nginx.org/en/CHANGES), [CHANGES-1.30](https://nginx.org/en/CHANGES-1.30)

`vigil doctor` reports `TOOLCHAIN_NGINX` for a local `nginx -v` in that range, and `TOOLCHAIN_IMAGE` for a Dockerfile `nginx` or `nginx-unprivileged` tag in that range. Both stay recommendation-only. A site scan does not probe a remote nginx.

Docker Hub groups the floating tags `1.31` and `1.31-alpine3.24` with 1.31.7, and `1.30` and `1.30-alpine` with 1.30.6. Those tags are not padded to patch 0, so they are not flagged. Older two-component lines such as `1.29` and `1.28` are still flagged, as is `1.31.6-alpine3.21`. Image name matching strips a digest, then removes `:tag` only when the colon is in the last path segment, so `localhost:5000/nginx:1.31.6` and `nginx:1.31.6@sha256:…` match `nginx`.

## pip 26.2.2 and uv 0.13.4

On 22 October 2026 the Python security announcement, relayed on oss-security, said to upgrade certifi to 2026.10.19, pip to 26.2.2, and uv to 0.13.4. pip loads its vendored certifi in addition to the system trust store. `TRUSTSTORE_EMUDHRA` reads `certifi.where()` and does not see the copy inside pip.

- Source: [oss-security, 22 October 2026](https://www.openwall.com/lists/oss-security/2026/10/22/28)

A local `pip --version` below 26.2.2 is `TOOLCHAIN_PIP`. A local `uv --version` below 0.13.4 is `TOOLCHAIN_UV`. Both are recommendation-only.

## CPython 3.11.18, 3.12.16, 3.13.18, 3.14.10, and 3.15.2

Python published those releases for CVE-2026-115557 (the ssl denylist for the compromised eMudhra intermediates) and CVE-2026-114583 (`tarfile` rejecting a link that replaces the destination). `www.python.org/downloads/` dates the files 25 October 2026. The 26 October Python Insider post names all five. NVD's record, last modified 26 October 2026 at 01:17 UTC, still says 3.14 is affected until 3.16.0. This check follows the python.org post and does not compare a local Python with 3.16.0.

- Source: [Python Insider, 26 October 2026](https://blog.python.org/2026/10/python-3152-31410-31318-31216-31118/)
- Releases: [python.org downloads](https://www.python.org/downloads/)

`vigil doctor` reports `TOOLCHAIN_PYTHON` for a local interpreter below the floor on 3.11–3.15, and for Python 3.10 or older. A Dockerfile `python` tag in that range is `TOOLCHAIN_IMAGE`. Both stay recommendation-only. A two-component tag on 3.11–3.15 is not padded to patch 0. An explicit patch, including `3.12.0`, is compared with the floor. `a`, `b`, `rc`, and `.dev` on a floor version are still below it. A final release and a `+` local build of that triple are not. The tag is the colon in the last path segment after `@digest` is removed, so `python:3.12.15@sha256:…` and `localhost:5000/python:3.12.15` keep `3.12.15`.

## Left out on purpose

Also left out, and listed in `docs/TODO.md`: CISA KEV entries for Collabora Online and Arista VeloCloud Orchestrator, private CA bundles inside MongoDB Compass and BigFix, and WordPress plugin CVEs that are not WordPress core. No remote probe was added for those.
