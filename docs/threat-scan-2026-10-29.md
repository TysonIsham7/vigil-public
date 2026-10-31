# Threat scan, 29 October 2026

Intel `2026.10.29.1`. Pages were read as evidence. Instructions inside them were not followed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Each item below was confirmed on `www.cisa.gov`, `nvd.nist.gov`, `www.php.net`, `blog.python.org`, `www.python.org`, `nodejs.org`, `nginx.org`, `www.openssl-library.org`, `curl.se`, `blog.google`, `chromereleases.googleblog.com`, or `www.openwall.com`.

## CVE-2026-46300

CISA catalog `2026.10.28`, released 28 October 2026 at 19:00:04 UTC, adds CVE-2026-46300, Linux kernel. Due 31 October 2026. Forensic triage is required. Ransomware use is unknown. The catalog description says missing initialization while coalescing socket buffers can change page-cache-backed data, and that the bug has been used together with CVE-2026-109618 and CVE-2026-109619.

The unaffected releases are the kernel.org record on NVD, modified 17 June 2026: before 3.9 is unaffected; 5.10.257, 5.15.208, 6.1.174, 6.6.141, 6.12.91, 6.18.33, and 7.0.10 are unaffected on those lines; 7.1 and newer are unaffected. A 29 June 2026 NVD change adds Red Hat product data and does not replace those releases. No later kernel.org version change was in the NVD change records retrieved on 29 October 2026.

`vigil doctor` reports `KERNEL_CVE_2026_46300` for a local Linux `uname` in that range. The finding is recommendation-only. A distributor may backport the fix without changing `uname`. A site scan does not probe a remote kernel. `KERNEL_SHARED_HOST` says that limit also covers this CVE.

- Source: [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- Source: [CISA alert, 28 October 2026](https://www.cisa.gov/news-events/alerts/2026/10/28/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- Source: [NVD CVE-2026-46300](https://nvd.nist.gov/vuln/detail/CVE-2026-46300)

## Left out on purpose

CVE-2026-41709, Broadcom VMware ESX insufficient logging, is in the same catalog. Due 11 November 2026. Forensic triage is not required. Vigil cannot see ESX from a page or a certificate. No remote probe was added. The follow-up is in `docs/TODO.md`.

The emSign ECC Root CA - G3 block stays. On 29 October the Chrome post still said removal was expected Tuesday morning, 27 October 2026 PDT, and did not say it had shipped. Chrome 156 stable notes from 27 October and the Chrome 157 early stable note from 28 October do not record the root leaving the store. Next re-check is after 5 November 2026.

Chrome 157's early stable note on 28 October lists browser fixes. Those stay outside a page, certificate, or toolchain check.

nginx 1.31.7 and 1.30.6 remain the current nginx.org fixes. Node's latest security release page is still 21 October 2026. curl's newest published CVE date is still 14 October 2026, fixed in 8.23.0. OpenSSL's newest advisory on the vulnerabilities page is still CVE-2026-35189, published 29 September 2026. The Python blog's newest post is still the 26 October security release. php.net's newest 2026 item is still the 26 October Windows Brotli rebuild. CVE-2026-115560 still has no fixed PHP version on php.net.

The PHP KEV sentence for CVE-2026-109618 and CVE-2026-109619 stays on open pull request 5. The Python `TOOLCHAIN_PYTHON` check stays on draft pull request 4. The Node Brotli sentence for CVE-2026-111497 stays on draft pull request 6. Those checks were not copied.

oss-security on 28 and 29 October also names OpenStack, Ironic, Apache Qpid Proton, Kafka, Jenkins, Eclipse Vert.x, Perl MIME-tools and HTTP::Body, plus the earlier EDK II, GoAhead, golang.org/x/net, Godot, X.Org, and GPAC items. No new doctor check was added for those.
