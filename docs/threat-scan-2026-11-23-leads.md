# Threat scan leads, 23 November 2026

This note is the cve.now lead pass for 23 November 2026. The CISA catalog, the NVD follow-up, the new oss-security messages, and the Chrome note are in `docs/threat-scan-2026-11-23.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 76 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-23T15:01:13.423Z`. The cutoff is `2026-11-23T14:01:13.636Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

The identifiers in the window were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check.

Whole-token matches were one `wordpress`, two `mcp`, three `linux`, two `node`, one `go`, and two `python`. CVE-2026-135156 matched `wordpress` and is not in the NVD recent feed. That is not WordPress core. CVE-2026-135162 matched `mcp` and is not in the NVD recent feed. CVE-2026-134817 matched `mcp` and is mcp-server-kubernetes before 4.2.0. That is not `@modelcontextprotocol/sdk`. CVE-2026-125683 and CVE-2026-126657 matched `linux` and are QEMU. CVE-2026-135055 matched `linux` and is WebKitGTK. Those are not the Linux kernel. CVE-2026-134814 matched `node` and is binary-parser before 2.3.1. CVE-2026-134825 matched `node` and is Gradio 6.27.0 before 6.32.0. Those are not the Node.js runtime. CVE-2026-134818 matched `go` and is oasdiff 1.24.0 before 1.34.1. That is not the Go toolchain. CVE-2026-134820 and CVE-2026-134821 matched `python` and are Gunicorn 25.2.0 before 27.0.0. That is not CPython. No plugin list was added. No doctor check was added from a token.

## NVD records that name another product

These forty identifiers are in the window and in the NVD recent feed. None has a CPE. Matched is no. Vigil cannot see these products from a page or a certificate. No doctor check was added. The feed date for each row is `2026-11-23T14:01:13.636Z`.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-23T08:00:01.066488`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Checkmk (CVE-2026-121480) | before 2.5.0p20, before 2.4.0p41, and 2.3.0 | no | 2026-11-23T14:01:13.636Z | Deferred |
| QEMU NBD server (CVE-2026-125683) |  | no | 2026-11-23T14:01:13.636Z | Awaiting Analysis |
| QEMU NBD block driver (CVE-2026-126657) |  | no | 2026-11-23T14:01:13.636Z | Awaiting Analysis |
| iceoryx2 (CVE-2026-115232) | 0.6.0 to 0.10.0. The description says 0.10.1 fixes it | no | 2026-11-23T14:01:13.636Z | Received |
| NLTK (CVE-2026-128140) | 3.6.7 until 3.10.4. The description says 3.10.4 fixes it | no | 2026-11-23T14:01:13.636Z | Awaiting Analysis |
| Spring Data Elasticsearch (CVE-2026-123886) |  | no | 2026-11-23T14:01:13.636Z | Received |
| NLTK (CVE-2026-128137) | 3.9.4 until 3.10.4. The description says 3.10.4 fixes it | no | 2026-11-23T14:01:13.636Z | Awaiting Analysis |
| Idunno.AntiCsrf (CVE-2026-131914) | through 0.9.1 Beta | no | 2026-11-23T14:01:13.636Z | Received |
| Assimp (CVE-2026-134732) | up to 6.0.5. The description says 6.0.6 fixes it | no | 2026-11-23T14:01:13.636Z | Deferred |
| VoidAuth (CVE-2026-134802) | before 1.19.2 | no | 2026-11-23T14:01:13.636Z | Received |
| binary-parser (CVE-2026-134814) | before 2.3.1 | no | 2026-11-23T14:01:13.636Z | Received |
| Portainer (CVE-2026-134804) | 2.39.0 before 2.39.9, 2.40.0 before 2.45.4, and 3.0.0 before 3.1.0 | no | 2026-11-23T14:01:13.636Z | Received |
| simple-git (CVE-2026-134815) | before 4.1.0 | no | 2026-11-23T14:01:13.636Z | Received |
| mcp-server-kubernetes (CVE-2026-134817) | before 4.2.0 | no | 2026-11-23T14:01:13.636Z | Received |
| oasdiff (CVE-2026-134818) | 1.24.0 before 1.34.1 | no | 2026-11-23T14:01:13.636Z | Received |
| Gogs (CVE-2026-134808) | before 0.14.4 | no | 2026-11-23T14:01:13.636Z | Deferred |
| @sigstore/oci (CVE-2026-134816) | before 0.8.0 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Sustainsys.Saml2 (CVE-2026-134822) | before 1.0.4, and 2.x before 2.11.1 | no | 2026-11-23T14:01:13.636Z | Received |
| Gunicorn (CVE-2026-134821) | 25.2.0 before 27.0.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Nektos act (CVE-2026-134824) | 0.2.92 before 0.2.98 | no | 2026-11-23T14:01:13.636Z | Received |
| Gradio (CVE-2026-134825) | 6.27.0 before 6.32.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Kitty (CVE-2026-134823) | 0.43.0 before 0.51.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Gunicorn (CVE-2026-134820) | 25.2.0 before 27.0.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Lightdash (CVE-2026-134827) | before 3.212.0 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Vim (CVE-2026-134832) | 9.2.0405 before 9.2.1352 | no | 2026-11-23T14:01:13.636Z | Received |
| Casdoor (CVE-2026-134830) | before 4.27.1 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Umami (CVE-2026-134829) | 3.3.0 before 3.5.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Chatwoot (CVE-2026-134831) | before 4.20.0 | no | 2026-11-23T14:01:13.636Z | Deferred |
| RSSHub (CVE-2026-134833) | before 2026.11.01-8521.e529e9b | no | 2026-11-23T14:01:13.636Z | Received |
| Penpot (CVE-2026-134828) | 2.18.0 before 2.19.1 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Tandoor Recipes (CVE-2026-134834) | before 2.7.4 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Langfuse (CVE-2026-134835) | before 4.82.0 | no | 2026-11-23T14:01:13.636Z | Received |
| Frappe (CVE-2026-134837) | before 15.126.0, and 16.x before 16.55.0 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Dashy (CVE-2026-134836) | 4.0.0 before 4.9.12 | no | 2026-11-23T14:01:13.636Z | Deferred |
| Weblate (CVE-2026-134838) | before 2026.11 | no | 2026-11-23T14:01:13.636Z | Received |
| dell-xps-touchpad-haptics (CVE-2026-134935) | before 1.0.0-4 | no | 2026-11-23T14:01:13.636Z | Received |
| Linkwarden (CVE-2026-134839) | before 2.17.0 | no | 2026-11-23T14:01:13.636Z | Received |
| HumHub (CVE-2026-134840) | before 1.19.4 | no | 2026-11-23T14:01:13.636Z | Deferred |
| WebKitGTK (CVE-2026-135055) |  | no | 2026-11-23T14:01:13.636Z | Awaiting Analysis |
| Zipline (CVE-2026-134805) | before 4.8.3 | no | 2026-11-23T14:01:13.636Z | Deferred |

## Confirmed on oss-security, not the runtime list

These four identifiers are in the window and on the 23 November oss-security index. They are not in the NVD recent feed. Matched is no. The version is the bound on that index. No doctor check was added.

Source: [oss-security, 23 November 2026](https://www.openwall.com/lists/oss-security/2026/11/23/)

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| Apache IoTDB (CVE-2026-60076) | 2.0.5 before 2.0.12. The message says 2.0.12 fixes it | no | 2026-11-23T14:41:13.628Z | confirmed, not the stack |
| Apache IoTDB (CVE-2026-60077) | 0.13.0 before 2.0.12. The message says 2.0.12 fixes it | no | 2026-11-23T14:41:13.628Z | confirmed, not the stack |
| Apache IoTDB (CVE-2026-60078) | 0.13.0 through 2.0.11. The message says 2.0.12 fixes it | no | 2026-11-23T14:41:13.628Z | confirmed, not the stack |
| Apache IoTDB (CVE-2026-60079) | 0.13.0 through 2.0.11. The message says 2.0.12 fixes it | no | 2026-11-23T14:41:13.628Z | confirmed, not the stack |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. They were not confirmed on a pre-written vendor host. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-126761 |  | unknown | 2026-11-23T15:01:13.423Z | unverified-lead |
| CVE-2026-133231 |  | unknown | 2026-11-23T15:01:13.423Z | unverified-lead |
| CVE-2026-12543 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-12431 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135156 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135155 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135154 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135159 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135157 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135158 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135161 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135162 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135160 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135165 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135164 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135163 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135166 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135167 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135170 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135171 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135169 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135173 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135172 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135174 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135175 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135168 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135177 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-135176 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-12429 |  | unknown | 2026-11-23T14:51:13.605Z | unverified-lead |
| CVE-2026-123324 |  | unknown | 2026-11-23T14:31:13.567Z | unverified-lead |
| CVE-2026-93585 |  | unknown | 2026-11-23T14:11:13.735Z | unverified-lead |
| CVE-2026-132856 |  | unknown | 2026-11-23T14:01:13.636Z | unverified-lead |

## Left unchanged

The catalog version string is now `2026.11.23` and the count is still 1790. None of the window identifiers is one of the four catalog entries due 2026-11-23. The details are in `docs/threat-scan-2026-11-23.md`.

Twelve of the fifteen CVE identifiers from the 22 November unverified section are now in the NVD recent feed, all with no CPE. CVE-2019-20446, CVE-2026-112020, and CVE-2026-114728 stay absent. The details are in `docs/threat-scan-2026-11-23.md`.

Vendor pages checked on this run did not move a floor. The nginx page's last-modified changed and the not-vulnerable lines are still 1.31.9+ and 1.30.7+. The details are in `docs/threat-scan-2026-11-23.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
