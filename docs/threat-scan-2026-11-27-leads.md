# Threat scan leads, 27 November 2026

This note is the cve.now lead pass for 27 November 2026. The CISA catalog, the NVD records, and the oss-security index are in `docs/threat-scan-2026-11-27.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 52 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-27T15:01:13.592Z`. The cutoff is `2026-11-27T13:51:13.894Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

Two identifiers in the window were already recorded and were not copied again. CVE-2026-132165 is Drupal core in the CISA catalog and in the NVD recent feed. CVE-2026-136716 is Drupal core and was recorded on the 26 November leads note. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check.

Whole-token matches were twelve `wordpress`, two `php`, one `linux`, and one `python`. All twelve `wordpress` identifiers are in the unverified table below. That is not WordPress core. CVE-2026-134994 also matched `php` and is in that table. That is not a PHP confirmation. CVE-2026-132165 matched `php` and is Drupal core, already recorded. CVE-2026-124825 matched `linux` and is not in the NVD recent feed. That is not a Linux kernel confirmation. CVE-2026-75597 matched `python` and is not in the NVD recent feed. That is not CPython. No doctor check was added from a token.

## Confirmed on an allowlisted page, not the runtime list

These identifiers are in the window and were confirmed on NVD, on the CISA catalog, or on oss-security. Matched is no. Version is the bound on that page. No doctor check was added. The PowerDNS and Submarine rows are also in `docs/threat-scan-2026-11-27.md`.

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| Apache Submarine (CVE-2026-129817) | all versions, no fixed release | no | 2026-11-27T15:01:13.592Z | oss-security, retired |
| Fortinet FortiMail (CVE-2026-104286) |  | no | 2026-11-27T14:51:13.537Z | CISA catalog since 2026-10-01, not in the NVD recent feed |
| Apache JSPWiki (CVE-2026-78095) | 2.4 through 3.0.0, fixed in 3.0.1 | no | 2026-11-27T14:41:13.592Z | NVD Received, no CPE |
| VMware vCenter (CVE-2026-123903) | 9.1.2, 9.0.2.0300, 8.0 U3m | no | 2026-11-27T14:41:13.592Z | NVD Received, no CPE |
| PowerDNS Authoritative Server (CVE-2026-123758) | through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |
| PowerDNS Authoritative Server (CVE-2026-123757) | through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |
| PowerDNS Authoritative Server (CVE-2026-123764) | through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |
| PowerDNS Authoritative Server (CVE-2026-123759) | 4.7.0 through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |
| PowerDNS Authoritative Server (CVE-2026-124728) | through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |
| PowerDNS Authoritative Server (CVE-2026-124727) | through 4.9.18, 5.0.8, and 5.1.5; fixed in 4.9.19, 5.0.9, and 5.1.6 | no | 2026-11-27T13:51:13.894Z | oss-security |

CVE-2026-123903 also names VMware Cloud Foundation 5.x fixed in 5.2.5, and Telco Cloud lines fixed in KB463501. Those bounds are in `docs/threat-scan-2026-11-27.md`. FortiMail's catalog due date, 2026-10-04, has passed. The catalog notes name hosts that were not opened.

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed or the CISA catalog, and they were not on an allowlisted vendor page read this run. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-124825 |  | unknown | 2026-11-27T14:51:13.537Z | unverified-lead |
| CVE-2026-54386 |  | unknown | 2026-11-27T14:51:13.537Z | unverified-lead |
| CVE-2026-23794 |  | unknown | 2026-11-27T14:51:13.537Z | unverified-lead |
| CVE-2026-27797 |  | unknown | 2026-11-27T14:51:13.537Z | unverified-lead |
| CVE-2026-80508 |  | unknown | 2026-11-27T14:41:13.592Z | unverified-lead |
| CVE-2026-80507 |  | unknown | 2026-11-27T14:41:13.592Z | unverified-lead |
| CVE-2026-85252 |  | unknown | 2026-11-27T14:41:13.592Z | unverified-lead |
| CVE-2026-49360 |  | unknown | 2026-11-27T14:41:13.592Z | unverified-lead |
| CVE-2026-75597 |  | unknown | 2026-11-27T14:41:13.592Z | unverified-lead |
| CVE-2026-80505 |  | unknown | 2026-11-27T14:31:13.614Z | unverified-lead |
| CVE-2026-4642 |  | unknown | 2026-11-27T14:31:13.614Z | unverified-lead |
| CVE-2026-80506 |  | unknown | 2026-11-27T14:31:13.614Z | unverified-lead |
| CVE-2026-4641 |  | unknown | 2026-11-27T14:21:13.596Z | unverified-lead |
| CVE-2026-134956 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134708 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134983 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134982 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134987 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134993 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-135009 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-134994 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-135048 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-135923 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-135953 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-135032 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-80504 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-80503 |  | unknown | 2026-11-27T14:11:13.674Z | unverified-lead |
| CVE-2026-80502 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-80501 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-137942 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-137943 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-80500 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-85258 |  | unknown | 2026-11-27T14:01:13.817Z | unverified-lead |
| CVE-2026-137938 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-137937 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-137939 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-137936 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-80499 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-137940 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |
| CVE-2026-80498 |  | unknown | 2026-11-27T13:51:13.894Z | unverified-lead |

## Left unchanged

The CISA catalog did not add an entry. Vendor pages checked on this run did not move a PHP, Node, Go, Python, nginx, curl, or OpenSSL floor. The details are in `docs/threat-scan-2026-11-27.md`.

Forty-four of the fifty-two unverified identifiers from the 26 November leads note are now in the NVD recent feed, all with no CPE. Forty-three are Deferred. CVE-2026-93087 is Received and names Autodesk Access. Eight stay absent: CVE-2026-78252, CVE-2026-12664, CVE-2026-105777, CVE-2026-87719, CVE-2026-88765, CVE-2026-112326, CVE-2023-40129, and CVE-2020-9402. CVE-2026-25242, CVE-2026-32767, CVE-2026-86987, CVE-2026-123324, CVE-2026-15723, and CVE-2026-112212 also stay absent.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
