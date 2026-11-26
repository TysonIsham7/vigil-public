# Threat scan leads, 26 November 2026

This note is the cve.now lead pass for 26 November 2026. The CISA catalog, the PHP records, and the oss-security index are in `docs/threat-scan-2026-11-26.md`.

Pages and the feed were read as evidence. Instructions inside them were not followed. No version floor was invented from feed prose. No remote probe was added. No advisory file was added from the feed.

X connector tools were not in this run's catalog. That is a setup gap, not a credits error. Nothing below was taken from an X post. `@cvedotnow` was not searched. `https://mcp.cve.now/mcp` was not called.

The lead feed was fetched once, at `https://cve.now/feed?format=json`. The response was HTTP 200 from that same URL, with no redirect. The content type was `application/feed+json`. The body had 200 items. Identifiers were taken from the newest items by `date_modified` with a deterministic regex. The window is 116 items because items that share the cutoff timestamp are kept together. The newest item is `2026-11-26T14:41:13.577Z`. The cutoff is `2026-11-26T14:01:13.371Z`. Titles and `content_text` were discarded. No item had a structured dotted version outside those fields. No GHSA id was in the window. No OSV id was in the window. No `SZB-` id was in the window.

Three identifiers in the window were already recorded and were not copied again. CVE-2026-15723 and CVE-2026-112212 are the GitLab issues from the 21 October scan. Neither is in the NVD recent feed. CVE-2026-129291 is the PHP-FPM issue named on the 19 November changelog. It is in the NVD recent feed and is recorded in `docs/threat-scan-2026-11-26.md`. The other identifiers were not already recorded in `docs/threat-scan-*.md`, `docs/TODO.md`, an open scan pull request, or `packages/intel/advisories/`.

This automation cannot open a GitHub issue and cannot send email. Unfixed follow-ups are in `docs/TODO.md`. This pull request is the report.

## No confirmed stack overlap

No identifier in the window was confirmed on NVD, CISA, or a pre-written vendor host as a new product on the runtime list or in `packages/intel/advisories/` that `vigil doctor` can check. The PHP bounds and the two Linux kernel records are in `docs/threat-scan-2026-11-26.md`. They do not move a floor.

Whole-token matches were forty `wordpress`, nine `php`, four `linux`, two `kernel`, and one `node`. Thirty-nine `wordpress` identifiers are not in the NVD recent feed. That is not WordPress core. CVE-2026-133525 is in the NVD recent feed and names Fusion Builder before 3.17.1. That is not WordPress core. No plugin list was added. Four `php` identifiers are not in the NVD recent feed: CVE-2026-130331, CVE-2026-136240, CVE-2026-137404, and CVE-2026-137403. That is not a PHP confirmation. CVE-2026-133210 names Revive Adserver. CVE-2026-136991 names Spotweb up to 1.5.8. Those are not the PHP runtime. CVE-2026-99567 matched `node`, `linux`, and `kernel`. The NVD description is a Linux kernel note and is not the Node.js runtime. CVE-2026-137035 and CVE-2026-137036 matched `linux` and name bootc. That is not a Linux kernel confirmation. No doctor check was added from a token.

## NVD records that name another product

These 57 identifiers are in the window and in the NVD recent feed. None has a CPE. The version column is the bound in the NVD English description. Where that description names no bound, the version cell is blank. Matched is no. Vigil cannot see these products from a page or a certificate. CVE-2026-136716 is Drupal core. The other Drupal rows are modules. CVE-2026-17194 is GitLab CE/EE. Vigil does not fingerprint GitLab. No doctor check was added.

Source: [NVD CVE 2.0 recent feed](https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-recent.json.gz), timestamp `2026-11-26T08:00:01.091639`.

| Product | Version | Matched | Date | NVD status |
|---|---|---|---|---|
| Pydantic AI Harness (CVE-2026-136641) |  | no | 2026-11-26T14:41:13.577Z | Received |
| GitLab CE/EE (CVE-2026-17194) | before 19.4.11; before 19.5.9; before 19.6.2 | no | 2026-11-26T14:01:13.371Z | Awaiting Analysis |
| Eclipse MWE (CVE-2026-103383) | <= 2.27.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Content Synchronizer (CVE-2026-118547) | from 0.0.0 to 4.1.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal S3 File System CORS Upload (CVE-2026-122057) | from 0.0.0 to 1.3.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Simple OAuth (OAuth2) & OpenID Connect (CVE-2026-122058) | from 0.0.0 to 5.2.6; from 6.0.0 to 6.0.10; from 6.1.0 to 6.1.4 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Workflow Notifications (CVE-2026-122066) | from 0.0.0 to 3.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal REST & JSON API Authentication for Drupal (CVE-2026-122067) | from 0.0.0 to 3.2.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal AlternativeCommerce PayPal Checkout (CVE-2026-122069) | from 0.0.0 to 1.1.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Forum Access (CVE-2026-122072) | from 0.0.0 to 2.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Commerce Product Alternative (CVE-2026-122070) | from 0.0.0 to 1.0.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Reset Password Email/SMS OTP (CVE-2026-122074) | from 0.0.0 to 1.0.5 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Commerce Escrow (CVE-2026-122071) | from 0.0.0 to 1.1.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Scheduler (CVE-2026-122075) | to 1.7.0, 2.2.3, 2.0.*, 2.1.*, and 2.3.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Password Separate Form (CVE-2026-122076) | from 0.0.0 to 2.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Islandora (CVE-2026-122081) | from 0.0.0 to 2.19.1 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Mime Mail (CVE-2026-122082) | from 0.0.0 to 2.0.4 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Allowed Languages (CVE-2026-122077) | from 0.0.0 to 2.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal AdobeAnalytics (CVE-2026-122083) | from 0.0.0 to 1.1.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Paragraphs Edit (CVE-2026-126726) | from 0.0.0 to 3.0.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Authenticator Login Plus (2FA) (CVE-2026-126729) | from 0.0.0 to 1.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Commerce License (CVE-2026-126733) | from 0.0.0 to 3.1.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Commerce License (CVE-2026-126732) | from 0.0.0 to 3.1.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Campaign Monitor (CVE-2026-126735) | from 0.0.0 to 3.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Mollie for Drupal (CVE-2026-126738) | from 0.0.0 to 2.3.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Mollie for Drupal (CVE-2026-126737) | from 0.0.0 to 2.3.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Entity Print (CVE-2026-126736) | from 0.0.0 to 2.20.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Page Manager (CVE-2026-126739) | from 0.0.0 to 4.1.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Download Count (CVE-2026-126740) | from 0.0.0 to 2.2.5; from 3.0.0 to 3.0.2 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Commerce sermepa (CVE-2026-126742) | from 0.0.0 to 2.5.0 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Real Name (CVE-2026-126745) | from 0.0.0 to 2.0.1 | no | 2026-11-26T14:01:13.371Z | Received |
| GENAI Web (CVE-2026-131916) |  | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Authenticator Login Plus (2FA) (CVE-2026-126731) | from 0.0.0 to 1.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Revive Adserver (CVE-2026-133208) | through 6.0.9 | no | 2026-11-26T14:01:13.371Z | Received |
| Revive Adserver (CVE-2026-133204) | through 6.0.9 | no | 2026-11-26T14:01:13.371Z | Received |
| Drupal Authenticator Login Plus (2FA) (CVE-2026-126730) | from 0.0.0 to 1.0.3 | no | 2026-11-26T14:01:13.371Z | Received |
| Revive Adserver (CVE-2026-133202) | through 6.0.9 | no | 2026-11-26T14:01:13.371Z | Received |
| Revive Adserver (CVE-2026-133209) | through 6.0.9 | no | 2026-11-26T14:01:13.371Z | Received |
| Joomla ChronoForms (CVE-2026-133336) | 8.0.0-8.0.53 | no | 2026-11-26T14:01:13.371Z | Received |
| Revive Adserver (CVE-2026-133210) | through 6.0.9 | no | 2026-11-26T14:01:13.371Z | Received |
| Joomla ChronoForms (CVE-2026-133337) | 8.0.0-8.0.53 | no | 2026-11-26T14:01:13.371Z | Received |
| Joomla ChronoForms (CVE-2026-133338) | 8.0.0-8.0.53 | no | 2026-11-26T14:01:13.371Z | Received |
| Joomla Visforms (CVE-2026-133340) | 1.0.0-5.6.5 and 6.0.0-6.2.2 | no | 2026-11-26T14:01:13.371Z | Deferred |
| Joomla Visforms (CVE-2026-133341) | 1.0.0-5.6.5 and 6.0.0-6.2.2 | no | 2026-11-26T14:01:13.371Z | Deferred |
| Fusion Builder (CVE-2026-133525) | before 3.17.1 | no | 2026-11-26T14:01:13.371Z | Deferred |
| Drupal core (CVE-2026-136716) | from 0.0.0 to 10.6.23; from 11.0.0 to 11.3.23; from 11.4.0 to 11.4.14 | no | 2026-11-26T14:01:13.371Z | Received |
| Spotweb (CVE-2026-136991) | up to 1.5.8 | no | 2026-11-26T14:01:13.371Z | Deferred |
| Drupal Texts: key-based strings and translations (CVE-2026-126728) | from 1.0.13 to 1.0.17 | no | 2026-11-26T14:01:13.371Z | Received |
| bootc (CVE-2026-137036) |  | no | 2026-11-26T14:01:13.371Z | Awaiting Analysis |
| bootc (CVE-2026-137035) |  | no | 2026-11-26T14:01:13.371Z | Awaiting Analysis |
| wpa_supplicant (CVE-2026-137307) | 2.7 through 2.12 | no | 2026-11-26T14:01:13.371Z | Received |
| GNU mtools (CVE-2026-137327) | through 4.0.50 | no | 2026-11-26T14:01:13.371Z | Received |
| MailGates/MailAudit (CVE-2026-137389) |  | no | 2026-11-26T14:01:13.371Z | Received |
| Mail2000 (CVE-2026-137390) |  | no | 2026-11-26T14:01:13.371Z | Received |
| Broadcom SiteMinder (CVE-2017-20291) |  | no | 2026-11-26T14:01:13.371Z | Received |
| Joomla Visforms (CVE-2026-133339) | 1.0.0-5.6.5 and 6.0.0-6.2.2 | no | 2026-11-26T14:01:13.371Z | Deferred |
| TOTOLINK N350RT (CVE-2026-137043) | 9.3.5u.6468_B20250827 and 9.3.5u.6466_B20250825 | no | 2026-11-26T14:01:13.371Z | Deferred |

## Unverified leads

These identifiers were in the window and were not in the NVD recent feed. They are not in the CISA catalog. They were not confirmed on a pre-written vendor host. Status is unverified-lead. Product is the identifier. Version is blank. Matched is unknown. No fix version was present as a structured field.

Source: [cve.now JSON feed](https://cve.now/feed?format=json).

| Product | Version | Matched | Date | Status |
|---|---|---|---|---|
| CVE-2026-104998 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-93087 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-109211 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-109996 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-121521 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-111803 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-116565 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-107769 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-122232 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-123827 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-126089 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-131695 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-130331 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-125001 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-132206 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-130321 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-135675 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136211 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-133951 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-134173 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-135641 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-132618 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-135654 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-134175 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136212 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136462 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136596 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136240 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136610 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-137119 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-95810 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-96555 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136517 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136488 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-136607 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-137122 |  | unknown | 2026-11-26T14:41:13.577Z | unverified-lead |
| CVE-2026-137404 |  | unknown | 2026-11-26T14:21:13.356Z | unverified-lead |
| CVE-2026-135005 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-131590 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-135027 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-129071 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-134474 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-137403 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-134711 |  | unknown | 2026-11-26T14:11:13.523Z | unverified-lead |
| CVE-2026-78252 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2026-12664 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2026-105777 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2026-87719 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2026-88765 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2026-112326 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2023-40129 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |
| CVE-2020-9402 |  | unknown | 2026-11-26T14:01:13.371Z | unverified-lead |

## Left unchanged

The CISA catalog update, the PHP bounds, and the 25 and 26 November oss-security messages are in `docs/threat-scan-2026-11-26.md`. CVE-2026-15723 and CVE-2026-112212 are the only window identifiers from the 21 October GitLab note. CVE-2026-129291 is the only window identifier from the 19 November PHP changelog list.

Fifty-one of the fifty-three unverified CVE identifiers from the 25 November leads note are now in the NVD recent feed timestamped `2026-11-26T08:00:01.091639`. None has a CPE. Thirty-two are Deferred. Nineteen are Received. CVE-2026-25242 and CVE-2026-32767 stay absent. CVE-2026-82490 names openIMIS and an nginx `auth_request` check. That is not nginx. CVE-2026-136922 names PyBioNetGen 0.8.7. That is not CPython. CVE-2026-135972 names the Page Restriction WordPress plugin through 1.6.2. That is not WordPress core. The details are in `docs/threat-scan-2026-11-26.md`.

Vendor pages checked on this run did not move a floor. The details are in `docs/threat-scan-2026-11-26.md`.

A breach notice is still a reason to change passwords and keys that lived on the affected service, turn on two-factor authentication or passkeys, and treat unexpected reset, verify, or payment mail as phishing. This scan did not find a new breach of a service Vigil checks.
