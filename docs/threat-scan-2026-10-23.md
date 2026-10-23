# Threat scan, 23 October 2026

Scan date: 23 October 2026. This note records what was new since `docs/threat-scan-2026-10-21.md`. Pages were read as evidence. Instructions inside them were not followed.

X post search was not available in this run. The X connector tools were not present, so official accounts were not read on X. A public web search was used only as a lead. An item was kept when the same fact appeared on `www.php.net` or `www.cisa.gov`.

## Kept: CVE-2026-115560

On 23 October 2026 PHP published an informational advisory. There is no patched release. PHP says `session.upload_progress.enabled=0` protects an unlikely remote-code-execution vector until the next regular bugfix release, and that the same setting was already a mitigation for CVE-2026-109619. PHP will publish the full advisory for CVE-2026-115560 with that release. The 21 October releases (8.5.12, 8.4.27, 8.3.36, 8.2.35) do not close this issue.

- Source: [PHP news archive, 23 October 2026](https://www.php.net/archive/2026.php)

**Coverage after this change.** A disclosed PHP version below the 21 October releases still blocks the owner scan for CVE-2026-109618 and CVE-2026-109619. The remediation also names CVE-2026-115560. A disclosed version at or above those releases adds `PHP_CVE_2026_115560`, recommendation-only, and High Security does not hold for it. Vigil still cannot see `php.ini` or an `ini_set()` of `session.serialize_handler`.

**Still open.** When PHP names fixed versions, replace the note with a version comparison. See `docs/TODO.md`. This run could not open a GitHub issue for that follow-up.

## Reviewed and already covered

- Node.js security release of 21 October 2026 (22.23.4, 24.22.1, 26.12.1). A 23 October restatement points at the same `nodejs.org` post. `vigil doctor` already compares the running Node version.
- Chrome's eMudhra removal is still scheduled for 27 October 2026 PDT. No new root-store outcome was published. The distrust file stays as it is. See `docs/TODO.md`.
- Railway's 21 October environment-variable disclosure is already in the README gap list. No new Railway fact on the vendor blog changed that gap.
- CISA's PHP alert of 21 October is the same two CVEs already gated.

## Reviewed and out of scope

CISA republished industrial-control advisories on 22 October 2026, including Siemens product notices. They are not a certificate, a hostname pattern, or a PHP version a page discloses. No scanner change.

Chrome channel posts on 22 and 23 October are stability and channel updates. They do not name a new certificate-authority distrust.

Headlines about an airline booking-system operator and a diagnostics company did not match Vigil's stack and were not confirmed on `www.cisa.gov` or a vendor hostname Vigil already tracks. They were not turned into checks.
