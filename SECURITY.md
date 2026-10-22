# Security policy

Vigil is an early first-pass scanner. It is not an audit, and it does not
execute the code it reads. A valid certificate does not mean a site is safe.
See the README section "Vigil doesn't fix everything."

## Reporting a vulnerability

Use GitHub private vulnerability reporting. Open the repository's Security
tab and choose **Report a vulnerability**. That report stays private to the
maintainers.

Do not send a vulnerability report to a personal email address. Do not open
a public issue for an unpublished vulnerability. Do not include exploit
payloads, customer source, secrets, or live credentials.

If private vulnerability reporting is not enabled yet, ask a maintainer to
turn it on before sending details. Do not fall back to a public issue or a
personal inbox.

## Repo hygiene

Do not commit secrets, API keys, `vg_live_` keys, machine names, usernames,
home-directory paths, IP addresses that identify a person or host, or Apple
team IDs. Put placeholders in `.env.example` only. The committed Safari team
id stays the placeholder `XXXXXXXXXX`.

CI runs gitleaks and trufflehog. A pre-commit hook runs `scripts/secret-scan.mjs`.

## Scanner boundaries

Analysis is text, structure, and network metadata (DNS, TLS, headers). The
scanner does not eval, compile, or sandbox untrusted input. URL fetches are
SSRF-checked before the request and again after every redirect.
