# Vigil — Build Spec Sheet

Phase 1 product as implemented. First-pass security scanner for AI-generated websites (HTML, CSS, JS, light static backends). Not a pentest, not a compliance certificate.

**One-line job:** read untrusted source as text inside a short-lived workspace, report high-precision findings, delete the source, return an ephemeral report plus an improved generation prompt and a `block_deploy` flag.

---

## Product rules (non-negotiable)

1. **Never execute untrusted code.** No `eval`, no VM, no user JS. Analysis is regex and structural checks over text.
2. **Never store source.** Uploads, fetched pages, and Drive reads live only in a per-job memory buffer. The buffer is zeroed and dropped in `finally`, including on timeout and failure. Persisted `artifact_bytes` is always `0`. `code_deleted` is always true after a finished job.
3. **High precision over coverage.** Critical findings are deploy blockers only when confidence is high and `recommendationOnly` is false. Weaker signals are labeled recommendations and do **not** set `block_deploy`.
4. **Ephemeral reports.** Full report (evidence snippets included) lives in process memory for **15 minutes**, then is gone. The database keeps metadata and a lightweight finding list only. A user may explicitly save that lightweight list.
5. **Separate admin plane.** User accounts (email / Google / X) never grant admin. Admin is its own table, password + TOTP, own session cookie.
6. **SSRF-safe URL fetches.** Block localhost, link-local, RFC1918, CGNAT, metadata hosts, and non-http(s). Re-check the URL after redirects. Cap response size.
7. **Disclaimer on every report.** Vigil is a first-pass filter. Money, health, or credential sites still need a professional.

---

## Users and surfaces

| Surface | Who | Auth |
|---|---|---|
| Marketing, Learn, Docs, Status | Anyone | None |
| Scan, Report, History, Account, Connectors | Signed-in user | Email/password, Google, X |
| `POST/GET /api/v1/scans` | Agent | Bearer API key `vg_live_…` |
| `/admin/*` | Operator | Separate password + TOTP |

Public routes: `/`, `/learn`, `/docs`, `/status`, `/login`, `/signup`.
Signed-in routes: `/scan`, `/report/$id`, `/history`, `/account`, `/connectors`.
Admin: `/admin/login` (first-run setup if no admin exists), `/admin` (ops), `/admin/users`, `/admin/config`, `/admin/rules`, `/admin/audit`.

---

## Scan inputs

All scans require a signed-in user (UI) or an API key (agent). A kill switch refuses new jobs with a maintenance message. Source is not stored in that case either.

| Source | How |
|---|---|
| Paste | One or more named text files |
| Upload | Files, or a single `.zip` (path traversal stripped, size/count limits) |
| Sample | Built-in vulnerable fixture. No user code. |
| URL | Public `http(s)` page. Follow redirects, re-check SSRF, pull up to 4 same-origin scripts |
| Drive | Public share link fetch. Private files only if operator has set Drive OAuth client id + secret. One-time read; buffer wiped after the job |

Optional fields on every job: original generation **prompt** (used only to write an improved prompt) and a **hosting hint** (`vercel` | `netlify` | `cloudflare`) that adds an informational header note.

### Hard limits (admin-tunable)

| Limit | Default |
|---|---|
| Wall clock | 12s |
| Per file | 2 MB |
| Total upload | 8 MB |
| File count | 40 |
| Live response | 1.5 MB |
| IP burst | 12 scans / 10 min |

---

## Analysis

Line-oriented static rules. Skip blank lines and `//` / `/*` comment lines. One finding per rule per file per line. Secrets are redacted in evidence (prefix kept, rest replaced).

**Deploy blockers** (`severity: critical`, `recommendationOnly: false`). Any one of these sets `block_deploy: true`.

| ID | Fires when |
|---|---|
| `XSS_UNSAFE_SINK` | `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write` **and** an untrusted source on the same line (location, searchParams, storage, `req.query` / body / params, cookie, referrer) |
| `XSS_EVAL` | `eval(`, `new Function(`, or `setTimeout` / `setInterval` with a string |
| `XSS_INLINE_HANDLER` | HTML `on*` attribute (`onclick`, `onerror`, `onload`, …) |
| `XSS_JAVASCRIPT_URI` | `href` / `src` / `action` / `formaction` = `javascript:` |
| `OPEN_REDIRECT` | `location` / `location.href` / `assign` / `replace` assigned from query, hash, or request data |
| `SECRET_AWS_ACCESS_KEY` | `AKIA` + 16 alphanumerics |
| `SECRET_PRIVATE_KEY` | PEM `BEGIN … PRIVATE KEY` |
| `SECRET_STRIPE_LIVE` | `sk_live_…` |
| `SECRET_OPENAI` | `sk-` + 20+ chars |
| `SECRET_GITHUB_PAT` | `ghp_…` |
| `SECRET_GENERIC_KEY` | `api_key` / `secret_key` / `auth_token` / `bearer` assigned a long quoted token |

**Recommendations only.** Shown, never a deploy block.

| ID | Severity | Note |
|---|---|---|
| `XSS_INNERHTML_LITERAL` | high | HTML sink with no proven untrusted source on that line |
| `XSS_DANGEROUSLY_SET_INNER_HTML` | high | React `dangerouslySetInnerHTML` |
| `PROTO_POLLUTION` | high | `__proto__` or `constructor["prototype"]` write |
| `MIXED_CONTENT` | high | `http://` in `src` / `href` / `action` |
| `COOKIE_JS_WRITE` | high | `document.cookie =` without `Secure` |
| `TOKEN_IN_STORAGE` | high | token/secret/password/api key written to web storage |
| `CSP_WEAK` | high | CSP meta or header text contains `unsafe-inline` or `unsafe-eval` |
| `CSP_MISSING` | high | HTML document has no CSP meta. Dropped if the live response already sends a CSP header |
| `POSTMESSAGE_WILDCARD` | medium | `postMessage(..., "*")` |
| `HEADER_*` | high for CSP, else medium | URL scan only. Failed header checks |
| `COOKIE_FLAGS` | high | `Set-Cookie` missing Secure, HttpOnly, or SameSite |
| `TLS_INVALID` / `TLS_HTTP_ONLY` | high | URL scan only |
| `HOSTING_HEADERS` | informational | Hosting hint present |

**URL-only header checks:** CSP, CSP-Report-Only, HSTS (skip on http), `X-Content-Type-Options: nosniff`, `X-Frame-Options` or CSP `frame-ancestors`, Referrer-Policy, Permissions-Policy, COOP. TLS probe on https hosts (authorized, issuer, days remaining).

Each finding carries: stable `id`, `occurrenceId`, severity, confidence, title, summary, why it matters, remediation steps, file, line, redacted evidence, `agentAction`, category, `recommendationOnly`.

---

## Report

```
block_deploy = any finding where severity == critical AND recommendationOnly == false
```

Report version `1.0`. Fields: id, createdAt, sourceType, domain, hostingHint, blockDeploy, summary counts, findings, headers, cookies, tls, improvedPrompt, education blurbs, disclaimer, `codeDeleted: true`, `retention: "ephemeral"`, expiresAt (now + 15 min), filesAnalyzed, bytesAnalyzed.

UI: severity groups, evidence, remediation, agent action, block-deploy banner, JSON download, “save lightweight list” (ids, titles, severities, file names, improved prompt — no evidence, no source).

**Improved prompt.** If the user supplied a prompt: append a fixed SECURITY CONSTRAINTS appendix (strict CSP, no HTML sinks, no client secrets, no open redirects, https only, server cookies with Secure/HttpOnly/SameSite, no inline handlers). If `XAI_API_KEY` is set, optionally rewrite via `grok-4.5` and fall back to the deterministic appendix on any failure. If no prompt was given, omit `improvedPrompt`.

---

## Agent API

Auth: `Authorization: Bearer vg_live_…`. Key stored as a hash plus a display prefix. Revocable. Plan caps how many keys exist (free 1, pro 5, team 20).

`POST /api/v1/scans`

```json
{
  "source": {
    "type": "files | url | drive",
    "files": [{ "name": "index.html", "content": "…" }],
    "url": "https://example.com",
    "drive": "https://drive.google.com/…"
  },
  "prompt": "optional original prompt",
  "hosting": "vercel | netlify | cloudflare"
}
```

`200` body: `{ id, status: "complete", block_deploy, code_deleted: true, report, improved_prompt }`.
Errors: `401 unauthorized`, `429 rate_limited`, `503 scanning_paused`, `400` invalid JSON / drive / SSRF / empty input.

`GET /api/v1/scans/:id` returns the in-memory report while it lives, otherwise the lightweight finding list. Never source.

`GET /api/health` is public: scanner ok, API ok, `codeRetention: "none"`.

---

## Auth, plans, rate limits

User auth: email/password plus Google and X. Session required before any scan. New users get a `profiles` row, plan `free`.

| Plan | Daily scans | API keys | Saved history rows |
|---|---|---|---|
| Free | 5 | 1 | 3 |
| Pro | 50 | 5 | 200 |
| Team | 200 | 20 | 1000 |

Absolute daily ceiling **500**, even for Team. Daily counts use completed + running + queued jobs since local midnight. Admin can change the numbers in `app_config` without a deploy. Stripe keys are config slots only; billing is not wired in Phase 1.

---

## Data retained

| Table | What | What is forbidden |
|---|---|---|
| `profiles` | plan, credits, role | — |
| `api_keys` | hash, prefix, name, last used, revoked | raw key after creation |
| `scan_jobs` | counts, `block_deploy`, finding ids, lightweight meta, improved prompt, timestamps, `artifact_bytes = 0` | source, evidence, full pages |
| `saved_history` | user-saved lightweight list + improved prompt | source, evidence |
| `rate_limit_events` | user id, **hashed** IP, action | raw IP |
| `aggregate_stats` | category counts | — |
| `admin_accounts` / `admin_sessions` / `admin_audit` | operator identity, TOTP secret, audit | user source |
| `app_config` | tunables; secrets flagged `is_secret` | — |

No source column exists. Do not add one.

---

## Admin plane

First visit to `/admin/login` with zero admin rows is setup: email, password, then TOTP (RFC 6238). Confirm the code before the account is active. Later logins require password + TOTP. Failed logins lock the account. Admin session is separate from the user session.

Admin can:

- See scan volume, today’s jobs, account count
- Set a public status message and mark scanner / API down
- Flip the kill switch (`scanner.enabled`)
- Edit timeouts, size limits, and daily ceilings
- Enter operator secrets (Drive client secret, SMTP password, Stripe secret, optional TLS-checker key). Secrets are not echoed back
- Browse the rule catalog (read-only list of ids and severities)
- Read the audit log
- Inspect users (plan, usage). No access to their source, because it was never stored

---

## Google Drive

- **Default:** paste a public share link. Fetch the file once, scan, wipe.
- **Optional:** OAuth client id + secret in admin config enables a connect flow (`/api/connectors/drive/start` → callback). Read once per scan. Do not keep a long-lived copy of file bytes.
- If OAuth is not configured, the UI says share-link only. Do not pretend private Drive works.

---

## Look and voice

Dark editorial security product. Background `#0b0b0c`, ivory text `#f3f2ee`, silver primary `#d5d8de`, critical `#c45a48`. Display face Newsreader, body IBM Plex Sans. One accent, no gradient blobs, no emoji icons (Lucide). Landing headline: “See the obvious holes before anyone else does.” Primary CTA is sign-in until a session exists, then “New scan”. Mobile must not overflow at ~390px. Every report repeats the first-pass disclaimer and the ephemeral notice.

---

## Out of scope (Phase 1)

- Executing or sandboxing real browsers / headless Chrome
- Dependency CVE databases, SAST of non-web languages, authenticated app crawling
- Storing source “just for re-scan”
- Multiplayer or shared live reports
- Charging cards (config slots exist; checkout does not)
- Treating recommendation-only findings as deploy blocks

---

## Done when

1. Sample scan returns Critical findings and `block_deploy: true`, and the workspace is empty afterward.
2. A clean static page does not block deploy.
3. Pasting source, uploading a zip, and scanning a public URL all return a report and leave zero source bytes stored.
4. Full report disappears after 15 minutes; saved history still shows titles and ids only.
5. API key call matches the UI result for the same input.
6. Admin cannot be reached with a normal user session. Kill switch stops new scans and says source is not at risk.
7. Private IPs, localhost, and cloud metadata URLs are refused.
8. Mobile layout has no horizontal overflow.
