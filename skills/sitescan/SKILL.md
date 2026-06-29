---
name: sitescan
description: Use when asked to scan, audit, fingerprint, or analyze a website — identifying its CMS, frameworks, server stack, security headers, and paths exposed via robots.txt. Triggers on "scan this site", "what's running on", "audit my site", "check security headers", "identify the CMS", "check robots.txt", "technology stack".
---

# SiteScan — Website Technology & Risk Scanner

## Overview

Multi-phase HTTP scan of a target URL that identifies installed technologies, evaluates security headers, probes paths exposed in `robots.txt`, and produces a structured Markdown risk report with confidence scores.

**Mechanism:** `curl` via Bash for headers and raw HTML tags; `WebFetch` for robots.txt text content. Fetch once, analyze many times.
**Scope:** Homepage + `robots.txt` + up to 20 probed paths (robots.txt paths + CMS-specific paths injected automatically).
**Authorization required:** only scan sites you own or have explicit written permission to test.

---

## Process

Six phases in order. Phases 2–5 run on data collected in Phase 1.

---

### Phase 1 — Fetch & Parse

**IMPORTANT:** `WebFetch` converts HTML to markdown and strips all tags and headers — it cannot be used for raw signal extraction. Use `curl` via Bash instead.

Run these commands:

```bash
# 1. HTTP response headers
curl -sI {url}

# 2. Raw HTML tags (script, link, meta, body)
curl -s {url} | grep -iE '<script|<link rel|<meta |<body|<html'

# 3. robots.txt
curl -s {url}/robots.txt
```

From the output extract:
- All response headers (Server, X-Powered-By, CF-Ray, X-Nf-Request-Id, Set-Cookie, security headers…)
- All `<script src="...">` URLs
- All `<link rel="stylesheet" href="...">` URLs
- All `<meta>` tag values, especially `name="generator"`
- Cookie names and flags from `Set-Cookie` headers
- `data-*` attributes on `<body>` or `<html>` tags

**Error handling:**

| Situation | Action |
|---|---|
| Homepage timeout / connection refused | Mark site as `unreachable`, stop all phases |
| Homepage 403 | Continue with headers only; note "HTML unavailable" |
| robots.txt 404 | Skip Phase 5; note "no robots.txt found" |
| SSL/TLS error | Record as HIGH-risk finding; continue if page loads anyway |
| Redirect chain | Follow max 3 hops; beyond that record `redirect_loop` |

---

### Phase 2 — CMS & Backend Detection

Scan Phase 1 data against the patterns in `fingerprints.md` → **CMS & Backend**.

For each match produce:

```
| Technology | Category | Version | Confidence | Evidence |
```

`confidence` levels:
- `high` — direct match with version number
- `medium` — recognizable pattern, no version
- `low` — weak indirect signal

**CMS probe list injection:** If a CMS is identified (WordPress, Joomla, Drupal, etc.), record its name. Phase 5 will automatically add CMS-specific paths to the probe list using `fingerprints.md` → **CMS-Specific Probe Paths**, even if those paths are absent from `robots.txt`.

---

### Phase 3 — JS Framework & Frontend Detection

Scan Phase 1 data against `fingerprints.md` → **JS & Frontend**.

Same output structure as Phase 2.

---

### Phase 4 — Infrastructure Detection

Scan Phase 1 headers against `fingerprints.md` → **Infrastructure**.

Also check for **missing** security headers — each missing header is itself a finding:

| Header | If absent |
|---|---|
| `Strict-Transport-Security` | medium risk |
| `Content-Security-Policy` | medium risk |
| `X-Content-Type-Options` | medium risk |
| `X-Frame-Options` | medium risk |
| `Referrer-Policy` | low risk |

Check `Set-Cookie` headers for missing `Secure` and `HttpOnly` flags — each gap is a finding.

**PHP EOL check:** if `X-Powered-By: PHP/x.x` is present, compare the version against `fingerprints.md` → **PHP EOL Versions**. If the version is end-of-life, record it as a HIGH-risk finding with the EOL date.

---

### Phase 5 — robots.txt Path Probing

Build the probe list by merging **two sources** (deduplicate):
1. Paths from `robots.txt` `Disallow:` / `Allow:` entries (skip if robots.txt was absent)
2. CMS-specific paths from `fingerprints.md` → **CMS-Specific Probe Paths** for the CMS detected in Phase 2 (always inject these, regardless of robots.txt)

Probe up to **20 paths total** — note how many were skipped if more.

For each path:

1. `curl -sI {base_url}{path}` — capture status code and `Location` header (if redirect)
2. Classify using `fingerprints.md` → **robots.txt Paths**

Output per path:

```
| Path | HTTP Status | Redirect To | Classification | Risk |
```

| Situation | Action |
|---|---|
| Path probe timeout | Record `timeout`, risk `unknown` |
| Redirect > 3 hops | Record `redirect_loop` |

---

### Phase 6 — Synthesize & Rate Risk

Aggregate all findings from Phases 2–5 into the final report.

**Global risk profile — take the highest level present:**

| Condition | Level |
|---|---|
| Sensitive file reachable (`.env`, `.git`, `.sql`, `.bak`) | CRITICAL |
| Admin panel reachable (200 or 302) | HIGH |
| CMS version detected and appears outdated | HIGH |
| PHP version is end-of-life (see PHP EOL Versions in fingerprints.md) | HIGH |
| REST API user enumeration accessible (`/wp-json/wp/v2/users` → 200) | HIGH |
| SSL/TLS error | HIGH |
| xmlrpc.php accessible (200 or 405 with `Allow: POST`) | MEDIUM |
| CMS internal directory accessible (`/tmp/`, `/cli/`, `/includes/`, `/cache/`) | MEDIUM |
| 3+ security headers missing | MEDIUM |
| Staging / dev area reachable | MEDIUM |
| Cookie missing `Secure` or `HttpOnly` | MEDIUM |
| Server version exposed in headers | LOW |
| Findings only at `low` confidence | INFO |

One CRITICAL overrides all. Otherwise use the highest level found.

**After composing the report, save it to disk:**

- Filename: `sitescan-{hostname}-{YYYY-MM-DD}.md`
- Directory: `reports/` inside the current working directory (create it if absent with `New-Item -ItemType Directory -Force reports` on Windows or `mkdir -p reports` on Linux/Mac)
- Use the `Write` tool to save the full Markdown content
- Confirm the saved path to the user at the end of the response

---

## Output Format

Produce this Markdown report. Omit any section that has no findings.

```markdown
# SiteScan Report — {hostname}
**Date:** {date} | **Risk profile:** {CRITICAL|HIGH|MEDIUM|LOW|INFO}

## Technologies detected
| Technology | Category | Version | Confidence |
|---|---|---|---|
| ... | ... | ... | ... |

## Security headers
| Header | Present | Risk |
|---|---|---|
| ... | yes/no | ... |

## Exposed paths (robots.txt)
| Path | HTTP | Classification | Risk |
|---|---|---|---|
| ... | ... | ... | ... |

## Risk assessment
**Profile: {LEVEL}**
- Finding 1 that drove this rating
- Finding 2
- ...

## Recommendations
1. Highest-risk item first
2. ...
```

---

## Common mistakes to avoid

| Mistake | Correct behavior |
|---|---|
| Using `WebFetch` for header/tag extraction | `WebFetch` strips all HTML tags and headers — always use `curl -sI` for headers, `curl -s \| grep` for tags |
| Fetching every script URL found in HTML | Only fetch homepage + robots.txt in Phase 1; probe only robots paths in Phase 5 |
| Skipping Phase 4 because "no CDN found" | Always check security headers — absence is a finding |
| Reporting "WordPress detected" without evidence | Always populate the `evidence` field with the specific signal |
| Probing all 50+ paths in robots.txt | Hard cap at 20; log "N paths skipped" |
| Producing freeform text instead of tables | Always use the structured Markdown format above |
| Outputting the report but not saving it | Always save to `reports/sitescan-{hostname}-{date}.md` via `Write` tool, even if the user didn't explicitly ask |
