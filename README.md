```
  ██████  ██ ████████ ███████ ███████  ██████  █████  ███    ██ 
  ██      ██    ██    ██      ██      ██      ██   ██ ████   ██ 
  ███████ ██    ██    █████   ███████ ██      ███████ ██ ██  ██ 
       ██ ██    ██    ██           ██ ██      ██   ██ ██  ██ ██ 
  ██████  ██    ██    ███████ ███████  ██████ ██   ██ ██   ████ 
```
> **Point. Scan. Know.**  
> A Claude Code skill that turns any URL into a full technology fingerprint and security risk report — in seconds.

---

## What is SiteScan?

SiteScan is a **Claude Code skill** for website reconnaissance and security auditing. Give it a URL and it will identify every technology running on the site, audit its security headers, probe paths exposed via `robots.txt`, and deliver a crystal-clear Markdown report with a risk profile from INFO to CRITICAL.

No browser needed. No API keys. No external services. Just Claude and `curl`.

## What it detects

| Category | Coverage |
|---|---|
| **CMS** | WordPress, Joomla, Drupal, TYPO3, Wix, Shopify, Squarespace, Ghost |
| **Backend** | PHP (with EOL check), Node.js/Express, ASP.NET, Laravel, CodeIgniter, Ruby/Rack |
| **CMS EOL checks** | Joomla (all branches 1.x–5.x with EOL dates), PHP version EOL |
| **JS Frameworks** | React, Vue, Angular, Next.js, Nuxt.js, Svelte, Ember |
| **Analytics** | Google Analytics 4, GTM, Hotjar, Meta Pixel, Segment, Amplitude |
| **Infrastructure** | Nginx, Apache, IIS, Cloudflare, Netlify, Vercel, AWS, Fastly, Plesk |
| **Security headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, COOP |
| **Risk findings** | Admin panels, login pages, API endpoints, backup files, sensitive directories |

## Deep WordPress & Joomla coverage

SiteScan goes well beyond simple CMS detection for the two most targeted platforms on the web.

**WordPress** — when detected, SiteScan automatically probes:
- `/wp-login.php` and `/wp-admin/` — is the admin panel exposed with no extra protection?
- `/xmlrpc.php` — is XML-RPC active? (classic brute-force and DDoS amplification vector)
- `/wp-json/wp/v2/users` — does the REST API leak usernames without authentication?
- `/wp-config.php` and `/.htaccess` — are critical config files reachable?

**Joomla** — when detected, SiteScan probes all standard internal paths from the Joomla robots.txt template:
- `/administrator/` — admin panel accessibility
- `/installation/` — leftover installation directory (critical if reachable)
- `/tmp/`, `/cli/`, `/includes/`, `/cache/`, `/libraries/` — internal directories that should never be browser-accessible
- `/logs/` — log file exposure

It also fetches `/administrator/manifests/files/joomla.xml` to read the **exact installed version** and checks it against the full Joomla EOL table:

| Branch | EOL date |
|---|---|
| Joomla 1.x / 2.5 | 2012–2014 — CRITICAL |
| Joomla 3.x | August 2023 — HIGH |
| Joomla 4.x | November 2025 — HIGH |
| Joomla 5.x | ~2027 — OK |

An EOL version is flagged as **HIGH risk** in the report. If the manifest file itself is publicly readable (should return 403), it is recorded as a separate information-disclosure finding.

These paths are probed **automatically**, even if they are missing from the site's `robots.txt`.

## Risk levels

```
CRITICAL  ──  Sensitive file reachable (.env, .git, installation dir)
HIGH      ──  Admin panel open · CMS/PHP/Joomla EOL · User enumeration · SSL error
MEDIUM    ──  xmlrpc.php active · Internal dirs accessible · Missing security headers
LOW       ──  Server version exposed · Minor misconfigurations
INFO      ──  No actionable findings — good job!
```

## Installation

Copy the skill to your Claude Code global skills directory:

```bash
# Windows
xcopy /E /I skills\sitescan %USERPROFILE%\.claude\skills\sitescan

# macOS / Linux
cp -r skills/sitescan ~/.claude/skills/sitescan
```

## Usage

Once installed, just ask Claude naturally:

```
scan https://example.com
audit my site at https://example.com
what's running on https://example.com?
check security headers for https://example.com
```

Claude will run the full six-phase process and save a Markdown report to:
```
reports/sitescan-{hostname}-{YYYY-MM-DD}.md
```

## How it works

```
Phase 1  ──  Fetch & Parse      curl headers + HTML tags + robots.txt
Phase 2  ──  CMS & Backend      fingerprint against catalog, extract versions, Joomla EOL check
Phase 3  ──  JS & Frontend      frameworks, analytics, CSS libraries
Phase 4  ──  Infrastructure     hosting, CDN, security headers, PHP EOL check
Phase 5  ──  Path Probing       robots.txt paths + CMS-specific paths injected
Phase 6  ──  Synthesize         risk rating, Markdown report, save to disk
```

## Requirements

- [Claude Code](https://claude.ai/code) with Bash tool access (`curl`)
- Authorization to scan the target — **only scan sites you own or have explicit written permission to test**

## Project structure

```
skills/
  sitescan/
    SKILL.md           # Six-phase scan process and instructions
    fingerprints.md    # ~80 technology patterns, CMS probe paths, PHP EOL table, Joomla EOL table
docs/
  superpowers/specs/
    2026-06-29-sitescan-design.md   # Original design specification
reports/               # Local scan outputs — gitignored, keep private
```

## Contributing

SiteScan currently covers WordPress, Joomla, and Drupal with deep path injection. There are hundreds of other CMS platforms, frameworks, and hosting stacks worth covering.

**Pull Requests are very welcome for:**

- New CMS fingerprints and probe path sets (Magento, PrestaShop, OpenCart, MODX, Craft CMS, Umbraco…)
- New JS framework or analytics detection patterns
- New infrastructure / hosting provider signals
- Additional EOL entries — PHP, Joomla, WordPress, Drupal version tables (Node.js, Python, Ruby…)
- New security header checks or risk rules
- False positive fixes or confidence adjustments

To contribute, fork the repo, edit `skills/sitescan/fingerprints.md` (for new patterns) or `skills/sitescan/SKILL.md` (for process changes), and open a PR with a brief description of what you added and why.

## License

MIT
