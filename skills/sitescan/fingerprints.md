# SiteScan Fingerprint Catalog

Reference file for SKILL.md phases 2–5.

---

## CMS & Backend

| Signal | Where to look | Technology | Category | Version extractable? |
|---|---|---|---|---|
| `meta[generator]` contains "WordPress" | HTML | WordPress | CMS | yes (from value) |
| Script/link path contains `/wp-content/` or `/wp-includes/` | HTML tags | WordPress | CMS | no |
| Cookie name starts with `wp_` or equals `wordpress_logged_in_...` | Set-Cookie | WordPress | CMS | no |
| `meta[generator]` contains "Drupal" | HTML | Drupal | CMS | sometimes |
| Header `X-Generator: Drupal x` | headers | Drupal | CMS | yes |
| Path `/sites/default/files/` in HTML | HTML | Drupal | CMS | no |
| `meta[generator]` contains "Joomla" | HTML | Joomla | CMS | sometimes |
| `meta[generator]` contains "Helix Ultimate" | HTML | Joomla (Helix template) | CMS | no |
| Path `/components/com_` in HTML | HTML | Joomla | CMS | no |
| Path `/media/vendor/` in script/link src | HTML tags | Joomla | CMS | no |
| Script JSON with `class="joomla-script-options"` | HTML | Joomla | CMS | no |
| robots.txt comment "If the Joomla site is installed within a folder" | robots.txt | Joomla | CMS | no |
| Link path `/media/templates/administrator/atum/` | HTML | Joomla 4.x/5.x | CMS | no |
| Bootstrap 5.x in `/media/vendor/bootstrap/` + jQuery 3.7+ | HTML tags | Joomla 5.x | CMS | no (but implies 5.x) |
| `meta[generator]` contains "TYPO3" | HTML | TYPO3 | CMS | sometimes |
| Path `/typo3/` in HTML | HTML | TYPO3 | CMS | no |
| `meta[generator]` contains "Wix" | HTML | Wix | CMS | no |
| HTML contains `_wixCIDX` or `wixBiSession` | HTML | Wix | CMS | no |
| HTML contains `data-shopify` or `cdn.shopify.com` | HTML/script | Shopify | CMS | no |
| Script path contains `static.squarespace.com` | HTML | Squarespace | CMS | no |
| HTML contains `data-ghost-root` or `ghost.io` | HTML | Ghost | CMS | no |
| Header `X-Powered-By: PHP/x.x.x` | headers | PHP | backend_language | yes |
| Cookie `PHPSESSID` | Set-Cookie | PHP | backend_language | no |
| Header `X-Powered-By: Express` | headers | Node.js/Express | backend_framework | no |
| Header `X-Powered-By: ASP.NET` | headers | ASP.NET | backend_framework | no |
| Header `X-AspNet-Version: x.x` | headers | ASP.NET | backend_framework | yes |
| Cookie `laravel_session` | Set-Cookie | Laravel | backend_framework | no |
| Cookie `ci_session` | Set-Cookie | CodeIgniter | backend_framework | no |
| Cookie `JSESSIONID` | Set-Cookie | Java (Servlet) | backend_language | no |
| Cookie `rack.session` | Set-Cookie | Ruby/Rack | backend_framework | no |
| Header `X-Powered-By: Next.js` | headers | Next.js | backend_framework | sometimes |
| Header `X-Powered-By: PleskLin` | headers | Plesk (Linux) | hosting | no |
| Header `X-Powered-By: PleskWin` | headers | Plesk (Windows) | hosting | no |

---

---

## CMS-Specific Probe Paths

When a CMS is detected in Phase 2, **always inject these paths** into the Phase 5 probe list, regardless of robots.txt content. Merge with robots.txt paths and deduplicate before probing.

### WordPress
| Path | Classification | Notes |
|---|---|---|
| `/wp-login.php` | login_page | Main login; 200 = unprotected |
| `/wp-admin/` | admin_panel | Redirects to wp-login.php if not logged in |
| `/wp-json/wp/v2/users` | api_endpoint | 200 = user enumeration possible (HIGH risk) |
| `/xmlrpc.php` | legacy_endpoint | 405 with Allow:POST = active; brute force / pingback vector |
| `/wp-config.php` | sensitive_file | Should return 403/404; 200 = CRITICAL |
| `/.htaccess` | sensitive_file | Should return 403; 200 = CRITICAL |

### Joomla
| Path | Classification | Notes |
|---|---|---|
| `/administrator/` | admin_panel | 200 = unprotected admin |
| `/installation/` | sensitive_file | Should be 404 after install; 200 = CRITICAL |
| `/tmp/` | restricted_area | 200 = internal temp dir exposed |
| `/cli/` | other | 200 = CLI scripts accessible |
| `/includes/` | other | 200 = internal includes exposed |
| `/cache/` | restricted_area | 403 expected; 200 = risk |
| `/libraries/` | restricted_area | 403 expected |
| `/logs/` | restricted_area | 404 expected; 200 = log exposure |

### Drupal
| Path | Classification | Notes |
|---|---|---|
| `/user/login` | login_page | Main login page |
| `/admin/` | admin_panel | Admin panel |
| `/sites/default/files/` | restricted_area | File uploads |
| `/.git/` | sensitive_file | CRITICAL if accessible |
| `/CHANGELOG.txt` | sensitive_file | Exposes exact Drupal version |
| `/core/CHANGELOG.txt` | sensitive_file | Drupal 8+ version disclosure |

---

## PHP EOL Versions

If `X-Powered-By: PHP/x.x` reveals any of these versions, record as **HIGH risk** with the EOL date.

| Branch | EOL date | Risk note |
|---|---|---|
| PHP 5.x | 2018-12-31 | CRITICAL — no patches for 6+ years |
| PHP 7.0 | 2018-12-03 | HIGH |
| PHP 7.1 | 2019-12-01 | HIGH |
| PHP 7.2 | 2020-11-30 | HIGH |
| PHP 7.3 | 2021-12-06 | HIGH |
| PHP 7.4 | 2022-11-28 | HIGH |
| PHP 8.0 | 2023-11-26 | HIGH |
| PHP 8.1 | 2024-12-31 | MEDIUM (recently EOL) |
| PHP 8.2 | 2026-12-31 | OK — active support |
| PHP 8.3 | 2027-12-31 | OK — active support |
| PHP 8.4 | 2028-12-31 | OK — latest stable |

---

## Joomla EOL Versions

When Joomla is detected in Phase 2, fetch `/administrator/manifests/files/joomla.xml` and extract `<version>`. Match the **major.minor branch** (e.g. `4.4.x` → branch `4.x`) against this table.

| Branch | EOL date | Risk note |
|---|---|---|
| Joomla 1.x | 2012-12-31 | CRITICAL — unsupported for 10+ years |
| Joomla 2.5 | 2014-12-31 | CRITICAL — unsupported for 10+ years |
| Joomla 3.x | 2023-08-17 | HIGH — EOL since August 2023 |
| Joomla 4.x | 2025-11-17 | HIGH — EOL since November 2025 |
| Joomla 5.x | ~2027-11 (TBD) | OK — current supported branch |
| Joomla 6.x | TBD | OK — future branch |

> Joomla's support policy: security fixes for the previous major branch for 2 years after a new major release. Joomla 5.0 was released November 2023 → Joomla 4.x EOL November 2025.

**Additional finding:** if the manifest returns HTTP 200 (publicly readable without authentication), record it as a LOW-risk information-disclosure finding regardless of the version found.

---

## JS & Frontend

| Signal | Where to look | Technology | Category |
|---|---|---|---|
| `<body data-pagefind-body>` attribute present | HTML body tag | Pagefind (static search) | js_library |
| `data-i18n` attributes on multiple elements + no server-side framework | HTML | Custom static i18n | js_library |
| All JS/CSS in `bundle.js` / `bundle.css` with version query string, no CMS paths | HTML tags | Custom static site (hand-built or SSG) | backend |
| Script src contains `react.min.js` or `react.development.js` | script tags | React | js_framework |
| Script src contains `react-dom` | script tags | React | js_framework |
| HTML contains `__NEXT_DATA__` or `<div id="__next">` | HTML | Next.js | js_framework |
| HTML contains `window.__NUXT__` or `data-n-head` | HTML | Nuxt.js | js_framework |
| Script src contains `vue.min.js` or `vue.esm` | script tags | Vue.js | js_framework |
| Script src contains `angular.min.js` or `@angular/core` | script tags | Angular | js_framework |
| Script src contains `svelte` | script tags | Svelte | js_framework |
| Script src contains `ember.min.js` | script tags | Ember.js | js_framework |
| Script src contains `jquery.min.js` or `jquery-x.x.x` | script tags | jQuery | js_library |
| Script src contains `jquery.slim` | script tags | jQuery Slim | js_library |
| Script src contains `lodash.min.js` | script tags | Lodash | js_library |
| Script src contains `moment.min.js` | script tags | Moment.js | js_library |
| Script src contains `gtag/js` or `googletagmanager.com/gtag` | script tags | Google Analytics 4 | analytics |
| Script src contains `google-analytics.com/analytics.js` | script tags | Google Analytics UA | analytics |
| Script src contains `googletagmanager.com/gtm.js` | script tags | Google Tag Manager | analytics |
| Script src contains `hotjar.com` | script tags | Hotjar | analytics |
| Script src contains `connect.facebook.net/en_US/fbevents` | script tags | Meta Pixel | analytics |
| Script src contains `cdn.segment.com` | script tags | Segment | analytics |
| Script src contains `cdn.amplitude.com` | script tags | Amplitude | analytics |
| Script src contains `cdn.intercomcdn.com` | script tags | Intercom | crm |
| Link stylesheet contains `bootstrap.min.css` or `bootstrap@` | link tags | Bootstrap | css_framework |
| Link stylesheet contains `tailwind` | link tags | Tailwind CSS | css_framework |
| Link stylesheet contains `bulma` | link tags | Bulma | css_framework |
| Link stylesheet contains `foundation` | link tags | Foundation | css_framework |
| Link stylesheet contains `font-awesome` or `fontawesome` | link tags | Font Awesome | icon_library |
| Link rel=`preconnect` href contains `fonts.googleapis.com` | link tags | Google Fonts | font_service |

---

## Infrastructure

| Signal | Where to look | Technology | Category | Version extractable? |
|---|---|---|---|---|
| Header `Server: nginx/x.x.x` | headers | Nginx | web_server | yes |
| Header `Server: Apache/x.x.x` | headers | Apache | web_server | yes |
| Header `Server: Microsoft-IIS/x.x` | headers | IIS | web_server | yes |
| Header `Server: LiteSpeed` | headers | LiteSpeed | web_server | no |
| Header `Server: cloudflare` | headers | Cloudflare | cdn | no |
| Header `CF-Ray` present | headers | Cloudflare | cdn | no |
| Header `X-Vercel-Id` present | headers | Vercel | hosting | no |
| Header `X-Vercel-Cache` present | headers | Vercel | hosting | no |
| Header `X-Netlify-*` present | headers | Netlify | hosting | no |
| Header `X-NF-Request-ID` present | headers | Netlify | hosting | no |
| Header `X-Amz-Cf-Id` present | headers | AWS CloudFront | cdn | no |
| Header `X-Amz-Request-Id` present | headers | AWS | hosting | no |
| Header `X-GitHub-Request-Id` present | headers | GitHub Pages | hosting | no |
| Header `X-Fastly-Request-ID` present | headers | Fastly | cdn | no |
| Header `X-Cache` contains "HIT" or "MISS" | headers | Generic CDN/cache | cdn | no |
| Header `Via` contains "varnish" | headers | Varnish Cache | cache | no |
| **Missing** `Strict-Transport-Security` | headers | — | security_header_missing | — |
| **Missing** `Content-Security-Policy` | headers | — | security_header_missing | — |
| **Missing** `X-Content-Type-Options` | headers | — | security_header_missing | — |
| **Missing** `X-Frame-Options` | headers | — | security_header_missing | — |
| **Missing** `Referrer-Policy` | headers | — | security_header_missing | — |
| `Set-Cookie` header without `Secure` flag | headers | — | insecure_cookie | — |
| `Set-Cookie` header without `HttpOnly` flag | headers | — | xss_vulnerable_cookie | — |

---

## robots.txt Paths

Use these patterns to classify each probed path.

| Path pattern | Classification | Default risk |
|---|---|---|
| `/admin`, `/wp-admin`, `/administrator`, `/adm`, `/_admin` | admin_panel | alto |
| `/login`, `/wp-login`, `/user/login`, `/signin`, `/auth` | login_page | medio |
| `/api/`, `/api/v1/`, `/v1/`, `/v2/`, `/graphql`, `/rest/` | api_endpoint | medio |
| `.bak`, `.sql`, `.zip`, `.tar.gz`, `/backup`, `/backups` | backup_file | alto |
| `/staging`, `/stage`, `/dev`, `/development`, `/test`, `/beta`, `/uat` | staging_area | medio |
| `/private`, `/secret`, `/internal`, `/hidden` | restricted_area | medio |
| `/.git`, `/.env`, `/.htaccess`, `/config`, `/wp-config` | sensitive_file | critico |
| `/sitemap.xml`, `/sitemap_index.xml`, `/news-sitemap.xml` | sitemap | info |
| `/phpmyadmin`, `/pma`, `/dbadmin` | admin_panel | critico |
| `/cgi-bin/`, `/scripts/` | legacy_cgi | medio |
| `/xmlrpc.php` | legacy_endpoint | medio (verifica con curl -sI: 405+Allow:POST = attivo) |
| `/wp-json/wp/v2/users` | api_endpoint | alto se 200 (user enumeration) |
| `/tmp/`, `/cli/`, `/includes/`, `/cache/`, `/libraries/` | restricted_area | medio se 200 |
| `/installation/`, `/CHANGELOG.txt`, `/core/CHANGELOG.txt` | sensitive_file | critico se 200 |
| Everything else | other | info |

**Risk elevation rule:** if HTTP status is 200 or 301/302 (reachable), upgrade `info` → `low` and `medio` → `alto` for `admin_panel`, `login_page`, and `sensitive_file` classifications.

---

## .NET Framework EOL Versions

When ASP.NET is detected in Phase 2, extract the CLR build prefix from `X-AspNet-Version` and match against this table. Apply narrowing signals from **ASP.NET Version Narrowing Signals** before assigning a final risk level.

| CLR prefix | Framework versions | EOL date | Risk |
|---|---|---|---|
| `1.0.*` | .NET 1.0 | 2009-07-14 | CRITICAL |
| `1.1.*` | .NET 1.1 | 2013-10-08 | CRITICAL |
| `2.0.*` | .NET 2.0 | 2011-07-12 | CRITICAL |
| `2.0.*` | .NET 3.0 | 2011-07-12 | CRITICAL |
| `2.0.*` | .NET 3.5 SP1 | 2029-01-09 | OK — still supported (bundled with Windows) |
| `4.0.*` | .NET 4.0 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5.1 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5.2 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6.1 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6.2 | 2027-01-12 | OK |
| `4.0.*` | .NET 4.7 – 4.8.1 | 2029-01-09 | OK |

> CLR `4.0.*` covers Framework 4.0–4.8.1. Without narrowing, the range is ambiguous — report MEDIUM "potentially EOL" if the floor cannot be confirmed above 4.6.2.

---

## .NET Core / .NET 5+ EOL Versions

When `Server: Kestrel` or other .NET Core signals are detected in Phase 2b, match the detected version against this table.

| Version | Type | EOL date | Risk |
|---|---|---|---|
| .NET Core 1.0 / 1.1 | STS | 2019-06-27 | CRITICAL |
| .NET Core 2.0 | STS | 2018-10-01 | CRITICAL |
| .NET Core 2.1 | LTS | 2021-08-21 | HIGH |
| .NET Core 2.2 | STS | 2019-12-23 | CRITICAL |
| .NET Core 3.0 | STS | 2020-03-03 | CRITICAL |
| .NET Core 3.1 | LTS | 2022-12-13 | HIGH |
| .NET 5 | STS | 2022-05-10 | HIGH |
| .NET 6 | LTS | 2024-11-12 | HIGH |
| .NET 7 | STS | 2024-05-14 | HIGH |
| .NET 8 | LTS | 2026-11-10 | OK — supported |
| .NET 9 | STS | 2026-05-12 | OK — supported |
| .NET 10 | LTS | ~2027-11 (TBD) | OK — in release |

---

## ASP.NET / IIS Known CVEs

Consulted during Phase 2b Step 5. List only CVEs whose affected version range overlaps the detected range. If confidence is `low` or `medium`, annotate each as "potentially applicable — confirm exact version before ruling out."

| CVE | Component | Affected versions | CVSS | Type |
|---|---|---|---|---|
| CVE-2010-3332 | ASP.NET ViewState | .NET 1.1 – 4.0 | 7.5 | Padding Oracle → info disclosure + RCE. Mitigated by ViewState MAC; removed in .NET 4.5 redesign. |
| CVE-2015-1635 | HTTP.sys (IIS kernel driver) | Windows Server 2008/2008R2/2012/2012R2 | 10.0 | Unauthenticated RCE via malformed Range header (MS15-034). |
| CVE-2017-8759 | .NET Framework WSDL/SOAP | .NET 2.0 – 4.7 | 7.8 | RCE via crafted WSDL document. |
| CVE-2021-31166 | HTTP.sys (IIS kernel driver) | Windows 10 20H2, Server 2019/2022 | 9.8 | Wormable unauthenticated RCE (KB5003173). |
| CVE-2021-26701 | System.Text.RegularExpressions | .NET Core 2.1, 3.1, .NET 5 | 9.8 | RCE via crafted regex input. |

> For full CVE coverage: NVD filter `cpe:2.3:a:microsoft:.net_framework` or `cpe:2.3:a:microsoft:asp.net_core`

---

## ASP.NET-Specific Probe Paths

Injected automatically into Phase 5 when ASP.NET is detected in Phase 2. Merge with robots.txt paths and deduplicate before probing.

### Diagnostics and logging
| Path | Classification | Risk if 200 | Notes |
|---|---|---|---|
| `/elmah.axd` | logging_endpoint | CRITICAL | Stack traces + exception log accessible without auth |
| `/trace.axd` | legacy_endpoint | HIGH | Request trace viewer with session data |
| `/__browserLink/requestData/` | dev_artifact | HIGH | VS Browser Link — must not exist in production |

### WebForms handlers (version signals + attack surface)
| Path | Classification | Risk if 200/400 | Notes |
|---|---|---|---|
| `/WebResource.axd` | resource_handler | LOW | 400 = handler active (expected without params); confirms WebForms |
| `/ScriptResource.axd` | resource_handler | LOW | Confirms WebForms + ScriptManager |
| `/bundles/` | bundle_endpoint | LOW | 200 = Bundling active → floor .NET 4.5 |

### Sensitive IIS/ASP.NET files
| Path | Classification | Risk if 200 | Notes |
|---|---|---|---|
| `/web.config.bak` | sensitive_file | CRITICAL | Backup config with connection strings and keys |
| `/Web.config` | sensitive_file | CRITICAL | Case variation — some servers are case-sensitive |
| `/.vs/` | dev_artifact | CRITICAL | Visual Studio solution data folder |
| `/app_offline.htm` | other | INFO | Maintenance page — confirms ASP.NET stack |
| `/global.asax` | other | LOW | Root application handler — info disclosure |
| `/aspnet_client/` | legacy_endpoint | LOW | Legacy ASP.NET client-side files |

### API and documentation
| Path | Classification | Risk if 200 | Notes |
|---|---|---|---|
| `/swagger` | api_docs | MEDIUM | Swagger UI — exposes API surface |
| `/swagger/v1/swagger.json` | api_docs | HIGH | Full JSON schema with all endpoints |
| `/api/` | api_endpoint | MEDIUM | API root — endpoint enumeration possible |
| `/health` | status_endpoint | LOW | Health check — may expose version and dependencies |

### Framework-specific
| Path | Classification | Risk if 200 | Notes |
|---|---|---|---|
| `/signalr/negotiate` | websocket_endpoint | LOW | Confirms SignalR + version in JSON body |
| `/_framework/blazor.server.js` | js_bundle | LOW | Confirms Blazor Server (.NET 5+) |
| `/WebService.asmx` | legacy_endpoint | MEDIUM | ASMX web service — SOAP interface exposed |

---

## ASP.NET Version Narrowing Signals

Applied sequentially in Phase 2b Step 2 (.NET Framework) and Step 3 (.NET Core/5+). Each signal that fires narrows the version range or raises the floor.

| Signal | Where | Information extracted |
|---|---|---|
| `X-AspNet-Version` build prefix | Response header | CLR branch → initial framework range |
| `X-AspNetMvc-Version` header | Response header | MVC version → framework version floor |
| `/bundles/` → HTTP 200 | Probe result | Floor .NET 4.5 (ASP.NET Bundling added in MVC 4/.NET 4.5) |
| Cookie `SameSite` attribute present | `Set-Cookie` header | Floor .NET 4.7.2 |
| `/WebResource.axd` → 200 or 400 | Probe result | Confirms WebForms handler active |
| `Server: Kestrel` | Response header | Branch .NET Core/5+ |
| `/_framework/blazor.server.js` → 200 | Probe result | Confirms .NET 5+ |
| `/health` → JSON with `"version"` field | Probe body | Explicit .NET Core/5+ version string |
| `/swagger/v1/swagger.json` → `"info.version"` | Probe body | API version (indicative) |
