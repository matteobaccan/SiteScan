# SiteScan — Design Spec
**Data:** 2026-06-29
**Stato:** Approvato

---

## Obiettivo

Skill per Claude Code che, dato un URL, esegue una scansione HTTP della homepage e del `robots.txt` del sito, identifica le tecnologie installate (CMS, framework JS, infrastruttura), sonda i percorsi elencati nel `robots.txt`, e produce un report Markdown strutturato con confidence score e valutazione del rischio.

**Contesto d'uso:** audit del proprio portfolio di siti web per rilevare tecnologie obsolete, header di sicurezza mancanti, e superfici esposte.

---

## Architettura — Pipeline multi-agent

La skill orchestra 6 sub-agent in sequenza/parallelo:

```
Input: URL
    │
    └─► [Agent 1] Fetcher & Parser          ← SEQUENZIALE, blocca gli altri
            fetch homepage + robots.txt
            output: RawSiteData
    │
    ├─► [Agent 2] CMS & Backend Detector    ─┐
    ├─► [Agent 3] JS & Frontend Detector     ├─ PARALLELI su RawSiteData
    ├─► [Agent 4] Infrastructure Detector    │
    └─► [Agent 5] robots.txt Path Prober   ─┘
    │
    └─► [Agent 6] Synthesizer & Risk Rater  ← SEQUENZIALE, attende Agent 2-5
            output: Report Markdown
```

---

## Contratti dati

### RawSiteData (output Agent 1)

```json
{
  "url": "https://example.com",
  "homepage": {
    "status_code": 200,
    "headers": { "server": "nginx/1.24", "x-powered-by": "PHP/8.1" },
    "html": "<html>...",
    "script_tags": ["https://cdn.example.com/wp-includes/js/jquery.min.js"],
    "link_tags": ["https://example.com/wp-content/themes/..."],
    "meta_tags": { "generator": "WordPress 6.4.2" },
    "cookie_names": ["PHPSESSID", "wp_logged_in_..."]
  },
  "robots": {
    "raw": "User-agent: *\nDisallow: /wp-admin/",
    "paths": ["/wp-admin/", "/private/"]
  }
}
```

### DetectionResult[] (output Agent 2, 3, 4)

```json
[
  {
    "technology": "WordPress",
    "category": "CMS",
    "version": "6.4.2",
    "confidence": "high",
    "evidence": ["meta[generator]='WordPress 6.4.2'", "path /wp-content/"]
  }
]
```

`confidence`: `high` (segnale diretto + versione) | `medium` (pattern, no versione) | `low` (indizio debole)

`category`: `CMS` | `backend_language` | `backend_framework` | `js_framework` | `analytics` | `cdn` | `web_server` | `hosting` | `security_header` | `css_framework`

### PathProbeResult[] (output Agent 5)

```json
[
  {
    "path": "/wp-admin/",
    "status_code": 302,
    "redirect_to": "/wp-login.php",
    "classification": "admin_panel",
    "risk": "alto"
  }
]
```

`classification`: `admin_panel` | `login_page` | `api_endpoint` | `backup_file` | `staging_area` | `restricted_area` | `sensitive_file` | `sitemap` | `other`

---

## Catalogo fingerprint

### Agent 2 — CMS & Backend

| Segnale | Dove | Tecnologia |
|---|---|---|
| `meta[generator]` contiene "WordPress" | HTML | WordPress |
| Path `/wp-content/`, `/wp-includes/` | script/link | WordPress |
| Cookie `PHPSESSID` | headers | PHP session |
| Header `X-Powered-By: PHP/x.x` | headers | PHP + versione |
| Header `X-Powered-By: Express` | headers | Node.js/Express |
| `meta[generator]` contiene "Drupal" | HTML | Drupal |
| Path `/sites/default/files/` | HTML | Drupal |
| Header `X-Generator: Drupal` | headers | Drupal |
| `meta[generator]` contiene "Joomla" | HTML | Joomla |
| Path `/components/com_` | HTML | Joomla |
| Header `X-Powered-By: ASP.NET` | headers | ASP.NET |
| Cookie `laravel_session` | headers | Laravel |
| Cookie `ci_session` | headers | CodeIgniter |
| Path `/wp-login.php` → 200 (probe) | robots | WordPress confirmed |

### Agent 3 — JS Framework & Frontend

| Segnale | Dove | Tecnologia |
|---|---|---|
| Script path contiene `react`, `react.min.js` | script tags | React |
| Script path contiene `vue.js`, `vue.min.js` | script tags | Vue.js |
| Script path contiene `angular.js` | script tags | Angular |
| Script path contiene `jquery.min.js` | script tags | jQuery |
| HTML contiene `__NEXT_DATA__` o `<div id="__next">` | HTML | Next.js |
| HTML contiene `__nuxt` o `data-n-head` | HTML | Nuxt.js |
| Script path contiene `gtag/js`, `googletagmanager` | script tags | Google Analytics/GTM |
| Script path contiene `hotjar` | script tags | Hotjar |
| Script path contiene `fbevents` | script tags | Meta Pixel |
| Link stylesheet contiene `bootstrap` | link tags | Bootstrap |
| Link stylesheet contiene `tailwind` | link tags | Tailwind CSS |

### Agent 4 — Infrastructure

| Segnale | Dove | Tecnologia |
|---|---|---|
| Header `Server: nginx/x.x` | headers | Nginx + versione |
| Header `Server: Apache/x.x` | headers | Apache + versione |
| Header `Server: cloudflare` | headers | Cloudflare |
| Header `CF-Ray` presente | headers | Cloudflare |
| Header `X-Vercel-Id` presente | headers | Vercel |
| Header `X-Netlify-*` presente | headers | Netlify |
| Header `X-Amz-*` presente | headers | AWS |
| Header `Strict-Transport-Security` assente | headers | HTTPS non enforced (rischio) |
| Header `X-Content-Type-Options` assente | headers | Header sicurezza mancante |
| Header `X-Frame-Options` assente | headers | Header sicurezza mancante |
| Header `Content-Security-Policy` assente | headers | Header sicurezza mancante |
| Cookie `Set-Cookie` senza flag `Secure` | headers | Cookie insicuro |
| Cookie `Set-Cookie` senza flag `HttpOnly` | headers | Cookie vulnerabile XSS |

### Agent 5 — robots.txt Path Risk

| Pattern nel path | Classificazione | Rischio |
|---|---|---|
| `/admin`, `/wp-admin`, `/administrator` | admin_panel | alto |
| `/login`, `/wp-login`, `/user/login` | login_page | medio |
| `/api/`, `/v1/`, `/v2/`, `/graphql` | api_endpoint | medio |
| `/backup`, `/.bak`, `/.sql`, `/.zip` | backup_file | alto |
| `/staging`, `/dev`, `/test`, `/beta` | staging_area | medio |
| `/private`, `/secret`, `/internal` | restricted_area | medio |
| `/.git`, `/.env`, `/config` | sensitive_file | critico |
| `/sitemap.xml` | sitemap | info |

---

## Gestione errori

| Situazione | Comportamento |
|---|---|
| Timeout / connessione rifiutata | Segnala `unreachable`, salta il sito |
| HTTP 403 su homepage | Procede con soli header, segnala "HTML non disponibile" |
| robots.txt assente (404) | Salta Agent 5, segnala "nessun robots.txt trovato" |
| robots.txt con più di 20 path | Sonda i primi 20 path, segnala quanti ne sono stati saltati |
| Path da robots.txt → timeout | Classifica come `timeout`, rischio `unknown` |
| Redirect: segui max 3, poi `redirect_loop` | — |
| SSL error | Finding di rischio `alto` |

---

## Risk Rating (Agent 6)

| Condizione | Contributo |
|---|---|
| File sensibile raggiungibile (`.env`, `.git`) | critico |
| CMS con versione nota e obsoleta | alto |
| Admin panel raggiungibile (200/302) | alto |
| SSL error | alto |
| Header sicurezza mancanti (3+) | medio |
| Cookie senza flag `Secure`/`HttpOnly` | medio |
| Staging/dev area accessibile | medio |
| Server con versione esposta | basso |
| Finding solo con confidence `low` | info |

**Profilo finale:** un solo finding `critico` → CRITICO; 1+ `alto` → ALTO; resto → MEDIO/BASSO/INFO.

---

## Output — Report Markdown

```markdown
# SiteScan Report — example.com
**Data:** 2026-06-29 | **Profilo rischio:** ALTO

## Tecnologie rilevate
| Tecnologia | Categoria | Versione | Confidence |
|---|---|---|---|
| WordPress | CMS | 6.4.2 | high |
| PHP | Backend | 8.1 | high |
| jQuery | JS Library | — | medium |
| Nginx | Web Server | 1.24 | high |
| Cloudflare | CDN | — | high |

## Header di sicurezza
| Header | Presente | Rischio |
|---|---|---|
| Strict-Transport-Security | no | medio |
| Content-Security-Policy | no | medio |
| X-Frame-Options | sì | — |

## Percorsi esposti (robots.txt)
| Path | HTTP | Classificazione | Rischio |
|---|---|---|---|
| /wp-admin/ | 302 | admin_panel | alto |
| /private/ | 403 | restricted_area | basso |

## Valutazione rischi
**Profilo: ALTO**
- Admin panel /wp-admin/ raggiungibile (302 → /wp-login.php)
- 2 header di sicurezza mancanti
- Versione Nginx esposta nell'header Server

## Raccomandazioni
1. Nascondere la versione del server nella configurazione Nginx
2. Aggiungere header Content-Security-Policy e HSTS
3. Valutare protezione aggiuntiva per /wp-admin/ (IP allowlist, 2FA)
```

---

## Struttura file skill

```
skills/
  sitescan/
    SKILL.md          ← skill principale con processo e istruzioni agent
    fingerprints.md   ← catalogo completo pattern (file companion)
```
