# ASP.NET Deep Analysis — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Estendere il skill SiteScan con rilevamento approfondito di siti ASP.NET: branch detection (.NET Framework vs .NET Core/5+), narrowing della versione, check EOL, correlazione CVE, e 19 probe paths specifici.

**Architecture:** Due file Markdown da modificare — `fingerprints.md` riceve 5 nuove sezioni dati (tabelle EOL, CVE, probe paths, segnali di narrowing); `SKILL.md` riceve una nuova Phase 2b con algoritmo a 5 step, un aggiornamento alla Phase 5 per iniettare i probe paths ASP.NET, e nuove righe nella risk table di Phase 6.

**Tech Stack:** Markdown (skill testuale), `curl` via Bash per i probe, `Edit` tool per le modifiche ai file.

## Global Constraints

- I probe paths ASP.NET sono al massimo 19 (limite "Completo" concordato in fase di design)
- Ogni nuova sezione di `fingerprints.md` deve iniziare con `## ` per essere referenziabile da `SKILL.md` con la sintassi `fingerprints.md` → **Nome Sezione**
- Non rinumerare le Phase esistenti — Phase 2b è una sotto-fase, non sposta Phase 3-6
- Spec di riferimento: `docs/superpowers/specs/2026-07-01-aspnet-analysis-design.md`

---

## File Map

| File | Modifica |
|---|---|
| `skills/sitescan/fingerprints.md` | Append 5 nuove sezioni in fondo al file |
| `skills/sitescan/SKILL.md` | Insert Phase 2b dopo Phase 2; update Phase 5 source list; add rows to Phase 6 risk table |

---

## Task 1: Estendi `fingerprints.md` con le 5 nuove sezioni

**Files:**
- Modify: `skills/sitescan/fingerprints.md` (append in fondo)

**Interfaces:**
- Produces: sezioni referenziabili come `fingerprints.md` → **`.NET Framework EOL Versions``, **`.NET Core/5+ EOL Versions`**, **`ASP.NET / IIS Known CVEs`**, **`ASP.NET-Specific Probe Paths`**, **`ASP.NET Version Narrowing Signals`**

- [ ] **Step 1: Verifica il tail attuale del file**

Apri `skills/sitescan/fingerprints.md` e conferma che le ultime righe siano:

```
**Risk elevation rule:** if HTTP status is 200 or 301/302 (reachable), upgrade `info` → `low` and `medio` → `alto` for `admin_panel`, `login_page`, and `sensitive_file` classifications.
```

- [ ] **Step 2: Aggiungi le 5 nuove sezioni**

Usa il tool `Edit` su `skills/sitescan/fingerprints.md`.

`old_string`:
```
**Risk elevation rule:** if HTTP status is 200 or 301/302 (reachable), upgrade `info` → `low` and `medio` → `alto` for `admin_panel`, `login_page`, and `sensitive_file` classifications.
```

`new_string`:
```
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
```

- [ ] **Step 3: Verifica il conteggio delle sezioni aggiunte**

Apri `skills/sitescan/fingerprints.md` e scorri fino in fondo. Devono essere presenti esattamente queste 5 intestazioni `## `:
- `## .NET Framework EOL Versions`
- `## .NET Core / .NET 5+ EOL Versions`
- `## ASP.NET / IIS Known CVEs`
- `## ASP.NET-Specific Probe Paths`
- `## ASP.NET Version Narrowing Signals`

- [ ] **Step 4: Commit**

```bash
git add skills/sitescan/fingerprints.md
git commit -m "feat(sitescan): add ASP.NET EOL tables, CVE list, probe paths, narrowing signals to fingerprints"
```

---

## Task 2: Aggiungi Phase 2b a `SKILL.md`

**Files:**
- Modify: `skills/sitescan/SKILL.md` (insert after Phase 2, before Phase 3)

**Interfaces:**
- Consumes: Phase 2 detection result (`X-Powered-By: ASP.NET`, `X-AspNet-Version`, `Server: Kestrel`)
- Produces: `aspnet_branch` (Framework | Core), `aspnet_version_range` (es. `"4.5–4.8.1"`), `aspnet_confidence` (high | medium | low), list of applicable CVEs — used by Phase 5 (probe injection) and Phase 6 (risk rating)

- [ ] **Step 1: Localizza il punto di inserimento in SKILL.md**

In `skills/sitescan/SKILL.md`, trova il blocco che termina così (fine della sezione Phase 2):

```
Extract the `<version>` tag value. Compare the major branch against `fingerprints.md` → **Joomla EOL Versions**. If the branch is end-of-life, record it as a HIGH-risk finding with the EOL date. Note also whether the manifest is publicly readable (it should return 403 — a 200 response is itself a LOW-risk information-disclosure finding).

---

### Phase 3 — JS Framework & Frontend Detection
```

- [ ] **Step 2: Inserisci Phase 2b**

Usa il tool `Edit` su `skills/sitescan/SKILL.md`.

`old_string`:
```
Extract the `<version>` tag value. Compare the major branch against `fingerprints.md` → **Joomla EOL Versions**. If the branch is end-of-life, record it as a HIGH-risk finding with the EOL date. Note also whether the manifest is publicly readable (it should return 403 — a 200 response is itself a LOW-risk information-disclosure finding).

---

### Phase 3 — JS Framework & Frontend Detection
```

`new_string`:
```
Extract the `<version>` tag value. Compare the major branch against `fingerprints.md` → **Joomla EOL Versions**. If the branch is end-of-life, record it as a HIGH-risk finding with the EOL date. Note also whether the manifest is publicly readable (it should return 403 — a 200 response is itself a LOW-risk information-disclosure finding).

---

### Phase 2b — ASP.NET Deep Scan

Runs only when Phase 2 detected `X-Powered-By: ASP.NET` or `X-AspNet-Version`. Consult `fingerprints.md` → **ASP.NET Version Narrowing Signals** throughout.

#### Step 1 — Determine branch

| Signal | Conclusion |
|---|---|
| `X-AspNet-Version` present + `X-Powered-By: ASP.NET` | .NET Framework (classic CLR) |
| `Server: Kestrel` | .NET Core / .NET 5+ |
| Neither Framework signal + cookie `__Host-` prefix or other .NET Core hints | Likely .NET Core/5+ behind proxy |

#### Step 2 — .NET Framework: narrow the version

Apply in sequence — each signal that fires raises the version floor:

```
X-AspNet-Version build prefix → initial range:
    1.0.* → .NET 1.0
    1.1.* → .NET 1.1
    2.0.* → .NET 2.0 / 3.0 / 3.5 SP1
    4.0.* → .NET 4.0 – 4.8.1  (ambiguous — continue probing)

X-AspNetMvc-Version header (if present):
    5.x → floor .NET 4.5
    4.x → floor .NET 4.0
    3.x → floor .NET 4.0
    2.x → floor .NET 3.5 / 4.0

Probe: curl -sI {url}/bundles/
    200 → floor .NET 4.5

Cookie SameSite attribute present in Set-Cookie:
    → floor .NET 4.7.2

Probe: curl -sI {url}/WebResource.axd
    200 or 400 → WebForms handler active (record as confirming signal)
```

Set `aspnet_confidence`:
- `high` — exact version known (rare, e.g. from error page disclosure)
- `medium` — range narrowed by ≥1 signal beyond CLR prefix (e.g. `"4.5–4.8.1"`)
- `low` — only CLR prefix available (e.g. `"4.0–4.8.1"`)

#### Step 3 — .NET Core/5+: detect version

```bash
# Health endpoint — may return JSON with version
curl -s {url}/health

# Swagger schema — look for "info.version"
curl -s {url}/swagger/v1/swagger.json

# Blazor detection
curl -sI {url}/_framework/blazor.server.js
```

If no probe returns a version: set `aspnet_confidence: low`, note
"version not determinable automatically — verify manually".

#### Step 4 — Apply EOL table

- .NET Framework branch → consult `fingerprints.md` → **`.NET Framework EOL Versions`**
- .NET Core/5+ branch → consult `fingerprints.md` → **`.NET Core / .NET 5+ EOL Versions`**

If the detected range overlaps EOL versions, record a finding with the risk level from the table.

For ambiguous `4.0.*` range with `confidence: low` or `medium` where floor is below 4.6.2:
record MEDIUM — "potentially EOL — exact version unverifiable without direct access".

#### Step 5 — CVE correlation

Consult `fingerprints.md` → **`ASP.NET / IIS Known CVEs`**.
Include in the report only CVEs whose affected version range overlaps the detected range.
If `aspnet_confidence` is `low` or `medium`, annotate each CVE as
"potentially applicable — confirm exact version before ruling out".

Always append this footer when the CVE section is non-empty:
> For full CVE coverage: NVD filter `cpe:2.3:a:microsoft:.net_framework` or `cpe:2.3:a:microsoft:asp.net_core`

---

### Phase 3 — JS Framework & Frontend Detection
```

- [ ] **Step 3: Verifica l'inserimento**

Apri `skills/sitescan/SKILL.md` e cerca `### Phase 2b`. Deve essere presente tra `### Phase 2` e `### Phase 3`, senza interruzioni di numerazione nelle fasi successive.

- [ ] **Step 4: Commit**

```bash
git add skills/sitescan/SKILL.md
git commit -m "feat(sitescan): add Phase 2b ASP.NET deep scan to SKILL.md"
```

---

## Task 3: Aggiorna Phase 5 e Phase 6 in `SKILL.md`

**Files:**
- Modify: `skills/sitescan/SKILL.md`

**Interfaces:**
- Consumes: `aspnet_branch` e `aspnet_version_range` da Phase 2b
- Produces: probe list estesa con path ASP.NET; risk profile aggiornato

- [ ] **Step 1: Aggiorna Phase 5 — aggiungi ASP.NET alla probe injection**

Trova in `skills/sitescan/SKILL.md`:

```
2. CMS-specific paths from `fingerprints.md` → **CMS-Specific Probe Paths** for the CMS detected in Phase 2 (always inject these, regardless of robots.txt)
```

Sostituisci con:

```
2. CMS-specific paths from `fingerprints.md` → **CMS-Specific Probe Paths** for the CMS detected in Phase 2 (always inject these, regardless of robots.txt)
3. If ASP.NET detected in Phase 2: paths from `fingerprints.md` → **ASP.NET-Specific Probe Paths** (always inject these, regardless of robots.txt or CMS detection)
```

- [ ] **Step 2: Aggiorna Phase 6 — aggiungi le nuove righe alla risk table**

Trova in `skills/sitescan/SKILL.md`:

```
| Condition | Level |
|---|---|
| Sensitive file reachable (`.env`, `.git`, `.sql`, `.bak`) | CRITICAL |
```

Sostituisci con:

```
| Condition | Level |
|---|---|
| Sensitive file reachable (`.env`, `.git`, `.sql`, `.bak`) | CRITICAL |
| `/elmah.axd` accessible (200) | CRITICAL |
| .NET Framework ≤ 4.0 detected (CLR `1.x` or `2.0.*` and narrowing excludes 3.5 SP1) | CRITICAL |
| `web.config.bak` or `.vs/` accessible (200) | CRITICAL |
```

- [ ] **Step 3: Aggiungi le righe HIGH nella risk table**

Trova:

```
| Admin panel reachable (200 or 302) | HIGH |
```

Sostituisci con:

```
| Admin panel reachable (200 or 302) | HIGH |
| `/__browserLink/requestData/` accessible (200) — VS debug artifact in production | HIGH |
| `/trace.axd` accessible (200) | HIGH |
| .NET Framework 4.5–4.6.1 detected (EOL 2022-04-26) | HIGH |
| .NET Core / .NET 5–7 detected (all EOL) | HIGH |
| CVE applicable to detected ASP.NET version range | HIGH |
| `/swagger/v1/swagger.json` accessible (200) — full API schema exposed | HIGH |
```

- [ ] **Step 4: Aggiungi le righe MEDIUM nella risk table**

Trova:

```
| 3+ security headers missing | MEDIUM |
```

Sostituisci con:

```
| 3+ security headers missing | MEDIUM |
| .NET Framework 4.x with ambiguous range (narrowing inconclusive, floor below 4.6.2) | MEDIUM |
| `/WebService.asmx` accessible (200) — legacy SOAP interface exposed | MEDIUM |
| `/swagger` accessible (200) without authentication | MEDIUM |
```

- [ ] **Step 5: Aggiungi le righe LOW nella risk table**

Trova:

```
| Server version exposed in headers | LOW |
```

Sostituisci con:

```
| Server version exposed in headers | LOW |
| `X-AspNetMvc-Version` header exposed | LOW |
| `/global.asax` accessible (200) | LOW |
```

- [ ] **Step 6: Verifica la risk table aggiornata**

Apri `skills/sitescan/SKILL.md`, cerca `### Phase 6` e conta le righe della tabella. Devono essere presenti tutte le nuove righe nei livelli CRITICAL, HIGH, MEDIUM e LOW, nell'ordine corretto (CRITICAL in cima).

- [ ] **Step 7: Commit**

```bash
git add skills/sitescan/SKILL.md
git commit -m "feat(sitescan): update Phase 5 probe injection and Phase 6 risk table for ASP.NET"
```

---

## Task 4: Verifica end-to-end con una scansione reale

**Files:** nessuno — passo di verifica manuale

**Interfaces:**
- Consumes: tutti i task precedenti completati
- Produces: conferma che il skill produce output corretto su un sito ASP.NET noto

- [ ] **Step 1: Esegui il skill su `manager.afdsud.it`**

Lancia una nuova scansione su `https://manager.afdsud.it/` seguendo il skill aggiornato.

- [ ] **Step 2: Verifica Phase 2b — branch detection**

L'output deve contenere:
- Branch: `.NET Framework` (da `X-AspNet-Version: 4.0.30319` + `X-Powered-By: ASP.NET`)
- Range iniziale: `4.0 – 4.8.1`

- [ ] **Step 3: Verifica Phase 2b — narrowing**

Il skill deve eseguire:
```bash
curl -sI https://manager.afdsud.it/bundles/
curl -sI https://manager.afdsud.it/WebResource.axd
```
e aggiornare il range in base al risultato (es. se `/bundles/` → 200, floor diventa 4.5).

- [ ] **Step 4: Verifica Phase 2b — CVE correlation**

L'output deve listare i CVE applicabili al range rilevato, con annotazione `confidence`.
CVE-2010-3332 deve essere escluso se il range è confermato ≥ 4.5 (padding oracle non si applica).

- [ ] **Step 5: Verifica Phase 5 — probe injection**

La sezione "Exposed paths" del report deve includere le probe ASP.NET:
`/elmah.axd`, `/trace.axd`, `/__browserLink/requestData/`, `/WebResource.axd`,
`/web.config.bak`, `/.vs/`, `/swagger`, `/swagger/v1/swagger.json`, ecc.

- [ ] **Step 6: Salva il report aggiornato**

Il report finale deve essere salvato come `reports/sitescan-manager.afdsud.it-2026-07-01-v2.md`
(o una data corrente se diversa) tramite il tool `Write`.

- [ ] **Step 7: Commit finale**

```bash
git add reports/
git commit -m "chore: add updated ASP.NET-aware scan report for manager.afdsud.it"
```
