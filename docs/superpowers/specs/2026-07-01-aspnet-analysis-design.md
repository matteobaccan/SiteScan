# Design Spec — ASP.NET Deep Analysis for SiteScan
**Date:** 2026-07-01
**Status:** Approved

---

## Obiettivo

Estendere il skill SiteScan con un'analisi approfondita dei siti ASP.NET: rilevamento del branch (.NET Framework vs .NET Core/5+), narrowing della versione esatta, check EOL, correlazione CVE noti, e probe paths specifici per la superficie IIS/ASP.NET.

---

## Scope

- **.NET Framework** (CLR classico, IIS, WebForms, MVC 1–5)
- **.NET Core / .NET 5–10** (Kestrel, app moderne)
- **CVE coverage:** tabella curata per casi critici + rimando a NVD per copertura completa
- **Probe paths:** fino a 19 path ASP.NET-specifici iniettati in Phase 5

---

## Approccio

**Approccio C** — estensione coerente con il pattern esistente:
- Logica di analisi in `SKILL.md` (nuova Phase 2b)
- Dati di riferimento (EOL, CVE, probe paths) in `fingerprints.md` (nuove sezioni)

---

## Modifiche a `SKILL.md`

### Nuova Phase 2b — ASP.NET Deep Scan

Si attiva condizionalmente dopo Phase 2 se viene rilevato `X-Powered-By: ASP.NET` oppure `X-AspNet-Version`.

#### Step 1 — Determina il branch

| Segnale | Conclusione |
|---|---|
| `X-AspNet-Version` presente + `X-Powered-By: ASP.NET` | .NET Framework (CLR classico) |
| `Server: Kestrel` | .NET Core / .NET 5+ |
| Assenza di entrambi i segnali Framework + cookie `__Host-` prefix o altri segnali .NET Core | Probabilmente .NET Core/5+ dietro proxy |

#### Step 2 — Per .NET Framework: narrowing della versione

Applica in sequenza — ogni segnale restringe il range:

```
X-AspNet-Version build prefix → range iniziale:
    1.0.* → .NET 1.0
    1.1.* → .NET 1.1
    2.0.* → .NET 2.0 / 3.0 / 3.5 SP1
    4.0.* → .NET 4.0 – 4.8.1 (ambiguo, serve probing)

X-AspNetMvc-Version header (se presente):
    5.x → floor .NET 4.5
    4.x → floor .NET 4.0 (compatibile anche con 4.5)
    3.x → floor .NET 4.0
    2.x → floor .NET 3.5 / 4.0

Probe: curl -sI {url}/bundles/
    200 → floor .NET 4.5 (ASP.NET Bundling introdotto in MVC 4 / .NET 4.5)

Cookie SameSite attribute presente nei Set-Cookie header:
    → floor .NET 4.7.2

Probe: curl -sI {url}/WebResource.axd
    200 o 400 → handler WebForms attivo → conferma WebForms
```

Risultato: range come `"4.5 – 4.8.1"` con `confidence: medium`.
Se nessun segnale oltre il CLR prefix: range `"4.0 – 4.8.1"` con `confidence: low`.

#### Step 3 — Per .NET Core/5+: rilevamento versione

```
Probe: curl -s {url}/health
    200 + JSON → cerca campo "version" nel body

Probe: curl -s {url}/swagger/v1/swagger.json
    200 → cerca "info.version" nel JSON

Probe: curl -sI {url}/_framework/blazor.server.js
    200 → Blazor Server confermato (implica .NET 5+)

Header X-Powered-By:
    Alcune configurazioni espongono "ASP.NET Core x.x"
```

Se nessun probe restituisce una versione: `confidence: low`, annotare
"versione .NET Core/5+ non determinabile automaticamente — verificare manualmente".

#### Step 4 — Applica tabella EOL

Consulta `fingerprints.md` → **`.NET Framework EOL Versions`** o **`.NET Core/5+ EOL Versions`**
in base al branch rilevato. Se il range di versione si sovrappone a versioni EOL, registra
finding con il livello di rischio corrispondente.

Regola per range ambigui (.NET Framework `4.0.*` senza narrowing conclusivo):
segnalare MEDIUM — "versione potenzialmente EOL — verificare la versione esatta".

#### Step 5 — Correlazione CVE

Consulta `fingerprints.md` → **`ASP.NET / IIS Known CVEs`**.
Elenca nel report solo i CVE il cui range di versioni affette si sovrappone al range rilevato.

Se `confidence: low` o `medium`: annotare ogni CVE come "potenzialmente applicabile —
verificare la versione esatta prima di escluderlo".

Footer fisso in ogni report che include la sezione CVE:
> Per la copertura CVE completa: NVD filter `cpe:2.3:a:microsoft:.net_framework`
> oppure `cpe:2.3:a:microsoft:asp.net_core`

---

### Aggiornamento Phase 5 — Probe Injection

Quando ASP.NET è rilevato in Phase 2, iniettare i path dalla sezione
`fingerprints.md` → **`ASP.NET-Specific Probe Paths`** nella probe list di Phase 5,
esattamente come avviene per WordPress/Joomla/Drupal.

---

### Aggiornamento Phase 6 — Risk Table

Nuove righe da aggiungere (in ordine di severità):

| Condizione | Livello |
|---|---|
| `/elmah.axd` accessibile (200) | CRITICAL |
| .NET Framework ≤ 4.0 rilevato | CRITICAL |
| `web.config.bak` o `.vs/` accessibile (200) | CRITICAL |
| `/__browserLink/requestData/` accessibile (200) | HIGH |
| `/trace.axd` accessibile (200) | HIGH |
| .NET Framework 4.5 – 4.6.1 rilevato (EOL 2022-04-26) | HIGH |
| .NET Core / .NET 5–7 rilevato (tutti EOL) | HIGH |
| CVE applicabile al range di versione rilevato | HIGH |
| `/swagger/v1/swagger.json` accessibile (200) | HIGH |
| .NET Framework 4.x con range ambiguo (narrowing non conclusivo) | MEDIUM |
| `/WebService.asmx` accessibile (200) | MEDIUM |
| `/swagger` accessibile (200) senza auth | MEDIUM |
| `X-AspNetMvc-Version` header esposto | LOW |
| `/global.asax` accessibile (200) | LOW |

---

## Modifiche a `fingerprints.md`

### Nuova sezione: .NET Framework EOL Versions

| CLR prefix | Framework versions | EOL date | Risk |
|---|---|---|---|
| `1.0.*` | .NET 1.0 | 2009-07-14 | CRITICAL |
| `1.1.*` | .NET 1.1 | 2013-10-08 | CRITICAL |
| `2.0.*` | .NET 2.0 | 2011-07-12 | CRITICAL |
| `2.0.*` | .NET 3.0 | 2011-07-12 | CRITICAL |
| `2.0.*` | .NET 3.5 SP1 | 2029-01-09 | OK |
| `4.0.*` | .NET 4.0 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5.1 | 2016-01-12 | CRITICAL |
| `4.0.*` | .NET 4.5.2 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6.1 | 2022-04-26 | HIGH |
| `4.0.*` | .NET 4.6.2 | 2027-01-12 | OK |
| `4.0.*` | .NET 4.7 – 4.8.1 | 2029-01-09 | OK |

> Nota: CLR `4.0.*` copre Framework 4.0–4.8.1. Senza narrowing, il range è ambiguo.
> Segnalare MEDIUM se il floor rilevato non supera 4.6.2.

### Nuova sezione: .NET Core / .NET 5+ EOL Versions

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
| .NET 8 | LTS | 2026-11-10 | OK |
| .NET 9 | STS | 2026-05-12 | OK |
| .NET 10 | LTS | ~2027-11 (TBD) | OK |

### Nuova sezione: ASP.NET / IIS Known CVEs

| CVE | Componente | Versioni affette | CVSS | Tipo |
|---|---|---|---|---|
| CVE-2010-3332 | ASP.NET ViewState | .NET 1.1 – 4.0 | 7.5 | Padding Oracle → info disclosure + RCE |
| CVE-2015-1635 | HTTP.sys (driver IIS) | Windows Server 2008/2008R2/2012/2012R2 | 10.0 | RCE unauthenticated via header Range malformato (MS15-034) |
| CVE-2017-8759 | .NET Framework WSDL/SOAP | .NET 2.0 – 4.7 | 7.8 | RCE via documento WSDL artefatto |
| CVE-2021-31166 | HTTP.sys (driver IIS) | Windows 10 20H2, Server 2019/2022 | 9.8 | RCE wormable unauthenticated (KB5003173) |
| CVE-2021-26701 | System.Text.RegularExpressions | .NET Core 2.1, 3.1, .NET 5 | 9.8 | RCE via input regex artefatto |

### Nuova sezione: ASP.NET-Specific Probe Paths

**Diagnostica e logging**
| Path | Classification | Risk se 200 | Note |
|---|---|---|---|
| `/elmah.axd` | logging_endpoint | CRITICAL | Stack trace + exception log senza auth |
| `/trace.axd` | legacy_endpoint | HIGH | Request trace viewer con dati di sessione |
| `/__browserLink/requestData/` | dev_artifact | HIGH | VS Browser Link — non deve esistere in produzione |

**Handler WebForms**
| Path | Classification | Risk se 200/400 | Note |
|---|---|---|---|
| `/WebResource.axd` | resource_handler | LOW | 400 = handler attivo (atteso senza parametri); conferma WebForms |
| `/ScriptResource.axd` | resource_handler | LOW | Conferma WebForms + ScriptManager |
| `/bundles/` | bundle_endpoint | LOW | 200 = Bundling attivo → floor .NET 4.5 |

**File sensibili IIS/ASP.NET**
| Path | Classification | Risk se 200 | Note |
|---|---|---|---|
| `/web.config.bak` | sensitive_file | CRITICAL | Backup config con connstring e chiavi |
| `/Web.config` | sensitive_file | CRITICAL | Case variation |
| `/.vs/` | dev_artifact | CRITICAL | Cartella Visual Studio con solution data |
| `/app_offline.htm` | other | INFO | Maintenance page |
| `/global.asax` | other | LOW | Root application handler |
| `/aspnet_client/` | legacy_endpoint | LOW | File legacy ASP.NET client-side |

**API e documentazione**
| Path | Classification | Risk se 200 | Note |
|---|---|---|---|
| `/swagger` | api_docs | MEDIUM | Swagger UI — espone surface API |
| `/swagger/v1/swagger.json` | api_docs | HIGH | Schema JSON completo con tutti gli endpoint |
| `/api/` | api_endpoint | MEDIUM | Root API |
| `/health` | status_endpoint | LOW | Health check — può esporre versione e dipendenze |

**Framework specifici**
| Path | Classification | Risk se 200 | Note |
|---|---|---|---|
| `/signalr/negotiate` | websocket_endpoint | LOW | Conferma SignalR + versione nel body JSON |
| `/_framework/blazor.server.js` | js_bundle | LOW | Conferma Blazor Server (.NET 5+) |
| `/WebService.asmx` | legacy_endpoint | MEDIUM | ASMX web service — interfaccia SOAP esposta |

### Nuova sezione: ASP.NET Version Narrowing Signals

| Segnale | Dove | Informazione estratta |
|---|---|---|
| `X-AspNet-Version` build prefix | header | CLR branch → range framework iniziale |
| `X-AspNetMvc-Version` | header | Versione MVC → floor framework |
| `/bundles/` → 200 | probe | Floor .NET 4.5 |
| Cookie `SameSite` attribute | Set-Cookie header | Floor .NET 4.7.2 |
| `/WebResource.axd` → 200/400 | probe | Conferma WebForms attivo |
| `Server: Kestrel` | header | Branch .NET Core/5+ |
| `/_framework/blazor.server.js` → 200 | probe | .NET 5+ confermato |
| `/health` → JSON con "version" | probe | Versione .NET Core/5+ esplicita |
| `/swagger/v1/swagger.json` → "info.version" | probe | Versione API (indicativa) |
