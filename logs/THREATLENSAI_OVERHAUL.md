# ThreatLensAI — Comprehensive Overhaul Plan

## Current State Analysis

### 1. ML/AI Compatibility & Inference Validation

**Models available** (`data_science/outputs/artifacts/`):
- `cve_tfidf_logreg.joblib` — TF-IDF + Logistic Regression for CVE text
- `cve_xgb_model.joblib` — XGBoost for CVE (not referenced by backend)
- `domain_model.joblib` — Domain classifier with label encoder
- `ip_logreg_model.joblib` — IP Logistic Regression
- `ip_xgb_model.joblib` — IP XGBoost
- `otx_classical_label_encoder.joblib` — OTX label encoder
- `otx_transformer_label_encoder.joblib` — Transformer label encoder
- `otx_transformer/` — HuggingFace transformer checkpoint directory

**Issues found:**
- `threat-lens-ai/models/` is **empty** — models must be copied from `data_science/outputs/artifacts/`
- Backend `modeling_service.py` references `otx_attackids_tfidf_ovr_logreg.joblib` which **does not exist** in artifacts
- `modeling_service.py` uses `load_joblib_artifact()` which searches: `joblib_model_path` → `models_path` → `./models/` → `/models/` — none of these point to `data_science/outputs/artifacts/`
- Heuristic fallback functions (`_heuristically_analyze_unseen_*`) produce fabricated features (hash-based MD5 → random-looking country/ASN/owner), damaging ML model trust
- Column mapping between heuristic output and `_build_domain_df`/`_build_ip_df` is mostly correct but some fields differ (e.g., `data_source` vs `Data_Source` casing)

### 2. Threat Intelligence & API Reliability — Expanded Free-Tier Architecture

**Architecture principle:** All API clients extend `BaseAPIClient` (async httpx with retry/rate-limit handling). The `enrichment_pipeline.py` orchestrates queries in parallel via `asyncio.gather()`. More sources = richer feature vectors for ML models. Each source contributes to the `source_breakdown` and `evidence` fields independently.

**Current (4 sources):**

| Source | Type | Status | Free Tier Limit |
|--------|------|--------|----------------|
| ✅ AbuseIPDB | IP reputation | Working | 1,000 checks/day |
| ✅ AlienVault OTX | IP/Domain/Pulse | Working | Unlimited |
| ✅ NVD | CVE details | Working | 50 req/30s (with key) |
| ❌ Cloudflare Registrar | WHOIS | Broken (400/403) | N/A |

**Target (13 sources) — all free tiers, no paid plans:**

| # | Source | Type | Free Limit | API Key Needed | Prerequisite |
|---|--------|------|-----------|---------------|-------------|
| 1 | **AbuseIPDB** | IP reputation | 1,000/day | ✅ Yes | `ABUSEIPDB_API_KEY` in .env |
| 2 | **AlienVault OTX** | IP/Domain/Pulse | Unlimited | ✅ Yes | `OTX_API_KEY` in .env |
| 3 | **NVD** | CVE details | 50 req/30s | ✅ Yes | `NVD_API_KEY` in .env |
| 4 | **CISA KEV** | Known exploited vulns | Unlimited | ❌ No | Public JSON feed |
| 5 | **FIRST EPSS** | CVE exploit probability | Unlimited | ❌ No | `https://api.first.org/data/v1/epss` |
| 6 | **GreyNoise** | IP classification | 50/day | ✅ Yes | [Sign up](https://greynoise.io) |
| 7 | **VirusTotal** | Multi-engine IP/Domain/URL | 500/day | ✅ Yes | [Sign up](https://virustotal.com) |
| 8 | **URLScan.io** | Domain analysis/screenshots | Free tier | ✅ Yes | [Sign up](https://urlscan.io) |
| 9 | **ThreatFox** | IOC search (abuse.ch) | Free | ✅ Auth-Key | [Get key](https://threatfox.abuse.ch) |
| 10 | **URLhaus** | Malware URLs (abuse.ch) | Free | ✅ Auth-Key | [Get key](https://urlhaus.abuse.ch) |
| 11 | **MalwareBazaar** | Hash lookup (abuse.ch) | Free | ✅ Auth-Key | [Get key](https://malwarebazaar.abuse.ch) |
| 12 | **WhoisJSON** | WHOIS/registrar | 1,000/month | ✅ Yes | [Sign up](https://whoisjson.com) |
| 13 | **RDAP (direct)** | WHOIS replacement | Unlimited | ❌ No | IETF standard, zero setup |

**Cloudflare → RDAP/WhoisJSON migration:**
- `cloudflare_client.py` is **deprecated** — both endpoints fail (400/403)
- Create `services/api_clients/rdap_client.py` — RDAP direct (no API key)
- Create `services/api_clients/whoisjson_client.py` — WhoisJSON fallback (API key)
- The enrichment pipeline tries RDAP first, falls back to WhoisJSON

**How parallel enrichment works (13 sources at once):**
```python
# enrichment_pipeline.py - parallel enrichment for IPs
tasks = [
    abuseipdb_client.check_ip(ip),
    otx_client.get_ip_reputation(ip),
    greynoise_client.check_ip(ip),
    virustotal_client.get_ip_report(ip),
    threatfox_client.search_ioc(ip),
]
results = await asyncio.gather(*tasks, return_exceptions=True)
```

Each source returns `None` if unavailable or rate-limited — the pipeline gracefully degrades.

### 3. Logging, Monitoring & Error Analysis

**Critical bugs from `error_logs_may_23th.txt`:**
1. **Page reloads 2-3x after domain scan** — Root cause found in `search.js:21`:
   ```js
   window.location.href = "index.html?q=" + encodeURIComponent(query);
   ```
   This triggers full page redirect, and `ui.js`'s `loadIndexPage()` then re-scans via `sessionStorage` pending_query mechanism AND URL `?q=` param, causing cascade of 2-3 scans.

2. **Cloudflare Registrar failures** — Every domain scan triggers 2 API calls (generic + account-scoped), both fail → wasted latency

3. **Source breakdown always shows 2 items** — `_source_breakdown_from_results()` always builds at least one item; combined with exact_detail prepend, minimum is 2 items regardless of actual data

4. **Score doesn't match DS standards** — Scoring functions use arbitrary weights; `_verdict_from_score` thresholds don't align with ML model output ranges

### 4. Network Scanning & Enrichment (Nmap)

**Current state:** Gated behind `ENABLE_NMAP_SCAN=false` — completely disabled.

**Paper inspiration (LocalAI-Sec):**
- Uses `nmap -sV -oX` for version detection
- Extracts CPE identifiers → NVD lookup for CVEs
- Local LLM (Ollama) for unknown service analysis
- **Key: Only scans internal/RFC1918 IPs — never external**

**Implementation requirements:**
- `nmap` binary must be installed on host
- XML parsing via `xml.etree.ElementTree`
- CPE generation from service/version pairs
- NVD CVE lookup from CPE strings
- Maximum 60s timeout, sandboxed subprocess

### 5. Data Engineering, Drift Monitoring & Retraining

**Data flow assessment:**
- CSV files exist in 3 locations: `backend/data/`, `backend/data/unmodified_raw/`, `data_science/data/raw/`
- `unmodified_raw/` CSVs have slightly different formatting (microsecond timestamps, float indicators_count)
- `load_csv.py` imports CSVs into SQLite DB on startup
- Export endpoint (`/model/export/{indicator_type}`) streams CSV with correct column schema
- Background sync (`POST /model/sync`) fetches CISA KEV, NVD recent CVEs, OTX pulses
- `training_metadata` table tracks dataset growth

**Inconsistencies:**
- Backend `data/` CSVs use `Title_Case` headers (e.g., `Malicious_Votes`), matching modeling_service column map
- `unmodified_raw/` has identical structure but slightly different numeric formatting
- `data_science/data/raw/` has `snake_case` headers matching data science notebook conventions
- The export endpoint normalizes to `Title_Case` — data scientists need to adapt for retraining

### 6. Front-End UX/UI & Analyst Experience

**Tip of the Day:** Currently hardcoded in `tips.py` (20 static strings). Never updates without code change.

**Proposed dynamic sources:**
1. **CISA KEV Feed** — Fetch latest known exploited vulnerabilities daily
2. **NVD Recent CVEs** — Trending vulnerabilities with high CVSS
3. **MITRE ATT&CK** — Random technique spotlight
4. **OTX Latest Pulses** — Top threat indicator trends

**Page reload bug:** See section 3.1 above.

**UI improvements:**
- Source breakdown should show actual vendor counts (like VirusTotal's "X/Y security vendors flagged")
- Score should display with ML confidence bands
- Export button for analyst to download scan results as CSV
- "View raw JSON" toggle for power users

---

## Overhaul Plan (Phased)

### Multi-Agent Coordination Strategy

The overhaul is executed by multiple specialized agents in parallel. Each agent has a defined scope, deliverables, and handoff protocol.

#### Agent Roles

| Agent | Scope | Key Files | Deliverables |
|-------|-------|-----------|-------------|
| **Data Science Agent** | ML pipeline, notebooks, feature engineering | `data_science/notebooks/*.ipynb`, `data_science/configs/lookups/` | Retrained .joblib models, updated feature configs |
| **Backend Agent** | API clients, scoring, enrichment, ML adapter | `threat-lens-ai/backend/app/services/`, `routers/`, `utils/` | API contracts, scoring schema, enriched CSV exports |
| **Frontend Agent** | HTML, JS, CSS, UI rendering | `threat-lens-ai/frontend/` | SPA navigation, verdict card redesign, loading skeletons |
| **Integration Agent** | Cross-cutting, gate verification, cleanup | Root `.env.example`, `AGENTS.md`, `CHANGELOG.md` | Gate passes, cleanup, documentation audit |

#### Execution Rules

1. **Stage-gated:** Stage 1 → Stage 2 → Stage 3. No overlaps between stages.
2. **Within-stage parallelism:** Agents work concurrently on files they own. No two agents edit the same file.
3. **Contract-driven handoff:** Agents write JSON contract files to `threat-lens-ai/logs/contracts/` before handoff:
   - `api_contract.json` — Backend → Frontend (endpoint schemas, response shapes)
   - `model_manifest.json` — Data Science → Backend (.joblib paths, feature columns, F1 scores)
   - `scoring_contract.json` — Backend → Frontend (risk bands, confidence ranges)
4. **Gate verification:** Integration agent runs all verification commands at each gate. If any criterion fails, the root cause must be fixed before proceeding.

#### Phase-Level Agent Assignments

| Phase | Lead Agent | Supporting Agent | Contract File |
|-------|-----------|-----------------|---------------|
| 1: Copy Models & Fix Inference | Integration | Data Science | `model_manifest.json` |
| 2: Multi-Source Intel Layer (13 APIs) | Backend | Integration | `api_contract.json` |
| 3: Fix Page Reload Bug | Frontend | — | — |
| 4: Fix Source Breakdown & Scoring | Backend | — | `scoring_contract.json` |
| 5: Nmap Integration | Backend | Integration | — |
| 6: Dynamic Tip of the Day | Backend | — | — |
| 7: Data Consistency & Retraining Pipeline | Backend | Data Science | `model_manifest.json` |
| 8: UI/UX Enhancements | Frontend | Backend | `scoring_contract.json` |

#### File Ownership Matrix

| File Pattern | Owner |
|-------------|-------|
| `data_science/notebooks/` | Data Science Agent |
| `data_science/configs/lookups/` | Data Science Agent |
| `data_science/outputs/artifacts/` | Data Science Agent |
| `threat-lens-ai/backend/app/services/api_clients/` | Backend Agent |
| `threat-lens-ai/backend/app/services/*.py` | Backend Agent |
| `threat-lens-ai/backend/app/utils/scoring.py` | Backend Agent |
| `threat-lens-ai/backend/app/schemas/` | Backend Agent |
| `threat-lens-ai/frontend/assets/js/*.js` | Frontend Agent |
| `threat-lens-ai/frontend/*.html` | Frontend Agent |
| `threat-lens-ai/backend/.env.example` | Integration Agent |
| Root `AGENTS.md`, `THREATLENSAI_OVERHAUL.md` | Integration Agent |

---

### Phase 1: Copy Models & Fix Inference Path

**What:**
1. Copy all `.joblib` files from `data_science/outputs/artifacts/` to `threat-lens-ai/models/`
2. Copy `otx_transformer/` directory to `threat-lens-ai/models/`
3. Add `models_path` config pointing to `threat-lens-ai/models/`
4. Verify ALL model files referenced in `modeling_service.py` exist in `models/`
5. Create missing `otx_attackids_tfidf_ovr_logreg.joblib` or remove references

### Phase 2: Build Multi-Source Intel Layer (13 APIs)

**Credentials you need to create** (see prerequisites table above for signup URLs):

| Env Variable | Source | Signup URL |
|-------------|--------|-----------|
| `GREYNOISE_API_KEY` | GreyNoise | https://greynoise.io |
| `VIRUSTOTAL_API_KEY` | VirusTotal | https://virustotal.com |
| `URLSCAN_API_KEY` | URLScan.io | https://urlscan.io |
| `THREATFOX_AUTH_KEY` | ThreatFox (abuse.ch) | https://threatfox.abuse.ch |
| `URLHAUS_AUTH_KEY` | URLhaus (abuse.ch) | https://urlhaus.abuse.ch |
| `MALWAREBAZAAR_AUTH_KEY` | MalwareBazaar (abuse.ch) | https://malwarebazaar.abuse.ch |
| `WHOISJSON_API_KEY` | WhoisJSON | https://whoisjson.com |

**No credential needed** for: RDAP (direct), FIRST EPSS, CISA KEV (public feeds).

**New files to create:**
```
services/api_clients/
├── greynoise_client.py          # IP noise classification (50/day free)
├── virustotal_client.py         # Multi-engine IP/Domain/URL lookup (500/day)
├── urlscan_client.py            # Domain scan + screenshots (free tier)
├── threatfox_client.py          # abuse.ch IOC search (free Auth-Key)
├── urlhaus_client.py            # abuse.ch malware URL search (free Auth-Key)
├── malewarebazaar_client.py     # abuse.ch hash lookup (free Auth-Key)
├── rdap_client.py               # RDAP WHOIS replacement (free, no key)
├── whoisjson_client.py          # WhoisJSON fallback (1,000/mo free)
├── epss_client.py               # FIRST EPSS exploit scoring (free, no key)
└── __init__.py                  # Export all clients
```

**Files to modify:**
- `enrichment_pipeline.py` — parallelize all 13 sources per indicator type
- `cloudflare_client.py` — mark deprecated
- `config.py` — add all new API key env vars
- `.env` — add new keys

**Parallel enrichment design:**
- IP scan → AbuseIPDB + OTX + GreyNoise + VirusTotal + ThreatFox + RDAP
- Domain scan → OTX + VirusTotal + URLScan + ThreatFox + RDAP + WhoisJSON
- CVE scan → NVD + CISA KEV + EPSS
- OTX pulse → already self-contained

All calls in `asyncio.gather()` — slow sources don't block fast ones.

### Phase 3: Fix Page Reload Bug

**What:**
1. Fix `search.js` — replace `window.location.href = "index.html?q=..."` with SPA-style navigation
2. Fix `ui.js` — prevent double-scan from both sessionStorage and URL params
3. Add dedup logic so `click` event on rescan buttons triggers only one scan

### Phase 4: Fix Source Breakdown & Scoring

**What:**
1. Fix `_source_breakdown_from_results()` to accurately reflect actual vendor detections
2. Align scoring thresholds with ML model confidence ranges
3. Add actual engine/vendor names from API responses instead of generic `source_type`

### Phase 5: Implement Nmap Integration

**What:**
1. Create `backend/app/services/nmap_service.py`:
   - Subprocess with `nmap -sV -oX -`
   - XML parsing with `xml.etree.ElementTree`
   - CPE string generation for service:version pairs
   - RFC1918-only guard (10.x, 172.16-31.x, 192.168.x)
   - 60s timeout, sandboxed execution
2. Create `backend/app/models/nmap_results.py`
3. Integrate into `enrichment_pipeline.py` — only for internal IPs when `ENABLE_NMAP_SCAN=true`
4. Wire into scan flow for IP indicators

### Phase 6: Dynamic Tip of the Day

**What:**
1. Replace hardcoded list with dynamic API aggregation:
   - Fetch latest CISA KEV → format as tip
   - Fetch NVD highest CVSS → format as tip
   - Fall back to curated static list if APIs unreachable
2. Add cache layer (24h TTL) so tips only refresh daily
3. Add `vulnerability_tip`, `threat_tip`, `general_tip` categories

### Phase 7: Data Consistency & Retraining Pipeline

**What:**
1. Normalize CSV column naming between `data_science/` and `backend/`:
   - Add `normalize_columns()` to export endpoint to produce both `Title_Case` and `snake_case` formats
   - Or add `/model/export/{indicator_type}?format=snake_case` parameter
2. Sync `unmodified_raw/` with `data/` on import to keep consistent
3. Add scheduled automated background sync (via `POST /model/sync` cron)
4. Add database growth dashboard endpoint (`GET /model/stats`) showing:
   - Total records per indicator type
   - API-enriched records count
   - Last export timestamp
   - Recommended retrain flag when enriched records > threshold

### Phase 8: UI/UX Enhancements

**What:**
1. Fix verdict display to show actual engine counts (like VirusTotal's "X/Y")
2. Add score confidence indicator (sparkline or range)
3. Add "Download Report as CSV" button
4. Add raw JSON view toggle
5. Improve source breakdown with actual vendor names from API responses
6. Add search history with filters/deletion

---

## Verification Criteria

| Criterion | How to Verify |
|-----------|--------------|
| Models load correctly | `GET /model/status` returns all models as `true` |
| API enrichment works | Scan a new IP/domain → `data_source` is `live_api` |
| No Cloudflare errors | Check `enrichment_log` table — no Cloudflare entries with failure |
| No page reload loop | Scan a domain → URL doesn't reload, single scan request in logs |
| Source breakdown matches API | Scan an IP → source_breakdown shows AbuseIPDB/OTX with correct verdicts |
| Tip of day is dynamic | `GET /tip-of-the-day` returns different content that references current threats |
| Nmap works (if enabled) | `ENABLE_NMAP_SCAN=true`, scan localhost → CPEs extracted, NVD lookup succeeds |
| Export CSV matches training schema | Download from `/model/export/ip` → columns match `data_science/data/raw/` |
| Retraining is possible | Data scientist can download CSV, train model, drop .joblib into `models/`, restart backend |

---

## Stage 3: RC2 Implementation

**Scope:** Frontend UI/UX polish + backend score computation overhaul + cross-cutting concerns.  
**Prerequisite:** Stage 1 + Stage 2 Gates pass 100%.

### Multi-Agent Task Splitting (RC2)

| Task | Agent | Dependencies |
|------|-------|-------------|
| A1–A4 (Model health, source grid, verdict tags, CVE/OTX counters) | **Frontend** | None |
| A5–A7 (Loading skeletons, details page, CSS) | **Frontend** | None |
| B1–B3 (Scoring framework, confidence calibration, consensus) | **Backend** | None |
| B4–B5 (Temporal decay, ensemble integration) | **Backend** | B1–B3 |
| D1–D3 (Env example, rate limiting, error handling) | **Integration** | B1–B3 |
| E1–E5 (Cleanup, docs, regression) | **Integration** | All above |

**Parallelism allowed within phases** (A + B are independent).  
**No shared file writes** — Frontend edits `ui.js`, Backend edits `scoring.py`, Integration edits `.env.example`.

---

### Phase A: UI/UX Polish (Frontend)

#### A1. Replace "Models ❌ models" with Model Health Status Panel
- **Files:** `frontend/assets/js/ui.js` (lines 397–417), `frontend/index.html`
- **Current:** `renderModelHealthBar()` dumps raw ✅ model_name (F1=X) text.
- **New — Two-tier display:**
  - **Admin mode** (when /model/status returns detailed metadata): Show expandable card with per-model F1, sample count, training date, loaded status, and composite health score
  - **General user mode** (fallback): Show simple status bar: 🧠 4/5 models active with green/amber/red indicator
- **Visual layout:**
  ```
  ┌─────────────────────────────────────────────────────────────┐
  │ 🧠 Model Health                                    [Details] │
  │ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ │
  │ IP: ✅ F1=1.0  │  Domain: ✅ F1=0.92  │  CVE: ⚠ F1=0.49  │
  │ OTX: ⚠ F1=0.49  │  Nmap: ❌ Off                           │
  └─────────────────────────────────────────────────────────────┘
  ```
- **Color-code:** F1 ≥ 0.80 = green, 0.50–0.79 = amber, < 0.50 = red
- "Details" toggle expands to show training metadata, sample counts, last retrain date
- On index.html: positioned between header and scan form (replace current #modelHealthBar div)
- On results.html / details.html: compact single-row bar in header area

#### A2. Redesign Results Page — Source Breakdown Card Grid
- **Files:** `frontend/assets/js/ui.js` (renderSourceBreakdown, renderMlCard)
- **Current:** Flat list of cards, each with source_type, verdict, score, note.
- **New design:**
  - Grid layout with visual hierarchy: ML prediction card first (largest, violet border), then API sources in 2-column grid, then heuristic sources
  - Each source card gets:
    - Colored left border by type (API=cyan, ML=violet, Heuristic=amber, Network=emerald)
    - Verdict as prominent badge (not just text)
    - Score as mini progress bar (0–10 scale)
    - Confidence as small pill
    - Source type icon: 🔌 API, 🧠 ML, ⚙ Heuristic, 🌐 Network
  - ML card specifically gets:
    - Per-class probability bars (already implemented but needs better layout)
    - Ensemble vote display
    - Model metadata tooltip

#### A3. Enlarge Verdict Tags — Better Vertical Spacing
- **Files:** `frontend/assets/js/ui.js` (renderVerdictSummary, lines 121–179)
- **Current:** Tags packed in flex-wrap gap-2 inline.
- **New design:**
  - Verdict badge: larger (px-4 py-2 text-sm instead of px-3 py-1 text-xs)
  - Risk band badge: same enlarged sizing
  - Score pill: separate line below verdict badge
  - Confidence bar: full-width with proper margin (mt-3 instead of inline)
  - Detection counters: only show when total > 0 and not OTX/CVE

#### A4. Remove CVE/OTX Placeholder Detection Counters
- **Files:** `frontend/assets/js/ui.js` (renderVerdictSummary, showInlinePreview)
- **Current:** ui.js:162-175 always renders 3-column grid even for CVE/OTX where counts are always 0/0/0.
- **Fix:**
  - Wrap the 3-column detection grid in `if (!isOtxCve && total > 0)` condition
  - For CVE/OTX, replace with single "Reference record — no engine verdicts" note
  - In inline preview (showInlinePreview): same conditional rendering

#### A5. Loading Skeletons — Enhanced Multi-Stage
- **Files:** `frontend/assets/js/ui.js` (doScanFromQuery)
- **Current:** Single skeleton block at ui.js:798-808.
- **Enhancement:**
  - Show skeleton per-section (verdict, source breakdown, evidence, sidebar) for progressive loading
  - Add subtle progress indicator: "Querying APIs... (3/11)" that updates as sources complete
  - Stagger skeleton fade-in with transition-opacity for smoother feel

#### A6. Details Page Enhancement
- **Files:** `frontend/assets/js/ui.js` (renderDetail)
- **Current:** Metadata grid + evidence + source breakdown + raw JSON.
- **Enhancements:**
  - Add visual timeline/history section showing first seen, last enriched, last scanned
  - Improve metadata grid: consistent key formatting (Title Case), add icons per field type
  - Add "Re-scan" button that triggers live API enrichment (not just DB lookup)
  - Add copy-to-clipboard for raw JSON
  - Add breadcrumb navigation: Home > Results > Details

#### A7. CSS Micro-Improvements
- Add `scroll-mt-20` to sections for smooth anchor scrolling
- Add `select-all` utility to query labels for easy copy
- Consistent border-radius: all cards use `rounded-3xl` (currently mixed rounded-2xl/rounded-3xl)
- Add subtle `backdrop-blur` to header for glass effect on scroll

---

### Phase B: Backend Score Computation Overhaul

#### B1. Research-Grounded Scoring Framework
- **Files:** `backend/app/utils/scoring.py`, `backend/app/services/scan_service.py`
- **Current:** Heuristic weight accumulation with magic numbers.
- **New — Weighted Multi-Signal Scoring:**

| Signal | Weight | Source |
|--------|--------|--------|
| ML model probability | 0.30 | modeling_service.py |
| API consensus ratio | 0.25 | enrichment_pipeline.py |
| Heuristic lexical score | 0.15 | scoring.py |
| Temporal recency | 0.10 | Enrichment timestamps |
| Severity weight | 0.10 | NVD CVSS / vote counts |
| Source credibility | 0.10 | Per-source reliability |

- **Implementation:**

```python
def compute_composite_score(
    ml_prediction: Optional[Dict],
    api_sources: List[Dict],
    heuristic_score: float,
    last_enriched: Optional[datetime],
    source_credibility: Dict[str, float],
) -> Tuple[float, str, Dict]:
    """
    Returns (score, risk_band, breakdown_dict).

    Score is a weighted composite 0-10, calibrated so:
    - 8.5-10.0 = CRITICAL (active exploitation / high confidence malicious)
    - 6.5-8.49 = HIGH
    - 4.0-6.49 = MEDIUM
    - 1.5-3.99 = LOW
    - 0.0-1.49 = IGNORE
    """
```

- **Key changes:**
  - ML probability is Platt-calibrated (not raw confidence * 10)
  - API consensus = (malicious_sources / total_sources) * 10 with penalty for disagreement
  - Temporal decay: score *= max(0.5, 1.0 - days_since_enrichment / 30) (half-life ~30 days)
  - Source credibility: AbuseIPDB=0.9, VirusTotal=0.85, NVD=0.95, RDAP=0.7, heuristic=0.5
  - Final score clipped to [0, 10] and rounded to 2 decimal places

#### B2. Confidence Calibration
- **Files:** `backend/app/utils/scoring.py`, `backend/app/services/scan_service.py`
- **Current:** `_confidence_from_score()` uses hardcoded thresholds per verdict.
- **New:** Use Platt scaling or isotonic regression on held-out calibration set to map ML probability → calibrated confidence with proper confidence intervals.

```python
def calibrate_confidence(
    ml_probability: float,
    n_sources: int,
    agreement_ratio: float,
) -> Tuple[float, float, float]:
    """
    Returns (calibrated_confidence, ci_low, ci_high).

    Uses Platt scaling + bootstrap CI from source agreement.
    """
```

- Confidence interval widens when sources disagree or ML confidence is moderate
- CI narrows when multiple sources agree and ML confidence is extreme

#### B3. API Consensus Scoring
- **Files:** `backend/app/services/scan_service.py` (_aggregate_detections)
- **Current:** Counts malicious/suspicious/clean from source breakdown items.
- **New:** Weighted consensus:

```python
def weighted_consensus(source_breakdown: List[Dict]) -> float:
    """
    Weighted vote: each source contributes (verdict_score * credibility).
    Returns 0-10 composite from API sources only.
    """
    weights = {"MALICIOUS": 1.0, "SUSPICIOUS": 0.5, "CLEAN": 0.0, "UNKNOWN": None}
    credibility = {"ABUSEIPDB": 0.9, "VIRUSTOTAL": 0.85, "NVD": 0.95}
    # Only count sources with actual verdicts (not UNKNOWN)
```

#### B4. Temporal Decay for Stale Intelligence
- **Files:** `backend/app/utils/scoring.py`
- Add time-based decay factor:

```python
def temporal_decay(last_enriched: Optional[datetime], half_life_days: int = 30) -> float:
    if last_enriched is None:
        return 0.7  # unknown age -> penalty
    days = (datetime.utcnow() - last_enriched).days
    return max(0.5, math.exp(-0.693 * days / half_life_days))
```

- Applied to API consensus component only (not ML model, not heuristic).

#### B5. ML Score Integration — Ensemble Disagreement Penalty
- **Files:** `backend/app/services/scan_service.py`, `backend/app/services/modeling_service.py`
- **Current:** `score = round(ml_confidence * 10.0, 2)` — raw conversion.
- **New:**
  - Use ensemble disagreement between XGB and LogReg (both exist for IPs):
    ```python
    ensemble_agreement = 1.0 - abs(xgb_prob - logreg_prob)
    ml_adjusted_score = calibrated_prob * 10.0 * ensemble_agreement
    ```
  - For single-model predictions (CVE, Domain, OTX): use Platt calibration
  - ML score is a component of the composite, not the whole score

---

### Phase C: User Authentication

#### C1. Auth System Design
- **New files:**
  - `backend/app/models/user.py` — User ORM model
  - `backend/app/routers/auth.py` — Login/Register/Refresh endpoints
  - `backend/app/services/auth_service.py` — JWT + password hashing
  - `backend/app/schemas/auth.py` — Auth request/response schemas
- **Tech stack:**
  - JWT (access token: 15min, refresh token: 7 days)
  - bcrypt for password hashing (via passlib)
  - Pydantic validation for auth schemas
  - SQLite/PostgreSQL users table

#### C2. User Model
```python
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user")  # "user" | "admin" | "analyst"
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime, nullable=True)
    scan_count = Column(Integer, default=0)
    api_quota_daily = Column(Integer, default=100)
```

#### C3. Auth Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| /api/auth/register | POST | Register new user |
| /api/auth/login | POST | Login, return JWT pair |
| /api/auth/refresh | POST | Refresh access token |
| /api/auth/me | GET | Current user profile |
| /api/auth/change-password | POST | Change password |

#### C4. Protected Routes
- All /api/scan endpoints require valid JWT (rate limits per role)
- /api/admin/* endpoints require role=admin
- /api/model/* endpoints require role=analyst or admin
- Frontend: add login page, store token in httpOnly cookie or localStorage, attach Authorization header

#### C5. Frontend Auth Integration
- **New file:** `frontend/assets/js/auth.js` — token management, login form handling
- **New page:** `frontend/login.html` — login/register form
- **Modify** `frontend/assets/js/api.js`: attach Authorization: Bearer <token> header to all requests
- Add role-based UI elements (admin panel visibility, scan quota display)

---

### Phase D: Cross-Cutting Concerns

#### D1. `.env.example` Creation
- Create `threat-lens-ai/backend/.env.example` with all variables documented.

#### D2. Rate Limiting
- Add per-user rate limiting middleware (already partially in config but not enforced):
```python
@app.middleware("http")
async def rate_limit(request, call_next):
    user = get_current_user(request)
    if user.scan_count >= user.api_quota_daily:
        return JSONResponse(status_code=429, content={"detail": "Daily quota exceeded"})
```

#### D3. Error Handling Standardization
- All API clients should return structured error responses, not raw exceptions.

---

## Stage 3 — RC2 Gate: Testing & Validation

| # | Criterion | Command / Method |
|---|-----------|------------------|
| 1 | Model health panel shows per-model F1 with color coding | Visual: green ≥ 0.80, amber 0.50–0.79, red < 0.50 |
| 2 | Source breakdown uses grid layout with colored left borders | Visual: API=cyan, ML=violet, Heuristic=amber, Network=emerald |
| 3 | Verdict tags are larger with separate score line | Visual: px-4 py-2 text-sm, score on separate line |
| 4 | CVE/OTX pages show "Reference record" not 0/0/0 counters | curl /scan?q=CVE-2024-1708 \| jq .evidence — no zero counters |
| 5 | Loading skeletons appear per-section with fade-in | Visual: staggered skeleton blocks during scan |
| 6 | Details page has timeline, re-scan button, copy-to-clipboard | Visual inspection of /intel/IP/185.220.101.42 |
| 7 | Score uses weighted multi-signal composite (not heuristic) | Code review of scoring.py: no magic number weights |
| 8 | Confidence is Platt-calibrated with proper CI | curl /scan?q=185.220.101.42 \| jq .confidence_interval |
| 9 | API consensus scoring weights by source credibility | Code review of weighted_consensus() in scan_service.py |
| 10 | Temporal decay applied to stale enrichment data | Code review: temporal_decay() called in score computation |
| 11 | Ensemble disagreement penalty applied to ML score | Code review: ensemble_agreement factor in modeling_service.py |
| 12 | Auth endpoints exist (register, login, refresh, me) | curl -X POST /api/auth/register \| jq returns success |
| 13 | Protected routes reject unauthenticated requests | curl /api/scan?q=test without token returns 401 |
| 14 | Frontend login page renders and token persists | Visual: login.html → submit → scan works with stored token |
| 15 | .env.example contains all documented variables | File exists at backend/.env.example |
| 16 | Rate limiting returns 429 when quota exceeded | curl with token × quota+1 requests returns 429 |

**Any failure → fix root cause, re-test. RC2 is complete only when all 16 criteria pass.**

---

### Phase E: Final Cleanup (After All Gates Passed)

Executed once Stage 1, Stage 2, and Stage 3 (RC2) gates all pass 100%.

#### E1. Remove Deprecated Files
- **Files:** `threat-lens-ai/backend/app/services/api_clients/cloudflare_client.py`
- Delete `cloudflare_client.py` entirely (RDAP + WhoisJSON replacement confirmed working, zero imports reference it)
- Remove any orphaned `otx_transformer/` directory references or lingering CodeBERT artifacts

#### E2. Temporary Artifact Cleanup
- Remove any debug notebooks, test `.joblib` files, or scratch CSVs from `threat-lens-ai/` and `data_science/` directories
- Clear `logs/` of outdated error log files (keep only current RC2 plan docx)
- Ensure `threat-lens-ai/models/` contains only production `.joblib` files referenced by `modeling_service.py`

#### E3. Documentation Audit
- Verify `CHANGELOG.md` is complete and reflects all Stage 1, Stage 2, and RC2 changes
- Verify `AGENTS.md` Known Bugs section: all fixed bugs marked with ✅, remaining limitations noted
- Verify `.env.example` has all variables with clear descriptions and signup URLs
- Verify `README` or any onboarding docs reference the correct setup flow (API keys, env, auth)

#### E4. Final Regression Sweep
- **Frontend:** Click through all demo buttons on index page, verify inline previews render. Navigate to results.html, details.html — no JS console errors.
- **Backend:** Run all verification commands from all three stage gates — zero failures.
- **Auth:** Register a new user, login, scan, logout, verify protected routes reject unauthenticated requests.
- **Scoring:** Scan the same indicator twice — verify scores are deterministic (same input → same output).
- **API degradation:** Temporarily revoke an API key, verify scan gracefully degrades (no 500 errors).

#### E5. Repository Housekeeping
- Run `git status` to confirm no unintended files are tracked
- Add `.env` to `.gitignore` if not already present
- Ensure `node_modules/`, `__pycache__/`, `.ipynb_checkpoints/` are gitignored
- Final `git log --oneline -20` review for commit message quality

---

## Recommended Execution Order (RC2)

1. **A1–A4** (quick wins, visible impact) — 4–6 hrs
2. **B1–B3** (core scoring overhaul — biggest quality improvement) — 6–8 hrs
3. **C1–C3** (auth backend — foundation for everything else) — 4–6 hrs
4. **A5–A7** (UI polish) — 3–4 hrs
5. **B4–B5** (scoring refinements) — 2–3 hrs
6. **C4–C5** (auth frontend) — 3–4 hrs
7. **D1–D3** (cleanup) — 2–3 hrs

**Total estimated effort: 24–32 hours**

## Verification Commands — RC2

```bash
# Backend health with auth
curl -X POST "http://localhost:8000/api/auth/register" -H "Content-Type: application/json" -d '{"username":"test","email":"test@test.com","password":"test"}'
curl -X POST "http://localhost:8000/api/auth/login" -H "Content-Type: application/json" -d '{"username":"test","password":"test"}'

# Authenticated scan
TOKEN="..."
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scan?q=185.220.101.42" | jq ".calibrated_confidence, .confidence_interval, .risk_band"

# Weighted consensus score breakdown
curl -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scan?q=185.220.101.42" | jq ".score_breakdown"

# Rate limit test
for i in $(seq 1 101); do curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" "http://localhost:8000/scan?q=test"; done

# .env.example check
cat threat-lens-ai/backend/.env.example | head -20
```

---

## Cumulative Update 3 — Look-and-Feel Improvement Plan

**Scope:** Visual fixes from screenshot analysis + Dark/Light Mode reimplementation.
**Plan:** `logs/cumulative_update_3_look_and_feel.md` (5 phases, ~5–7 hrs total).

### Issues

| # | Issue | Severity | Fix |
|---|-------|----------|-----|
| 1 | Verdict band always `bg-slate-700` because `riskBandBgClass("")` returns truthy default | High | Explicit ternary: `riskBand ? class : verdictBandClass(verdict)` (ui.js:158) |
| 2 | Dark/Light mode reimplementation (theme.js was deleted in RC2, now needed again) | Medium | CSS custom properties + `theme.js` toggle + Tailwind `darkMode: 'class'` |
| 3 | Source card `bg-*-500/5` tints invisible on dark background | Low | Bump to `/10` opacity (ui.js:289,454) |
| 4 | Confidence bar completely absent when `calibrated_confidence` is null | Medium | Text fallback label in verdict card (ui.js:~192) |
| 5 | Minor polish: "Dataset engines" → "Data sources", long note truncation, missing F1 for `ip_logreg_model` | Low | Label rename + CSS `.line-clamp-3` (ui.js:305,1130; tailwind.css) |

### Implementation Order
| Phase | Task | Effort |
|-------|------|--------|
| 1 | Fix verdict band color logic (Issue 1) | 5 min |
| 2 | Source card tint opacity fix (Issue 3) | 15 min |
| 3 | Confidence bar fallback (Issue 4) | 15 min |
| 4 | Minor polish (Issue 5) | 30 min |
| 5 | Dark/Light mode: CSS variables + theme.js (Issue 2) | 4–6 hrs |

### File Changes
| File | Changes |
|------|---------|
| `ui.js` | Fix band condition, bump tint opacity, add confidence fallback, truncate notes, rename label |
| `tailwind.css` | Add CSS custom properties for dark/light, `.line-clamp-3`, body background transition |
| `theme.js` | **New file** — dark/light toggle with `localStorage` persistence + `prefers-color-scheme` respect |
| `index.html`, `results.html`, `details.html` | Add `darkMode: 'class'` to Tailwind config, add theme toggle button, load `theme.js` |

### Verification (12 criteria)
See `logs/cumulative_update_3_look_and_feel.md` section 9 for full verification table.
Key checks: verdict band color per verdict, both themes render correctly, theme persists on reload, source tints visible, confidence fallback shows.

---

## Cumulative Update 4 — Source Card Polish & Light Mode Consistency

**Date:** 2026-05-29 (revised)  
**Scope:** Fix UI/UX issues from visual audit of `logs/visual_logs_issue/` screenshots  
**Status:** 17 items DONE, 1 CRITICAL REMAINING (source breakdown card grid responsiveness)

---

### 1. Implementation Progress — What's DONE

Screenshots in `logs/visual_logs_issue/{night,light}/` across 5 scan types:
- `hal-cert.com` (DOMAIN — 1 source)
- `113.141.73.248` (IP — 3 sources)
- `CVE-2026-9950` (CVE — 1 source, Reference record)
- `nexus-posta.com` (DOMAIN — 1 source, CLEAN)
- `172.233.115.32` (IP — 2 sources)

#### Confirmed Done (code + screenshot evidence)

| # | Item | File/Line | Evidence |
|---|------|-----------|----------|
| 1 | Model Health unwrap (index page) | `ui.js:930-931` | `resp.models \|\| resp` — screenshots show "5/5 active" on index |
| 2 | Model Health unwrap (detail page) | `ui.js:1256-1258` | Same fix applied |
| 3 | Card padding `p-5` | `ui.js:300` | Cards visibly have 20px internal padding |
| 4 | Card ring `ring-1 ring-slate-800/30` | `ui.js:300` | Ring visible in dark mode, light override in CSS |
| 5 | Header flex-wrap `items-start flex-wrap` | `ui.js:301` | Badge + source type don't overlap |
| 6 | Badge `shrink-0` | `ui.js:311` | Badge stays compact on long names |
| 7 | Note `title` attribute (hover tooltip) | `ui.js:313` | `title="..."` present in code |
| 8 | Score bar `h-3` (12px) | `ui.js:317-318` | Bars clearly visible in all screenshots |
| 9 | Score bar track `bg-slate-800/70` | `ui.js:317` | Track visible in dark, light override in CSS |
| 10 | Confidence separator `border-t` | `ui.js:323` | `mt-3 pt-3 border-t border-slate-800/50` |
| 11 | ML card `p-5 ring-slate-800/30` | `ui.js:356` | Consistent with source cards |
| 12 | Dynamic grid cols (1 vs 2) | `ui.js:284-285` | Single-source scans use `md:grid-cols-1` |
| 13 | CI text `text-white/90` | `ui.js:185` | Better contrast on verdict band |
| 14 | Tip card `tip-card` class | `ui.js:492` | Class added to container |
| 15 | Light mode source card tints | `tailwind.css:96-99` | 4 tint overrides present |
| 16 | Light mode ring/scorebar/border overrides | `tailwind.css:100-102` | All 3 overrides present |
| 17 | Light mode tip-card bg | `tailwind.css:105` | `#f1f5f9` bg + `#e2e8f0` border |

---

### 2. Remaining Issue — Source Breakdown Card Grid Responsiveness

#### Problem Statement

When 2+ source cards appear in the Source Breakdown section, the cards **do not behave responsively**:
- Cards in the same row have **unequal heights** (shorter card leaves dead space below)
- With 3 sources, the **3rd card breaks to a new row alone** creating asymmetric layout
- The overall section feels "mentally broken" — tight spacing, unbalanced visual weight

#### Root Cause Analysis

The grid at `ui.js:284-285` uses `md:grid-cols-2` but lacks:

1. **`items-stretch`** — Cards in the same row don't equalize height. The AbuseIPDB card with a long note is taller than the RDAP card, leaving dead space below the shorter card.

2. **Responsive column count for 3+ items** — When 3 API items exist (AbuseIPDB + VirusTotal + RDAP), all go into a `md:grid-cols-2` grid. Row 1 has 2 cards, row 2 has 1 card alone. On a `lg:grid-cols-[1.3fr_0.7fr]` layout at 1280px, the left column is ~768px — three cards at ~240px each + gaps would fit in 3 columns.

3. **`min-w-0`** missing on cards — Content can force cards wider than the column width.

#### Fix

**File:** `ui.js`

##### renderSourceBreakdown() — lines 284-285

Current:
```javascript
+ (apiHtml ? '<div class="mt-3 grid gap-3 ' + (apiItems.length === 1 ? 'md:grid-cols-1' : 'md:grid-cols-2') + ' animate-slideUp stagger-1">' + apiHtml + "</div>" : "")
+ (otherHtml ? '<div class="mt-3 grid gap-3 ' + (otherItems.length === 1 ? 'md:grid-cols-1' : 'md:grid-cols-2') + ' animate-slideUp stagger-2">' + otherHtml + "</div>" : "");
```

Replace with:
```javascript
+ (apiHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (apiItems.length === 1 ? 'md:grid-cols-1' : apiItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-1">' + apiHtml + "</div>" : "")
+ (otherHtml ? '<div class="mt-3 grid gap-3 items-stretch ' + (otherItems.length === 1 ? 'md:grid-cols-1' : otherItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3') + ' animate-slideUp stagger-2">' + otherHtml + "</div>" : "");
```

##### renderSourceCard() — line 300

Replace `min-w-0` with `overflow-hidden` (min-w-0 caused badge text to overflow card on narrow columns). Add `truncate` on text elements inside the left side. Increase vertical spacing:
```javascript
+ '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' ' + bgTint + ' p-5 ring-1 ring-slate-800/30">'
```

Changes inside `renderSourceCard()`:
- Card container: `min-w-0` → `overflow-hidden` (prevents badge overflow without constraining min-width)
- Left side wrapper: add `min-w-0` on the `<div class="flex items-center gap-2">` and `<div>` children
- Source type text: add `truncate` class
- Engine text: add `truncate` class  
- Note spacing: `mt-3` → `mt-4`
- Score section spacing: `mt-3` → `mt-4`
- Confidence separator: `mt-3 pt-3` → `mt-4 pt-3`

##### renderMlCard() — line 356

Same fixes — `min-w-0` → `overflow-hidden`, header gets `flex-wrap` + `items-start`, engine badge gets `shrink-0`, summary gets `truncate`, all `mt-3` gaps → `mt-4`:
```javascript
+ '<div class="rounded-2xl border-l-4 overflow-hidden ' + sourceBorderClass(st) + ' bg-violet-500/5 p-5 ring-1 ring-slate-800/30">'
```

---

### 3. Summary of Changes Applied

| File | Line | Change |
|------|------|--------|
| `ui.js` | 284 | Add `items-stretch` + 3-col grid for 3+ items: `(apiItems.length === 1 ? 'md:grid-cols-1' : apiItems.length === 2 ? 'md:grid-cols-2' : 'md:grid-cols-2 lg:grid-cols-3')` |
| `ui.js` | 285 | Same pattern for `otherHtml` |
| `ui.js` | 300 | `min-w-0` → `overflow-hidden` on card; left side gets `min-w-0` + `truncate` |
| `ui.js` | 301 | Header `items-center` → `items-start` + `flex-wrap` |
| `ui.js` | 305-306 | `truncate` on source type and engine text |
| `ui.js` | 311 | `shrink-0` on badges |
| `ui.js` | 313 | note `mt-3` → `mt-4` |
| `ui.js` | 314 | score section `mt-3` → `mt-4` |
| `ui.js` | 323 | confidence `mt-3 pt-3` → `mt-4 pt-3` |
| `ui.js` | 356 | `min-w-0` → `overflow-hidden` on ML card; header `items-start flex-wrap`; engine `shrink-0`; summary `truncate` |
| `ui.js` | 369,380,386 | ML card `mt-3` → `mt-4` |

**Total changes:** ~18 line edits across `renderSourceCard()` and `renderMlCard()`

---

### 4. Verification (5 criteria)

| # | Criterion | Test |
|---|-----------|------|
| 1 | 3-source IP scan: all 3 cards in one row on 1280px+ | Visual: no card breaks to new row alone |
| 2 | 2-source IP scan: cards equal height in same row | Visual: no dead space below shorter card |
| 3 | 1-source domain scan: single column, no empty space | Visual: card fills full width |
| 4 | Cards have adequate vertical spacing (`mt-4` between sections) | Visual: note, score bar, confidence have distinct separation |
| 5 | Badge text never overflows card boundary | Visual: "INFORMATIONAL" fits inside card on all viewport sizes |
