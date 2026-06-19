# ThreatLensAI — RC2→Final: Detailed Analysis & Implementation Plan

**Date:** 2026-06-19  
**Scope:** Thorough inspection of all 5 issue areas + critic agent evaluation plan  
**Status:** Analysis complete — awaiting approval before implementation

---

## Table of Contents

1. [Issue #1: Domain Modeling / RDAP Failures](#1-domain-modeling--rdap-failures)
2. [Issue #2: SQLite / PostgreSQL Mixing](#2-sqlite--postgresql-mixing)
3. [Issue #3: Project Structure Consolidation](#3-project-structure-consolidation)
4. [Issue #4: End-to-End Test Plan](#4-end-to-end-test-plan)
5. [Issue #5: Critic Agent Evaluation Plan](#5-critic-agent-evaluation-plan)
6. [Consolidated Implementation Plan](#consolidated-implementation-plan)
7. [Risk Register](#risk-register)

---

## 1. Domain Modeling / RDAP Failures

### Root Cause Analysis

The RDAP client (`backend/app/services/api_clients/rdap_client.py`) itself is structurally sound — it tries 6 RDAP servers in sequence with proper timeout and fallback. The real problem is **downstream of the RDAP call**, in how the results flow through the enrichment pipeline and into the domain model's ML prediction.

#### Failure Chain

```
RDAP API call → returns JSON → enrichment_pipeline.enrich_domain()
  → _save_domain_to_db() extracts registrar from RDAP entities
  → MaliciousDomain row saved with registrar="Unknown" (if RDAP entities empty)
  → scan_service calls enrich_domain(domain_row)
  → modeling_service.predict_domain(features) 
  → build_domain_features() → DataFrame with 43 columns
  → domain_model.joblib.predict() → FAILS or returns wrong result
```

**Specific problems identified:**

1. **RDAP registrar extraction is fragile** (`enrichment_pipeline.py:750-762`): The code looks for `"registrar"` in `roles` list, then navigates `vcardArray` to find `fn` (formatted name). Many RDAP servers return registrar info in different formats — some use `"vcardArray"` with different nesting, others use `"handle"` or top-level `"name"` fields. When RDAP returns data but the entity structure doesn't match the expected pattern, `registrar` stays `"Unknown"`.

2. **Domain model expects 43 specific features** (`data_science/src/features.py:112-128`): The `_DOMAIN_EXPECTED_FEATURES` list has 48 columns. The `enrich_domain()` function in `modeling_service.py:592-614` only extracts 16 attributes from the DB row. **Missing features that the model was trained on:**
   - `domain_string` — not extracted from DB row
   - `domain_age_days` — not extracted
   - `log_domain_age` — not extracted
   - `is_new_domain` — not extracted
   - `entropy`, `digit_ratio`, `vowel_ratio`, `special_ratio` — not extracted
   - `subdomain_count`, `token_count`, `max_token_length` — not extracted
   - `consecutive_consonants`, `consecutive_digits` — not extracted
   - `suspicious_keyword_count`, `contains_*_keyword` — not extracted
   - `is_randomized_domain` — not extracted
   - `has_creation_date`, `has_registrar`, `has_nameservers`, `whois_field_count` — not extracted

3. **The local fallback `_build_domain_df_local()` in `modeling_service.py:133-202` computes ALL 43 features** — but it's only used when `data_science/src/features.py` import fails. When the import succeeds, `build_domain_features()` from `data_science/src/features.py` is used, which also computes all 43 features BUT expects them as input keys in the features dict. The `enrich_domain()` function doesn't provide them.

4. **The domain model (`domain_model.joblib`) was trained on the full 43-feature set** (Char TF-IDF + LGBM per the AGENTS.md baseline table). When `predict_domain()` receives a DataFrame with only 16 populated columns and 27 zeros/defaults, the model's predictions are unreliable — it's essentially running on garbage features.

5. **RDAP `_build_domain_source_items()` only checks for registrar** (`enrichment_pipeline.py:267-282`): Even when RDAP returns valid data with network info, name, country, etc., the code only creates a source item if a registrar entity is found. This means RDAP data is often silently discarded even when the API call succeeded.

### Fix Plan for Domain Modeling

**P0 — Fix `enrich_domain()` feature extraction** (`modeling_service.py:592-614`):  
The function must compute all 43 features that `build_domain_features()` expects. The simplest fix: instead of manually extracting 16 fields, call `build_domain_features()` with the domain string and available DB fields, letting the function compute derived features (entropy, digit_ratio, etc.) from the domain string itself. The DB provides: `malicious_votes`, `suspicious_votes`, `harmless_votes`, `total_engines`, `tld`, `registrar`, `creation_date`, `reputation`, `popularity_rank`, `threat_severity`, `categories`, `whois_summary`, `data_source`. Everything else can be computed from the domain string.

**P0 — Fix `_save_domain_to_db()` RDAP parsing** (`enrichment_pipeline.py:750-762`):  
Add fallback registrar extraction from:
- `rdap_data.get("name")` — top-level network name
- Entity `handle` field when `vcardArray` navigation fails
- `rdap_data.get("remarks", [{}])[0].get("description")` — some registrars put info here

**P1 — Fix `_build_domain_source_items()` to use all RDAP data** (`enrichment_pipeline.py:267-282`):  
Create source items for ANY RDAP data (not just registrar), including network name, country, and entity handles.

**P1 — Add RDAP response validation**: Log the actual RDAP response structure when all extraction paths fail, so future debugging is possible.

---

## 2. SQLite / PostgreSQL Mixing

### Current State

The codebase has **three database access patterns** that are inconsistently applied:

| Component | Sync/Async | DB Library | File |
|-----------|-----------|------------|------|
| `database.py` | Sync | `sqlalchemy.create_engine` | `backend/app/database.py` |
| `database_async.py` | Async | `sqlalchemy.ext.asyncio` | `backend/app/database_async.py` |
| `inspect_db.py` | Sync | Raw `sqlite3` | `backend/scripts/inspect_db.py` |
| `migrate_db.py` | Sync | Raw `sqlite3` | `backend/scripts/migrate_db.py` |

**Problems identified:**

1. **Schema uses SQLite-specific types** (`backend/sql/schema.sql`):  
   - `DOUBLE PRECISION` — PostgreSQL type, not valid in SQLite (silently accepted)
   - `BIGSERIAL` — PostgreSQL-specific, not valid in SQLite
   - `INTEGER PRIMARY KEY AUTOINCREMENT` — SQLite-specific, fails in PostgreSQL
   - `BOOLEAN` — works in both but stored differently
   - The `malicious_domains` table uses `DOUBLE PRECISION` for `reputation` — this is PostgreSQL syntax that SQLite accepts but ignores

2. **No `enrichment_breakdown` column in schema** (`schema.sql:34-56`):  
   The `malicious_domains` table definition is missing `enrichment_breakdown TEXT` — but the ORM model (`domain.py:30`) has it. This means `Base.metadata.create_all()` will create it (via SQLAlchemy), but the raw SQL schema is out of sync.

3. **Raw `sqlite3` scripts won't work with PostgreSQL**: `inspect_db.py` and `migrate_db.py` use `sqlite3.connect()` — these are dev-only utilities but will break if the project fully migrates.

4. **The `docker-compose.yml` has both `api` (PostgreSQL) and `api-sqlite` (SQLite) services** — the project is maintaining two parallel deployment paths, doubling the testing surface.

5. **`requirements.txt` already has `psycopg2-binary` and `asyncpg`** — the dependencies are ready, just not the default.

### Fix Plan for PostgreSQL Migration

**P0 — Make PostgreSQL the default**:  
- Change `config.py` default: `DATABASE_URL=postgresql+psycopg2://postgres:postgres@localhost:5432/threatlensai`
- Update `.env.example` to show PostgreSQL URL
- Keep SQLite as fallback for local dev without Docker

**P0 — Fix `schema.sql` for cross-DB compatibility**:  
- Replace `DOUBLE PRECISION` → `Float` (SQLAlchemy handles the mapping)
- Replace `BIGSERIAL` → `BigInteger` with `autoincrement=True`
- Replace `INTEGER PRIMARY KEY AUTOINCREMENT` → use SQLAlchemy's `Column(Integer, primary_key=True)` which maps correctly to both
- Better yet: **remove `schema.sql` as the primary schema definition** and rely on `Base.metadata.create_all()` (SQLAlchemy models are already the source of truth). Keep `schema.sql` as reference/documentation only, clearly marked.

**P0 — Add `enrichment_breakdown` to schema.sql** for documentation consistency.

**P1 — Update `docker-compose.yml`**: Remove `api-sqlite` service and `frontend` service (nginx). Keep only `db` + `api` with PostgreSQL. This is the production-like config.

**P1 — Update raw `sqlite3` scripts**: Either remove them or add a PostgreSQL path using `psycopg2`.

**P2 — Run migration**: Use the existing `migrate_sqlite_to_postgres.py` script to migrate existing SQLite data to PostgreSQL. Run as a one-time operation.

---

## 3. Project Structure Consolidation

### Current State

```
environment_1/
├── data_science/           # ML training code, models, notebooks, configs
│   ├── configs/lookups.py  # Lookup tables (also duplicated in threat-lens-ai?)
│   ├── src/features.py     # Feature engineering (imported by modeling_service.py!)
│   ├── outputs/artifacts/  # .joblib models (copied to threat-lens-ai/models/)
│   ├── data/raw/           # Training CSVs (also in threat-lens-ai/backend/data/)
│   └── skills/ml-dl-architect.md
├── savestates/             # RC1.zip, RC2.zip archives
├── threat-lens-ai/         # Main web application
│   ├── agents/             # Critic agent personas
│   ├── backend/            # FastAPI app
│   ├── frontend/           # Static HTML/JS
│   ├── models/             # .joblib models (copy of data_science/outputs/artifacts/)
│   ├── skills/             # Workflow skills
│   └── logs/               # Implementation logs, visual benchmarks
├── THREATLENSAI_OVERHAUL.md  # 883-line plan doc (should be in logs/)
├── AGENTS.md               # Agent routing (root level)
├── package.json            # Root-level (puppeteer for visual tests)
└── .gitignore
```

**Problems:**

1. **`data_science/src/features.py` is imported by `modeling_service.py`** via `sys.path.insert()` — this is a fragile cross-directory dependency. If `data_science/` is moved or renamed, the backend breaks silently (falls back to local functions, but those may diverge).

2. **Models are duplicated**: `data_science/outputs/artifacts/*.joblib` and `threat-lens-ai/models/*.joblib` — 10 model files in two places. They can get out of sync.

3. **Training CSVs are duplicated**: `data_science/data/raw/*.csv` and `threat-lens-ai/backend/data/*.csv` — same 4 files.

4. **`THREATLENSAI_OVERHAUL.md`** is at the project root — should be in `threat-lens-ai/logs/`.

5. **`savestates/`** contains only RC1.zip and RC2.zip — these are archive snapshots that should be in `threat-lens-ai/logs/savestates/` or just kept as-is if they're git-level archives.

6. **`data_science/configs/lookups.py`** and `data_science/configs/lookups/*.json` — the AGENTS.md says `configs/lookups.py` is a self-contained internal API. But the backend doesn't import it; it has its own lookup logic in `normalization.py`. This is a split-brain situation.

### Target Structure

```
environment_1/
├── threat-lens-ai/              # Consolidated project root
│   ├── agents/                  # Critic agent personas (unchanged)
│   │   ├── code-reviewer.md
│   │   ├── security-auditor.md
│   │   ├── test-engineer.md
│   │   ├── web-performance-auditor.md
│   │   └── README.md
│   ├── skills/                  # Workflow skills (unchanged)
│   │   ├── spec-driven-development/
│   │   ├── planning-and-task-breakdown/
│   │   ├── incremental-implementation/
│   │   ├── test-driven-development/
│   │   ├── code-review-and-quality/
│   │   ├── security-and-hardening/
│   │   └── shipping-and-launch/
│   ├── ml/                      # Merged from data_science/
│   │   ├── src/
│   │   │   ├── features.py      # Feature engineering (single source of truth)
│   │   │   └── utils.py
│   │   ├── configs/
│   │   │   ├── lookups.py       # Lookup tables API
│   │   │   └── lookups/         # JSON lookup files
│   │   │       ├── attack_keywords.json
│   │   │       ├── brand_keywords.json
│   │   │       ├── high_risk_countries.json
│   │   │       ├── high_risk_tlds.json
│   │   │       ├── known_malicious_asns.json
│   │   │       └── suspicious_keywords.json
│   │   ├── models/              # .joblib models (single source of truth)
│   │   │   ├── cve_tfidf_logreg.joblib
│   │   │   ├── domain_model.joblib
│   │   │   ├── ip_logreg_model.joblib
│   │   │   ├── ip_xgb_model.joblib
│   │   │   ├── otx_ensemble_config.joblib
│   │   │   ├── otx_label_encoder.joblib
│   │   │   ├── otx_label_powerset_rf.joblib
│   │   │   ├── otx_minilm_logreg.joblib
│   │   │   ├── otx_tfidf_vectorizer.joblib
│   │   │   ├── otx_xgb_baseline.joblib
│   │   │   └── version.json
│   │   ├── notebooks/           # Jupyter notebooks
│   │   │   ├── 01_eda_and_inspection.ipynb
│   │   │   ├── 02_preprocessing_and_feature_engineering.ipynb
│   │   │   ├── 03_modeling_and_evaluation.ipynb
│   │   │   └── 03_modeling_and_evaluation_executed.ipynb
│   │   ├── data/
│   │   │   ├── raw/             # Original training CSVs (snake_case)
│   │   │   ├── interim/         # Inspected parquet files
│   │   │   ├── processed/       # Processed parquet files
│   │   │   └── splits/          # Train/test splits
│   │   ├── scripts/             # ML training scripts
│   │   │   ├── phase1_data_quality.py
│   │   │   ├── phase3_model_retraining.py
│   │   │   └── ...
│   │   ├── outputs/             # Training outputs
│   │   │   └── artifacts/       # (models moved up to ml/models/)
│   │   ├── logs/                # ML training logs
│   │   │   ├── Data Science Log.txt
│   │   │   └── ...
│   │   └── skills/
│   │       └── ml-dl-architect.md
│   ├── backend/                 # FastAPI application
│   │   ├── app/
│   │   │   ├── config.py        # Updated: MODELS_DIR → ../ml/models
│   │   │   ├── database.py      # PostgreSQL default
│   │   │   ├── database_async.py
│   │   │   ├── main.py
│   │   │   ├── models/          # SQLAlchemy ORM models
│   │   │   ├── routers/         # FastAPI route handlers
│   │   │   ├── services/
│   │   │   │   ├── api_clients/ # External API integrations
│   │   │   │   ├── enrichment_pipeline.py  # Fixed RDAP parsing
│   │   │   │   ├── modeling_service.py     # Fixed feature extraction
│   │   │   │   ├── scan_service.py
│   │   │   │   └── ...
│   │   │   ├── schemas/         # Pydantic models
│   │   │   └── utils/           # Scoring, normalization
│   │   ├── data/                # Runtime CSVs (Title_Case)
│   │   │   ├── 1_otx_threat_intel.csv
│   │   │   ├── 2_cve_vulnerabilities.csv
│   │   │   ├── 3_malicious_domains.csv
│   │   │   ├── 4_malicious_ips.csv
│   │   │   └── unmodified_raw/
│   │   ├── scripts/             # DB management scripts
│   │   ├── sql/                 # Schema reference
│   │   ├── tests/               # Backend tests
│   │   ├── requirements.txt
│   │   ├── Dockerfile
│   │   └── docker-entrypoint.sh
│   ├── frontend/                # Static HTML/JS (unchanged)
│   │   ├── index.html
│   │   ├── results.html
│   │   ├── details.html
│   │   └── assets/
│   ├── logs/                    # Project logs
│   │   ├── THREATLENSAI_OVERHAUL.md  # Moved from root
│   │   ├── RC2-TO-FINAL-*.md
│   │   ├── implementation_plan.md
│   │   ├── cumulative_update_*.md
│   │   ├── visual_logs/
│   │   └── savestates/          # RC1.zip, RC2.zip (moved from /savestates)
│   ├── docker-compose.yml       # PostgreSQL-only
│   └── README.md
├── AGENTS.md                    # Root-level agent routing (updated paths)
└── package.json                 # Root-level (puppeteer for visual tests)
```

### Consolidation Steps

1. **Create `threat-lens-ai/ml/` directory** and move `data_science/src/`, `data_science/configs/`, `data_science/outputs/artifacts/*.joblib`, `data_science/data/raw/`, `data_science/data/interim/`, `data_science/data/processed/`, `data_science/data/splits/`, `data_science/notebooks/`, `data_science/scripts/`, `data_science/logs/`, `data_science/skills/` into it.

2. **Copy (don't move) `data_science/outputs/artifacts/*.joblib`** to `threat-lens-ai/ml/models/` — this is the single source of truth for models. The `data_science/outputs/artifacts/` copies can be removed after.

3. **Update `modeling_service.py` sys.path**: Change from `parents[4] / "data_science" / "src"` to `parents[4] / "ml" / "src"` (or better: use a proper package import by adding `ml/` to the Python path in `main.py` startup).

4. **Update `config.py` MODELS_DIR**: Change from `"../models"` to `"../ml/models"`.

5. **Move `THREATLENSAI_OVERHAUL.md`** to `threat-lens-ai/logs/`.

6. **Move `savestates/RC1.zip` and `savestates/RC2.zip`** to `threat-lens-ai/logs/savestates/`.

7. **Update `AGENTS.md`** paths to reflect new structure.

8. **Remove `data_science/` and `savestates/`** from root after verification.

---

## 4. End-to-End Test Plan

### Test Phases (after consolidation)

| Phase | Test | Command / Method | Pass Criteria |
|-------|------|-----------------|---------------|
| **T1** | Backend starts | `cd threat-lens-ai/backend && python -m uvicorn app.main:app --reload` | Server starts on :8000, no import errors |
| **T2** | Health endpoint | `curl http://localhost:8000/api/health` | Returns `{"status":"ok"}` |
| **T3** | Model status | `curl http://localhost:8000/api/model/status` | All 6 models show `"loaded": true` |
| **T4** | DB tables exist | `curl http://localhost:8000/api/health` (triggers create_all) | No SQL errors in logs |
| **T5** | IP scan (cached) | `curl "http://localhost:8000/api/scan?q=185.220.101.42"` | Returns `risk_band`, `calibrated_confidence`, `source_breakdown` with ≥1 item |
| **T6** | Domain scan (cached) | `curl "http://localhost:8000/api/scan?q=doubleclick.net"` | Returns `risk_band`, `ml_prediction` with non-null label |
| **T7** | CVE scan (cached) | `curl "http://localhost:8000/api/scan?q=CVE-2024-1234"` | Returns verdict, score |
| **T8** | Domain ML prediction | Check `ml_prediction` in T6 response | `label` is "malicious" or "benign", `confidence` > 0 |
| **T9** | Frontend loads | Open `http://localhost:8000/` in browser | Index page renders, no JS errors |
| **T10** | Search works | `curl "http://localhost:8000/api/search?q=malware"` | Returns results array |
| **T11** | Unit tests | `cd threat-lens-ai/backend && python -m pytest tests/ -v` | All 4 test files pass |
| **T12** | PostgreSQL migration | `python scripts/migrate_sqlite_to_postgres.py --sqlite ./threatlensai.db --postgres ... --dry-run` | Reports record counts without errors |

### Critical Test: Domain ML Prediction (T8)

This is the key test for Issue #1 fix. After the fix:
- `predict_domain()` should receive a DataFrame with all 43 features properly populated
- The `enrich_domain()` function should compute derived features from the domain string
- The model prediction should return a meaningful label (not crash or return null)

---

## 5. Critic Agent Evaluation Plan

### Agent Invocation Order

The critic agents should be invoked **in sequence** (not parallel) for the first pass, because each agent's findings may inform the next:

```
1. code-reviewer      → Code quality, correctness, architecture
2. security-auditor   → Security vulnerabilities (informed by code-reviewer's findings)
3. test-engineer      → Test coverage gaps (informed by both above)
4. web-performance-auditor → Frontend performance (independent)
5. ml-dl-architect    → ML model quality (independent)
```

### Agent 1: Code Reviewer

**Scope:** All files changed during RC2→Final implementation
**Focus areas:**
- `modeling_service.py` — feature extraction fix correctness
- `enrichment_pipeline.py` — RDAP parsing robustness
- `database.py` / `database_async.py` — PostgreSQL compatibility
- `config.py` — default DATABASE_URL change
- `schema.sql` — cross-DB compatibility

**Invocation:** Load `threat-lens-ai/agents/code-reviewer.md`, provide the diff of all changes.

### Agent 2: Security Auditor

**Scope:** Full backend codebase + API client implementations
**Focus areas:**
- API key handling in `.env` (not committed, not logged)
- Input validation on scan endpoint (SQL injection, XSS)
- RDAP/WhoisJSON response parsing (injection via malformed JSON)
- CORS configuration (currently `["*"]` — should be restricted in production)
- Rate limiting on scan endpoint (currently none)

**Invocation:** Load `threat-lens-ai/agents/security-auditor.md`, provide full file listing.

### Agent 3: Test Engineer

**Scope:** `backend/tests/` directory + all new/modified code
**Focus areas:**
- Current test coverage (4 test files — what do they cover?)
- Missing tests for: RDAP failure paths, domain feature extraction, PostgreSQL migration, heuristic fallbacks
- Integration test for full scan pipeline

**Invocation:** Load `threat-lens-ai/agents/test-engineer.md`, provide test file listing + source files.

### Agent 4: Web Performance Auditor

**Scope:** `frontend/` directory
**Focus areas:**
- Core Web Vitals of the vanilla JS frontend
- API response time impact on LCP/INP
- Frontend JS bundle size (4 JS files)

**Invocation:** Load `threat-lens-ai/agents/web-performance-auditor.md`, provide frontend file listing.

### Agent 5: ML/DL Architect

**Scope:** `ml/` directory (consolidated from data_science/)
**Focus areas:**
- Domain model (Char TF-IDF + LGBM) — is 162 samples enough?
- IP model (XGBoost F1=1.0) — overfit risk
- OTX ensemble — is the label powerset approach optimal?
- Feature engineering parity between training and inference

**Invocation:** Load `threat-lens-ai/ml/skills/ml-dl-architect.md`, provide model files + training notebooks.

---

## Consolidated Implementation Plan

### Phase 1: Project Consolidation (No code changes, just moves)

| Step | Action | Files Changed | Risk |
|------|--------|---------------|------|
| 1.1 | Create `threat-lens-ai/ml/` directory structure | New dirs | Low |
| 1.2 | Move `data_science/src/` → `threat-lens-ai/ml/src/` | Move | Low |
| 1.3 | Move `data_science/configs/` → `threat-lens-ai/ml/configs/` | Move | Low |
| 1.4 | Copy `data_science/outputs/artifacts/*.joblib` → `threat-lens-ai/ml/models/` | Copy | Low |
| 1.5 | Move `data_science/data/` → `threat-lens-ai/ml/data/` | Move | Low |
| 1.6 | Move `data_science/notebooks/` → `threat-lens-ai/ml/notebooks/` | Move | Low |
| 1.7 | Move `data_science/scripts/` → `threat-lens-ai/ml/scripts/` | Move | Low |
| 1.8 | Move `data_science/logs/` → `threat-lens-ai/ml/logs/` | Move | Low |
| 1.9 | Move `data_science/skills/` → `threat-lens-ai/ml/skills/` | Move | Low |
| 1.10 | Move `THREATLENSAI_OVERHAUL.md` → `threat-lens-ai/logs/` | Move | Low |
| 1.11 | Move `savestates/*.zip` → `threat-lens-ai/logs/savestates/` | Move | Low |
| 1.12 | Update `AGENTS.md` paths | Edit | Low |
| 1.13 | Verify backend still starts (T1-T4) | Test | Low |

### Phase 2: Domain Modeling Fix

| Step | Action | Files Changed | Risk |
|------|--------|---------------|------|
| 2.1 | Fix `enrich_domain()` to compute all 43 features | `modeling_service.py` | Medium |
| 2.2 | Fix `_save_domain_to_db()` RDAP registrar extraction | `enrichment_pipeline.py` | Medium |
| 2.3 | Fix `_build_domain_source_items()` to use all RDAP data | `enrichment_pipeline.py` | Low |
| 2.4 | Add RDAP response logging for debugging | `enrichment_pipeline.py` | Low |
| 2.5 | Update `modeling_service.py` sys.path for new `ml/` location | `modeling_service.py` | Low |
| 2.6 | Run T5-T8 tests | Test | Medium |

### Phase 3: PostgreSQL Migration

| Step | Action | Files Changed | Risk |
|------|--------|---------------|------|
| 3.1 | Change default DATABASE_URL to PostgreSQL | `config.py` | Low |
| 3.2 | Update `.env.example` | `.env.example` | Low |
| 3.3 | Fix `schema.sql` for cross-DB compatibility | `schema.sql` | Medium |
| 3.4 | Add `enrichment_breakdown` to `schema.sql` | `schema.sql` | Low |
| 3.5 | Update `docker-compose.yml` (remove SQLite service) | `docker-compose.yml` | Low |
| 3.6 | Update `MODELS_DIR` in config | `config.py` | Low |
| 3.7 | Run T1-T4 tests with PostgreSQL | Test | Medium |
| 3.8 | Run migration script (dry-run then real) | `migrate_sqlite_to_postgres.py` | High |

### Phase 4: Critic Agent Evaluation

| Step | Action | Agent | Duration |
|------|--------|-------|----------|
| 4.1 | Code review of all changes | `code-reviewer` | ~15 min |
| 4.2 | Security audit | `security-auditor` | ~15 min |
| 4.3 | Test coverage analysis | `test-engineer` | ~10 min |
| 4.4 | Web performance audit | `web-performance-auditor` | ~10 min |
| 4.5 | ML architecture review | `ml-dl-architect` | ~15 min |
| 4.6 | Fix S1/S2 bugs found by agents | Manual | ~2 hours |
| 4.7 | Re-run critic agents on fixes | All | ~30 min |

### Phase 5: Final Verification

| Step | Action | Criteria |
|------|--------|----------|
| 5.1 | Full T1-T12 test suite | All pass |
| 5.2 | Clean-slate pipeline test (delete DB, restart, scan) | All scans return valid results |
| 5.3 | Architect sign-off | All critic agents approve |

---

## Risk Register

| # | Risk | Probability | Impact | Mitigation |
|---|------|------------|--------|------------|
| R1 | Domain model still fails after feature fix (model trained on different feature set) | Medium | High | Inspect model's `feature_names_in_` to verify exact training features; retrain if needed |
| R2 | PostgreSQL migration loses data | Low | High | Backup SQLite DB before migration; run dry-run first; test with copy |
| R3 | `sys.path` hack for `ml/src/features.py` breaks in production | Medium | Medium | Replace with proper package import; add `ml/` to `PYTHONPATH` in Dockerfile |
| R4 | RDAP servers return different JSON structures per TLD | High | Medium | Add per-TLD parsing strategies; log unknown structures for future fixes |
| R5 | Critic agents find Critical issues that require major rework | Medium | High | Budget 2 hours for fixes in Phase 4; defer non-critical to post-release |
| R6 | Model files are large and slow to copy | Low | Low | Models are ~50MB total; acceptable for git |
| R7 | `enrichment_breakdown` column missing in existing SQLite DB | Medium | Medium | SQLAlchemy `create_all()` adds missing columns; verify with `inspect_db.py` |

---

## Approval Checklist

Before implementation begins, confirm:

- [ ] **Issue #1 (Domain/RDAP):** Approve the 4-step fix plan (2.1-2.6)?
- [ ] **Issue #2 (PostgreSQL):** Approve PostgreSQL as default, SQLite as fallback?
- [ ] **Issue #3 (Consolidation):** Approve the target directory structure?
- [ ] **Issue #4 (E2E Tests):** Approve the 12-phase test plan?
- [ ] **Issue #5 (Critic Agents):** Approve the 5-agent evaluation sequence?
- [ ] **Scope:** Any items to add/remove from the plan?
- [ ] **Priority:** Confirm P0 items must be fixed before Final release?

---

*Document prepared by OWL — 2026-06-19*
