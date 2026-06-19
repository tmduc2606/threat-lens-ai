# ThreatLensAI — RC2 → Final Release Implementation Plan

**Date:** 2026-06-18
**Scope:** 6 prioritized work items (P0 × 2, P1 × 2, P2 × 2) derived from the Catalogue Assessment
**Framework:** Agent-persona-driven execution with phase-gated skill workflows

---

## Execution Framework

### Agent Persona Assignment Matrix

Each work item is assigned to a primary agent persona. Personas never invoke other personas — orchestration belongs to the user or slash commands.

| Persona | Role | Used For |
|---------|------|----------|
| `code-reviewer` | Senior Staff Engineer | Five-axis review before merge |
| `security-auditor` | Security Engineer | Vulnerability detection, OWASP audit |
| `test-engineer` | QA Engineer | Test strategy, Prove-It pattern, coverage |
| `ml-dl-architect` | ML/DL Architect | Model evaluation, architecture review |
| `web-performance-auditor` | Web Performance Engineer | CWV audit, loading/rendering analysis |

### Skill Workflow Phase Gates

Each work item follows the phase-appropriate skill or agent persona:

| Phase | Skill / Persona | Location |
|-------|----------------|----------|
| **Starting** — spec & architecture | `spec-driven-development` skill | `threat-lens-ai/skills/spec-driven-development/SKILL.md` |
| **Starting** — task breakdown | `planning-and-task-breakdown` skill | `threat-lens-ai/skills/planning-and-task-breakdown/SKILL.md` |
| **During development** — implementation | `incremental-implementation` skill | `threat-lens-ai/skills/incremental-implementation/SKILL.md` |
| **During development** — testing | `test-driven-development` skill | `threat-lens-ai/skills/test-driven-development/SKILL.md` |
| **Before merge** — code review & quality | `code-review-and-quality` skill | `threat-lens-ai/skills/code-review-and-quality/SKILL.md` |
| **Before merge** — security & hardening | `security-and-hardening` skill | `threat-lens-ai/skills/security-and-hardening/SKILL.md` |
| **Before deploy** — shipping & launch | `shipping-and-launch` skill | `threat-lens-ai/skills/shipping-and-launch/SKILL.md` |
| **Anytime** — performance audit | `web-performance-auditor` agent persona | `threat-lens-ai/agents/web-performance-auditor.md` |

### Orchestration Pattern

```
User (orchestrator)
  ├── P0-1: Evaluate MiniLM OTX Model
  │     └── ml-dl-architect (single perspective)
  │     └── Shipping gate: shipping-and-launch skill (pre-launch checklist)
  │
  ├── P0-2: Add model_version to /model/status
  │     └── test-engineer (TDD skill)
  │     └── Review gate: code-review-and-quality skill (5-axis review)
  │
  ├── P1-1: Skip ML for Heuristic-Only Inputs
  │     └── test-engineer (TDD skill)
  │     └── Review gate: code-review-and-quality skill (5-axis review)
  │
  ├── P1-2: Add POST /model/retrain Endpoint
  │     └── test-engineer (TDD skill)
  │     └── Review gate: code-review-and-quality skill (5-axis review)
  │     └── Security gate: security-and-hardening skill (OWASP + SSRF + secrets)
  │
  ├── P2-1: SQLite → PostgreSQL Migration Path
  │     └── test-engineer (TDD skill)
  │     └── Security gate: security-and-hardening skill (credential handling)
  │     └── Performance gate: web-performance-auditor agent (concurrent load)
  │
  └── P2-2: Shared Feature Engineering Module
        └── ml-dl-architect (architecture review)
        └── test-engineer (TDD skill)
        └── Review gate: code-review-and-quality skill (5-axis review)
```

---

## P0-1: Evaluate MiniLM OTX Model Performance

**Priority:** P0 — OTX model misses target by 32% (Micro F1 0.305 vs 0.45 target)
**Agent:** `ml-dl-architect`
**Skill:** `incremental-implementation` (during development)

### Problem
The OTX MiniLM + LogReg model (`otx_minilm_logreg.joblib`, 516KB) exists in artifacts and is loaded by `modeling_service.py`, but was **never evaluated in the executed notebook**. The baseline TF-IDF + XGBoost achieves Micro F1 = 0.305. The MiniLM model may be better, worse, or broken — it's unknown.

### Implementation Steps

1. **Load the executed notebook** `data_science/notebooks/03_modeling_and_evaluation_executed.ipynb`
2. **Add evaluation cells** for the existing MiniLM model:
   - Load `otx_minilm_logreg.joblib` and `otx_label_encoder.joblib`
   - Run inference on the OTX test split (same `otx_test.parquet` used for baseline)
   - Compute Micro F1, Macro F1, Hamming Loss, per-class classification report
   - Compare against the TF-IDF baseline (Micro F1 = 0.305, Macro F1 = 0.102)
3. **If MiniLM is better**: Update the baseline reference in `modeling_service.py` and AGENTS.md performance table
4. **If MiniLM is worse or broken**: Document findings; recommend either (a) retraining with proper hyperparameter tuning, or (b) falling back to the TF-IDF baseline with improved threshold tuning
5. **Decision gate**: The `ml-dl-architect` produces a verdict: KEEP (MiniLM), REPLACE (with retrained model), or DEPRECATE (remove MiniLM, use baseline only)

### Acceptance Criteria
- [ ] MiniLM model evaluated on OTX test split with Micro F1 and Macro F1 reported
- [ ] Comparison table: TF-IDF baseline vs MiniLM vs Label Powerset RF (if testable)
- [ ] Decision documented: KEEP / REPLACE / DEPRECATE
- [ ] If KEEP: AGENTS.md performance baseline updated
- [ ] If REPLACE: Retraining notebook cell added and executed

### Files Touched
- `data_science/notebooks/03_modeling_and_evaluation_executed.ipynb` (add evaluation cells)
- `threat-lens-ai/backend/app/services/modeling_service.py` (if model swap needed)
- `AGENTS.md` (performance baseline table update)

---

## P0-2: Add model_version to /model/status Response

**Priority:** P0 — No model version tracking exists; operators can't tell which model is loaded
**Agent:** `test-engineer` (TDD) → `code-reviewer` (review)
**Skill:** `test-driven-development` (during development)

### Problem
`GET /model/status` returns model loaded/f1/samples metadata but no version string. The `TrainingMetadata` table has a `model_version` column but it's never populated or exposed. When models are updated (e.g., after retraining), there's no way to verify which version is active without checking file timestamps.

### Implementation Steps

**RED Phase — Write failing test first:**
1. Create `tests/test_model_status.py` (or add to existing test file)
2. Write test: `test_model_status_includes_version()` — calls `GET /model/status`, asserts `model_version` field present in response
3. Run test → **must fail** (field doesn't exist yet)

**GREEN Phase — Minimal implementation:**
1. Add `model_version` field to the response dict in `modeling_service.py` → `get_model_status()`
2. Read version from a new `models/version.json` file (format: `{"cve": "v1.0.0", "domain": "v1.0.0", "ip": "v1.0.0", "otx": "v1.0.0"}`)
3. Create `threat-lens-ai/models/version.json` with initial values
4. Run test → **must pass**

**REFACTOR Phase:**
1. Add version bump logic to the retraining export flow (P1-2 will build on this)
2. Ensure version is included in `ScanResponse.model_status` output

### Acceptance Criteria
- [ ] `GET /model/status` returns `model_version` per model (e.g., `{"ip_xgb_model": {"loaded": true, "model_version": "v1.0.0", ...}}`)
- [ ] `models/version.json` exists with all 4 model versions
- [ ] Test written first, watched fail, then pass
- [ ] `code-reviewer` approves the change (5-axis review)

### Files Touched
- `threat-lens-ai/backend/app/services/modeling_service.py`
- `threat-lens-ai/models/version.json` (new)
- `tests/test_model_status.py` (new or existing)

---

## P1-1: Skip ML Prediction for Heuristic-Only Inputs

**Priority:** P1 — Distribution shift risk: synthetic heuristic features fed to models trained on real data
**Agent:** `test-engineer` (TDD) → `code-reviewer` (review)
**Skill:** `test-driven-development` (during development)

### Problem
When an unseen IP/domain is queried and all APIs fail, `_heuristically_analyze_unseen_*()` generates features using MD5 hash (deterministic but synthetic). These synthetic features are then fed into `predict_ip()` / `predict_domain()` — models trained on **real** AbuseIPDB/VirusTotal data. The model's probability output is unreliable for these inputs, but the UI displays it as if it were a real prediction.

### Implementation Steps

**RED Phase:**
1. Write test: `test_heuristic_only_scan_skips_ml()` — triggers a scan with an unknown IP (all APIs mocked to fail), asserts `ml_prediction` in response is `None` or labeled `"ML_N/A"`
2. Write test: `test_heuristic_scan_shows_warning_in_evidence()` — asserts evidence contains a warning like "ML prediction unavailable — heuristic-only analysis"
3. Run tests → **must fail**

**GREEN Phase:**
1. In `scan_service.py` → `scan_intelligence()`: after heuristic fallback is used, set `ml_prediction = None` and add evidence item `"ML prediction unavailable — heuristic-only analysis"`
2. In `modeling_service.py` → `enrich_ip()` / `enrich_domain()`: skip ML prediction call when `provenance == "heuristic_fallback"`
3. In `scoring.py` → `compute_composite_score()`: already handles `ml_prediction=None` gracefully (ML component becomes 0)
4. Run tests → **must pass**

**REFACTOR Phase:**
1. Add a `prediction_source` field to source breakdown items: `"live_api"`, `"heuristic"`, `"ml"`, `"ml_unavailable"`
2. Update `ui.js` to render "ML N/A" badge when `ml_prediction` is null

### Acceptance Criteria
- [ ] Heuristic-only scans return `ml_prediction: null` (not a fabricated probability)
- [ ] Evidence includes a clear warning about ML unavailability
- [ ] UI renders "ML N/A" badge for heuristic-only results
- [ ] Live API scans still include ML prediction as before (no regression)
- [ ] Tests written first, watched fail, then pass
- [ ] `code-reviewer` approves

### Files Touched
- `threat-lens-ai/backend/app/services/scan_service.py`
- `threat-lens-ai/backend/app/services/modeling_service.py`
- `threat-lens-ai/backend/app/utils/scoring.py` (verify graceful None handling)
- `threat-lens-ai/frontend/assets/js/ui.js` (ML N/A badge)
- `tests/test_heuristic_fallback.py` (new)

---

## P1-2: Add POST /model/retrain Endpoint

**Priority:** P1 — No automated retraining; model staleness will grow over time
**Agent:** `test-engineer` (TDD) → `code-reviewer` (review)
**Skill:** `test-driven-development` (during development)

### Problem
The export endpoint (`GET /model/export/{type}`) exists and `TrainingMetadata` table tracks exports, but there's no way to trigger retraining. The AGENTS.md specified `GET /model/retrain` but it was never implemented. As new enrichment data accumulates via background sync, the models become increasingly stale.

### Implementation Steps

**RED Phase:**
1. Write test: `test_retrain_endpoint_exists()` — calls `POST /model/retrain?type=ip`, returns 202 Accepted with job_id
2. Write test: `test_retrain_returns_job_status()` — polls `GET /model/retrain/status/{job_id}`, returns status: pending/running/completed/failed
3. Write test: `test_retrain_updates_version()` — after retrain completes, `models/version.json` is updated
4. Run tests → **must fail**

**GREEN Phase:**
1. Add `POST /model/retrain` router in `modeling.py` — accepts `type` parameter (ip/domain/cve/otx/all)
2. Implement async retraining job using `asyncio.create_task()`:
   - Loads exported CSV from `GET /model/export/{type}`
   - Runs retraining script (`scripts/phase3_model_retraining.py` or equivalent)
   - Saves new `.joblib` to `models/`
   - Updates `models/version.json` (increment patch version)
   - Invalidates `lru_cache` on `ml_adapter.py` model loaders
3. Add `GET /model/retrain/status/{job_id}` for polling
4. Run tests → **must pass**

**REFACTOR Phase:**
1. Add retraining trigger to `TrainingMetadata` — auto-suggest retrain when `api_enriched_records` grows >20% since last export
2. Add admin auth check (if auth is added later) or API key gate

### Acceptance Criteria
- [ ] `POST /model/retrain?type=ip` returns 202 with job_id
- [ ] Retrain runs asynchronously (doesn't block the API)
- [ ] `GET /model/retrain/status/{job_id}` returns current status
- [ ] After retrain: new `.joblib` in `models/`, `version.json` updated, cache invalidated
- [ ] Tests written first, watched fail, then pass
- [ ] `code-reviewer` approves

### Files Touched
- `threat-lens-ai/backend/app/routers/modeling.py`
- `threat-lens-ai/backend/app/services/modeling_service.py` (cache invalidation)
- `threat-lens-ai/models/version.json`
- `threat-lens-ai/backend/scripts/phase3_model_retraining.py` (may need updates)
- `tests/test_retrain.py` (new)

---

## P2-1: SQLite → PostgreSQL Migration Path

**Priority:** 2 — SQLite is a bottleneck for concurrent access; not production-scalable
**Agent:** `test-engineer` (TDD) → `security-auditor` (review)
**Skill:** `test-driven-development` (during development)

### Problem
The app uses SQLite with synchronous SQLAlchemy. This works for single-user demo but fails under concurrent access (multiple API calls writing to DB simultaneously). The `enrichment_pipeline.py` uses `asyncio.gather()` for API calls but synchronous DB writes — creating a bottleneck.

### Implementation Steps

**RED Phase:**
1. Write test: `test_concurrent_scans_no_db_lock()` — fires 5 concurrent scans, asserts all complete without `sqlite3.OperationalError: database is locked`
2. Write test: `test_postgres_connection_string()` — verifies `DATABASE_URL` with `postgresql://` scheme is accepted
3. Run tests → **must fail** (SQLite will lock under concurrent writes)

**GREEN Phase:**
1. Add `asyncpg` and `databases` (or `sqlalchemy[async]`) to `requirements.txt`
2. Create `backend/app/database_async.py` — async engine + session factory using `create_async_engine`
3. Modify `config.py` → `Settings.database_url` — support both `sqlite://` and `postgresql+asyncpg://` schemes
4. Add migration script `backend/scripts/migrate_sqlite_to_postgres.py` — reads SQLite, writes to PostgreSQL
5. Update `docker-compose.yml` to include PostgreSQL service
6. Run tests → **must pass** (with PostgreSQL)

**REFACTOR Phase:**
1. Update all `db.commit()` calls in `enrichment_pipeline.py` to use `await db.commit()`
2. Add connection pool configuration (min_size=5, max_size=20)
3. `security-auditor` reviews: connection string handling, no SQL injection via parameterized queries, credentials in env vars only

### Acceptance Criteria
- [ ] App works with both SQLite (default) and PostgreSQL (opt-in via `DATABASE_URL`)
- [ ] Concurrent scans complete without DB lock errors
- [ ] Migration script exists for SQLite → PostgreSQL data transfer
- [ ] Docker Compose includes PostgreSQL service
- [ ] `security-auditor` approves DB credential handling
- [ ] Tests written first, watched fail, then pass

### Files Touched
- `threat-lens-ai/backend/app/config.py`
- `threat-lens-ai/backend/app/database.py` + `database_async.py` (new)
- `threat-lens-ai/backend/requirements.txt`
- `threat-lens-ai/docker-compose.yml`
- `threat-lens-ai/backend/scripts/migrate_sqlite_to_postgres.py` (new)
- `tests/test_concurrent_db.py` (new)

---

## P2-2: Shared Feature Engineering Module

**Priority:** 2 — Feature engineering duplicated between notebooks and backend; drift risk
**Agent:** `ml-dl-architect` (review) → `test-engineer` (TDD)
**Skill:** `incremental-implementation` (during development)

### Problem
Feature engineering for Domain and IP models is implemented in two places:
1. **Notebook** (`02_preprocessing_and_feature_engineering.ipynb`) — used for training
2. **Backend** (`modeling_service.py` → `_build_domain_df()`, `_build_ip_df()`) — used for inference

If the notebook's preprocessing changes (new features, different scaling), the backend functions must be manually synchronized. This has already caused issues (the `domain_model.joblib` expects features from the notebook's pipeline, but the backend's `_build_domain_df()` is a separate implementation).

### Implementation Steps

**RED Phase:**
1. Write test: `test_backend_features_match_training()` — loads a sample from `data/splits/ip_train.parquet`, runs through both the notebook's preprocessing and the backend's `_build_ip_df()`, asserts feature vectors are identical
2. Write test: `test_domain_feature_count()` — asserts `_build_domain_df()` output has exactly the same columns as the model's `feature_names_in_`
3. Run tests → **may fail** if drift exists

**GREEN Phase:**
1. Create `data_science/src/features.py` — shared feature engineering module with functions:
   - `build_ip_features(raw_dict) -> pd.DataFrame`
   - `build_domain_features(raw_dict) -> pd.DataFrame`
   - `build_cve_features(text) -> str`
2. Refactor `modeling_service.py` → `_build_ip_df()` and `_build_domain_df()` to call `features.py` instead of inline implementation
3. Refactor notebook `02_preprocessing` to import from `src/features.py` (add `sys.path.append`)
4. Run tests → **must pass**

**REFACTOR Phase:**
1. Add `features.py` to the backend's Python path (already in `sys.path` via `configs/paths.py`)
2. `ml-dl-architect` reviews: feature definitions match training-time exactly
3. Add a CI-style test that runs both notebook preprocessing and backend feature building on the same input and compares outputs

### Acceptance Criteria
- [ ] `data_science/src/features.py` exists with shared feature functions
- [ ] Backend `_build_ip_df()` and `_build_domain_df()` delegate to `features.py`
- [ ] Notebook imports from `src/features.py`
- [ ] Test proves backend features match training features (same columns, same values)
- [ ] `ml-dl-architect` approves feature parity
- [ ] No regression in model predictions (run existing scan tests)

### Files Touched
- `data_science/src/features.py` (new)
- `data_science/src/utils.py` (may be absorbed)
- `threat-lens-ai/backend/app/services/modeling_service.py`
- `data_science/notebooks/02_preprocessing_and_feature_engineering.ipynb`
- `tests/test_feature_parity.py` (new)

---

## Cross-Cutting: Before Merge & Before Deploy Gates

After each P0/P1/P2 item completes its development cycle (implement → test → refactor), it enters the phase-appropriate gate:

### Before Merge — Code Review & Quality Gate
**Skill:** `code-review-and-quality` (`threat-lens-ai/skills/code-review-and-quality/SKILL.md`)

Every item must pass a structured 5-axis review using the skill's framework:
1. **Correctness** — Does it do what the spec says? Edge cases? Error paths?
2. **Readability** — Can another engineer understand it without help?
3. **Architecture** — Does it follow existing patterns? Clean module boundaries?
4. **Security** — Input validation, secrets, injection vectors (see security-and-hardening skill for deep dive)
5. **Performance** — No N+1 queries, no unbounded loops

The skill defines severity prefixes for findings: *(no prefix)* = required, **Critical:** = blocks merge, **Nit:** = optional, **Optional:** = suggestion, **FYI** = informational.

**Change sizing rule:** ~100 lines = good, ~300 = acceptable, ~1000 = too large, split it.

**Approve standard:** Approve when it definitely improves overall code health, even if it isn't perfect.

### Before Merge — Security & Hardening Gate
**Skill:** `security-and-hardening` (`threat-lens-ai/skills/security-and-hardening/SKILL.md`)

Required for items that touch attack surface (P1-2 retrain endpoint, P2-1 DB migration):
- **Threat model first:** Map trust boundaries, name assets, run STRIDE
- **OWASP Top 10 prevention patterns:** Injection, broken auth, XSS, broken access control, SSRF
- **Three-tier boundary system:** Always Do / Ask First / Never Do
- **Secrets management:** `.env` not committed, no secrets in logs, rotate if exposed
- **Supply-chain hygiene:** `npm ci` in CI, lockfile committed, review new dependencies
- **AI/LLM security** (if applicable): Model output treated as untrusted, prompt injection defense

### Before Deploy — Shipping & Launch Gate
**Skill:** `shipping-and-launch` (`threat-lens-ai/skills/shipping-and-launch/SKILL.md`)

Required for P0-1 (model evaluation affects production model selection) and P2-1 (infrastructure change):
- **Pre-launch checklist:** Code quality, security, performance, accessibility, infrastructure, documentation
- **Feature flag strategy:** Deploy with flag OFF → enable for team → canary (5% → 25% → 50% → 100%) → monitor → clean up
- **Staged rollout with decision thresholds:** Error rate within 10% of baseline = advance; 10-100% above = hold; >2x = roll back
- **Monitoring & observability:** Application metrics, infrastructure metrics, client metrics (CWV)
- **Rollback plan:** Documented before deploy, tested dry run, < 1 min for feature flag, < 5 min for redeploy

---

## Execution Order & Dependencies

```
Phase 1 (Parallel):
  P0-1: Evaluate MiniLM OTX Model          [ml-dl-architect]
  P0-2: Add model_version to /status       [test-engineer → code-reviewer]

Phase 2 (After P0-2 completes):
  P1-1: Skip ML for Heuristic-Only Inputs  [test-engineer → code-reviewer]
  P1-2: Add POST /model/retrain Endpoint   [test-engineer → code-reviewer]
        ↑ Depends on P0-2 (version.json exists)

Phase 3 (Parallel, after P1-1):
  P2-1: SQLite → PostgreSQL Migration      [test-engineer → security-auditor]
  P2-2: Shared Feature Engineering Module  [ml-dl-architect → test-engineer]
        ↑ Depends on P0-1 (model evaluation complete)
```

---

## Verification Summary

| Item | Test Command | Review Gate | Security Gate | Deploy Gate |
|------|-------------|-------------|---------------|-------------|
| P0-1 | Notebook execution + metrics comparison | `ml-dl-architect` verdict | — | `shipping-and-launch` skill (pre-launch checklist) |
| P0-2 | `pytest tests/test_model_status.py -v` | `code-review-and-quality` skill (5-axis) | — | — |
| P1-1 | `pytest tests/test_heuristic_fallback.py -v` | `code-review-and-quality` skill (5-axis) | — | — |
| P1-2 | `pytest tests/test_retrain.py -v` | `code-review-and-quality` skill (5-axis) | `security-and-hardening` skill (OWASP + SSRF + secrets) | — |
| P2-1 | `pytest tests/test_concurrent_db.py -v` | `code-review-and-quality` skill (5-axis) | `security-and-hardening` skill (credential handling) | `shipping-and-launch` skill (infra checklist) + `web-performance-auditor` agent (concurrent load) |
| P2-2 | `pytest tests/test_feature_parity.py -v` | `code-review-and-quality` skill (5-axis) + `ml-dl-architect` (arch review) | — | — |

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| MiniLM evaluation reveals model is broken | P0-1 becomes "retrain OTX" — scope increase | Decision gate after evaluation; if broken, defer retraining to separate effort |
| PostgreSQL migration breaks existing SQLite workflows | P2-1 blocks release | SQLite remains default; PostgreSQL is opt-in via DATABASE_URL |
| Feature parity test reveals drift | P2-2 requires fixing drift before proceeding | Fix drift in P2-2 scope; don't skip the test |
| Retrain endpoint OOMs on large datasets | P1-2 crashes in production | Add memory check before retraining; limit to one model at a time |
