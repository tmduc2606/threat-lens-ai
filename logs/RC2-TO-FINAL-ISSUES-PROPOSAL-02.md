# ThreatLensAI | RC2 → Final Release Cumulative Update Proposal | No. 2

**Date:** 2026-06-18
**Scope:** Notable issues found during end-to-end assessment of all 6 priorities
**Source:** Multi-agent implementation (2 models) across P0-1 through P2-2

---

## Issue Classification

| ID | Priority | Category | Component | Status |
|----|----------|----------|-----------|--------|
| I-01 | **Critical** | Feature Parity | P2-2 / modeling_service.py | ❌ Bug |
| I-02 | **High** | Missing Feature | P1-2 / modeling.py retrain | ❌ Missing |
| I-03 | **High** | Missing Feature | P2-1 / config.py async | ❌ Missing |
| I-04 | **Medium** | Code Quality | P2-2 / modeling_service.py | ⚠️ Smell |
| I-05 | **Medium** | Incomplete Implementation | P1-1 / scan_service.py | ⚠️ Gap |
| I-06 | **Medium** | Frontend | UI / results.html + ui.js | ⚠️ Gap |
| I-07 | **Low** | SHAP Warning | modeling_service.py | ℹ️ Info |
| I-08 | **Low** | Test Coverage | P1-1, P1-2, P2-1, P2-2 | ⚠️ Gap |
| I-09 | **Low** | Config | config.py | ℹ️ Note |
| I-10 | **Info** | Notebook | P0-1 evaluation | ℹ️ Info |

---

## I-01 [CRITICAL] — Domain Feature Parity: `is_randomized_domain` column missing

**File:** `data_science/src/features.py` (line ~161) vs `backend/app/services/modeling_service.py` `_build_domain_df_local` (line ~187)

**Problem:** The shared `features.py` module removed the `is_randomized_domain` column calculation that was present in the original `_build_domain_df()`. The local fallback `_build_domain_df_local()` also lacks it. The domain model was trained with this feature. Removing it will cause a feature mismatch error at inference time.

**Evidence:**
- Original `_build_domain_df()` had: `is_randomized_domain = 1 if (len(domain) > 20 and entropy > 4.0) or digit_ratio > 0.5 else 0`
- `features.py` build_domain_features: **missing**
- `_build_domain_df_local()`: **missing**

**Impact:** Domain model prediction will fail with feature name mismatch when the model expects `is_randomized_domain` but the DataFrame doesn't contain it.

**Fix Required:** Add `is_randomized_domain` calculation to both `features.py` and `_build_domain_df_local()`.

---

## I-02 [HIGH] — Retrain endpoint: async DB session bug

**File:** `backend/app/routers/modeling.py` (line ~757)

**Problem:** The retrain endpoint passes a synchronous SQLAlchemy `db: Session` (from `Depends(get_db)`) to an `asyncio.create_task()` background coroutine. The `_run_retrain()` function then calls synchronous DB methods (`db.query()`, `db.add()`, `db.commit()`) inside an async task. This will:
1. Block the event loop during retraining
2. Potentially cause `db` session errors since the session was created in the request context but used in a background task that outlives the request

**Evidence:**
```python
# Line 757
asyncio.create_task(_run_retrain(job_id, model_type, db))  # db is sync Session

# _run_retrain uses db.query(), db.add(), db.commit() synchronously
```

**Impact:** Retrain job will likely fail with session errors for large datasets, or block the API during processing.

**Fix Required:** Either (a) use the async session (`AsyncSessionLocal`) inside `_run_retrain`, or (b) collect all needed data from the DB before spawning the task, passing data not the session.

---

## I-03 [HIGH] — PostgreSQL: asyncpg not in requirements.txt

**File:** `backend/requirements.txt`

**Problem:** The `database_async.py` module imports `from sqlalchemy.ext.asyncio import create_async_engine` and uses `postgresql+asyncpg://` URLs, but `asyncpg` is not listed in `requirements.txt`. Without it, the async engine creation will fail with `ModuleNotFoundError`.

**Evidence:** `pip show asyncpg` would fail on a fresh install.

**Impact:** PostgreSQL migration path (P2-1) is non-functional until `asyncpg` is installed.

**Fix Required:** Add `asyncpg>=0.29.0` to `requirements.txt`.

---

## I-04 [MEDIUM] — Feature module path resolution is fragile

**File:** `backend/app/services/modeling_service.py` (lines 18-20)

**Problem:** The path to `data_science/src` is resolved using a chain of `.parent.parent.parent.parent.parent` which assumes a specific directory depth. If the project structure changes, this breaks silently and falls back to the local implementation, defeating the purpose of P2-2.

```python
_ds_src = Path(__file__).resolve().parent.parent.parent.parent.parent / "data_science" / "src"
```

**Impact:** Silent fallback to duplicated code if directory structure changes. The shared module won't actually be shared.

**Fix Required:** Use a project-root-relative path or add the path to `sys.path` in `main.py` at startup.

---

## I-05 [MEDIUM] — P1-1 heuristic fallback: provenance variable set but check is unreachable

**File:** `backend/app/services/scan_service.py` (lines 579, 682)

**Problem:** The `provenance = "heuristic_fallback"` variable is set at line 579, and checked at line 682 (`elif provenance == "heuristic_fallback"`). However, line 682 is inside an `elif` block that only executes `if verdict != "UNKNOWN"`. But when `ml_prediction is None` (the heuristic case), `verdict` stays `"UNKNOWN"` (set at line 628), so `verdict != "UNKNOWN"` is `False`, and the code correctly falls to the `elif` branch. This is actually correct logic.

**However:** The `ml_prediction` variable from line 574 (`ml_prediction = None`) is later conditionally set at lines 629-654. If `ml_prediction` gets set by the CVE/OTX branches (lines 584-589), `verdict` could become non-UNKNOWN. But for IP/domain, `ml_prediction` stays `None` so `verdict` stays `"UNKNOWN"`. The logic is correct for the IP/domain case.

**Actual Bug:** The `provenance` variable is only set inside the `if top_result is None` block. If `top_result` is not None (e.g., enrichment returned results), the heuristic fallback path is never entered, even for truly unseen indicators. This is by design but means P1-1 only works when ALL enrichment sources return nothing.

**Impact:** For IPs/domains that have partial enrichment data (e.g., RDAP returns something but DB has no record), ML prediction will still be attempted on heuristic features — the distribution shift risk remains in this edge case.

---

## I-06 [MEDIUM] — Frontend UI: ML N/A badge not rendered in results.html

**File:** `threat-lens-ai/frontend/results.html` and `assets/js/ui.js`

**Problem:** The backend correctly sets `prediction_source: "ml_unavailable"` in source breakdown items for heuristic-only scans (I-05), but the frontend `ui.js` doesn't render an "ML N/A" badge or special styling for source items with `prediction_source == "ml_unavailable"`. Users won't visually distinguish between "ML said MALICIOUS" and "ML was not available."

**Impact:** P1-1's UX improvement is incomplete. Users see "N/A" in the source breakdown but no clear visual indicator.

**Fix Required:** Add a conditional render in `ui.js` for `prediction_source === 'ml_unavailable'` that shows a gray "ML N/A" badge.

---

## I-07 [LOW] — SHAP TreeExplainer dtype warning for categorical columns

**File:** `backend/app/services/modeling_service.py` (`_shap_explain`, line ~460)

**Problem:** `shap.TreeExplainer` fails when the input DataFrame contains string-typed columns (Country, Continent, ASN, Owner, Network, Threat_Label, Threat_Category, Regional_Registry, TOR_Node). These are categorical features that were one-hot-encoded during training but are passed as raw strings to SHAP.

**Evidence:** Warning in test output:
```
TreeExplainer failed: DataFrame.dtypes for data must be int, float, bool or category.
Invalid columns: Country: str, Continent: str, ASN: str, ...
```

**Impact:** SHAP explainability panel will be empty for IP model predictions. Non-critical for release.

**Fix Required:** Either (a) pass the pre-transformed numeric features to SHAP, or (b) encode categoricals before SHAP computation.

---

## I-08 [LOW] — Test coverage gaps

**Status:** Only P0-2 has automated tests (`tests/test_model_status.py`).

**Missing tests:**
- P1-1: No test for heuristic fallback scan (ml_prediction=null, evidence warning, ml_unavailable source)
- P1-2: No test for retrain endpoint (POST returns 202, status polling, version update)
- P2-1: No test for async DB session creation or migration script
- P2-2: No test verifying feature parity between `features.py` and inline implementation

**Impact:** Regressions in these areas won't be caught by CI.

---

## I-09 [LOW] — Config: `config.py` has only a comment change for PostgreSQL

**File:** `backend/app/config.py` (line 23)

**Problem:** The only change to `config.py` is a comment update: `# Supports: sqlite:///..., postgresql+psycopg2://..., postgresql+asyncpg://...`. No actual code changes to support async URLs. The `Settings.database_url` field is unchanged.

**Impact:** Informational only. The comment is correct — the URL format is supported by SQLAlchemy. No functional change needed.

---

## I-10 [INFO] — P0-1: MiniLM evaluation lacks decision summary

**File:** `data_science/notebooks/03_modeling_and_evaluation_executed.ipynb`

**Problem:** The notebook computes MiniLM metrics but doesn't produce a clear side-by-side comparison table (TF-IDF baseline vs MiniLM vs Ensemble) or a KEEP/REPLACE/DEPRECATE decision.

**Impact:** The evaluation exists but the conclusion is not documented. A reviewer cannot quickly determine whether the MiniLM model meets the 0.45 Micro F1 target.

---

## Aggregate Summary

| Category | Count | Critical | High | Medium | Low | Info |
|----------|-------|----------|------|--------|-----|------|
| Bugs | 2 | 1 (I-01) | 1 (I-02) | — | — | — |
| Missing Features | 2 | — | 1 (I-03) | 1 (I-06) | — | — |
| Incomplete Implementation | 1 | — | — | 1 (I-05) | — | — |
| Code Quality | 2 | — | — | 1 (I-04) | 1 (I-07) | — |
| Test Coverage | 1 | — | — | — | 1 (I-08) | — |
| Documentation | 2 | — | — | — | 1 (I-09) | 1 (I-10) |
| **Total** | **10** | **1** | **2** | **4** | **3** | **1** |

**Recommendation:** Fix I-01 (critical) and I-02, I-03 (high) before merge. I-04 through I-10 can be addressed in a follow-up cleanup sprint.
