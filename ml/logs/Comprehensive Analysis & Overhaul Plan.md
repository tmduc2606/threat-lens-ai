# ThreatLensAI — Comprehensive Preprocessing & Modeling Analysis & Overhaul Plan

**Date:** May 27, 2026
**Author:** AI Analysis Agent
**Scope:** Full pipeline analysis across OTX, CVE, Domains, IPs datasets

---

## I. Executive Summary

The ThreatLensAI data science pipeline processes four distinct cybersecurity datasets (OTX: 2365, CVE: 1585, Domains: 162, IPs: 200 records) through EDA → Preprocessing → Modeling stages. Current performance is **well below production-ready** for most tasks:

| Dataset | Best Model | Current Best Metric | Target | Status |
|---------|-----------|---------------------|--------|--------|
| OTX (multi-label ATT&CK) | TF-IDF + XGBoost OvR | Micro F1 = 0.305 | ≥ 0.45 | **FAIL** |
| OTX (DL) | CodeBERT + MLP | Micro F1 = 0.178 | ≥ 0.40 | **FAIL** |
| CVE (ransomware binary) | TF-IDF + LogReg | F1 = 0.512 | ≥ 0.65 | **FAIL** |
| Domains (severity 3-class) | Char TF-IDF + LGBM | Macro F1 = 0.45 | ≥ 0.65 | **FAIL** |
| IPs (severity 3-class) | XGBoost (Calibrated) | Macro F1 = 0.867 | ≥ 0.85 | **PASS** (but tiny dataset) |

---

## II. Detailed Pipeline Analysis

### A. OTX Threat Intelligence (Multi-Label ATT&CK Classification)

#### Current Pipeline
1. **Text normalization**: lowercasing, punctuation removal on Title, Description, Tags, Malware_Families, Industries, Countries
2. **Feature extraction**: TF-IDF (1-2 word n-grams, max 30K features)
3. **Time features**: pulse_age_days, log_pulse_age
4. **Structured features**: TLP_encoded, Created_month, malware family presence flags (top 20), ATT&CK lexical keyword signals (binary indicators)
5. **Label engineering**: Attack_IDs collapsed to base techniques (T1059.001 → T1059), deduplicated, rare labels filtered (MIN_ATTACK_FREQ = 20)
6. **Modeling**: OneVsRestClassifier + XGBoost, CodeBERT embeddings + MLP, DistilBERT fine-tuning

#### What's Working
- T1059 (Execution) gets F1=0.82 — most frequent technique (314 support)
- T1486 (Data Destruction) gets F1=0.77 (36 support)
- Per-technique threshold optimization improves Macro F1 by 5 points
- The collapse of sub-techniques to parent reduces sparsity

#### What's Failing
- **57 out of 101 techniques have 0.0 F1** — the model completely misses them
- CodeBERT Micro F1 (0.178) is worse than TF-IDF baseline (0.305) — **a code embedding model on CTI text is wrong**
- DistilBERT macro F1 (0.008) with accuracy=0.0 — **architecture is fundamentally not suited** for 384-label multi-label problem with 2352 samples
- `unknown` appears 33 times in test set labels — contaminating the evaluation
- MIN_ATTACK_FREQ = 20 drops many rare but important TTPs
- Indicators_Count and Subscribers are all-zero columns (no variance)

#### Literature-Grounded Fixes
1. **Replace CodeBERT with all-MiniLM-L6-v2**: A sentence-transformer designed for semantic textual similarity; 384-dim embeddings that work better on small data
2. **Label Powerset transformation**: Instead of OvR, group co-occurring techniques via LabelPowerset with RF/LGBM base
3. **Multi-label SMOTE (MLSMOTE)**: Synthetically generate rare label combinations
4. **Add MITRE ATT&CK hierarchy**: Map each technique → tactic (e.g., T1204 → TA0005) as a structural feature — provides regularization for rare techniques
5. **Remove "unknown" labels**: 35 records in test set have only "unknown" — these are noise
6. **Reduce MIN_ATTACK_FREQ to 10**: Recover important but less frequent techniques
7. **Stratified multilabel K-fold**: Use iterative-stratification for train/test split
8. **Target thresholds**: Raise Micro F1 target from 0.305 to ≥ 0.45

### B. CVE Vulnerability Prioritization (Binary Ransomware Risk)

#### Current Pipeline
1. Text TF-IDF on concatenated vendorProject + product + vulnerabilityName + shortDescription + requiredAction + cwes
2. Logistic Regression (CalibratedClassifierCV, cv=5)
3. Threshold tuning on training data (optimal: 0.33)
4. XGBoost alternative (same F1)

#### What's Working
- Accuracy = 0.814 — dominated by majority class (80% Unknown)
- Calibrated probabilities produce reasonable risk bands (LOW/MEDIUM/HIGH)

#### What's Failing
- **F1 = 0.512** — barely better than random for ransomware-linked class
- **1268/1585 entries are "Unknown"** — the target is 80% unlabeled
- `requiredAction` is nearly identical across hundreds of records (893 "Apply updates per vendor instructions") — this adds noise to TF-IDF
- CWE is stored as free text, not normalized to CWE IDs
- No EPSS scores, no CVSS, no vendor/severity features
- No CWE → CAPEC → ATT&CK mapping for enrichment

#### Literature-Grounded Fixes
1. **Reframe to regression**: Use continuous risk score (EPSS * CWE_severity * days_to_due_inverse) instead of binary
2. **Add structured features**: vendor frequency encoding, CWE risk weights, CVE year
3. **EPSS API enrichment**: Every CVE gets an EPSS score via public API
4. **CWE → CAPEC → ATT&CK mapping**: Multi-label sparse features via VulZoo approach
5. **Ensemble**: Text TF-IDF + Structured XGBoost, weighted by calibration error
6. **Stratified k-fold**: 5-fold cross-validation splits by target ratio

### C. Domains Malicious Detection (3-Class Severity)

#### Current Pipeline
1. **Structured features**: Domain_Length, Reputation, vote counts, domain_age_days, ratios, log features, entropy, vowel/digit/special ratios, subdomain/token counts, consecutive char counts, brand/suspicious keyword flags, TLD risk score, WHOIS completeness
2. **Char-TF-IDF** (3-5 grams, max 10K features) on domain string
3. **FeatureUnion** of structured + char-TF-IDF
4. **LGBMClassifier + CalibratedClassifierCV** (cv=5)

#### What's Working
- CLEAN class gets F1=0.90 (27 support)
- char n-grams capture domain structure signals

#### What's Failing
- **Medium class F1 = 0.0** — model cannot distinguish suspicious from clean
- **Only 162 samples** — 80/20 split yields 33 test samples (6 medium, 27 low)
- 6 medium support in test set is statistically meaningless
- char-TF-IDF on 162 samples with 10K features is massively overparameterized
- "High" severity merged into "medium" (only 2 high in test set)

#### Literature-Grounded Fixes
1. **Binary classification**: Merge Medium+High → "SUSPICIOUS" vs "CLEAN"
2. **Leave-one-out or 5-fold stratified CV**: Single 80/20 split with 162 samples is unreliable
3. **SMOTE on minority class**: Only ~17 suspicious out of 162
4. **DomURLs_BERT approach**: Replace char TF-IDF with pre-trained domain BERT embeddings (arXiv:2409.09143)
5. **SecureReg registration features**: Add registration pattern entropy, registrar consistency, semantic density (arXiv:2401.03196)
6. **Use `configs/lookups.py` as internal API**: `preprocess_domains()` calls `get_high_risk_tlds()`, `get_suspicious_keywords()`, `get_brand_keywords()` internally — never at notebook top level. JSON files in `configs/lookups/` are the single source of truth; changes auto-propagate.
7. **RDAP live enrichment**: WhoisJSON age, nameserver count, registrar risk

### D. IPs Threat Severity (3-Class Classification)

#### Current Pipeline
1. **Numeric features**: Vote counts, ratios, log transforms, reputation_score_scaled, date features
2. **Categorical features**: Country, Continent, ASN, Owner, Network, Regional_Registry, tor_flag, ip_first_octet, geolocation risk flags
3. **ColumnTransformer**: StandardScaler for numeric, OneHotEncoder for categorical
4. **Logistic Regression + CalibratedClassifierCV**: 0.762 Macro F1
5. **XGBoost + CalibratedClassifierCV**: 0.867 Macro F1

#### What's Working
- Overall Macro F1 = 0.867 (XGBoost) is respectable
- LOW class precision/recall = 1.0

#### What's Failing
- **Total_Reports = 91 for all 200 records** — constant column, zero variance
- **Times_Submitted = 0 for all 200 records** — constant column
- **High class has only 3 support** in test set → statistically unreliable
- ASN has 31 unique values, many with count=1 (overfitting risk)
- Owner has 30 unique values in 200 rows
- Only 200 total records

#### Literature-Grounded Fixes
1. **Remove constant columns**: Total_Reports, Times_Submitted
2. **Merge rare ASNs** (freq < 3) into "other" category
3. **Lower decision threshold for "high" class**: Security domain should prioritize recall over precision for high-severity
4. **Add AbuseIPDB enrichment**: `abuseConfidenceScore` mapped to risk bands (0-25: LOW, 26-50: MEDIUM, 51-75: HIGH, 76-100: CRITICAL); `totalReports` and `lastReportedAt` recency as structured features
5. **Heuristic fallback via `configs/lookups.py`**: When AbuseIPDB API unavailable, use `get_known_malicious_asns()` and `get_high_risk_countries()` from `configs/lookups/known_malicious_asns.json` and `high_risk_countries.json` — these are called inside `preprocess_ips()` as internal API
6. **Bootstrap confidence intervals**: Report confidence bounds for 200-sample metrics
7. **IP range features**: CIDR /24 density of malicious IPs, ASN reputation scores

---

## III. Cross-Cutting Data Quality Issues

### A. "Unknown" Value Contamination

| Dataset | Column | "Unknown" Count | Total | Percentage |
|---------|--------|----------------|-------|------------|
| OTX | Malware_Families | 656 | 2365 | 27.7% |
| OTX | Attack_IDs | 189 | 2365 | 8.0% |
| OTX | Industries | 1229 | 2365 | 52.0% |
| OTX | Countries | 1306 | 2365 | 55.2% |
| OTX | Tags | 12 | 2365 | 0.5% |
| CVE | knownRansomwareCampaignUse | 1268 | 1585 | 80.0% |
| CVE | cwes | 167 | 1585 | 10.5% |
| Domains | Registrar | 72 | 162 | 44.4% |
| Domains | Creation_Date | 33 | 162 | 20.4% |
| Domains | Popularity_Rank | 88 | 162 | 54.3% |
| IPs | Threat_Label | 189 | 200 | 94.5% |
| IPs | Threat_Category | 107 | 200 | 53.5% |

### B. Dataset Size Limitations

- **Domains (162)**: Minimum viable dataset size for ML is ~500. Current 80/20 split yields unreliable evaluation.
- **IPs (200)**: Same issue — high class has what amounts to single-digit support.
- **OTX (2365)**: Adequate for text-based multi-label, but 101 labels with 2352 samples = ~23 samples/label average. Some labels have 2-3 samples.

### C. Column Standardization Inconsistency

- Data science raw CSVs use mixed casing: `has_numbers` (lowercase after standardize_columns) while backend expects `Has_Numbers`
- The `standardize_columns` function merely replaces spaces with underscores and strips — no capitalization normalization
- Backend `unmodified_raw/` is not synced with `data/raw/` — drift risk

---

## IV. Literature-Grounded Enhancement Catalog

| Paper | Key Idea | Applies To | Priority |
|-------|----------|------------|----------|
| Dincy et al. (2023) | OTX indicator reliability measurement | OTX | Medium |
| Freitas et al. (2025) — HAL9000 | EPSS + CVSS + OTX pulse fusion | CVE | **High** |
| Bonan et al. (2024) — VulZoo | CWE→CAPEC→ATT&CK mapping dataset | CVE | **High** |
| Patel (2024) | EPSS efficacy on KEV vulnerabilities | CVE | Medium |
| Sato (2025) | Vulnerability prioritization framework | CVE | Medium |
| Abdelkader et al. (2024) — DomURLs_BERT | Pretrained BERT for malicious domains | Domains | **High** |
| Ç et al. (2024) — SecureReg | NLP+MLP domain registration detection | Domains | **High** |
| Abdelaziz et al. (2024) | IoT botnet detection via network flow | IPs | Low (no flow data) |
| R & M (2026) — LocalAI-Sec | Nmap + NVD + local LLM for small orgs | All (via web app) | **High** |
| Ye et al. (2025) | Malicious URL detection survey | Domains | Medium |

---

## V. Overhaul Implementation Plan

### Phase 1: Data Quality (Week 1)

1. [ ] Add notebook cell to remove rows where Attack_List is `["unknown"]`
2. [ ] Reduce MIN_ATTACK_FREQ from 20 to 10
3. [ ] Remove constant columns from IP pipeline (Total_Reports, Times_Submitted)
4. [ ] Merge rare ASNs in IP pipeline (freq < 3 → "other")
5. [ ] Add vendor frequency encoding to CVE pipeline
6. [ ] Add CWE risk weight scoring to CVE pipeline (OWASP-based severity per CWE)

### Phase 2: Preprocessing Enhancements (Week 1-2)

7. [ ] Add domain entropy feature (Shannon entropy of domain string character distribution)
8. [ ] Add consecutive consonant/digit count features for domains
9. [ ] Add IP range-based features (CIDR /24 malicious density lookup)
10. [ ] Add MITRE ATT&CK tactic mapping from technique → tactic (structural feature for OTX)
11. [ ] Split CVE `requiredAction` out of TF-IDF (it's too repetitive, adds noise)
12. [ ] Normalize CWE values: strip "cwe-" prefix, sort multi-CWE entries

### Phase 3: Model Retraining (Week 2-3)

13. [ ] **OTX Retrain**:
    - Implement LabelPowerset + RandomForest baseline
    - Add all-MiniLM-L6-v2 embeddings (replace CodeBERT)
    - Ensemble: TF-IDF + MiniLM + structured features
    - Implement iterative-stratification for train/test split
    - Remove DistilBERT code (not salvageable)
14. [ ] **CVE Retrain**:
    - Add EPSS feature (pre-join from public CISA/NVD data or live fetch)
    - Ensemble: text TF-IDF LogReg + structured XGBoost
    - Reframe to regression: risk score = f(knownRansomware + days_to_due + CWE_severity)
    - Stratified 5-fold evaluation
15. [ ] **Domains Retrain**:
    - Binary classification (SUSPICIOUS vs CLEAN)
    - SMOTE on minority class
    - Leave-one-out cross-validation
    - Replace char TF-IDF with MiniLM on WHOIS + domain text
    - Add brand_keywords.json features already in configs
16. [ ] **IPs Retrain**:
    - Remove constant columns
    - Merge rare ASNs
    - Lower high-class threshold (target recall ≥ 0.80)
    - Bootstrap CI for evaluation

### Phase 4: Web Application Integration (Week 3-4)

17. [ ] Copy new .joblib artifacts to threat-lens-ai/models/
18. [ ] Update ml_adapter.py to load new models
19. [ ] Remove otx_transformer reference (DistilBERT gone)
20. [ ] Add missing `otx_attackids_tfidf_ovr_logreg.joblib` to fix known bug
21. [ ] Verify all models load via GET /model/status

### Phase 5: Live Lookups Sync & Enrichment (Week 4)

22. [ ] Add `POST /admin/lookups/sync` endpoint to update JSON files from external feeds:
    - `high_risk_tlds.json` ← Public Suffix List + PhishTank stats
    - `known_malicious_asns.json` ← BGP Ranking + AbuseIPDB top ASNs
    - `high_risk_countries.json` ← UN cybercrime indices (manual curation quarterly)
23. [ ] **`configs/lookups.py` gets last-resort remote fallback**: if JSON file missing, fetch from GitHub raw or backup URL before returning empty dict
24. [ ] Build EPSS client for live scoring
25. [ ] Build AbuseIPDB client for live IP enrichment (abuseConfidenceScore → risk bands)
26. [ ] Build WhoisJSON/RDAP client for domain enrichment
27. [ ] Wire enrichment results into retraining pipeline (export enriched CSV)
28. [ ] Add confidence bands (CRITICAL/HIGH/MEDIUM/LOW/IGNORE) to scoring.py
29. [ ] Add SHAP explainability for domain & IP models in backend

---

### Stage 1 Gate: Data Science Overhaul — Testing Checklist

**Phase 6 must NOT begin until ALL of the following pass:**

| # | Criterion | How to Verify |
|---|-----------|---------------|
| 1 | All 4 model types retrain within ~20 min budget | Run `03_modeling_and_evaluation.ipynb` end-to-end |
| 2 | OTX Micro F1 ≥ 0.45, Macro F1 ≥ 0.20 | `sklearn.metrics.f1_score(average="micro"/"macro")` |
| 3 | CVE F1 ≥ 0.65, AUC ≥ 0.80 | `sklearn.metrics.f1_score/roc_auc_score` |
| 4 | Domains Macro F1 ≥ 0.65, Suspicious Recall ≥ 0.70 | `sklearn.metrics.f1_score/recall_score` |
| 5 | IPs Macro F1 ≥ 0.85, High-class Recall ≥ 0.80 | `sklearn.metrics.f1_score/recall_score` |
| 6 | DistilBERT + CodeBERT removed from pipeline | No `otx_transformer` or `codebert` in `03_modeling.ipynb` |
| 7 | All 13 API clients exist and extend `BaseAPIClient` | `ls services/api_clients/` |
| 8 | `cloudflare_client.py` deprecated (unreferenced) | `rg "cloudflare" backend/` returns 0 hits |
| 9 | All APIs run in parallel via `asyncio.gather()` | Enrichment pipeline handles `httpx.HTTPError` per source |
| 10 | Nmap integration files exist (gated by `ENABLE_NMAP_SCAN=false`) | `services/nmap_service.py` + `models/nmap_results.py` |
| 11 | Source breakdown deduplication fixed | `curl /scan?q=1.2.3.4` has no redundant items |
| 12 | `.joblib` artifacts copied to `threat-lens-ai/models/` | All `.joblib` files present in models/ |
| 13 | `GET /model/status` returns all loaded = True | `curl localhost:8000/model/status \| jq` |
| 14 | `GET /model/stats` returns per-class F1 + calibration error | `curl localhost:8000/model/stats \| jq` |
| 15 | `GET /model/export/ip` and `/model/export/domain` produce `Title_Case` CSVs | Check column names |
| 16 | `POST /model/sync?feed=all` updates lookups | Check JSON files modified |
| 17 | `POST /admin/lookups/sync` updates JSON from external feeds | Check modified timestamps |
| 18 | `configs/lookups.py` has remote fallback when JSON missing | Disconnect network, verify fallback returns data |
| 19 | EPSS, AbuseIPDB, WhoisJSON/RDAP clients return expected data | `curl /scan?q=185.220.101.42` — source_breakdown has AbuseIPDB |
| 20 | Tip of the day returns dynamic content from APIs | `curl /tip-of-the-day` returns non-hardcoded tip |
| 21 | Confidence calibration bands added to `scoring.py` | Code review of `scoring.py` |

**Fix any failure → re-run → re-verify. Phase 6 is blocked until all 21 pass.**

---

### Phase 6: UI/UX Overhaul (Week 4-5)

Leverages new DS capabilities: calibrated probabilities, SHAP, ensemble, confidence intervals, model health.  
**Do NOT begin until Stage 1 Gate above passes 100%.**

#### 6A. Fix Page Reload Bug (Prerequisite)
30. [ ] **`search.js`**: Replace `window.location.href` with SPA navigation (`history.pushState` + `doScan()`)
31. [ ] **`ui.js`**: Dedup scan initiation — prevent double-scan from URL param + sessionStorage

#### 6B. Calibrated Confidence Bar
32. [ ] **Backend `schemas/common.py`**: Add `calibrated_confidence: Optional[float]`, `confidence_interval: Optional[Dict[str,float]]`, `risk_band: Optional[str]` to `ScanResponse`
33. [ ] **Backend `scoring.py`**: Replace heuristic `_confidence_from_score()` with calibrated probability mapping (model probability → CRITICAL/HIGH/MEDIUM/LOW/IGNORE)
34. [ ] **Frontend `ui.js`**: Replace `Confidence HIGH` text pill with colored progress bar (width=calibrated%) + CI tooltip
35. [ ] **Risk band colors**: CRITICAL=red-500, HIGH=orange-500, MEDIUM=amber-500, LOW=slate-400, IGNORE=slate-700

#### 6C. ML Engine Source Breakdown Card
36. [ ] **Backend `scan_service.py`**: Add `ML_PREDICTION` source breakdown item with `ml_model`, `ml_confidence`, `ml_classes`, `ml_probabilities`, `ml_ensemble_votes`, `ml_training_date`, `ml_training_samples`, `ml_f1_score`
37. [ ] **Frontend `ui.js`**: Detect `ML_PREDICTION` type and render expanded card with probability bars per class, ensemble member votes row, training metadata tooltip

#### 6D. SHAP Explainability Panel
38. [ ] **Backend `schemas/common.py`**: Add `shap_values: List[Dict[str,Any]]` to `DetailResponse` (feature, value, impact)
39. [ ] **Backend `modeling_service.py`**: Add `shap.TreeExplainer` (XGBoost) and `shap.LinearExplainer` (LogReg), return top 5-10 features
40. [ ] **Frontend `ui.js`**: New `renderShapPanel()` — horizontal bar chart showing feature name, bar width, impact value

#### 6E. Categorized Evidence
41. [ ] **Backend `scan_service.py`**: Return evidence as `List[Dict]` with `type` (api/ml/heuristic/network) + `text` instead of flat strings
42. [ ] **Frontend `ui.js`**: Color-code by type (api=cyan, ml=violet, heuristic=amber, network=emerald), add type badge icons, group by type

#### 6F. Sources Consulted & Model Health Header
43. [ ] **Backend `schemas/common.py`**: Expand `model_status` values from `bool` to `Dict` with `loaded`, `f1_score`, `samples`, `trained_at`, `stale`
44. [ ] **Frontend `ui.js` or `header.js`**: Render model health bar: `🧠 IP Model ✅ (F1=0.87) | Domain Model ⚠️ Stale`
45. [ ] **Frontend**: Show "Sources consulted" on results page with per-API status (✅ responded / ⚠️ timeout / ❌ error)

#### 6G. Loading Skeletons
46. [ ] **Frontend `ui.js`**: Replace `"Scanning..."` with animated skeleton placeholders per section (verdict, source breakdown, evidence)
47. [ ] Use Tailwind `animate-pulse` + `bg-slate-800` rounded blocks

#### 6H. CSV Export Overhaul
48. [ ] **Frontend `ui.js`**: Restructure CSV as proper table columns (source_type, engine, verdict, score, confidence, ml_probability, note)
49. [ ] Add per-class probabilities columns, SHAP top features, model metadata row

#### 6I. Keyboard Shortcut & Input Validation
50. [ ] **Frontend `index.html`**: Add Enter key handler on textarea, character limit (2000) with counter, trim whitespace on scan

---

### Stage 2 Gate: UI/UX Overhaul — Testing Checklist

**Must pass 100% before overhaul is considered complete.**

| # | Criterion | How to Verify |
|---|-----------|---------------|
| 1 | Page reload bug fixed: rescan buttons use SPA nav | Click rescan, check DevTools Network tab — no full page load |
| 2 | Calibrated confidence bar renders in UI | `curl /scan?q=185.220.101.42 \| jq .calibrated_confidence` returns float |
| 3 | Risk band badge shows correct color | Visual: CRITICAL=red, HIGH=orange, MEDIUM=amber, LOW=slate, IGNORE=slate-700 |
| 4 | ML Engine card shows per-class probabilities | `curl /scan?q=... \| jq '.source_breakdown[] \| select(.source_type=="ML_PREDICTION")'` has `ml_probabilities` |
| 5 | SHAP values returned for IP/Domain details | `curl /intel/IP/185.220.101.42 \| jq .shap_values` is non-empty array |
| 6 | Evidence items have `type` field | `curl /scan?q=185.220.101.42 \| jq '.evidence[0].type'` returns api/ml/heuristic/network |
| 7 | Model health bar renders in header | Visual: icons per model (✅/⚠️/❌) with F1 score |
| 8 | Sources consulted shows per-API status | Visual: AbuseIPDB(✅), VirusTotal(✅), RDAP(⚠️), etc. |
| 9 | Loading skeletons appear during scan | Visual: `animate-pulse` blocks on results page before data loads |
| 10 | CSV export includes per-class probs + SHAP | Download CSV, verify columns: ml_probability, shap_feature_1, etc. |
| 11 | Enter key triggers scan from textarea | Type query, press Enter → scan runs (no page reload) |
| 12 | Character limit enforced (2000 max) | Type 2001+ chars → input blocked or counter shows limit |
| 13 | Whitespace trimmed on scan trigger | Leading/trailing spaces → trimmed before API call |
| 14 | No regressions on index page quick-query buttons | Click each demo button → inline preview renders without error |
| 15 | No regressions on detail page | `curl /intel/IP/185.220.101.42 \| jq` — raw JSON toggle, metadata, tags all render |

**Any failure → fix root cause → re-test. Only greenlit when all 15 pass.**

---

## VI. Detailed Code Changes Required

### data_science/notebooks/02_preprocessing_and_feature_engineering.ipynb

```python
# === OTX Pipeline Changes ===
# 1. Remove unknown rows from Attack_List
otx_p = otx_p[~otx_p["Attack_List"].apply(lambda x: x == ["unknown"] or "unknown" in x)]

# 2. Reduce MIN_ATTACK_FREQ
MIN_ATTACK_FREQ = 10  # was 20

# 3. Add technique → tactic mapping
TECHNIQUE_TO_TACTIC = {
    "t1059": "ta0002",  # Execution
    "t1204": "ta0005",  # Defense Evasion → User Execution
    # ... full mapping from MITRE enterprise ATT&CK
}
otx_p["tactic_labels"] = otx_p["Attack_List"].apply(
    lambda x: list(set(TECHNIQUE_TO_TACTIC.get(t, "") for t in x))
)

# === CVE Pipeline Changes ===
# 1. CWE severity scoring
CWE_RISK_SCORE = {
    "cwe-22": 0.7, "cwe-77": 0.8, "cwe-79": 0.6, "cwe-89": 0.8, "cwe-94": 0.7,
    "cwe-119": 0.7, "cwe-120": 0.7, "cwe-125": 0.5, "cwe-200": 0.5, "cwe-287": 0.6,
    "cwe-306": 0.8, "cwe-352": 0.6, "cwe-416": 0.7, "cwe-434": 0.8, "cwe-502": 0.7,
    "cwe-787": 0.8, "cwe-862": 0.6, "cwe-918": 0.7, "unknown": 0.3
}
cve_p["cwe_risk_max"] = cve_p["cwe_list"].apply(
    lambda cwes: max([CWE_RISK_SCORE.get(c, 0.3) for c in (cwes or ["unknown"])])
)

# 2. Separate requiredAction (too repetitive for TF-IDF)
cve_p["risk_text"] = cve_p["vulnerabilityName"] + " " + cve_p["shortDescription"]
# requiredAction kept as separate structured feature

# === Domains Pipeline Changes ===
# 1. Domain string entropy
def shannon_entropy(s):
    if not s or len(s) == 0:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)

domains_p["domain_entropy"] = domains_p["Domain"].apply(shannon_entropy)

# 2. Consecutive features
domains_p["max_consecutive_consonants"] = domains_p["Domain"].apply(
    lambda x: max((len(list(g)) for c, g in itertools.groupby(x.lower()) if c in "bcdfghjklmnpqrstvwxyz"), default=0)
)

# 3. Flag suspicious keyword matches from configs (internal API — called inside preprocess_domains)
from configs.lookups import get_suspicious_keywords, get_brand_keywords
# These are called INSIDE the preprocess_domains() function, not at notebook top level
# JSON files in configs/lookups/ are the single source of truth
# Backend POST /admin/lookups/sync can update them from external feeds
SUSPICIOUS_KEYWORDS = get_suspicious_keywords()
BRAND_KEYWORDS = get_brand_keywords()

# === IPs Pipeline Changes ===
# 1. Drop constant columns  
DROP_CONSTANT_COLS = ["Total_Reports", "Times_Submitted"]
ips_p = ips_p.drop(columns=[c for c in DROP_CONSTANT_COLS if c in ips_p.columns])

# 2. Merge rare ASNs
asn_counts = ips_p["ASN"].value_counts()
rare_asns = asn_counts[asn_counts < 3].index
ips_p["ASN"] = ips_p["ASN"].apply(lambda x: "other" if x in rare_asns else x)
```

### data_science/notebooks/03_modeling_and_evaluation.ipynb

```python
# === OTX: Replace CodeBERT with all-MiniLM-L6-v2 ===
from sentence_transformers import SentenceTransformer

EMBED_MODEL = SentenceTransformer("all-MiniLM-L6-v2")  # 384-dim, designed for similarity

train_emb = EMBED_MODEL.encode(otx_train["combined_text"].tolist(), show_progress_bar=True, batch_size=32)
test_emb = EMBED_MODEL.encode(otx_test["combined_text"].tolist(), show_progress_bar=True, batch_size=32)

# === OTX: Add stratify-based train/test split ===
from skmultilearn.model_selection import iterative_train_test_split

X_train, y_train_classical, X_test, y_test_classical = iterative_train_test_split(
    X, y_multilabel, test_size=0.2
)

# === OTX: LabelPowerset baseline ===
from skmultilearn.problem_transform import LabelPowerset
from sklearn.ensemble import RandomForestClassifier

lp_model = LabelPowerset(classifier=RandomForestClassifier(n_estimators=300, random_state=42))
lp_model.fit(X_tfidf_train, y_train)
lp_preds = lp_model.predict(X_tfidf_test)

# === CVE: Ensemble text + structured ===
from sklearn.ensemble import VotingClassifier

# Text pipeline
text_clf = Pipeline([("tfidf", TfidfVectorizer(...)), ("clf", LogisticRegression(...))])
# Structured pipeline
struct_clf = Pipeline([("prep", ColumnTransformer(...)), ("clf", XGBClassifier(...))])

ensemble = VotingClassifier(
    estimators=[("text", text_clf), ("struct", struct_clf)],
    voting="soft",
    weights=[0.4, 0.6]  # weight by calibration error
)
```

---

## VII. Risk Band Calibration Mapping

Map model output probabilities to risk bands for the frontend:

```python
RISK_BANDS = {
    "CRITICAL":  (0.90, 1.00),
    "HIGH":      (0.70, 0.90),
    "MEDIUM":    (0.40, 0.70),
    "LOW":       (0.20, 0.40),
    "IGNORE":    (0.00, 0.20),
}
```

For IP model, lower the HIGH threshold (recall > precision):
```python
IP_RISK_BANDS = {
    "CRITICAL":  (0.80, 1.00),  # Lowered for security sensitivity
    "HIGH":      (0.50, 0.80),
    "MEDIUM":    (0.25, 0.50),
    "LOW":       (0.10, 0.25),
    "IGNORE":    (0.00, 0.10),
}
```

---

## VIII. Verification Criteria (by Stage)

### Stage 1: Data Science

| Criterion | Current | Target | Measurement |
|-----------|---------|--------|-------------|
| OTX Micro F1 | 0.305 | ≥ 0.45 | `sklearn.metrics.f1_score(average="micro")` |
| OTX Macro F1 | 0.102 | ≥ 0.20 | `sklearn.metrics.f1_score(average="macro")` |
| CVE F1 | 0.512 | ≥ 0.65 | `sklearn.metrics.f1_score` |
| CVE AUC-ROC | N/A | ≥ 0.80 | `sklearn.metrics.roc_auc_score` |
| Domains Macro F1 | 0.45 | ≥ 0.65 | `sklearn.metrics.f1_score(average="macro")` |
| Domains Suspicious Recall | N/A | ≥ 0.70 | `sklearn.metrics.recall_score` |
| IPs Macro F1 | 0.867 | ≥ 0.85 | `sklearn.metrics.f1_score(average="macro")` |
| IPs High-class Recall | 0.67 | ≥ 0.80 | `sklearn.metrics.recall_score` |
| Model loading via API | N/A | All models load | `GET /model/status` returns all True |
| DistilBERT removed | Present | Removed | No otx_transformer in artifacts or code |

### Stage 2: UI/UX

| Criterion | Current | Target | Measurement |
|-----------|---------|--------|-------------|
| Calibrated confidence in API | None | Present in ScanResponse | `curl /scan?q=... \| jq .calibrated_confidence` returns float |
| SHAP values in detail API | None | Present in DetailResponse | `curl /intel/IP/1.2.3.4 \| jq .shap_values` is non-empty |
| Page reload on rescan | Full reload | SPA navigation | Click rescan, verify no full page reload |
| Evidence categorized | Flat strings | Typed dicts | `curl /scan?q=... \| jq '.evidence[0].type'` returns api/ml/heuristic/network |
| Loading skeletons | "Scanning..." text | Placeholder blocks | Visual inspection during scan |
| Model health displayed | Not rendered | Icons in header | `model_status` shows F1, samples, training date |

---

## IX. References

1. Dincy, R. et al. (2025). Discerning reliable cyber threat indicators. arXiv:2306.16087
2. Freitas, T. et al. (2025). HAL9000 risk manager. arXiv:2508.13364
3. Bonan, R. et al. (2024). VulZoo vulnerability dataset. arXiv:2406.16347
4. Patel, R. (2024). EPSS efficacy in KEV. arXiv:2411.02618
5. Sato, N. (2025). Vulnerability chaining framework. arXiv:2506.01220
6. Abdelkader, E. et al. (2024). DomURLs_BERT. arXiv:2409.09143
7. Ç, F. et al. (2024). SecureReg domain detection. arXiv:2401.03196
8. R, D. & M, J. (2026). LocalAI-Sec: Lightweight privacy-preserving cybersecurity. (Source PDF in logs)
9. Abdelaziz, A. et al. (2024). IoT botnet detection. arXiv:2407.15688
10. Ye, T. et al. (2025). Malicious URL detection survey. arXiv:2504.16449
