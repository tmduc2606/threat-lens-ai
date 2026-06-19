# ThreatLensAI — Agent Instructions

This file is the entry point for AI agents working on the ThreatLensAI project. It defines the project structure, critical conventions, and — most importantly — **which agent persona or skill to invoke for each type of work**.

---

## Repository Structure

```
threat-lens-ai/
├── agents/                      # Pre-configured agent personas
│   ├── code-reviewer.md
│   ├── security-auditor.md
│   ├── test-engineer.md
│   └── web-performance-auditor.md
├── skills/                      # Workflow skills (phase-gated)
│   ├── spec-driven-development/
│   ├── planning-and-task-breakdown/
│   ├── incremental-implementation/
│   ├── test-driven-development/
│   ├── code-review-and-quality/
│   ├── security-and-hardening/
│   └── shipping-and-launch/
├── backend/
│   ├── app/
│   │   ├── config.py           # Settings (env-driven, PostgreSQL default)
│   │   ├── database.py         # Sync engine
│   │   ├── database_async.py   # Async engine
│   │   ├── main.py             # App entry, router registration
│   │   ├── models/             # SQLAlchemy ORM models
│   │   ├── routers/            # FastAPI route handlers
│   │   ├── services/
│   │   │   ├── api_clients/    # External API integrations (12 clients)
│   │   │   ├── enrichment_pipeline.py
│   │   │   ├── ml_adapter.py
│   │   │   ├── modeling_service.py
│   │   │   ├── scan_service.py
│   │   │   └── ...
│   │   ├── schemas/            # Pydantic models
│   │   └── utils/              # Scoring, normalization, helpers
│   ├── data/                   # Runtime CSV seed data (Title_Case columns)
│   │   └── unmodified_raw/
│   ├── scripts/                # DB management, migration
│   ├── sql/                    # Schema reference
│   ├── tests/                  # 17 tests (pytest)
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── index.html
│   ├── results.html
│   ├── details.html
│   └── assets/js/
│       ├── api.js
│       ├── ui.js
│       ├── search.js
│       └── theme.js
├── ml/                          # Machine learning pipeline
│   ├── models/                  # Trained .joblib artifacts (single source of truth)
│   ├── src/                     # Feature engineering (shared with backend)
│   │   ├── features.py
│   │   └── utils.py
│   ├── configs/                 # Lookup tables
│   │   ├── lookups.py
│   │   └── lookups/
│   ├── data/                    # Training data (raw, interim, processed, splits)
│   ├── notebooks/               # Jupyter notebooks
│   ├── scripts/                 # Training scripts
│   ├── outputs/artifacts/       # Training output mirrors
│   ├── logs/                    # Training logs
│   └── skills/
│       └── ml-dl-architect.md
├── logs/                        # Project logs, benchmarks, savestates
│   ├── CHANGELOG.md
│   ├── THREATLENSAI_OVERHAUL.md
│   ├── savestates/
│   └── visual_logs/
└── README.md
```

---

## Agent Persona Routing

**When the task matches a specialized role, invoke the corresponding agent persona instead of handling it generically.** Each persona has its own review framework, output format, and rules.

| Task Type | Agent Persona | File |
|-----------|--------------|------|
| Code review before merge | **Code Reviewer** — 5-axis review (correctness, readability, architecture, security, performance) | `agents/code-reviewer.md` |
| Security audit / vulnerability detection | **Security Auditor** — OWASP-based, STRIDE threat modeling | `agents/security-auditor.md` |
| Test strategy / coverage analysis / TDD | **Test Engineer** — Prove-It pattern, coverage gaps | `agents/test-engineer.md` |
| Core Web Vitals / performance audit | **Web Performance Auditor** — CWV scorecard, Lighthouse/CrUX | `agents/web-performance-auditor.md` |
| ML/DL architecture review | **ML/DL Architect** — Model selection, training, deployment | `ml/skills/ml-dl-architect.md` |

### Orchestration Patterns

- **Single perspective** → invoke the agent directly (e.g., "review this PR" → `code-reviewer`)
- **Parallel fan-out** → `/ship` composes `code-reviewer` + `security-auditor` + `test-engineer` in parallel, then synthesizes a go/no-go decision
- **Performance audit** → `/webperf` wraps `web-performance-auditor` (not included in `/ship` — web-only concern)
- **Personas never invoke other personas.** Composition belongs to slash commands or the user.

See `agents/README.md` for the full decision matrix and anti-patterns.

---

## Skill Workflow Phases

**Skills are step-by-step workflows with exit criteria.** They are organized by project phase. Load the relevant skill before starting work in that phase.

| Project Phase | Skill | Location |
|---------------|-------|----------|
| **Starting a project** — requirements, spec, architecture | `spec-driven-development` | `skills/spec-driven-development/SKILL.md` |
| **Starting a project** — task breakdown, dependency graph, parallelization | `planning-and-task-breakdown` | `skills/planning-and-task-breakdown/SKILL.md` |
| **During development** — incremental implementation | `incremental-implementation` | `skills/incremental-implementation/SKILL.md` |
| **During development** — test-driven development | `test-driven-development` | `skills/test-driven-development/SKILL.md` |
| **Before merge** — code review & quality gates | `code-review-and-quality` | `skills/code-review-and-quality/SKILL.md` |
| **Before merge** — security & hardening | `security-and-hardening` | `skills/security-and-hardening/SKILL.md` |
| **Before deploy** — shipping & launch | `shipping-and-launch` | `skills/shipping-and-launch/SKILL.md` |

> **Note:** When a phase's skill doesn't exist yet, the agent persona for that domain (e.g., `code-reviewer`, `security-auditor`) serves as the workflow guide.

---

## Critical Conventions

1. **Backend:** Python 3.10+ with FastAPI + SQLAlchemy + PostgreSQL (default) / SQLite (fallback)
2. **Frontend:** Vanilla JS + Tailwind CSS (CDN) — no framework
3. **CSV column naming:**
   - Backend runtime CSVs: `Title_Case` (e.g., `Malicious_Votes`, `Domain_Length`)
   - ML training raw CSVs: `snake_case` (e.g., `malicious_votes`, `domain_length`)
   - Export endpoint produces `Title_Case`
4. **API clients:** All use `httpx.AsyncClient` and extend `BaseAPIClient` in `backend/app/services/api_clients/`
5. **Nmap:** Gated behind `ENABLE_NMAP_SCAN=false` — never change this default
6. **Heuristic fallbacks:** For degraded mode only — real API data is primary
7. **LLM (Ollama):** For summarization only — never influences threat score
8. **`ml/configs/lookups.py`:** Self-contained internal API — preprocessing functions call `get_*()` internally. JSON files in `ml/configs/lookups/` are the single source of truth. Backend sync endpoint (`POST /api/admin/lookups/sync`) updates them from external feeds.
9. **Models:** All trained `.joblib` artifacts live in `ml/models/` (single source of truth). Backend loads via `MODELS_DIR` config.

---

## API Keys

| Env Variable | Service | Free Tier | Signup URL |
|-------------|---------|-----------|------------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB | 1,000 checks/day | https://abuseipdb.com |
| `OTX_API_KEY` | AlienVault OTX | Unlimited | https://otx.alienvault.com |
| `NVD_API_KEY` | NVD | 50 req/30s | https://nvd.nist.gov |
| `VIRUSTOTAL_API_KEY` | VirusTotal | 500 req/day | https://virustotal.com |
| `URLSCAN_API_KEY` | URLScan.io | Free tier | https://urlscan.io |
| `THREATFOX_AUTH_KEY` | ThreatFox (abuse.ch) | Free | https://threatfox.abuse.ch |
| `URLHAUS_AUTH_KEY` | URLhaus (abuse.ch) | Free | https://urlhaus.abuse.ch |
| `MALWAREBAZAAR_AUTH_KEY` | MalwareBazaar (abuse.ch) | Free | https://malwarebazaar.abuse.ch |
| `WHOISJSON_API_KEY` | WhoisJSON | 1,000/month | https://whoisjson.com |

**No keys needed for:** RDAP (free protocol), FIRST EPSS (public API), CISA KEV (public JSON feed).

---

## Known Bugs & Issues

| # | Bug | Severity | Status |
|---|-----|----------|--------|
| 1 | Page reload loop (`search.js:21`) | High | ✅ Fixed (RC2 A1) |
| 2 | Cloudflare Registrar API broken | High | ✅ Fixed — RDAP + WhoisJSON replacement |
| 3 | Missing OTX AttackID model | Medium | ✅ Fixed — `otx_minilm_logreg.joblib` + ensemble |
| 4 | Source breakdown always shows ≥2 items | Low | ❌ Remaining — filter to items with actual API data |
| 5 | Hardcoded tip of the day | Medium | ✅ Fixed — dynamic from CISA KEV / NVD / OTX |
| 6 | "Models ❌ models" rendering | Medium | ✅ Fixed — Model Health Status Panel |
| 7 | CVE/OTX placeholder detection counters | Medium | ✅ Fixed — conditional render guard |
| 8 | Scoring not calibrated to research standards | High | ✅ Fixed — weighted multi-signal composite |
| 9 | Verdict band always dark gray | High | ✅ Fixed — explicit riskBand check |
| 10 | Confidence bar missing when `calibrated_confidence` is null | Medium | ✅ Fixed — text fallback label |
| 11 | Domain ML prediction fails (27 missing features) | High | ✅ Fixed — `enrich_domain()` now provides all 43 features |
| 12 | RDAP registrar extraction fragile | Medium | ✅ Fixed — 4 fallback strategies |
| 13 | Models duplicated across folders | Low | ✅ Fixed — `ml/models/` is single source of truth |

---

## ML Model Performance Baseline

| Model | Dataset | Size | Metric | Score | Verdict |
|-------|---------|------|--------|-------|---------|
| TF-IDF + XGBoost OvR | OTX | 2352 | Micro F1 | 0.338 | Marginal |
| **MiniLM + LogReg OvR** | **OTX** | **2352** | **Micro F1** | **0.356** | **Improved** |
| **Ensemble (TF-IDF + MiniLM)** | **OTX** | **2352** | **Micro F1** | **0.490** | **Best** |
| TF-IDF + LogReg (Calibrated) | CVE | 1585 | F1 | 0.491 | Marginal |
| Char TF-IDF + LGBM (Calibrated) | Domains | 162 | Macro F1 | 0.920 | Good |
| XGBoost (Calibrated) | IPs | 200 | Macro F1 | 1.000 | Best (overfit risk) |

For ML architecture review and retraining guidance, invoke the `ml-dl-architect` agent (`ml/skills/ml-dl-architect.md`).

---

## Quick Verification

```bash
# Backend health
curl http://localhost:8000/api/health

# Model status
curl http://localhost:8000/api/model/status

# Scan test (no auth required)
curl "http://localhost:8000/api/scan?q=185.220.101.42" | jq ".calibrated_confidence, .risk_band"

# Model health metadata
curl http://localhost:8000/api/model/status
```
