# ThreatLensAI

**A cybersecurity intelligence platform that does neatly essential things** | scan IPs, domains, CVEs, and OTX pulses with ML-powered classification, multi-source enrichment, and explainable results.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688.svg)](https://fastapi.tiangolo.com)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16+-336791.svg)](https://www.postgresql.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Overview

ThreatLensAI is a full-stack threat intelligence platform that aggregates data from 13+ security APIs, classifies threats using trained ML models (XGBoost, LightGBM, Logistic Regression, MiniLM), and presents results through a clean, dark-mode web interface.

**Key capabilities:**

- **Multi-source enrichment**: AbuseIPDB, OTX, VirusTotal, NVD, EPSS, ThreatFox, URLhaus, MalwareBazaar, URLScan, RDAP, WhoisJSON, CISA KEV
- **ML-powered classification**: 6 trained models for IP, domain, CVE, and OTX threat categorization
- **Explainable results**: SHAP-based feature importance for every prediction
- **Weighted composite scoring**: Multi-signal risk scoring calibrated to research standards
- **Async architecture**: FastAPI + SQLAlchemy async with parallel API enrichment

## Architecture

```
threat-lens-ai/
├── backend/                  # FastAPI application
│   ├── app/
│   │   ├── config.py         # Settings (env-driven, PostgreSQL default)
│   │   ├── database.py       # Sync engine (SQLite/PostgreSQL)
│   │   ├── database_async.py # Async engine (aiosqlite/asyncpg)
│   │   ├── main.py           # App entry, router registration, static files
│   │   ├── models/           # SQLAlchemy ORM (9 tables)
│   │   ├── routers/          # 8 API routers
│   │   ├── services/
│   │   │   ├── api_clients/  # 12 external API clients (httpx async)
│   │   │   ├── enrichment_pipeline.py  # Parallel multi-source enrichment
│   │   │   ├── modeling_service.py     # ML prediction + feature engineering
│   │   │   ├── scan_service.py         # Scan orchestration + heuristics
│   │   │   └── ...
│   │   ├── schemas/          # Pydantic models
│   │   └── utils/            # Scoring, normalization, response helpers
│   ├── data/                 # Runtime CSV seed data (Title_Case columns)
│   ├── scripts/              # DB management, migration, inspection
│   ├── sql/                  # Schema reference (cross-DB compatible)
│   ├── tests/                # 17 tests (pytest)
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/                 # Vanilla JS + Tailwind CSS (CDN)
│   ├── index.html            # Search dashboard
│   ├── results.html          # Scan results with source breakdown
│   ├── details.html          # Single-IOC detail with SHAP explanation
│   └── assets/js/            # api.js, ui.js, search.js, theme.js
├── ml/                       # Machine learning pipeline
│   ├── models/               # 10 trained .joblib artifacts + version.json
│   ├── src/                  # Feature engineering (shared with backend)
│   │   ├── features.py       # build_domain_features(), build_ip_features()
│   │   └── utils.py
│   ├── configs/              # Lookup tables (TLDs, countries, keywords)
│   ├── data/                 # Training data (raw, interim, processed, splits)
│   ├── notebooks/            # EDA, preprocessing, modeling (Jupyter)
│   ├── scripts/              # Data quality, retraining, verification
│   ├── outputs/artifacts/    # Training output mirrors
│   ├── logs/                 # Training logs
│   └── skills/               # ML/DL architect agent persona
├── logs/                     # Project logs, benchmarks, visual screenshots
├── docker-compose.yml        # PostgreSQL + API
└── README.md
```

## Quick Start

### Prerequisites

- Python 3.10+
- PostgreSQL 16 (recommended) or SQLite (zero-config fallback)
- API keys for enrichment sources (optional — heuristic fallback works without keys)

### 1. Clone and install

```bash
git clone https://github.com/<your-org>/threat-lens-ai.git
cd threat-lens-ai/backend
python -m venv .venv
source .venv/bin/activate        # Linux/Mac
# .venv\Scripts\activate         # Windows
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — set DATABASE_URL and any API keys
```

**Database options:**

| Mode | `DATABASE_URL` |
|------|---------------|
| PostgreSQL (default) | `postgresql+psycopg2://postgres:postgres@localhost:5432/threatlensai` |
| SQLite (no setup) | `sqlite:///./threatlensai.db` |

### 3. Run

```bash
# Ensure models are in place (already included)
ls ../ml/models/*.joblib         # 10 .joblib files + version.json

# Start server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open [http://localhost:8000](http://localhost:8000)

### 4. Verify

```bash
curl http://localhost:8000/api/health
# {"status":"ok"}

curl http://localhost:8000/api/model/status
# All models: loaded=true

curl "http://localhost:8000/api/scan?q=185.220.101.42" | jq ".risk_band"
# "HIGH"
```

## API Reference

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan?q=<query>` | GET | Full scan — auto-detects IP, domain, CVE, or OTX pulse ID |
| `/api/scan` | POST | Scan with JSON body (`{"query": "...", "limit": 10}`) |
| `/api/model/status` | GET | Model health, F1 scores, training dates, versions |
| `/api/model/retrain?type=ip` | POST | Async retrain — returns `job_id` |
| `/api/model/retrain/status/{job_id}` | GET | Poll retrain progress |
| `/api/intel/{type}/{value}` | GET | Detail record with SHAP explanation |
| `/api/search?q=<term>` | GET | Full-text search across indexed sources |
| `/api/recent` | GET | Recent scans |
| `/api/tips` | GET | Dynamic threat tips from CISA KEV / NVD / OTX |
| `/api/feedback` | POST | Submit scan feedback |
| `/api/admin/lookups/sync` | POST | Sync lookup tables from external feeds |

## ML Models

| Model | Type | Dataset | Metric | Score |
|-------|------|---------|--------|-------|
| IP XGBoost | Classification | 200 IPs | Macro F1 | 1.000 |
| IP LogReg | Classification | 200 IPs | — | Baseline |
| Domain LGBM | Classification | 162 domains | Macro F1 | 0.920 |
| CVE TF-IDF + LogReg | Classification | 1,585 CVEs | F1 | 0.491 |
| OTX MiniLM + LogReg OvR | Multi-label | 2,352 pulses | Micro F1 | 0.356 |
| OTX Ensemble (TF-IDF + MiniLM) | Multi-label | 2,352 pulses | Micro F1 | 0.490 |

Models are stored in `ml/models/` and loaded at startup via `joblib`. The backend's `modeling_service.py` handles feature engineering, prediction, and SHAP explanation.

## Scoring

ThreatLensAI uses a **weighted multi-signal composite score** (0–10):

| Signal | Weight | Source |
|--------|--------|--------|
| ML model probability | 0.30 | Trained models |
| API consensus | 0.25 | Enrichment sources |
| Heuristic lexical | 0.15 | Domain/IP features |
| Temporal recency | 0.10 | Data freshness |
| Severity weight | 0.10 | Source severity |
| Source credibility | 0.10 | Per-source trust |

Risk bands: `CRITICAL` (8.5–10), `HIGH` (6.5–8.5), `MEDIUM` (4.0–6.5), `LOW` (1.5–4.0), `IGNORE` (0–1.5).

## Docker

```bash
cd threat-lens-ai
docker compose up --build -d     # PostgreSQL + API
docker compose logs -f api       # View logs
```

## Database Migration

```bash
# Preview
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite ./threatlensai.db \
  --postgres postgresql+psycopg2://user:pass@host/db \
  --dry-run

# Execute
python scripts/migrate_sqlite_to_postgres.py \
  --sqlite ./threatlensai.db \
  --postgres postgresql+psycopg2://user:pass@host/db
```

## Testing

```bash
cd threat-lens-ai/backend
python -m pytest tests/ -v
```

17 tests across 4 files: model versioning, heuristic fallback, retrain endpoints, feature parity.

## Tech Stack

- **Backend:** Python 3.10+, FastAPI, SQLAlchemy 2.0, Pydantic 2
- **Database:** PostgreSQL 16 (default), SQLite (fallback)
- **ML:** scikit-learn, XGBoost, LightGBM, sentence-transformers (MiniLM), SHAP
- **Enrichment:** httpx (async), 13 API integrations
- **Frontend:** Vanilla JS, Tailwind CSS (CDN), no framework
- **Containerization:** Docker, docker-compose

## License

MIT
