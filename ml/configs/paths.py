from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
INTERIM_DIR = DATA_DIR / "interim"
PROCESSED_DIR = DATA_DIR / "processed"
SPLITS_DIR = DATA_DIR / "splits"
OUTPUT_DIR = BASE_DIR / "outputs"
FIG_DIR = OUTPUT_DIR / "figures"
METRICS_DIR = OUTPUT_DIR / "metrics"
ARTIFACT_DIR = OUTPUT_DIR / "artifacts"

for p in [INTERIM_DIR, PROCESSED_DIR, SPLITS_DIR, FIG_DIR, METRICS_DIR, ARTIFACT_DIR]:
    p.mkdir(parents = True, exist_ok = True)