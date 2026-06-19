#!/usr/bin/env python3
"""Verify all Phase 1 data quality changes were applied to the notebook."""

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "02_preprocessing_and_feature_engineering.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

checks = {
    "MIN_ATTACK_FREQ=10": False,
    "unknown removal": False,
    "tactic mapping": False,
    "constant cols dropped": False,
    "rare ASNs merged": False,
    "CWE risk scoring": False,
    "requiredAction split": False,
    "lookups inside domains": False,
    "lookups inside ips": False,
    "stratified split": False,
}

for cell in nb["cells"]:
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "MIN_ATTACK_FREQ = 10" in src:
        checks["MIN_ATTACK_FREQ=10"] = True
    if "TECHNIQUE_TO_TACTIC" in src and "ta0002" in src:
        checks["tactic mapping"] = True
    if "Total_Reports" in src and "Times_Submitted" in src and "constant" in src.lower():
        checks["constant cols dropped"] = True
    if "rare_asns" in src:
        checks["rare ASNs merged"] = True
    if "CWE_RISK_SCORE" in src:
        checks["CWE risk scoring"] = True
    if "action_encoded" in src:
        checks["requiredAction split"] = True
    if "def preprocess_domains" in src and "get_suspicious_keywords" in src:
        checks["lookups inside domains"] = True
    if "def preprocess_ips" in src and "get_high_risk_countries" in src:
        checks["lookups inside ips"] = True
    if "StratifiedShuffleSplit" in src:
        checks["stratified split"] = True
    if "unknown" in src and "Attack_IDs" in src and "reset_index" in src:
        checks["unknown removal"] = True

all_pass = all(checks.values())
for k, v in checks.items():
    status = "OK" if v else "MISSING"
    print(f"  [{status}] {k}")

print()
if all_pass:
    print("All 10 Phase 1 checks passed!")
else:
    print("Some checks FAILED - need to investigate")
    exit(1)
