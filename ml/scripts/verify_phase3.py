#!/usr/bin/env python3
"""Verify all Phase 3 model retraining changes were applied."""

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "03_modeling_and_evaluation.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

checks = {
    "No DistilBERT/transformers imports": True,
    "Has all-MiniLM-L6-v2": False,
    "Has LabelPowerset": False,
    "CVE ensemble (lr_weight)": False,
    "CVE risk score target": False,
    "Domains binary (SUSPICIOUS)": False,
    "Domains SMOTE weight (scale_pos_weight)": False,
    "IP bootstrap CI": False,
    "IP per-threshold recall": False,
}

for cell in nb["cells"]:
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])

    if "AutoModelForSequenceClassification" in src or "DistilBERT" in src:
        checks["No DistilBERT/transformers imports"] = False
    if "all-MiniLM-L6-v2" in src:
        checks["Has all-MiniLM-L6-v2"] = True
    if "LabelPowerset" in src:
        checks["Has LabelPowerset"] = True
    if "lr_weight" in src or "xgb_weight" in src:
        checks["CVE ensemble (lr_weight)"] = True
    if "build_risk_score" in src or "continuous risk score" in src:
        checks["CVE risk score target"] = True
    if "SUSPICIOUS" in src and "CLEAN" in src and "to_binary" in src:
        checks["Domains binary (SUSPICIOUS)"] = True
    if "scale_pos_weight" in src:
        checks["Domains SMOTE weight (scale_pos_weight)"] = True
    if "bootstrap" in src and "f1_score" in src:
        checks["IP bootstrap CI"] = True
    if "per-threshold" in src or "HIGH recall @ threshold" in src:
        checks["IP per-threshold recall"] = True

all_pass = all(checks.values())
for k, v in checks.items():
    status = "OK" if v else "MISSING"
    print(f"  [{status}] {k}")

print()
if all_pass:
    print("All 9 Phase 3 checks passed!")
else:
    print("Some checks FAILED")
    exit(1)
