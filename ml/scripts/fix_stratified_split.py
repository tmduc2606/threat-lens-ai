#!/usr/bin/env python3
"""Fix the train/test split cell to use stratified splitting."""

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "02_preprocessing_and_feature_engineering.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

new_cell = (
    'datasets = {\n'
    '    "otx": otx_p,\n'
    '    "cve": cve_p,\n'
    '    "domains": domains_p,\n'
    '    "ips": ips_p\n'
    '}\n'
    '\n'
    '# Use stratified splits for better class balance on small datasets\n'
    'for name, df in datasets.items():\n'
    '    if name == "otx":\n'
    '        from sklearn.model_selection import train_test_split\n'
    '        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)\n'
    '    elif name == "cve":\n'
    '        from sklearn.model_selection import StratifiedShuffleSplit\n'
    '        y_strat = pd.qcut(df["days_to_due"].clip(lower=0), q=4, labels=False, duplicates="drop")\n'
    '        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)\n'
    '        train_idx, test_idx = next(sss.split(df, y_strat))\n'
    '        train_df = df.iloc[train_idx].reset_index(drop=True)\n'
    '        test_df = df.iloc[test_idx].reset_index(drop=True)\n'
    '    elif name == "domains":\n'
    '        from sklearn.model_selection import StratifiedShuffleSplit\n'
    '        y_strat = df["Threat_Severity"].astype(str).str.lower().map(lambda x: "medium" if x in ("high", "medium") else x)\n'
    '        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)\n'
    '        train_idx, test_idx = next(sss.split(df, y_strat))\n'
    '        train_df = df.iloc[train_idx].reset_index(drop=True)\n'
    '        test_df = df.iloc[test_idx].reset_index(drop=True)\n'
    '    elif name == "ips":\n'
    '        from sklearn.model_selection import StratifiedShuffleSplit\n'
    '        y_strat = df["Threat_Severity"].astype(str).str.lower()\n'
    '        sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)\n'
    '        train_idx, test_idx = next(sss.split(df, y_strat))\n'
    '        train_df = df.iloc[train_idx].reset_index(drop=True)\n'
    '        test_df = df.iloc[test_idx].reset_index(drop=True)\n'
    '    else:\n'
    '        from sklearn.model_selection import train_test_split\n'
    '        train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)\n'
    '\n'
    '    train_df.to_parquet(SPLITS_DIR / f"{name}_train.parquet", index=False)\n'
    '    test_df.to_parquet(SPLITS_DIR / f"{name}_test.parquet", index=False)\n'
)

for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "datasets" in src and "train_test_split" in src:
        cell["source"] = [new_cell]
        print(f"Replaced cell {i} with stratified split")
        break

with open(NOTEBOOK, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print("Done")
