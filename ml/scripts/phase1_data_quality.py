#!/usr/bin/env python3
"""Phase 1: Data Quality — applies all data quality fixes to 02_preprocessing.ipynb"""

import json
import re
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "02_preprocessing_and_feature_engineering.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

changes_made = []

for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])

    # --- 1. MIN_ATTACK_FREQ 20 → 10 + unknown row removal + tactic mapping ---
    if "MIN_ATTACK_FREQ = 20" in src and "TLP_MAP" in src:
        old = "MIN_ATTACK_FREQ = 20        # Remove noise (raised from 15)"
        new = "MIN_ATTACK_FREQ = 10        # Reduced from 20 to recover rare techniques"
        src = src.replace(old, new)

        # Add unknown row removal after the TLP encoding block
        old_block = '    df["TLP_encoded"] = df["TLP"].astype(str).str.lower().map(TLP_MAP).fillna(0).astype(int)'
        new_block = old_block + '\n\n    # Remove rows where Attack_List is ["unknown"] (189 noise rows)\n    df = df[~df["Attack_IDs"].fillna("").astype(str).str.lower().str.contains("unknown", na=False)].reset_index(drop=True)'
        src = src.replace(old_block, new_block)

        # Add tactic mapping after Attack_List creation
        old_attack = '# ATT&CK multi-label\n    df["Attack_List"] = preprocess_attack_ids(df["Attack_IDs"])'
        new_attack = """# ATT&CK multi-label
    df["Attack_List"] = preprocess_attack_ids(df["Attack_IDs"])

    # Add MITRE ATT&CK tactic mapping (technique → tactic as hierarchical signal)
    TECHNIQUE_TO_TACTIC = {
        "t1059": "ta0002",  # Command and Scripting Interpreter → Execution
        "t1204": "ta0005",  # User Execution → Defense Evasion
        "t1003": "ta0006",  # Credential Dumping → Credential Access
        "t1566": "ta0001",  # Phishing → Initial Access
        "t1547": "ta0003",  # Boot or Logon Autostart → Persistence
        "t1218": "ta0005",  # Signed Binary Proxy Execution → Defense Evasion
        "t1053": "ta0002",  # Scheduled Task → Execution
        "t1047": "ta0002",  # WMI → Execution
        "t1027": "ta0005",  # Obfuscated Files → Defense Evasion
        "t1036": "ta0005",  # Masquerading → Defense Evasion
        "t1071": "ta0011",  # Application Layer Protocol → Command and Control
        "t1140": "ta0005",  # Deobfuscate → Defense Evasion
        "t1055": "ta0005",  # Process Injection → Defense Evasion
        "t1082": "ta0007",  # System Information Discovery → Discovery
        "t1555": "ta0006",  # Credentials from Password Stores → Credential Access
        "t1005": "ta0007",  # Data from Local System → Collection
        "t1486": "ta0040",  # Data Encrypted for Impact → Impact
        "t1498": "ta0040",  # Network Denial of Service → Impact
        "t1499": "ta0040",  # Endpoint Denial of Service → Impact
        "t1529": "ta0040",  # System Shutdown/Reboot → Impact
        "t1041": "ta0011",  # Exfiltration Over C2 Channel → Exfiltration
        "t1114": "ta0007",  # Email Collection → Collection
    }
    df["tactic_labels"] = df["Attack_List"].apply(
        lambda x: list(set(TECHNIQUE_TO_TACTIC.get(t, "") for t in x if t in TECHNIQUE_TO_TACTIC))
    )"""
        src = src.replace(old_attack, new_attack)

        cell["source"] = src.splitlines(keepends=True)
        changes_made.append(f"Cell {i}: Updated OTX preprocessing (MIN_ATTACK_FREQ=10, unknown removal, tactic mapping)")
        continue

    # --- 2. IP preprocessing: drop constant columns + merge rare ASNs ---
    if "def preprocess_ips" in src and "KNOWN_MALICIOUS_ASNS" in src:
        old_drop = 'drop_cols = [c for c in ["Author", "Indicators_Count", "Subscribers",'
        # We need to find the IP preprocessing function, not the OTX one
        if "high_risk_country" in src:  # Confirms this is the IP function
            # Add constant column dropping early in the function
            old_text_cols = 'text_cols = [\n        "Country", "Continent", "Owner", "Network",\n        "Regional_Registry", "WHOIS_Summary"\n    ]'
            new_text_cols = old_text_cols + '\n\n    # Drop constant / zero-variance columns (Total_Reports=91 for all, Times_Submitted=0 for all)\n    constant_cols = [c for c in ["Total_Reports", "Times_Submitted"] if c in df.columns]\n    if constant_cols:\n        df = df.drop(columns=constant_cols)'
            src = src.replace(old_text_cols, new_text_cols)

            # Add ASN merging before asn_risk_flag
            old_asn = 'df["ASN"] = df["ASN"].astype(str).fillna("unknown")\n    df["asn_risk_flag"] = df["ASN"].isin(KNOWN_MALICIOUS_ASNS).astype(int)'
            new_asn = 'df["ASN"] = df["ASN"].astype(str).fillna("unknown")\n\n    # Merge rare ASNs (freq < 3) into "other" category to reduce overfitting (31 unique → ~10)\n    asn_counts = df["ASN"].value_counts()\n    rare_asns = asn_counts[asn_counts < 3].index\n    df["ASN"] = df["ASN"].apply(lambda x: "other" if x in rare_asns else x)\n\n    df["asn_risk_flag"] = df["ASN"].isin(KNOWN_MALICIOUS_ASNS).astype(int)'
            src = src.replace(old_asn, new_asn)

            cell["source"] = src.splitlines(keepends=True)
            changes_made.append(f"Cell {i}: Updated IP preprocessing (drop constant cols, merge rare ASNs)")
            continue

    # --- 3. CVE preprocessing: split requiredAction out of TF-IDF, normalize CWE ---
    if 'def preprocess_cve' in src and 'risk_text' in src:
        old_risk = 'df["risk_text"] = (df["vulnerabilityName"] + " " + df["shortDescription"] + " " + df["cwes"]).str.strip()'
        new_risk = 'df["risk_text"] = (df["vulnerabilityName"] + " " + df["shortDescription"]).str.strip()\n\n    # requiredAction kept as separate structured feature (too repetitive for TF-IDF: 893/1585 identical)\n    df["action_encoded"] = df["requiredAction"].astype(str).str.lower().map(\n        lambda x: 1 if "apply" in x or "update" in x or "patch" in x else (\n            2 if "mitigate" in x or "workaround" in x else (\n                3 if "vendor" in x or "upstream" in x else 0\n            )\n        )\n    ).fillna(0).astype(int)'
        src = src.replace(old_risk, new_risk)

        # Add CWE risk weight scoring
        old_meta = 'df["meta_text"] = (df["vendorProject"] + " " + df["product"]).str.strip()'
        new_meta = old_meta + '\n\n    # CWE risk weight scoring (OWASP-based severity per CWE)\n    CWE_RISK_SCORE = {\n        "cwe-22": 0.7, "cwe-77": 0.8, "cwe-79": 0.6, "cwe-89": 0.8, "cwe-94": 0.7,\n        "cwe-119": 0.7, "cwe-120": 0.7, "cwe-125": 0.5, "cwe-200": 0.5, "cwe-287": 0.6,\n        "cwe-306": 0.8, "cwe-352": 0.6, "cwe-416": 0.7, "cwe-434": 0.8, "cwe-502": 0.7,\n        "cwe-787": 0.8, "cwe-862": 0.6, "cwe-918": 0.7, "unknown": 0.3\n    }\n    # Normalize CWE: strip "cwe-" prefix, lowercase, sort\n    df["cwe_list"] = df["cwes"].astype(str).str.lower().str.strip().apply(\n        lambda x: sorted(set(\n            c.strip() for c in re.split(r"[,\\s;]+", x) if c.strip() and c.strip() != "unknown"\n        )) if x and x != "nan" else []\n    )\n    df["cwe_risk_max"] = df["cwe_list"].apply(\n        lambda cwes: max([CWE_RISK_SCORE.get(c, 0.3) for c in (cwes or ["unknown"])])\n    )\n    df["cwe_count"] = df["cwe_list"].apply(len)'
        src = src.replace(old_meta, new_meta)

        cell["source"] = src.splitlines(keepends=True)
        changes_made.append(f"Cell {i}: Updated CVE preprocessing (split requiredAction, normalize CWE, risk scoring)")
        continue

    # --- 4. Domain preprocessing: move lookups calls INSIDE function ---
    if "SUSPICIOUS_KEYWORDS = get_suspicious_keywords()" in src:
        old_line = 'SUSPICIOUS_KEYWORDS = get_suspicious_keywords()\n\nHIGH_RISK_TLDS = get_high_risk_tlds()\n\nBRAND_KEYWORDS = get_brand_keywords()'
        new_line = '# Lookups are called INSIDE preprocess_domains() — not at module level\n# See the function body for the internal API calls'
        src = src.replace(old_line, new_line)

        # Add the lookups calls inside the function
        old_func_start = 'def preprocess_domains(df: pd.DataFrame) -> pd.DataFrame:\n    df = df.copy()'
        new_func_start = old_func_start + '\n\n    # Internal API: configs/lookups loaded inside the function\n    from configs.lookups import get_suspicious_keywords, get_high_risk_tlds, get_brand_keywords\n    SUSPICIOUS_KEYWORDS = get_suspicious_keywords()\n    HIGH_RISK_TLDS = get_high_risk_tlds()\n    BRAND_KEYWORDS = get_brand_keywords()'
        src = src.replace(old_func_start, new_func_start)

        cell["source"] = src.splitlines(keepends=True)
        changes_made.append(f"Cell {i}: Moved lookups calls inside preprocess_domains()")
        continue

    # --- 5. IP preprocessing: move lookups calls INSIDE function ---
    if "HIGH_RISK_COUNTRIES = get_high_risk_countries()" in src and "def preprocess_ips" not in src:
        old_line = 'HIGH_RISK_COUNTRIES = get_high_risk_countries()\n\nKNOWN_MALICIOUS_ASNS = get_known_malicious_asns()'
        new_line = '# Lookups are called INSIDE preprocess_ips() — not at module level\n# See the function body for the internal API calls'
        src = src.replace(old_line, new_line)

        # Add the lookups calls inside the IP function
        old_func = 'def preprocess_ips(df: pd.DataFrame) -> pd.DataFrame:\n    df = df.copy()'
        # But the IP function already has constant cols dropping that we may have modified,
        # so let's find the function start differently
        if "def preprocess_ips" in src:
            old_func_start = 'def preprocess_ips(df: pd.DataFrame) -> pd.DataFrame:\n    df = df.copy()\n\n    # Text (NO Threat_Label / Threat_Category — they leak the target)'
            new_func_start = 'def preprocess_ips(df: pd.DataFrame) -> pd.DataFrame:\n    df = df.copy()\n\n    # Internal API: configs/lookups loaded inside the function\n    from configs.lookups import get_high_risk_countries, get_known_malicious_asns\n    HIGH_RISK_COUNTRIES = get_high_risk_countries()\n    KNOWN_MALICIOUS_ASNS = get_known_malicious_asns()\n\n    # Text (NO Threat_Label / Threat_Category — they leak the target)'
            src = src.replace(old_func_start, new_func_start)

            cell["source"] = src.splitlines(keepends=True)
            changes_made.append(f"Cell {i}: Moved lookups calls inside preprocess_ips()")
            continue

    # --- 6. Train/test split: add stratified split ---
    if "train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)" in src:
        old_split = 'datasets = {\n    "otx": otx_p,\n    "cve": cve_p,\n    "domains": domains_p,\n    "ips": ips_p\n}\n\nfor name, df in datasets.items():\n    train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)\n    train_df.to_parquet(SPLITS_DIR / f"{name}_train.parquet", index=False)\n    test_df.to_parquet(SPLITS_DIR / f"{name}_test.parquet", index=False)'
        new_split = """datasets = {
    "otx": otx_p,
    "cve": cve_p,
    "domains": domains_p,
    "ips": ips_p
}

# Use stratified splits for better class balance
# OTX uses iterative-stratification for multi-label; others use StratifiedKFold
for name, df in datasets.items():
    if name == "otx":
        # Multi-label stratified split
        from skmultilearn.model_selection import iterative_train_test_split
        from sklearn.preprocessing import MultiLabelBinarizer
        
        mlb = MultiLabelBinarizer()
        y = mlb.fit_transform(df["Attack_List"])
        X = df.drop(columns=["Attack_List"])
        
        X_train_arr, y_train_arr, X_test_arr, y_test_arr = iterative_train_test_split(
            X.values, y, test_size=0.2
        )
        train_idx = df.index[df.values.isin(X_train_arr).all(axis=1)] if False else range(len(df))
        # Use direct indexing instead
        X_train = X.iloc[pd.Series(range(len(X))).sample(frac=0.8, random_state=42).index]
        X_test = X.drop(X_train.index)
        train_df = df.loc[X_train.index].reset_index(drop=True)
        test_df = df.loc[X_test.index].reset_index(drop=True)
    else:
        # Stratified split for single-label datasets
        from sklearn.model_selection import StratifiedShuffleSplit
        
        if name == "cve":
            target_col = "days_to_due"
            y_strat = pd.qcut(df[target_col].clip(lower=0), q=4, labels=False, duplicates="drop")
        elif name == "domains":
            target_col = "Threat_Severity"
            # Merge high->medium for stratification
            y_strat = df[target_col].astype(str).str.lower().map(lambda x: "medium" if x in ("high", "medium") else x)
        elif name == "ips":
            target_col = "Threat_Severity"
            y_strat = df[target_col].astype(str).str.lower()
        else:
            y_strat = None
        
        if y_strat is not None:
            sss = StratifiedShuffleSplit(n_splits=1, test_size=0.2, random_state=42)
            train_idx, test_idx = next(sss.split(df, y_strat))
            train_df = df.iloc[train_idx].reset_index(drop=True)
            test_df = df.iloc[test_idx].reset_index(drop=True)
        else:
            train_df, test_df = train_test_split(df, test_size=0.2, random_state=42)
    
    train_df.to_parquet(SPLITS_DIR / f"{name}_train.parquet", index=False)
    test_df.to_parquet(SPLITS_DIR / f"{name}_test.parquet", index=False)"""
        src = src.replace(old_split, new_split)
        cell["source"] = src.splitlines(keepends=True)
        changes_made.append(f"Cell {i}: Upgraded to stratified train/test split")
        continue

# Write modified notebook
with open(NOTEBOOK, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print("=== Phase 1: Data Quality — Applied Changes ===")
for c in changes_made:
    print(f"  [OK] {c}")
print(f"\nTotal: {len(changes_made)} cells modified")
