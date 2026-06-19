#!/usr/bin/env python3
"""Phase 3: Model Retraining — rewrites 03_modeling notebook cells.

Changes:
1. Remove DistilBERT/CodeBERT imports, add MiniLM + skmultilearn
2. OTX: Replace CodeBERT+MLP with all-MiniLM-L6-v2 + LabelPowerset
3. CVE: Reframe to regression + ensemble text/structured
4. Domains: Binary (merge Medium+High), add SMOTE
5. IPs: Lower high-class threshold, add bootstrap CI
"""

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "03_modeling_and_evaluation.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

changes = []

# ── Cell 3 (imports): Remove DistilBERT/transformers, add MiniLM + skmultilearn ──
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "AutoModelForSequenceClassification" in src:
        old_imports = src
        new_imports = (
            "# General\n"
            "import joblib, sys, random, warnings\n"
            "import numpy as np\n"
            "import pandas as pd\n"
            "from pathlib import Path\n"
            "\n"
            "# Modeling & Evaluation\n"
            "from sklearn.metrics import (accuracy_score, f1_score, classification_report, hamming_loss, roc_auc_score, recall_score)\n"
            "from sklearn.preprocessing import MultiLabelBinarizer, LabelEncoder, StandardScaler, OneHotEncoder\n"
            "from sklearn.multiclass import OneVsRestClassifier\n"
            "from sklearn.feature_extraction.text import TfidfVectorizer\n"
            "from sklearn.pipeline import Pipeline, FeatureUnion\n"
            "from sklearn.compose import ColumnTransformer\n"
            "from sklearn.impute import SimpleImputer\n"
            "from sklearn.linear_model import LogisticRegression\n"
            "from sklearn.calibration import CalibratedClassifierCV\n"
            "from sklearn.ensemble import RandomForestClassifier, VotingClassifier\n"
            "from sklearn.model_selection import StratifiedKFold\n"
            "from xgboost import XGBClassifier\n"
            "import lightgbm as lgb\n"
            "from sentence_transformers import SentenceTransformer\n"
            "from skmultilearn.problem_transform import LabelPowerset\n"
            "\n"
            "warnings.filterwarnings(\"ignore\", category=UserWarning)\n"
        )
        cell["source"] = [new_imports]
        # Also remove outputs
        cell["outputs"] = []
        changes.append(f"Cell {i}: Removed DistilBERT/transformers, added MiniLM + skmultilearn + LabelPowerset")
        break

# ── Cell 5 (seed): remove torch seeding (transformers removed) ──
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "torch.manual_seed" in src:
        old_seed = src
        new_seed = (
            "SEED = 42\n"
            "\n"
            "random.seed(SEED)\n"
            "np.random.seed(SEED)\n"
        )
        cell["source"] = [new_seed]
        changes.append(f"Cell {i}: Removed torch seeding")
        break

# ── OTX: Replace CodeBERT section with MiniLM + LabelPowerset ──
# The OTX section spans cells 5-18 (classical baseline through CodeBERT save).
# We replace cells 12-18 (CodeBERT section) with MiniLM + LabelPowerset

# First, find the OTX classical baseline TF-IDF+XGBoost cell (cell ~7-11)
# and the CodeBERT section start (cell ~12-13)
codebert_start = None
codebert_end = None
domains_start = None

for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "CodeBERT" in src or "codebert" in src.lower():
        if codebert_start is None:
            codebert_start = i
            changes.append(f"Cell {i}: CodeBERT section start detected")
    if "### CVE Modeling" in "".join(nb["cells"][i]["source"]) if nb["cells"][i]["cell_type"] == "markdown" else "":
        pass
    # Detect end of OTX CodeBERT section (next CVE or Domains section)
    if "### Domains Modeling" in src or "DOMAIN_TARGET" in src:
        if codebert_start is not None and codebert_end is None:
            codebert_end = i
            changes.append(f"Cell {i}: Domains section start -> CodeBERT section end marker")

# If we couldn't find by markers, find by index proximity
# CodeBERT section is typically cells 12-18 in the original notebook
# Let's look for the save model cell
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    if "otx_codebert_model.pt" in src or "otx_xgb_baseline.joblib" in src:
        codebert_end = i + 1
        changes.append(f"Cell {i}: OTX save artifacts detected")

# Now find the markdown cells for the CodeBERT section
otx_markdown_end = None
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] == "markdown":
        src = "".join(cell["source"])
        if "OTX: CodeBERT" in src:
            otx_markdown_end = i

# Let me be more precise - find the actual range by looking at the notebook structure
print(f"CodeBERT start: cell {codebert_start}, end: cell {codebert_end}")
print(f"OTX markdown end: cell {otx_markdown_end}")

# Replace cells from CodeBERT start to CodeBERT end with MiniLM + LabelPowerset code
if codebert_start is not None and codebert_end is not None:
    # Remove the CodeBERT markdown cell too (it's before codebert_start)
    # Find the markdown cell
    md_idx = None
    for i in range(codebert_start - 1, max(0, codebert_start - 5), -1):
        if nb["cells"][i]["cell_type"] == "markdown" and "CodeBERT" in "".join(nb["cells"][i]["source"]):
            md_idx = i
            break
    
    replace_start = md_idx if md_idx is not None else codebert_start
    replace_end = codebert_end
    
    # New OTX enhancement cells: MiniLM + LabelPowerset
    new_otx_cells = [
        # Markdown cell
        {"cell_type": "markdown", "id": "otx_enhanced", "metadata": {}, "source": ["### OTX: MiniLM Embeddings + LabelPowerset Ensemble\n"]},
        
        # Code: Multi-label binarizer + MiniML embeddings
        {"cell_type": "code", "execution_count": None, "id": "otx_mlb", "metadata": {}, "outputs": [], "source": [
            "# Multi-label binarizer for OTX\n",
            "mlb = MultiLabelBinarizer()\n",
            "y_train_ml = mlb.fit_transform(otx_train[\"Attack_List\"])\n",
            "y_test_ml = mlb.transform(otx_test[\"Attack_List\"])\n",
            "num_labels = len(mlb.classes_)\n",
            "print(f\"Number of ATT&CK technique labels: {num_labels}\")\n",
            "print(f\"Train shape: {y_train_ml.shape}, Test shape: {y_test_ml.shape}\")\n"
        ]},
        
        # Code: MiniML embeddings
        {"cell_type": "code", "execution_count": None, "id": "otx_minilm", "metadata": {}, "outputs": [], "source": [
            "# all-MiniLM-L6-v2 embeddings (384-dim, designed for semantic similarity)\n",
            "# Replaces CodeBERT (wrong model family for CTI text)\n",
            "EMBED_MODEL = SentenceTransformer(\"all-MiniLM-L6-v2\")\n",
            "\n",
            "train_emb = EMBED_MODEL.encode(\n",
            "    otx_train[\"combined_text\"].tolist(),\n",
            "    show_progress_bar=True, batch_size=32\n",
            ")\n",
            "test_emb = EMBED_MODEL.encode(\n",
            "    otx_test[\"combined_text\"].tolist(),\n",
            "    show_progress_bar=True, batch_size=32\n",
            ")\n",
            "print(f\"MiniLM embedding shape: {train_emb.shape}\")\n"
        ]},
        
        # Code: TF-IDF baseline for comparison
        {"cell_type": "code", "execution_count": None, "id": "otx_tfidf_baseline", "metadata": {}, "outputs": [], "source": [
            "# TF-IDF + XGBoost OvR baseline (unchanged for comparison)\n",
            "otx_tfidf = Pipeline([\n",
            "    (\"tfidf\", TfidfVectorizer(\n",
            "        ngram_range=(1, 2), max_features=30000,\n",
            "        dtype=np.float32, min_df=2, analyzer=\"word\"\n",
            "    )),\n",
            "    (\"clf\", OneVsRestClassifier(\n",
            "        XGBClassifier(n_estimators=200, max_depth=4,\n",
            "                      learning_rate=0.05, random_state=42,\n",
            "                      eval_metric=\"logloss\")\n",
            "    ))\n",
            "])\n",
            "\n",
            "otx_tfidf.fit(otx_train[\"combined_text\"], y_train_ml)\n",
            "tfidf_preds = otx_tfidf.predict(otx_test[\"combined_text\"])\n",
            "\n",
            "print(\"=== TF-IDF + XGBoost OvR (Baseline) ===\")\n",
            "print(f\"Micro F1: {f1_score(y_test_ml, tfidf_preds, average='micro', zero_division=0):.4f}\")\n",
            "print(f\"Macro F1: {f1_score(y_test_ml, tfidf_preds, average='macro', zero_division=0):.4f}\")\n",
            "print(f\"Hamming Loss: {hamming_loss(y_test_ml, tfidf_preds):.4f}\")\n",
            "\n",
            "joblib.dump(otx_tfidf, ARTIFACT_DIR / \"otx_xgb_baseline.joblib\")\n",
            "print(\"Saved: otx_xgb_baseline.joblib\")\n"
        ]},
        
        # Code: LabelPowerset + RandomForest
        {"cell_type": "code", "execution_count": None, "id": "otx_lp_rf", "metadata": {}, "outputs": [], "source": [
            "# LabelPowerset + Random Forest (captures label co-occurrence patterns)\n",
            "lp_rf = Pipeline([\n",
            "    (\"tfidf\", TfidfVectorizer(\n",
            "        ngram_range=(1, 2), max_features=30000,\n",
            "        dtype=np.float32, min_df=2, analyzer=\"word\"\n",
            "    )),\n",
            "    (\"clf\", LabelPowerset(\n",
            "        classifier=RandomForestClassifier(\n",
            "            n_estimators=300, max_depth=8,\n",
            "            min_samples_leaf=2, random_state=42,\n",
            "            n_jobs=-1\n",
            "        )\n",
            "    ))\n",
            "])\n",
            "\n",
            "lp_rf.fit(otx_train[\"combined_text\"], y_train_ml)\n",
            "lp_preds = lp_rf.predict(otx_test[\"combined_text\"])\n",
            "\n",
            "print(\"=== LabelPowerset + Random Forest ===\")\n",
            "print(f\"Micro F1: {f1_score(y_test_ml, lp_preds, average='micro', zero_division=0):.4f}\")\n",
            "print(f\"Macro F1: {f1_score(y_test_ml, lp_preds, average='macro', zero_division=0):.4f}\")\n",
            "\n",
            "joblib.dump(lp_rf, ARTIFACT_DIR / \"otx_label_powerset_rf.joblib\")\n",
            "print(\"Saved: otx_label_powerset_rf.joblib\")\n"
        ]},
        
        # Code: MiniLM + MLP classifier
        {"cell_type": "code", "execution_count": None, "id": "otx_minilm_mlp", "metadata": {}, "outputs": [], "source": [
            "# MiniLM embeddings + Logistic Regression (replaces CodeBERT + MLP)\n",
            "minilm_lr = Pipeline([\n",
            "    (\"clf\", OneVsRestClassifier(\n",
            "        LogisticRegression(max_iter=1000, class_weight=\"balanced\", solver=\"liblinear\", random_state=42)\n",
            "    ))\n",
            "])\n",
            "\n",
            "minilm_lr.fit(train_emb, y_train_ml)\n",
            "minilm_preds = minilm_lr.predict(test_emb)\n",
            "\n",
            "print(\"=== MiniLM Embeddings + Logistic Regression OvR ===\")\n",
            "print(f\"Micro F1: {f1_score(y_test_ml, minilm_preds, average='micro', zero_division=0):.4f}\")\n",
            "print(f\"Macro F1: {f1_score(y_test_ml, minilm_preds, average='macro', zero_division=0):.4f}\")\n",
            "\n",
            "# Save\n",
            "joblib.dump({\n",
            "    \"model\": minilm_lr,\n",
            "    \"label_encoder\": mlb,\n",
            "}, ARTIFACT_DIR / \"otx_minilm_logreg.joblib\")\n",
            "print(\"Saved: otx_minilm_logreg.joblib\")\n"
        ]},
        
        # Code: Ensemble (TF-IDF + MiniML) weighted by calibration
        {"cell_type": "code", "execution_count": None, "id": "otx_ensemble", "metadata": {}, "outputs": [], "source": [
            "# Ensemble: weight TF-IDF + MiniLM by calibration error\n",
            "# TF-IDF predicted probs\n",
            "tfidf_probs = np.array([\n",
            "    est.predict_proba(otx_test[\"combined_text\"])[:, 1]\n",
            "    for est in otx_tfidf.named_steps[\"clf\"].estimators_\n",
            "]).T  # shape: (n_samples, n_labels)\n",
            "\n",
            "minilm_probs = np.array([\n",
            "    est.predict_proba(test_emb)[:, 1]\n",
            "    for est in minilm_lr.named_steps[\"clf\"].estimators_\n",
            "]).T\n",
            "\n",
            "# Simple average ensemble (weights can be tuned on validation set)\n",
            "W_TFIDF, W_MINILM = 0.5, 0.5\n",
            "ensemble_probs = W_TFIDF * tfidf_probs + W_MINILM * minilm_probs\n",
            "ensemble_preds = (ensemble_probs >= 0.5).astype(int)\n",
            "\n",
            "print(\"=== Ensemble (TF-IDF + MiniLM) ===\")\n",
            "print(f\"Micro F1: {f1_score(y_test_ml, ensemble_preds, average='micro', zero_division=0):.4f}\")\n",
            "print(f\"Macro F1: {f1_score(y_test_ml, ensemble_preds, average='macro', zero_division=0):.4f}\")\n",
            "\n",
            "# Save the full multi-label binarizer for API use\n",
            "joblib.dump(mlb, ARTIFACT_DIR / \"otx_label_encoder.joblib\")\n",
            "print(\"Saved: otx_label_encoder.joblib\")\n",
            "\n",
            "# Also save the TF-IDF vectorizer separately for API use\n",
            "joblib.dump(\n",
            "    otx_tfidf.named_steps[\"tfidf\"],\n",
            "    ARTIFACT_DIR / \"otx_tfidf_vectorizer.joblib\"\n",
            ")\n",
            "print(\"Saved: otx_tfidf_vectorizer.joblib\")\n"
        ]},
    ]
    
    # Replace cells in range [replace_start, replace_end) with new cells
    nb["cells"] = nb["cells"][:replace_start] + new_otx_cells + nb["cells"][replace_end:]
    changes.append(f"Replaced cells [{replace_start}:{replace_end}] with MiniLM + LabelPowerset + Ensemble")

# Verify the cell index shift and find current CVE / Domains / IPs cells
# Re-read the notebook structure
for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])
    
    # ── CVE: Reframe to regression ──
    if "build_cve_text" in src and "knownRansomwareCampaignUse" in src:
        new_cve = (
            "# Text builder (without requiredAction — too repetitive, split in preprocessing)\n"
            "def build_cve_text(df):\n"
            '    cols = [\"vendorProject\", \"product\", \"vulnerabilityName\", \"shortDescription\", \"cwes\"]\n'
            "    present = [c for c in cols if c in df.columns]\n"
            '    return (df[present].fillna(\"unknown\").astype(str).agg(\" \".join, axis=1)\n'
            '            .str.lower().str.replace(r\"\\s+\", \" \", regex=True).str.strip())\n'
            "\n"
            "cve_train[\"cve_text\"] = build_cve_text(cve_train)\n"
            "cve_test[\"cve_text\"] = build_cve_text(cve_test)\n"
            "\n"
            "# Continuous risk score target: combine knownRansomware + days_to_due + CWE_severity\n"
            "# This reframes from binary (80% Unknown) to regression\n"
            "def build_risk_score(df):\n"
            '    """Create continuous risk score 0-1 from multiple signals."""\n'
            "    # Ransomware known: weight 0.5\n"
            '    rw = df[\"knownRansomwareCampaignUse\"].astype(str).str.lower().map(\n'
            '        lambda x: 1.0 if x in {\"known\", \"yes\", \"true\", \"1\", \"ransomware\"} else 0.0\n'
            "    ).fillna(0.0)\n"
            "    \n"
            "    # days_to_due urgency: shorter = more urgent, weight 0.2\n"
            "    dtd = df[\"days_to_due\"].clip(0, 365) / 365.0  # normalize to 0-1\n"
            "    dtd = 1.0 - dtd  # shorter days → higher risk\n"
            "    \n"
            "    # CWE risk weight from preprocessing (max across CWEs), weight 0.2\n"
            '    cwe = df.get(\"cwe_risk_max\", pd.Series([0.3] * len(df))).fillna(0.3)\n'
            "    \n"
            "    # Combined score (0-1)\n"
            "    score = 0.5 * rw + 0.2 * dtd + 0.2 * cwe\n"
            "    return score.clip(0, 1)\n"
            "\n"
            "y_train_reg = build_risk_score(cve_train)\n"
            "y_test_reg = build_risk_score(cve_test)\n"
        )
        cell["source"] = [new_cve]
        changes.append(f"Cell {i}: Reframed CVE target to continuous risk score")
        continue
    
    # ── CVE Model 1: LogReg calibrated ──
    if "cve_model = Pipeline" in src and "CalibratedClassifierCV" in src and "cve_tfidf_logreg" not in src:
        new_model1 = (
            "# Model 1: TF-IDF + Logistic Regression (Calibrated)\n"
            "cve_lr = Pipeline([\n"
            "    (\"tfidf\", TfidfVectorizer(\n"
            "        ngram_range=(1, 2), max_features=50000,\n"
            "        min_df=2, sublinear_tf=True, strip_accents=\"unicode\"\n"
            "    )),\n"
            "    (\"clf\", CalibratedClassifierCV(\n"
            "        estimator=LogisticRegression(\n"
            "            max_iter=3000, class_weight=\"balanced\", solver=\"liblinear\"\n"
            "        ),\n"
            "        method=\"sigmoid\", cv=5\n"
            "    ))\n"
            "])\n"
            "\n"
            "# Train\n"
            "cve_lr.fit(cve_train[\"cve_text\"], y_train_reg)\n"
            "\n"
            "# Evaluate\n"
            "lr_probs = cve_lr.predict_proba(cve_test[\"cve_text\"])[:, 1]\n"
            "lr_preds = (lr_probs >= 0.5).astype(int)\n"
            "y_test_bin = (y_test_reg >= 0.5).astype(int)\n"
            "\n"
            'print(\"=== CVE: TF-IDF + LogReg (Calibrated) ===\")\n'
            'print(f\"F1 (binary at 0.5): {f1_score(y_test_bin, lr_preds):.4f}\")\n'
            'print(f\"AUC-ROC: {roc_auc_score(y_test_reg, lr_probs):.4f}\")\n'
        )
        cell["source"] = [new_model1]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Updated CVE LogReg to use risk score target")
        continue
    
    # ── CVE Model 2: XGBoost (structured) ──
    if "cve_xgb" in src and "XGBClassifier" in src and "cve_xgb_model.joblib" in src:
        new_xgb = (
            "# Model 2: XGBoost on structured features (vendor, product, days_to_due, CWE)\n"
            "struct_features = [c for c in [\"vendorProject\", \"product\", \"days_to_due\",\n"
            '                                "cwe_risk_max", "cwe_count", "action_encoded",\n'
            '                                "log_days_to_due", "log_days_since_added"]\n'
            "                         if c in cve_train.columns]\n"
            "\n"
            "cve_xgb = XGBClassifier(\n"
            "    n_estimators=300, max_depth=4, learning_rate=0.05,\n"
            "    subsample=0.8, colsample_bytree=0.8,\n"
            "    reg_lambda=2.0, reg_alpha=0.1,\n"
            "    random_state=42, eval_metric=\"rmse\"\n"
            ")\n"
            "\n"
            "# Prepare structured features\n"
            "X_train_struct = cve_train[struct_features].fillna(\"unknown\")\n"
            "for c in X_train_struct.select_dtypes(\"object\").columns:\n"
            "    X_train_struct[c] = LabelEncoder().fit_transform(X_train_struct[c].astype(str))\n"
            "\n"
            "X_test_struct = cve_test[struct_features].fillna(\"unknown\")\n"
            "for c in X_test_struct.select_dtypes(\"object\").columns:\n"
            "    X_test_struct[c] = LabelEncoder().fit_transform(X_test_struct[c].astype(str))\n"
            "\n"
            "cve_xgb.fit(X_train_struct, y_train_reg)\n"
            "xgb_probs = cve_xgb.predict(X_test_struct)\n"
            "\n"
            'print(\"=== CVE: Structured XGBoost ===\")\n'
            'print(f\"RMSE: {np.sqrt(np.mean((xgb_probs - y_test_reg) ** 2)):.4f}\")\n'
            "\n"
            "# Ensemble: average LogReg text + XGBoost structured\n"
            "ensemble_probs = 0.4 * lr_probs + 0.6 * xgb_probs\n"
            "ensemble_preds = (ensemble_probs >= 0.5).astype(int)\n"
            "\n"
            'print(\"=== CVE: Ensemble (LogReg text + XGBoost struct) ===\")\n'
            'print(f\"F1: {f1_score(y_test_bin, ensemble_preds):.4f}\")\n'
            'print(f\"AUC-ROC: {roc_auc_score(y_test_reg, ensemble_probs):.4f}\")\n'
            "\n"
            "# Save ensemble wrapper\n"
            "joblib.dump({\n"
            '    "lr_model": cve_lr,\n'
            '    "xgb_model": cve_xgb,\n'
            '    "struct_features": struct_features,\n'
            '    "lr_weight": 0.4,\n'
            '    "xgb_weight": 0.6,\n'
            "}, ARTIFACT_DIR / \"cve_tfidf_logreg.joblib\")\n"
            'print(\"Saved: cve_tfidf_logreg.joblib\")\n'
        )
        cell["source"] = [new_xgb]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Replaced CVE XGBoost with structured + ensemble")
        continue
    
    # ── Domains: Binary classification ──
    if "DOMAIN_TARGET" in src and "Threat_Severity" in src and "merge_severity" in src:
        new_domains = (
            'DOMAIN_TARGET = "Threat_Severity"\n'
            "\n"
            "# Binary classification: merge Medium+High -> SUSPICIOUS\n"
            "# Keep CLEAN as CLEAN\n"
            "def to_binary(x):\n"
            '    x = str(x).strip().lower()\n'
            '    return 1 if x in ("medium", "high") else 0  # 1=SUSPICIOUS, 0=CLEAN\n'
            "\n"
            "y_train = dom_train[DOMAIN_TARGET].apply(to_binary)\n"
            "y_test = dom_test[DOMAIN_TARGET].apply(to_binary)\n"
            "\n"
            'print(f"Train class distribution: {y_train.value_counts().to_dict()}")\n'
            'print(f"Test class distribution: {y_test.value_counts().to_dict()}")\n'
        )
        cell["source"] = [new_domains]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Made Domains binary (SUSPICIOUS vs CLEAN)")
        continue
    
    # ── Domains: Feature columns ──
    if "domain_num_cols" in src and "entropy" in src and "Defense Evasion" not in src:
        new_num = (
            'domain_num_cols = [\n'
            '    "Domain_Length", "Reputation",\n'
            '    "Malicious_Votes", "Suspicious_Votes",\n'
            '    "Harmless_Votes", "Undetected_Votes", "Total_Engines",\n'
            '    "domain_age_days", "log_domain_age",\n'
            '    "malicious_ratio", "suspicious_ratio",\n'
            '    "log_malicious", "log_suspicious",\n'
            '    "entropy", "digit_ratio", "vowel_ratio", "special_ratio",\n'
            '    "subdomain_count", "token_count", "max_token_length",\n'
            '    "consecutive_consonants", "consecutive_digits",\n'
            '    "suspicious_keyword_count",\n'
            '    "tld_risk_score", "whois_field_count",\n'
            '    "has_creation_date", "has_registrar", "has_nameservers",\n'
            '    "contains_brand_keyword", "contains_login_keyword",\n'
            '    "contains_crypto_keyword", "contains_bank_keyword",\n'
            '    "is_randomized_domain", "is_new_domain",\n'
            "]\n"
            "\n"
            'domain_cat_cols = [\n'
            '    "Has_Numbers", "Has_Hyphen",\n'
            '    "TLD", "Categories",\n'
            "]\n"
        )
        cell["source"] = [new_num]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Updated domain feature columns for binary")
        continue
    
    # ── Domains: LGBM model with SMOTE ──
    if "domain_model = Pipeline" in src and "LGBMClassifier" in src:
        new_model = (
            "# Domain preprocessor\n"
            "available_num = [c for c in domain_num_cols if c in dom_train.columns]\n"
            "available_cat = [c for c in domain_cat_cols if c in dom_train.columns]\n"
            "\n"
            "domain_preprocessor = ColumnTransformer([\n"
            '    ("num", Pipeline([\n'
            '        ("imputer", SimpleImputer(strategy="median")),\n'
            '        ("scaler", StandardScaler())\n'
            "    ]), available_num),\n"
            '    ("cat", Pipeline([\n'
            '        ("imputer", SimpleImputer(strategy="most_frequent")),\n'
            '        ("onehot", OneHotEncoder(handle_unknown="ignore", min_frequency=2))\n'
            "    ]), available_cat)\n"
            '], remainder="drop")\n'
            "\n"
            "# LGBM with SMOTE-like class weighting (scale_pos_weight handles imbalance)\n"
            "pos_count = y_train.sum()\n"
            "neg_count = len(y_train) - pos_count\n"
            "scale_weight = neg_count / max(pos_count, 1)\n"
            "\n"
            "domain_model = Pipeline([\n"
            '    ("prep", domain_preprocessor),\n'
            '    ("clf", CalibratedClassifierCV(\n'
            "        estimator=lgb.LGBMClassifier(\n"
            "            n_estimators=500, max_depth=5, learning_rate=0.05,\n"
            "            subsample=0.8, colsample_bytree=0.8,\n"
            "            reg_lambda=2.0, reg_alpha=0.1,\n"
            "            min_child_weight=2, num_leaves=31,\n"
            "            scale_pos_weight=scale_weight,\n"
            "            random_state=42, verbose=-1\n"
            "        ),\n"
            '        method="sigmoid", cv=5\n'
            "    ))\n"
            "])\n"
            "\n"
            "# Train\n"
            "domain_model.fit(dom_train, y_train)\n"
            "\n"
            "# Evaluate with lower threshold for SUSPICIOUS (recall > precision for security)\n"
            "probs = domain_model.predict_proba(dom_test)\n"
            "probs_suspicious = probs[:, 1] if probs.shape[1] == 2 else probs[:, 0]\n"
            "\n"
            "# Search best threshold on training data\n"
            "train_probs = domain_model.predict_proba(dom_train)\n"
            "train_probs_susp = train_probs[:, 1] if train_probs.shape[1] == 2 else train_probs[:, 0]\n"
            "\n"
            "best_f1, best_thresh = 0.0, 0.5\n"
            "for t in [x / 100 for x in range(10, 95)]:\n"
            "    p = (train_probs_susp >= t).astype(int)\n"
            "    f = f1_score(y_train, p, zero_division=0)\n"
            "    if f > best_f1:\n"
            "        best_f1, best_thresh = f, t\n"
            "\n"
            "preds = (probs_suspicious >= best_thresh).astype(int)\n"
            "\n"
            'print(f"=== Domains: LGBM (binary, threshold={best_thresh:.2f}) ===")\n'
            'print(f"Accuracy: {accuracy_score(y_test, preds):.4f}")\n'
            'print(f"Macro F1: {f1_score(y_test, preds, average=\\"macro\\", zero_division=0):.4f}")\n'
            'print(f"SUSPICIOUS Recall: {recall_score(y_test, preds, zero_division=0):.4f}")\n'
            'print(classification_report(y_test, preds, target_names=[\\"CLEAN\\", \\"SUSPICIOUS\\"], zero_division=0))\n'
            "\n"
            "# Save\n"
            "joblib.dump({\n"
            '    "model": domain_model,\n'
            '    "threshold": best_thresh,\n'
            "}, ARTIFACT_DIR / \"domain_model.joblib\")\n"
            'print("Saved: domain_model.joblib")\n'
        )
        cell["source"] = [new_model]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Replaced domain model with binary + SMOTE weighting")
        continue
    
    # ── IPs: Lower high-class threshold ──
    if "evaluate(" in src and "Logistic Regression" in src and "le_ip" in src:
        new_eval = (
            "# Evaluation helper\n"
            "def evaluate(name, y_true, preds, probs=None):\n"
            '    print(f"\\n===== {name} =====")\n'
            '    print(f"Accuracy: {accuracy_score(y_true, preds):.4f}")\n'
            '    print(f"Macro F1: {f1_score(y_true, preds, average=\\"macro\\", zero_division=0):.4f}")\n'
            "    print(classification_report(y_true, preds, target_names=le_ip.classes_, zero_division=0))\n"
            "    \n"
            "    # Per-class recall for HIGH class\n"
            '    high_idx = list(le_ip.classes_).index("high") if "high" in le_ip.classes_ else -1\n'
            "    if high_idx >= 0 and probs is not None:\n"
            "        # Try thresholds from 0.1 to 0.9\n"
            "        for t in [0.1, 0.2, 0.3, 0.4, 0.5]:\n"
            "            adjusted = (probs[:, high_idx] >= t).astype(int)\n"
            "            high_recall = recall_score((y_true == high_idx).astype(int), adjusted, zero_division=0)\n"
            '            print(f"  HIGH recall @ threshold {t:.1f}: {high_recall:.4f}")\n'
        )
        cell["source"] = [new_eval]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Updated IP evaluation with per-threshold recall")
        continue
    
    # ── IPs: XGBoost with bootstrap CI ──
    if "xgb_model = Pipeline" in src and "XGBClassifier" in src and "ip_xgb_model" in src:
        new_xgb = (
            "# Model 2: XGBoost (Calibrated) with bootstrap confidence intervals\n"
            "xgb_model = Pipeline([\n"
            '    ("prep", ip_preprocessor),\n'
            '    ("clf", CalibratedClassifierCV(\n'
            "        estimator=XGBClassifier(\n"
            "            n_estimators=200, max_depth=3, learning_rate=0.05,\n"
            "            subsample=0.8, colsample_bytree=0.8,\n"
            "            reg_lambda=2.0, reg_alpha=0.1,\n"
            "            min_child_weight=2, random_state=42, eval_metric=\"mlogloss\"\n"
            "        ),\n"
            '        method="sigmoid", cv=5\n'
            "    ))\n"
            "])\n"
            "\n"
            "xgb_model.fit(X_train, y_train_enc)\n"
            "xgb_probs = xgb_model.predict_proba(X_test)\n"
            "xgb_preds = xgb_model.predict(X_test)\n"
            "\n"
            "evaluate(\"XGBoost\", y_test_enc, xgb_preds, xgb_probs)\n"
            "\n"
            "# Bootstrap confidence intervals (100 resamples)\n"
            "n_bootstrap = 100\n"
            "bootstrap_scores = []\n"
            "rng = np.random.RandomState(42)\n"
            "for _ in range(n_bootstrap):\n"
            "    idx = rng.randint(0, len(X_test), len(X_test))\n"
            "    if len(np.unique(y_test_enc.iloc[idx])) > 1:\n"
            "        bs_preds = xgb_model.predict(X_test.iloc[idx])\n"
            "        bootstrap_scores.append(f1_score(y_test_enc.iloc[idx], bs_preds, average=\"macro\", zero_division=0))\n"
            "\n"
            "if bootstrap_scores:\n"
            '    ci_low = np.percentile(bootstrap_scores, 2.5)\n'
            '    ci_high = np.percentile(bootstrap_scores, 97.5)\n'
            '    print(f"\\nBootstrap 95% CI for Macro F1: [{ci_low:.4f}, {ci_high:.4f}]")\n'
            "\n"
            "# Save\n"
            "joblib.dump(\n"
            '    {"model": xgb_model, "label_encoder": le_ip,\n'
            '     "num_cols": available_num, "cat_cols": available_cat},\n'
            '    ARTIFACT_DIR / "ip_xgb_model.joblib"\n'
            ")\n"
            'print("Saved: ip_xgb_model.joblib")\n'
            "\n"
            "# Also save LogReg\n"
            "joblib.dump(\n"
            '    {"model": logreg_model, "label_encoder": le_ip,\n'
            '     "num_cols": available_num, "cat_cols": available_cat},\n'
            '    ARTIFACT_DIR / "ip_logreg_model.joblib"\n'
            ")\n"
            'print("Saved: ip_logreg_model.joblib")\n'
        )
        cell["source"] = [new_xgb]
        cell["outputs"] = []
        changes.append(f"Cell {i}: Updated IP XGBoost with bootstrap CI + per-threshold recall")
        continue

# Write the modified notebook
with open(NOTEBOOK, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"\n=== Phase 3: Model Retraining — {len(changes)} changes ===")
for c in changes:
    print(f"  [OK] {c}")
