#!/usr/bin/env python3
"""Fix remaining IP cells: evaluate(), XGBoost, and save cells."""

import json
from pathlib import Path

NOTEBOOK = Path(__file__).resolve().parent.parent / "notebooks" / "03_modeling_and_evaluation.ipynb"

with open(NOTEBOOK, "r", encoding="utf-8") as f:
    nb = json.load(f)

changes = []

for i, cell in enumerate(nb["cells"]):
    if cell["cell_type"] != "code":
        continue
    src = "".join(cell["source"])

    # 1. Replace the evaluate() function cell
    if 'def evaluate(name, y_true, preds):' in src and 'le_ip' in src and 'classification_report' in src:
        new_eval = (
            '# Evaluation helper with per-threshold HIGH class recall\n'
            'def evaluate(name, y_true, preds, probs=None):\n'
            '    """Evaluate with per-class metrics and HIGH-class recall at multiple thresholds."""\n'
            '    print(f"\\n===== {name} =====")\n'
            '    print(f"Accuracy: {accuracy_score(y_true, preds):.4f}")\n'
            '    print(f"Macro F1: {f1_score(y_true, preds, average=\\"macro\\", zero_division=0):.4f}")\n'
            '    print(classification_report(y_true, preds, target_names=le_ip.classes_, zero_division=0))\n'
            '\n'
            '    # Per-class recall for HIGH class at lower thresholds\n'
            '    high_idx = list(le_ip.classes_).index("high") if "high" in le_ip.classes_ else -1\n'
            '    if high_idx >= 0 and probs is not None:\n'
            '        print("  HIGH class recall @ different thresholds:")\n'
            '        for t in [0.1, 0.2, 0.3, 0.4, 0.5]:\n'
            '            adjusted = (probs[:, high_idx] >= t).astype(int)\n'
            '            high_recall = recall_score((y_true == high_idx).astype(int), adjusted, zero_division=0)\n'
            '            print(f"    threshold={t:.1f} -> recall={high_recall:.4f}")\n'
        )
        cell["source"] = [new_eval]
        changes.append(f"Cell {i}: Updated evaluate() with per-threshold HIGH recall")
        continue

    # 2. Replace XGBoost model + save cell
    if 'xgb_model = Pipeline' in src and 'ip_xgb_model' not in src:
        new_xgb = (
            '# Model 2: XGBoost (Calibrated) with bootstrap confidence intervals\n'
            'xgb_model = Pipeline([\n'
            '    ("prep", ip_preprocessor),\n'
            '    ("clf", CalibratedClassifierCV(\n'
            '        estimator=XGBClassifier(\n'
            '            n_estimators=200, max_depth=3, learning_rate=0.05,\n'
            '            subsample=0.8, colsample_bytree=0.8,\n'
            '            reg_lambda=2.0, reg_alpha=0.1,\n'
            '            min_child_weight=2, random_state=42, eval_metric="mlogloss"\n'
            '        ),\n'
            '        method="sigmoid", cv=5\n'
            '    ))\n'
            '])\n'
            '\n'
            'xgb_model.fit(X_train, y_train_enc)\n'
            'xgb_probs = xgb_model.predict_proba(X_test)\n'
            'xgb_preds = xgb_model.predict(X_test)\n'
            '\n'
            'evaluate("XGBoost", y_test_enc, xgb_preds, xgb_probs)\n'
            '\n'
            '# Bootstrap confidence intervals (100 resamples)\n'
            'n_bootstrap = 100\n'
            'bootstrap_scores = []\n'
            'rng = np.random.RandomState(42)\n'
            'for _ in range(n_bootstrap):\n'
            '    idx = rng.randint(0, len(X_test), len(X_test))\n'
            '    if len(np.unique(y_test_enc.iloc[idx])) > 1:\n'
            '        bs_preds = xgb_model.predict(X_test.iloc[idx])\n'
            '        bootstrap_scores.append(f1_score(y_test_enc.iloc[idx], bs_preds, average="macro", zero_division=0))\n'
            '\n'
            'if bootstrap_scores:\n'
            '    ci_low = np.percentile(bootstrap_scores, 2.5)\n'
            '    ci_high = np.percentile(bootstrap_scores, 97.5)\n'
            '    print(f"\\nBootstrap 95% CI for Macro F1: [{ci_low:.4f}, {ci_high:.4f}]")\n'
            '\n'
            '# Save both models (LogReg from cell above + XGBoost)\n'
            'joblib.dump(\n'
            '    {"model": xgb_model, "label_encoder": le_ip,\n'
            '     "num_cols": available_num, "cat_cols": available_cat},\n'
            '    ARTIFACT_DIR / "ip_xgb_model.joblib"\n'
            ')\n'
            'print("Saved: ip_xgb_model.joblib")\n'
            '\n'
            'joblib.dump(\n'
            '    {"model": logreg_model, "label_encoder": le_ip,\n'
            '     "num_cols": available_num, "cat_cols": available_cat},\n'
            '    ARTIFACT_DIR / "ip_logreg_model.joblib"\n'
            ')\n'
            'print("Saved: ip_logreg_model.joblib")\n'
        )
        cell["source"] = [new_xgb]
        changes.append(f"Cell {i}: Updated XGBoost with bootstrap CI + per-threshold recall + saves")
        continue

# Write
with open(NOTEBOOK, "w", encoding="utf-8") as f:
    json.dump(nb, f, indent=1, ensure_ascii=False)

print(f"=== Remaining IP fixes: {len(changes)} changes ===")
for c in changes:
    print(f"  [OK] {c}")
if not changes:
    print("  No changes made - patterns didn't match")
