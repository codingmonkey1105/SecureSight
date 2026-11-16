"""
Train a logistic-regression URL classifier on features exported by export_features.js.

Usage:  python eval/train_model.py eval/features.csv model-weights.json eval/heldout_urls.csv

Outputs
  model-weights.json   weights + scaler, loaded by risk-engine.js (no ML library needed in the browser)
  heldout_urls.csv     the 20% test split, never seen in training -> evaluate with eval/evaluate.js
"""
import json
import sys

import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

feat_csv, out_model, out_heldout = sys.argv[1], sys.argv[2], sys.argv[3]
df = pd.read_csv(feat_csv)
feature_cols = [c for c in df.columns if c not in ("url", "label")]

train, test = train_test_split(df, test_size=0.2, stratify=df["label"], random_state=42)
scaler = StandardScaler().fit(train[feature_cols])
clf = LogisticRegression(max_iter=2000, class_weight="balanced").fit(scaler.transform(train[feature_cols]), train["label"])

prob = clf.predict_proba(scaler.transform(test[feature_cols]))[:, 1]
pred = (prob >= 0.5).astype(int)
y = test["label"]
tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
print(f"Held-out test set: {len(test)} URLs")
print(f"Accuracy {accuracy_score(y, pred):.3f} | Precision {precision_score(y, pred):.3f} | Recall {recall_score(y, pred):.3f} "
      f"| F1 {f1_score(y, pred):.3f} | ROC-AUC {roc_auc_score(y, prob):.3f}")
print(f"Confusion: TP {tp}  FP {fp}  TN {tn}  FN {fn}")

coefs = sorted(zip(feature_cols, clf.coef_[0]), key=lambda t: -abs(t[1]))
print("\nMost influential features (standardised coefficients):")
for name, c in coefs[:8]:
    print(f"  {name:20s} {c:+.2f}")

model = {
    "features": feature_cols,
    "mean": scaler.mean_.tolist(),
    "std": scaler.scale_.tolist(),
    "weights": clf.coef_[0].tolist(),
    "bias": float(clf.intercept_[0]),
    "trained_on": len(train),
}
with open(out_model, "w") as f:
    json.dump(model, f, indent=1)
test[["url", "label"]].to_csv(out_heldout, index=False)
print(f"\nSaved {out_model} and {out_heldout}")
