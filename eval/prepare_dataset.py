"""
Convert the UCI PhiUSIIL Phishing URL dataset into the format used by this project.

PhiUSIIL labels: 1 = LEGITIMATE, 0 = PHISHING  (UCI documentation)
This project:    1 = PHISHING,   0 = BENIGN    -> labels are flipped here.

Usage:  python eval/prepare_dataset.py <path-to-phiusiil-csv> eval/urls.csv [per_class=20000]
"""
import sys
import pandas as pd

if len(sys.argv) < 3:
    sys.exit("Usage: python eval/prepare_dataset.py <phiusiil.csv> <out.csv> [per_class]")
src, dst = sys.argv[1], sys.argv[2]
per_class = int(sys.argv[3]) if len(sys.argv) > 3 else 20000

df = pd.read_csv(src)
cols = {c.lower(): c for c in df.columns}
if "url" not in cols or "label" not in cols:
    sys.exit(f"Expected 'URL' and 'label' columns, found: {list(df.columns)[:10]} ...")
df = df[[cols["url"], cols["label"]]].rename(columns={cols["url"]: "url", cols["label"]: "label"})

df["label"] = 1 - df["label"]                  # flip: now 1 = phishing, 0 = benign
df = df.drop_duplicates(subset="url")
n = min(per_class, int(df["label"].value_counts().min()))   # balanced classes
df = df.groupby("label").sample(n=n, random_state=42)       # GroupBy.sample keeps the label column
df = df.sample(frac=1, random_state=42).reset_index(drop=True)

df[["url", "label"]].to_csv(dst, index=False)
print(f"Wrote {len(df)} URLs to {dst} ({n} per class)")
print(df["label"].map({1: "phishing", 0: "benign"}).value_counts())
