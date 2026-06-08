#!/usr/bin/env python3
"""Train a DDoS classifier on the CICDDoS2019 corpus.

This implements the approach from the project report (Section 8): XGBoost /
Random Forest on CICDDoS2019, with PCA-style dimensionality reduction. The
resulting model.joblib can be loaded by detector.py with `--backend model`.

This script is a SCAFFOLD: it needs the dataset and ML libraries that aren't
bundled (they're large). Install them and point --data at the CICDDoS2019 CSVs:

    pip install -r requirements.txt
    python train_model.py --data path/to/CICDDoS2019/*.csv --out model.joblib

Expected CSV columns follow the CICFlowMeter feature names; the final column is
the label ('BENIGN' vs an attack name). The script:
  1. loads + concatenates the CSVs,
  2. cleans inf/NaN, encodes the label as benign(0)/attack(1),
  3. optionally reduces dimensionality with PCA,
  4. trains XGBoost (falls back to RandomForest if xgboost isn't installed),
  5. reports accuracy / precision / recall, and saves the pipeline.
"""

from __future__ import annotations

import argparse
import glob
import sys


def _require(mod: str):
    try:
        return __import__(mod)
    except ImportError:
        sys.exit(f"missing dependency '{mod}': pip install -r requirements.txt")


def main() -> None:
    ap = argparse.ArgumentParser(description="Train a CICDDoS2019 DDoS classifier")
    ap.add_argument("--data", nargs="+", required=True, help="CSV file(s) or globs")
    ap.add_argument("--out", default="model.joblib")
    ap.add_argument("--pca", type=int, default=0, help="PCA components (0 = disabled)")
    ap.add_argument("--test-size", type=float, default=0.2)
    args = ap.parse_args()

    pd = _require("pandas")
    _require("sklearn")
    np = _require("numpy")
    import joblib
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.decomposition import PCA
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report

    files = []
    for pat in args.data:
        files.extend(glob.glob(pat))
    if not files:
        sys.exit("no input CSVs matched --data")

    print(f"[train] loading {len(files)} file(s)...")
    df = pd.concat((pd.read_csv(f, low_memory=False) for f in files), ignore_index=True)
    df.columns = [c.strip() for c in df.columns]

    label_col = "Label" if "Label" in df.columns else df.columns[-1]
    y = (df[label_col].astype(str).str.upper() != "BENIGN").astype(int)
    X = df.drop(columns=[label_col]).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    print(f"[train] {len(X)} flows, {X.shape[1]} numeric features, "
          f"{y.mean()*100:.1f}% attack")

    steps = [("scaler", StandardScaler())]
    if args.pca > 0:
        steps.append(("pca", PCA(n_components=args.pca)))
        print(f"[train] PCA -> {args.pca} components")
    steps.append(("clf", _make_classifier()))
    pipe = Pipeline(steps)

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y)
    print("[train] fitting...")
    pipe.fit(X_tr, y_tr)

    print(classification_report(y_te, pipe.predict(X_te), target_names=["benign", "attack"]))
    joblib.dump(pipe, args.out)
    print(f"[train] saved {args.out}")


def _make_classifier():
    """XGBoost if available (the report's top performer), else RandomForest."""
    try:
        from xgboost import XGBClassifier
        print("[train] classifier: XGBoost")
        return XGBClassifier(
            n_estimators=200, max_depth=8, learning_rate=0.2,
            subsample=0.9, eval_metric="logloss", n_jobs=-1)
    except ImportError:
        from sklearn.ensemble import RandomForestClassifier
        print("[train] xgboost not installed; using RandomForest")
        return RandomForestClassifier(n_estimators=200, n_jobs=-1, random_state=42)


if __name__ == "__main__":
    main()
