# AggerShield ML / anomaly control plane

The **detection brain**. It never touches the request hot path — it watches
AggerShield's metrics and drives mitigation through the admin API. This mirrors
how real systems split a fast **data plane** (the Go proxy) from a smarter,
slower **control plane** (this).

```
AggerShield  ──/aggershield/stats──►  detector.py  ──/admin/mode──►  AggerShield
 (data plane)      (metrics)          (control plane)   (mitigate)     (data plane)
```

## Quick start (zero dependencies)

The default `ewma` backend is pure Python standard library — nothing to install.

```bash
# AggerShield must have admin enabled (admin.enabled + token).
python detector.py \
  --stats-url http://127.0.0.1:8080/aggershield/stats \
  --admin-url http://127.0.0.1:8080/aggershield/admin \
  --token YOUR_ADMIN_TOKEN
```

Each tick it prints request/s, block/s, a block ratio, and an anomaly score.
When the score crosses `--enter`, it POSTs `…/admin/mode?challenge=always`
(under-attack mode); after `--exit-ticks` calm ticks it relaxes back to
`adaptive`. Use `--dry-run` to log decisions without acting, and `--once` for a
single tick (used by CI/smoke tests).

**How it scores (ewma):** an online robust baseline (EWMA mean + mean absolute
deviation) of the request rate, combined with the block ratio. MAD resists being
poisoned by the very spike we're trying to catch, so a sudden flood scores high
even though the detector is learning continuously.

## ML model backend (CICDDoS2019 / XGBoost)

This is the report's Section-8 approach. It needs the dataset + ML libraries
(large, not bundled):

```bash
pip install -r requirements.txt
# Train on the CICDDoS2019 CSVs (XGBoost, optional PCA dim-reduction):
python train_model.py --data "path/to/CICDDoS2019/*.csv" --pca 24 --out model.joblib
# Then run the detector with the trained model:
python detector.py --backend model --model model.joblib --token YOUR_ADMIN_TOKEN
```

`train_model.py` loads + cleans the flows, encodes benign/attack labels, trains
XGBoost (falling back to RandomForest if xgboost isn't installed), prints a
precision/recall report, and saves a scikit-learn pipeline.

> The `ewma` backend is what runs out-of-the-box and in the demo; the model
> backend is the path to the high-accuracy classifier once you have the dataset.
