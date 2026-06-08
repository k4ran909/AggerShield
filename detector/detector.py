#!/usr/bin/env python3
"""AggerShield ML/anomaly control plane.

This is the "detection brain" that drives mitigation. It polls AggerShield's
/aggershield/stats endpoint, derives per-tick traffic features, scores them for
anomalies, and — when an attack is detected — flips AggerShield into
under-attack mode via the admin API (challenge=always). When traffic returns to
baseline it relaxes back to adaptive.

Two scoring backends:
  * "ewma"  (default) — pure standard-library robust anomaly detector. No
    dependencies, runs anywhere. Learns a baseline online (EWMA mean + mean
    absolute deviation) and flags ticks whose request rate / block rate is many
    deviations above baseline.
  * "model" — load a trained scikit-learn/XGBoost classifier (see
    train_model.py, built on the CICDDoS2019 corpus referenced in the project
    report). Requires joblib + the model file.

The control plane is deliberately separate from the data plane: it never sits in
the request hot path, it only watches metrics and pushes decisions.
"""

from __future__ import annotations

import argparse
import json
import time
import urllib.request
import urllib.error


def get_json(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def post(url: str, token: str, timeout: float = 5.0) -> dict:
    req = urllib.request.Request(url, method="POST")
    if token:
        req.add_header("X-AggerShield-Token", token)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


class EwmaDetector:
    """Online robust anomaly detector (EWMA mean + mean absolute deviation).

    A z-like score = (value - mean) / (mad + eps). MAD is far more robust to the
    very spikes we want to detect than plain variance, so the baseline isn't
    poisoned by the attack itself.
    """

    def __init__(self, alpha: float = 0.2):
        self.alpha = alpha
        self.mean: float | None = None
        self.mad: float = 0.0

    def score(self, value: float) -> float:
        if self.mean is None:  # first sample: seed the baseline
            self.mean = value
            return 0.0
        dev = value - self.mean
        score = dev / (self.mad + 1e-6)
        # Update baseline AFTER scoring so the current sample doesn't mask itself.
        self.mean += self.alpha * dev
        self.mad += self.alpha * (abs(dev) - self.mad)
        return score


def derive_features(prev: dict, cur: dict, dt: float) -> dict:
    """Per-second rates from two stats snapshots."""
    def rate(key):
        return max(0.0, (cur.get(key, 0) - prev.get(key, 0))) / dt

    total = rate("total_requests")
    blocked = rate("blocked_banned") + rate("rate_limited_per_ip") + rate("rate_limited_global")
    return {
        "req_per_sec": total,
        "block_per_sec": blocked,
        # Fraction of traffic being shed/blocked — climbs fast under attack.
        "block_ratio": (blocked / total) if total > 0 else 0.0,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="AggerShield anomaly control plane")
    ap.add_argument("--stats-url", default="http://127.0.0.1:8080/aggershield/stats")
    ap.add_argument("--admin-url", default="http://127.0.0.1:8080/aggershield/admin")
    ap.add_argument("--token", default="", help="admin token (X-AggerShield-Token)")
    ap.add_argument("--interval", type=float, default=2.0, help="poll seconds")
    ap.add_argument("--enter", type=float, default=6.0, help="score to enter attack mode")
    ap.add_argument("--exit-ticks", type=int, default=5, help="calm ticks before relaxing")
    ap.add_argument("--backend", choices=["ewma", "model"], default="ewma")
    ap.add_argument("--model", default="model.joblib", help="model file for --backend model")
    ap.add_argument("--dry-run", action="store_true", help="log decisions, don't act")
    ap.add_argument("--once", action="store_true", help="run a single tick and exit (testing)")
    args = ap.parse_args()

    scorer = EwmaDetector()
    model = None
    if args.backend == "model":
        model = _load_model(args.model)

    prev = None
    prev_t = None
    attack_mode = False
    calm = 0

    print(f"[detector] watching {args.stats_url} (backend={args.backend}, dry_run={args.dry_run})")
    while True:
        try:
            cur = get_json(args.stats_url)
            now = time.monotonic()
            if prev is not None:
                dt = max(1e-3, now - prev_t)
                feats = derive_features(prev, cur, dt)
                score = _score(args.backend, scorer, model, feats)
                attack = score >= args.enter
                _react(args, feats, score, attack, state={"attack_mode": attack_mode, "calm": calm})
                # state machine
                if attack:
                    if not attack_mode:
                        attack_mode = _set_mode(args, True)
                    calm = 0
                elif attack_mode:
                    calm += 1
                    if calm >= args.exit_ticks:
                        if _set_mode(args, False):
                            attack_mode = False
                        calm = 0
            prev, prev_t = cur, now
        except (urllib.error.URLError, OSError) as e:
            print(f"[detector] poll error: {e}")
        if args.once:
            return
        time.sleep(args.interval)


def _score(backend, scorer, model, feats) -> float:
    if backend == "model" and model is not None:
        # Map our few live features into the model's expected vector. A real
        # deployment would compute the full CICDDoS2019 feature set here.
        import numpy as np  # noqa: local import; only needed for model backend
        x = np.array([[feats["req_per_sec"], feats["block_per_sec"], feats["block_ratio"]]])
        proba = float(model.predict_proba(x)[0][1])  # P(attack)
        return proba * 10.0  # scale to the same range as the EWMA score
    # EWMA: combine a spike in request rate with a spike in block ratio.
    rate_score = scorer.score(feats["req_per_sec"])
    return rate_score + feats["block_ratio"] * 10.0


def _react(args, feats, score, attack, state) -> None:
    flag = "ATTACK" if attack else "ok"
    print(f"[detector] req/s={feats['req_per_sec']:.1f} "
          f"block/s={feats['block_per_sec']:.1f} "
          f"block_ratio={feats['block_ratio']:.2f} "
          f"score={score:.1f} -> {flag}"
          + ("  (attack-mode active)" if state["attack_mode"] else ""))


def _set_mode(args, attack: bool) -> bool:
    mode = "always" if attack else "adaptive"
    if args.dry_run:
        print(f"[detector] DRY-RUN would set challenge={mode}")
        return attack
    try:
        r = post(f"{args.admin_url}/mode?challenge={mode}", args.token)
        print(f"[detector] >>> set challenge={mode}: {r}")
        return attack
    except urllib.error.URLError as e:
        print(f"[detector] failed to set mode: {e}")
        return not attack  # report unchanged on failure


def _load_model(path: str):
    try:
        import joblib
    except ImportError:
        raise SystemExit("--backend model requires joblib (pip install -r requirements.txt)")
    return joblib.load(path)


if __name__ == "__main__":
    main()
