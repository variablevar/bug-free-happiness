#!/usr/bin/env python3
"""
evaluate_stats.py  v2
Changes vs v1:
  - run_stats() now also computes and prints the optimal ROC threshold
    (Youden's J) so you can re-apply it post-hoc without retraining.
  - Per-source bar chart now shows prob alongside correct/incorrect.
  - Minor: reset() added to clear state between multiple run() calls.
"""

from __future__ import annotations
import sys
from typing import Optional

import numpy as np
from scipy import stats

# ── In-memory store (populated by log_prediction) ─────────────────────────────
_records: list[dict] = []


def reset():
    """Clear all logged predictions (useful when running multiple experiments)."""
    global _records
    _records = []


def log_prediction(source: str, pred: int, true: int, prob: float):
    """Call once per fold inside train.py to record the held-out prediction."""
    _records.append(dict(source=source, pred=pred, true=true, prob=prob))


def save_predictions_csv(path: str = "outputs/predictions.csv"):
    """Optionally dump predictions to CSV for offline analysis."""
    import os, csv
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["source", "pred", "true", "prob"])
        w.writeheader()
        w.writerows(_records)
    print(f"[Stats] Predictions saved → {path}")


# ── Core statistics ───────────────────────────────────────────────────────────

def _youden_threshold(trues, probs):
    """Find threshold that maximises Youden's J = sensitivity + specificity - 1."""
    from sklearn.metrics import roc_curve
    fpr, tpr, thresholds = roc_curve(trues, probs)
    j_scores = tpr - fpr
    best_idx  = int(np.argmax(j_scores))
    return float(thresholds[best_idx]), float(tpr[best_idx]), float(1 - fpr[best_idx])


def run_stats(records: Optional[list[dict]] = None):
    """
    Compute and print a full statistical report on LOSO fold predictions.
    Uses _records global if records is not passed.
    """
    data = records if records is not None else _records
    if not data:
        print("[Stats] No predictions logged — call log_prediction() first.")
        return

    sources = [r["source"] for r in data]
    preds   = np.array([r["pred"]  for r in data])
    trues   = np.array([r["true"]  for r in data])
    probs   = np.array([r["prob"]  for r in data])

    correct     = (preds == trues).astype(float)
    n           = len(correct)
    mean_acc    = correct.mean()
    std_acc     = correct.std(ddof=1)
    null_acc    = 0.5   # chance level for balanced binary classification

    print("\n" + "=" * 60)
    print("  EVALUATE STATS  —  LOSO per-fold analysis")
    print("=" * 60)
    print(f"  N folds       : {n}")
    print(f"  Mean accuracy : {mean_acc:.4f}")
    print(f"  Std           : {std_acc:.4f}")
    print(f"  Min / Max     : {correct.min():.0f} / {correct.max():.0f}")

    # ── Normality test ────────────────────────────────────────────────────────
    if n >= 3:
        w_stat, sw_p = stats.shapiro(correct)
        is_normal    = sw_p > 0.05
        print(f"\n  Shapiro-Wilk  : W={w_stat:.4f}  p={sw_p:.4f}  "
              f"→ {'normal ✓' if is_normal else 'NOT normal ✗'}")
    else:
        is_normal = False
        print("\n  Shapiro-Wilk  : skipped (n < 3)")

    # ── Hypothesis test vs chance ─────────────────────────────────────────────
    print(f"\n  Null hypothesis: mean accuracy = {null_acc} (chance)")

    # One-sample t-test
    t_stat, t_p = stats.ttest_1samp(correct, null_acc)
    ci_low, ci_high = stats.t.interval(
        0.95, df=n - 1, loc=mean_acc, scale=stats.sem(correct)
    )
    print(f"  t-test        : t={t_stat:.4f}  p={t_p:.4f}  "
          f"95% CI=[{ci_low:.4f}, {ci_high:.4f}]  "
          f"→ {'significant ✓' if t_p < 0.05 else 'NOT significant ✗'}")

    # Wilcoxon signed-rank (more appropriate for binary per-fold outcomes)
    try:
        diffs = correct - null_acc
        if np.any(diffs != 0):
            w_stat2, w_p = stats.wilcoxon(diffs, alternative="two-sided")
            print(f"  Wilcoxon      : W={w_stat2:.1f}  p={w_p:.4f}  "
                  f"→ {'significant ✓' if w_p < 0.05 else 'NOT significant ✗'}")
        else:
            print("  Wilcoxon      : skipped (all diffs = 0)")
    except Exception as e:
        print(f"  Wilcoxon      : skipped ({e})")

    recommendation = "t-test" if is_normal else "Wilcoxon"
    print(f"  Recommendation: use {recommendation} result "
          f"(distribution {'is' if is_normal else 'is not'} normal)")

    # ── ROC threshold calibration ─────────────────────────────────────────────
    print("\n  ── Threshold Calibration (Youden's J) ──")
    try:
        from sklearn.metrics import roc_auc_score
        if len(set(trues)) > 1:
            auc = roc_auc_score(trues, probs)
            thresh, sens, spec = _youden_threshold(trues.tolist(), probs.tolist())
            preds_thresh = (probs >= thresh).astype(int)
            acc_thresh   = (preds_thresh == trues).mean()
            print(f"  AUC           : {auc:.4f}")
            print(f"  Optimal thresh: {thresh:.4f}")
            print(f"  At threshold  : sensitivity={sens:.3f}  specificity={spec:.3f}")
            print(f"  Acc @ thresh  : {acc_thresh:.3f}  "
                  f"({int((preds_thresh == trues).sum())}/{n})")
            print(f"  Tip: use  --threshold {thresh:.3f}  at inference time")
        else:
            print("  AUC: skipped (only one class in held-out set)")
    except ImportError:
        print("  sklearn not available — skipping AUC / threshold.")
    except Exception as e:
        print(f"  Threshold calibration error: {e}")

    # ── Per-source accuracy bar chart ─────────────────────────────────────────
    print("\n  ── Per-source accuracy ──")
    src_set = sorted(set(sources))
    for src in src_set:
        idxs  = [i for i, s in enumerate(sources) if s == src]
        n_src = len(idxs)
        c_src = sum(correct[i] for i in idxs)
        p_src = probs[idxs].mean()
        bar   = "█" * int(c_src) + "░" * (n_src - int(c_src))
        print(f"  {src:<30s} {bar}  "
              f"{int(c_src)}/{n_src}  prob={p_src:.3f}")

    print("=" * 60)
