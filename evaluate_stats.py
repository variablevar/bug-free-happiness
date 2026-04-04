"""
evaluate_stats.py
-----------------
Per-source statistical evaluation of the GIN classifier.

Usage (standalone — reads a predictions CSV saved during training):
    python evaluate_stats.py --preds outputs/predictions.csv

Usage (inline — import and call after each fold in train.py):
    from evaluate_stats import log_prediction, run_stats
    log_prediction(source, pred, true_label, prob)   # call per graph
    run_stats()                                       # call after all folds
"""

import argparse
import csv
import os
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy import stats


# ---------------------------------------------------------------------------
# Global in-memory store (used when this module is imported by train.py)
# ---------------------------------------------------------------------------
_predictions: list[tuple[str, int, int, float]] = []   # (source, pred, true, prob)


def log_prediction(source: str, pred: int, true: int, prob: float) -> None:
    """Call once per graph prediction during/after each fold."""
    _predictions.append((source, pred, true, prob))


def save_predictions_csv(path: str = "outputs/predictions.csv") -> None:
    """Flush in-memory predictions to a CSV for later analysis."""
    os.makedirs(Path(path).parent, exist_ok=True)
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "pred", "true", "prob"])
        writer.writerows(_predictions)
    print(f"[Stats] Predictions saved → {path}")


# ---------------------------------------------------------------------------
# Core aggregation
# ---------------------------------------------------------------------------

def _aggregate(records: list[tuple[str, int, int, float]]) -> tuple[list[str], np.ndarray]:
    """Aggregate per-graph records to one accuracy value per source."""
    bucket: dict[str, dict] = defaultdict(lambda: {"correct": 0, "total": 0})
    for source, pred, true, _ in records:
        bucket[source]["total"] += 1
        if pred == true:
            bucket[source]["correct"] += 1

    names = sorted(bucket.keys())
    acc = np.array([bucket[s]["correct"] / bucket[s]["total"] for s in names])
    return names, acc


# ---------------------------------------------------------------------------
# Statistical tests
# ---------------------------------------------------------------------------

def run_stats(
    records: list[tuple[str, int, int, float]] | None = None,
    chance: float = 0.5,
    alpha: float = 0.05,
    baseline_acc: np.ndarray | None = None,
) -> dict:
    """
    Run one-sample t-test, Wilcoxon signed-rank, and Shapiro-Wilk tests.

    Parameters
    ----------
    records       : list of (source, pred, true, prob) — defaults to module-level store
    chance        : null hypothesis mean (default 0.5 for balanced binary task)
    alpha         : significance level (default 0.05)
    baseline_acc  : optional np.ndarray of per-source accuracy from a baseline model
                    (same 30 sources, same order) for a paired t-test comparison

    Returns
    -------
    dict with all test statistics (also prints a formatted report)
    """
    if records is None:
        records = _predictions

    if not records:
        raise ValueError("No predictions found. Call log_prediction() or pass records=.")

    names, per_source_acc = _aggregate(records)
    n = len(per_source_acc)

    sep = "─" * 58

    print(f"\n{sep}")
    print(f"  Per-Source Accuracy Summary  (n={n} sources)")
    print(sep)
    print(f"  Mean  : {per_source_acc.mean():.4f}")
    print(f"  Std   : {per_source_acc.std(ddof=1):.4f}")
    print(f"  Min   : {per_source_acc.min():.4f}")
    print(f"  Max   : {per_source_acc.max():.4f}")
    print(f"  Median: {np.median(per_source_acc):.4f}")

    results: dict = {"n_sources": n, "mean_acc": per_source_acc.mean(), "per_source_acc": per_source_acc}

    # ── Shapiro-Wilk normality test ─────────────────────────────────────────
    sw_stat, sw_p = stats.shapiro(per_source_acc)
    normal = sw_p >= alpha
    results["shapiro_stat"] = sw_stat
    results["shapiro_p"] = sw_p
    results["data_normal"] = normal

    print(f"\n{sep}")
    print("  Shapiro-Wilk Normality Test")
    print(sep)
    print(f"  W = {sw_stat:.4f}   p = {sw_p:.4f}")
    if normal:
        print("  ✅ Data appears normal  →  t-test assumption holds")
    else:
        print("  ⚠️  Data is NOT normal  →  prefer Wilcoxon over t-test")

    # ── One-sample t-test vs. chance ────────────────────────────────────────
    t_stat, t_p = stats.ttest_1samp(per_source_acc, popmean=chance)
    ci = stats.t.interval(
        1 - alpha,
        df=n - 1,
        loc=per_source_acc.mean(),
        scale=stats.sem(per_source_acc),
    )
    results.update({"t_stat": t_stat, "t_p": t_p, "ci_low": ci[0], "ci_high": ci[1]})

    print(f"\n{sep}")
    print(f"  One-Sample t-Test  (H₀: mean accuracy = {chance})")
    print(sep)
    print(f"  t = {t_stat:.4f}   p = {t_p:.4f}")
    print(f"  95% CI: [{ci[0]:.4f}, {ci[1]:.4f}]")
    sig = "YES ✅" if t_p < alpha else "NO  ❌"
    print(f"  Significant (α={alpha}): {sig}")

    # ── Wilcoxon signed-rank test ────────────────────────────────────────────
    try:
        w_stat, w_p = stats.wilcoxon(per_source_acc - chance, alternative="two-sided")
        results.update({"wilcoxon_stat": w_stat, "wilcoxon_p": w_p})
        sig_w = "YES ✅" if w_p < alpha else "NO  ❌"

        print(f"\n{sep}")
        print(f"  Wilcoxon Signed-Rank Test  (H₀: median accuracy = {chance})")
        print(sep)
        print(f"  W = {w_stat:.4f}   p = {w_p:.4f}")
        print(f"  Significant (α={alpha}): {sig_w}")
    except ValueError as e:
        print(f"\n  [Wilcoxon skipped] {e}")

    # ── Paired t-test vs. baseline (optional) ───────────────────────────────
    if baseline_acc is not None:
        if len(baseline_acc) != n:
            print(f"\n  [Paired t-test skipped] baseline_acc length {len(baseline_acc)} ≠ {n}")
        else:
            t2, p2 = stats.ttest_rel(per_source_acc, baseline_acc)
            results.update({"paired_t_stat": t2, "paired_t_p": p2})
            sig_p = "YES ✅" if p2 < alpha else "NO  ❌"

            print(f"\n{sep}")
            print("  Paired t-Test  (GIN vs Baseline, per source)")
            print(sep)
            print(f"  t = {t2:.4f}   p = {p2:.4f}")
            print(f"  Mean diff: {(per_source_acc - baseline_acc).mean():.4f}")
            print(f"  Significant (α={alpha}): {sig_p}")

    # ── Per-source breakdown ─────────────────────────────────────────────────
    print(f"\n{sep}")
    print("  Per-Source Accuracy Breakdown")
    print(sep)
    for name, acc_val in zip(names, per_source_acc):
        bar = "█" * int(acc_val * 20)
        print(f"  {name:<40} {acc_val:.3f}  {bar}")

    print(f"{sep}\n")
    return results


# ---------------------------------------------------------------------------
# CLI entry point — reads predictions CSV written by train.py
# ---------------------------------------------------------------------------

def _load_csv(path: str) -> list[tuple[str, int, int, float]]:
    records = []
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            source = row["source"]
            pred = int(row["pred"])
            true = int(row["true"])
            prob = float(row["prob"])
            records.append((source, pred, true, prob))
    return records


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Per-source statistical tests for GIN results")
    parser.add_argument(
        "--preds",
        type=str,
        default="outputs/predictions.csv",
        help="Path to predictions CSV (columns: source, pred, true, prob)",
    )
    parser.add_argument("--chance", type=float, default=0.5, help="Null hypothesis accuracy (default 0.5)")
    parser.add_argument("--alpha", type=float, default=0.05, help="Significance level (default 0.05)")
    args = parser.parse_args()

    records = _load_csv(args.preds)
    print(f"[Stats] Loaded {len(records)} prediction records from {args.preds}")
    run_stats(records=records, chance=args.chance, alpha=args.alpha)
