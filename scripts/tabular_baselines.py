#!/usr/bin/env python3
"""Tabular baselines on manifest features with family-grouped CV."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "extracted_data" / "dataset_manifest.csv"
OUT_DIR = ROOT / "latex_dissertation" / "eval"

FEATURE_COLS = [
    "nodes",
    "edges",
    "max_score",
    "attack_steps",
    "injections",
    "c2_conns",
    "signal_behavioural_suspects_found",
    "signal_lolbin_c2_found",
    "signal_ransom_note_found",
    "signal_rwx_injections",
    "signal_hidden_processes",
    "signal_top_suspect_score",
    "signal_num_attack_motifs",
]


def load_features(manifest: Path, exclude_uncertain: bool) -> tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    df = pd.read_csv(manifest)
    df["uncertain"] = df["uncertain"].astype(str).str.lower().eq("true")
    if exclude_uncertain:
        df = df[~df["uncertain"]].copy()
    for col in FEATURE_COLS:
        if col not in df.columns:
            df[col] = 0
    X = df[FEATURE_COLS].fillna(0).astype(float)
    y = df["label"].astype(int).values
    groups = df["family"].astype(str).values
    return df, X.values, y, groups


def run_cv(model_name: str, estimator, X: np.ndarray, y: np.ndarray, groups: np.ndarray, n_splits: int, seed: int):
    n_groups = len(np.unique(groups))
    n_splits = min(n_splits, n_groups)
    cv = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    fold_metrics = []
    for fold, (tr, te) in enumerate(cv.split(X, y, groups)):
        est = estimator
        est.fit(X[tr], y[tr])
        pred = est.predict(X[te])
        proba = est.predict_proba(X[te])[:, 1] if hasattr(est, "predict_proba") else pred.astype(float)
        fold_metrics.append(
            {
                "fold": fold,
                "precision": float(precision_score(y[te], pred, zero_division=0)),
                "recall": float(recall_score(y[te], pred, zero_division=0)),
                "f1": float(f1_score(y[te], pred, zero_division=0)),
                "accuracy": float(accuracy_score(y[te], pred)),
                "roc_auc": float(roc_auc_score(y[te], proba)) if len(np.unique(y[te])) > 1 else None,
                "n_test": int(len(te)),
            }
        )
    return fold_metrics


def summarise(folds: list[dict]) -> dict:
    keys = ["precision", "recall", "f1", "accuracy", "roc_auc"]
    out = {}
    for k in keys:
        vals = [f[k] for f in folds if f.get(k) is not None]
        if vals:
            out[f"{k}_mean"] = float(np.mean(vals))
            out[f"{k}_std"] = float(np.std(vals))
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Tabular baselines with family-grouped CV")
    p.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    p.add_argument("--n-splits", type=int, default=5)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--exclude-uncertain", action="store_true")
    args = p.parse_args()

    df, X, y, groups = load_features(args.manifest, args.exclude_uncertain)
    models = {
        "logistic_regression": Pipeline(
            [("scaler", StandardScaler()), ("clf", LogisticRegression(max_iter=2000, random_state=args.seed))]
        ),
        "random_forest": RandomForestClassifier(
            n_estimators=200, random_state=args.seed, class_weight="balanced"
        ),
    }

    results = {
        "manifest": str(args.manifest),
        "n_samples": int(len(df)),
        "n_splits": args.n_splits,
        "seed": args.seed,
        "group_by": "family",
        "exclude_uncertain": args.exclude_uncertain,
        "feature_cols": FEATURE_COLS,
        "models": {},
    }

    for name, est in models.items():
        folds = run_cv(name, est, X, y, groups, args.n_splits, args.seed)
        results["models"][name] = {"folds": folds, "summary": summarise(folds)}

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "tabular_cv_results.json"
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
