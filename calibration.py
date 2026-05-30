#!/usr/bin/env python3
"""Calibration helpers for binary malware probabilities."""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
import torch
import torch.nn.functional as F


@dataclass
class TempScalingResult:
    temperature: float
    val_nll_before: float
    val_nll_after: float


def fit_temperature(logits: np.ndarray, labels: np.ndarray, max_iter: int = 200) -> TempScalingResult:
    if logits.ndim != 2 or logits.shape[1] != 2:
        raise ValueError(f"Expected logits [N,2], got {logits.shape}")
    if labels.ndim != 1:
        raise ValueError(f"Expected labels [N], got {labels.shape}")
    x = torch.tensor(logits, dtype=torch.float32)
    y = torch.tensor(labels, dtype=torch.long)

    t = torch.nn.Parameter(torch.tensor(1.0))
    opt = torch.optim.LBFGS([t], lr=0.05, max_iter=max_iter, line_search_fn="strong_wolfe")

    def closure():
        opt.zero_grad()
        temp = torch.clamp(t, min=0.05, max=20.0)
        loss = F.cross_entropy(x / temp, y)
        loss.backward()
        return loss

    before = float(F.cross_entropy(x, y).item())
    opt.step(closure)
    temp = float(torch.clamp(t.detach(), min=0.05, max=20.0).item())
    after = float(F.cross_entropy(x / temp, y).item())
    return TempScalingResult(temperature=temp, val_nll_before=before, val_nll_after=after)


def apply_temperature(logits: np.ndarray, temperature: float) -> np.ndarray:
    t = max(float(temperature), 1e-6)
    z = logits / t
    z = z - z.max(axis=1, keepdims=True)
    e = np.exp(z)
    return e / np.clip(e.sum(axis=1, keepdims=True), 1e-12, None)


def brier_score(probs: np.ndarray, labels: np.ndarray) -> float:
    p1 = probs[:, 1]
    y = labels.astype(np.float32)
    return float(np.mean((p1 - y) ** 2))


def expected_calibration_error(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> float:
    p1 = probs[:, 1]
    conf = np.maximum(p1, 1.0 - p1)
    pred = (p1 >= 0.5).astype(int)
    y = labels.astype(int)

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    ece = 0.0
    n = max(len(y), 1)
    for i in range(n_bins):
        lo, hi = bins[i], bins[i + 1]
        mask = (conf >= lo) & (conf < hi if i < n_bins - 1 else conf <= hi)
        if not np.any(mask):
            continue
        acc = float(np.mean(pred[mask] == y[mask]))
        c = float(np.mean(conf[mask]))
        ece += (np.sum(mask) / n) * abs(acc - c)
    return float(ece)


def reliability_curve_bins(probs: np.ndarray, labels: np.ndarray, n_bins: int = 10) -> list[dict]:
    p1 = probs[:, 1]
    conf = np.maximum(p1, 1.0 - p1)
    pred = (p1 >= 0.5).astype(int)
    y = labels.astype(int)

    bins = np.linspace(0.0, 1.0, n_bins + 1)
    out = []
    for i in range(n_bins):
        lo, hi = float(bins[i]), float(bins[i + 1])
        mask = (conf >= lo) & (conf < hi if i < n_bins - 1 else conf <= hi)
        n = int(np.sum(mask))
        if n == 0:
            out.append(
                {
                    "bin_index": i,
                    "bin_lower": lo,
                    "bin_upper": hi,
                    "count": 0,
                    "mean_confidence": 0.0,
                    "accuracy": 0.0,
                    "gap_abs": 0.0,
                }
            )
            continue
        acc = float(np.mean(pred[mask] == y[mask]))
        c = float(np.mean(conf[mask]))
        out.append(
            {
                "bin_index": i,
                "bin_lower": lo,
                "bin_upper": hi,
                "count": n,
                "mean_confidence": c,
                "accuracy": acc,
                "gap_abs": abs(acc - c),
            }
        )
    return out


def ks_separation(probs: np.ndarray, labels: np.ndarray) -> float:
    p1 = probs[:, 1]
    pos = np.sort(p1[labels == 1])
    neg = np.sort(p1[labels == 0])
    if len(pos) == 0 or len(neg) == 0:
        return 0.0
    points = np.unique(np.concatenate([pos, neg]))
    pos_cdf = np.searchsorted(pos, points, side="right") / len(pos)
    neg_cdf = np.searchsorted(neg, points, side="right") / len(neg)
    return float(np.max(np.abs(pos_cdf - neg_cdf)))


def roc_curve_points(probs: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    p1 = probs[:, 1]
    thresholds = np.unique(np.concatenate([[0.0, 1.0], p1]))
    tprs, fprs = [], []
    y = labels.astype(int)
    pos = max(int(np.sum(y == 1)), 1)
    neg = max(int(np.sum(y == 0)), 1)
    for th in thresholds:
        pred = (p1 >= th).astype(int)
        tp = int(np.sum((pred == 1) & (y == 1)))
        fp = int(np.sum((pred == 1) & (y == 0)))
        tprs.append(tp / pos)
        fprs.append(fp / neg)
    order = np.argsort(fprs)
    return thresholds[order], np.asarray(tprs)[order], np.asarray(fprs)[order]


def auc_from_roc(tpr: np.ndarray, fpr: np.ndarray) -> float:
    if len(tpr) < 2:
        return 0.0
    return float(np.trapz(tpr, fpr))


def choose_thresholds_by_roc(
    probs: np.ndarray,
    labels: np.ndarray,
    target_recall: float = 0.90,
    target_specificity: float = 0.90,
    max_ambiguity_width: float = 0.20,
    min_ambiguity_width: float = 0.06,
    precision_floor: float = 0.0,
    recall_floor: float = 0.0,
) -> tuple[float, float]:
    """
    Pick low/high probability thresholds from a validation ROC sweep.

    ``probs`` must be an (N, 2) matrix (binary softmax / isotonic output);
    ``labels`` is length-N with 0/1 ground truth.
    """
    thresholds, tpr, fpr = roc_curve_points(probs, labels)
    spec = 1.0 - fpr

    # High-recall-first selection: among recall-qualified thresholds, maximize specificity,
    # then choose the largest threshold for cleaner separation.
    recall_mask = tpr >= target_recall
    if np.any(recall_mask):
        cand = np.where(recall_mask)[0]
        best_spec = np.max(spec[cand])
        best = cand[spec[cand] >= (best_spec - 1e-12)]
        t_high = float(np.max(thresholds[best]))
    else:
        best_recall = np.max(tpr) if len(tpr) else 0.0
        cand = np.where(tpr >= (best_recall - 1e-12))[0]
        t_high = float(np.max(thresholds[cand])) if len(cand) else 0.7

    # Benign threshold bound: among specificity-qualified thresholds, maximize recall,
    # then keep threshold as high as possible (narrow ambiguity zone).
    spec = 1.0 - fpr
    spec_mask = spec >= target_specificity
    if np.any(spec_mask):
        cand = np.where(spec_mask)[0]
        best_recall = np.max(tpr[cand])
        best = cand[tpr[cand] >= (best_recall - 1e-12)]
        t_low = float(np.max(thresholds[best]))
    else:
        best_spec = np.max(spec) if len(spec) else 0.0
        cand = np.where(spec >= (best_spec - 1e-12))[0]
        t_low = float(np.max(thresholds[cand])) if len(cand) else 0.3

    # If SOC floors are provided, move t_high to a floor-satisfying threshold when possible.
    if precision_floor > 0.0 or recall_floor > 0.0:
        p1 = probs[:, 1]
        y = labels.astype(int)
        best_floor = None
        for th in np.unique(np.concatenate([[0.0, 1.0], p1])):
            pred = (p1 >= th).astype(int)
            tp = int(np.sum((pred == 1) & (y == 1)))
            fp = int(np.sum((pred == 1) & (y == 0)))
            fn = int(np.sum((pred == 0) & (y == 1)))
            pr = tp / max(tp + fp, 1)
            rc = tp / max(tp + fn, 1)
            ok = (pr >= precision_floor) and (rc >= recall_floor)
            score = (1 if ok else 0, rc, pr, float(th))
            if best_floor is None or score > best_floor[0]:
                best_floor = (score, float(th))
        if best_floor is not None and best_floor[0][0] == 1:
            t_high = max(t_high, float(best_floor[1]))

    # enforce ordering and bounded ambiguity band
    if t_low >= t_high:
        mid = 0.5 * (t_low + t_high)
        t_low = min(t_low, mid - 1e-3)
        t_high = max(t_high, mid + 1e-3)
    width = t_high - t_low
    if width > max_ambiguity_width:
        mid = 0.5 * (t_low + t_high)
        half = 0.5 * max_ambiguity_width
        t_low = max(0.0, mid - half)
        t_high = min(1.0, mid + half)
    width = t_high - t_low
    if width < min_ambiguity_width:
        mid = 0.5 * (t_low + t_high)
        half = 0.5 * min_ambiguity_width
        t_low = max(0.0, mid - half)
        t_high = min(1.0, mid + half)
        if (t_high - t_low) < min_ambiguity_width:
            if t_low <= 0.0:
                t_high = min(1.0, min_ambiguity_width)
            elif t_high >= 1.0:
                t_low = max(0.0, 1.0 - min_ambiguity_width)
    return t_low, t_high


@dataclass
class IsotonicCalibrator:
    """Piecewise-linear isotonic map for P(malware) on validation data."""

    x_thresholds: list[float]
    y_thresholds: list[float]

    def transform(self, p: np.ndarray) -> np.ndarray:
        p = np.asarray(p, dtype=float).reshape(-1)
        if not self.x_thresholds:
            return p
        xs = np.asarray(self.x_thresholds, dtype=float)
        ys = np.asarray(self.y_thresholds, dtype=float)
        return np.clip(np.interp(p, xs, ys), 0.0, 1.0)

    def to_dict(self) -> dict:
        return {"x_thresholds": self.x_thresholds, "y_thresholds": self.y_thresholds}

    @classmethod
    def from_dict(cls, d: dict) -> "IsotonicCalibrator":
        return cls(
            x_thresholds=list(d.get("x_thresholds") or []),
            y_thresholds=list(d.get("y_thresholds") or []),
        )


def fit_isotonic(p_mal: np.ndarray, labels: np.ndarray, n_bins: int = 15) -> IsotonicCalibrator:
    """Bucket-sort calibration (isotonic on bin means)."""
    p = np.asarray(p_mal, dtype=float).reshape(-1)
    y = np.asarray(labels, dtype=int).reshape(-1)
    if len(p) < 4:
        return IsotonicCalibrator(x_thresholds=[0.0, 1.0], y_thresholds=[0.0, 1.0])
    order = np.argsort(p)
    p_sorted = p[order]
    y_sorted = y[order]
    bins = np.array_split(np.arange(len(p)), max(2, min(n_bins, len(p) // 2)))
    xs, ys = [0.0], [0.0]
    for b in bins:
        if len(b) == 0:
            continue
        xs.append(float(np.mean(p_sorted[b])))
        ys.append(float(np.mean(y_sorted[b])))
    xs.append(1.0)
    ys.append(1.0)
    # enforce monotonicity on y
    for i in range(1, len(ys)):
        ys[i] = max(ys[i], ys[i - 1])
    return IsotonicCalibrator(x_thresholds=xs, y_thresholds=ys)


@dataclass
class SplitConformalBundle:
    """Split conformal thresholds for fused malware score."""

    alpha: float
    q_malicious: float
    q_benign: float
    nonconformity_malicious: list[float]
    nonconformity_benign: list[float]

    def conformal_review(self, p_mal: float, label_hint: int | None = None) -> bool:
        """If True, route to analyst review (score in ambiguous conformal set)."""
        p = float(p_mal)
        nc_mal = 1.0 - p
        nc_ben = p
        if label_hint == 1:
            return nc_mal > self.q_malicious
        if label_hint == 0:
            return nc_ben > self.q_benign
        return nc_mal > self.q_malicious and nc_ben > self.q_benign

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "q_malicious": self.q_malicious,
            "q_benign": self.q_benign,
            "nonconformity_malicious": self.nonconformity_malicious,
            "nonconformity_benign": self.nonconformity_benign,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SplitConformalBundle":
        return cls(
            alpha=float(d.get("alpha", 0.05)),
            q_malicious=float(d.get("q_malicious", 1.0)),
            q_benign=float(d.get("q_benign", 1.0)),
            nonconformity_malicious=list(d.get("nonconformity_malicious") or []),
            nonconformity_benign=list(d.get("nonconformity_benign") or []),
        )


def fit_split_conformal(
    p_mal: np.ndarray,
    labels: np.ndarray,
    alpha: float = 0.05,
) -> SplitConformalBundle:
    p = np.asarray(p_mal, dtype=float).reshape(-1)
    y = np.asarray(labels, dtype=int).reshape(-1)
    nc_mal = (1.0 - p)[y == 1]
    nc_ben = p[y == 0]
    q_mal = float(np.quantile(nc_mal, 1.0 - alpha)) if len(nc_mal) else 1.0
    q_ben = float(np.quantile(nc_ben, 1.0 - alpha)) if len(nc_ben) else 1.0
    return SplitConformalBundle(
        alpha=float(alpha),
        q_malicious=q_mal,
        q_benign=q_ben,
        nonconformity_malicious=nc_mal.tolist(),
        nonconformity_benign=nc_ben.tolist(),
    )

