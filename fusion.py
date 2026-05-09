#!/usr/bin/env python3
"""Hybrid ML + rules fusion utilities.

For systematically miscalibrated binary heads, prefer retraining or val-set
calibration (temperature / Platt) in train_binary_model + calibration.py;
runtime weights here are a stopgap for reporting."""

from __future__ import annotations


def heuristic_risk_score(features: dict) -> float:
    c2 = float(features.get("c2_signal", 0.0))
    inj = float(features.get("injection_signal", 0.0))
    cred = float(features.get("credential_access_signal", 0.0))
    score = (0.45 * c2) + (0.35 * inj) + (0.20 * cred)
    return max(0.0, min(1.0, score))


def ensemble_score(
    binary_probability: float,
    dual_delta: float,
    heuristic_score: float,
    *,
    w_binary: float = 0.55,
    w_dual: float = 0.25,
    w_heuristic: float = 0.20,
) -> float:
    """Convex blend of calibrated binary prob, normalized dual delta, and heuristic."""
    dual_norm = max(0.0, min(1.0, (dual_delta + 1.0) / 2.0))
    raw = (
        (w_binary * float(binary_probability))
        + (w_dual * dual_norm)
        + (w_heuristic * float(heuristic_score))
    )
    return max(0.0, min(1.0, raw))


def final_triage(ensemble: float, low: float = 0.40, high: float = 0.60) -> str:
    if ensemble >= high:
        return "likely_malicious"
    if ensemble <= low:
        return "likely_benign"
    return "needs_analyst_review"
