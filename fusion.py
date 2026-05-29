#!/usr/bin/env python3
"""Hybrid ML + rules fusion utilities.

For systematically miscalibrated binary heads, prefer retraining or val-set
calibration (temperature / Platt) in train_binary_model + calibration.py;
runtime weights here are a stopgap for reporting."""

from __future__ import annotations

import math
from dataclasses import asdict, dataclass


def heuristic_risk_score(features: dict) -> float:
    c2 = float(features.get("c2_signal", 0.0))
    inj = float(features.get("injection_signal", 0.0))
    cred = float(features.get("credential_access_signal", 0.0))
    score = (0.45 * c2) + (0.35 * inj) + (0.20 * cred)
    return max(0.0, min(1.0, score))


@dataclass
class UncertaintyGateDecision:
    triggered: bool
    reason: str | None
    metrics: dict

    def to_dict(self) -> dict:
        return asdict(self)


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


def _logit(p: float, eps: float = 1e-6) -> float:
    p = max(eps, min(1.0 - eps, float(p)))
    return float(math.log(p / (1.0 - p)))


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def ensemble_score_logit(
    binary_probability: float,
    dual_delta: float,
    heuristic_score: float,
    *,
    w_binary: float = 0.55,
    w_dual: float = 0.25,
    w_heuristic: float = 0.20,
) -> float:
    """Fuse calibrated components in logit space; return probability in [0, 1]."""
    dual_norm = max(0.0, min(1.0, (float(dual_delta) + 1.0) / 2.0))
    z = (
        w_binary * _logit(binary_probability)
        + w_dual * _logit(dual_norm)
        + w_heuristic * _logit(heuristic_score)
    )
    return _sigmoid(z)


def build_uncertainty_gate(
    *,
    dual_high_high: bool = False,
    mc_mal_variance: float = 0.0,
    mc_ben_variance: float = 0.0,
    ens_mal_variance: float = 0.0,
    ens_ben_variance: float = 0.0,
    binary_dual_gap: float = 0.0,
    dual_score_margin: float = 1.0,
    binary_probability: float | None = None,
    mc_variance_threshold: float = 0.03,
    ensemble_variance_threshold: float = 0.01,
    disagreement_threshold: float = 0.35,
    dual_score_margin_threshold: float = 0.10,
    abstention_mode: str = "calibrated",
    disagreement_p_low: float = 0.15,
    disagreement_p_high: float = 0.85,
) -> UncertaintyGateDecision:
    mode = str(abstention_mode or "calibrated").strip().lower()
    if mode == "disabled":
        return UncertaintyGateDecision(
            triggered=False,
            reason=None,
            metrics={"abstention_mode": mode},
        )

    reasons: list[str] = []
    max_mc_variance = max(float(mc_mal_variance), float(mc_ben_variance))
    max_ensemble_variance = max(float(ens_mal_variance), float(ens_ben_variance))
    if dual_high_high:
        reasons.append("dual_high_high_conflict")
    if max_mc_variance >= float(mc_variance_threshold):
        reasons.append("high_mc_dropout_variance")
    if max_ensemble_variance >= float(ensemble_variance_threshold):
        reasons.append("high_deep_ensemble_variance")

    apply_disagreement = True
    if mode == "calibrated" and binary_probability is not None:
        p_bin = float(binary_probability)
        apply_disagreement = disagreement_p_low < p_bin < disagreement_p_high
    if apply_disagreement and abs(float(binary_dual_gap)) >= float(disagreement_threshold):
        reasons.append("binary_dual_disagreement")
    if float(dual_score_margin) <= float(dual_score_margin_threshold):
        reasons.append("low_dual_margin")

    return UncertaintyGateDecision(
        triggered=bool(reasons),
        reason="|".join(reasons) if reasons else None,
        metrics={
            "abstention_mode": mode,
            "dual_high_high": bool(dual_high_high),
            "mc_variance_threshold": float(mc_variance_threshold),
            "ensemble_variance_threshold": float(ensemble_variance_threshold),
            "disagreement_threshold": float(disagreement_threshold),
            "dual_score_margin_threshold": float(dual_score_margin_threshold),
            "disagreement_p_low": float(disagreement_p_low),
            "disagreement_p_high": float(disagreement_p_high),
            "binary_probability": float(binary_probability) if binary_probability is not None else None,
            "disagreement_gate_active": bool(apply_disagreement),
            "mc_mal_variance": float(mc_mal_variance),
            "mc_ben_variance": float(mc_ben_variance),
            "ens_mal_variance": float(ens_mal_variance),
            "ens_ben_variance": float(ens_ben_variance),
            "binary_dual_gap": float(binary_dual_gap),
            "dual_score_margin": float(dual_score_margin),
        },
    )


def routing_tier(
    *,
    ensemble: float,
    p_malware: float,
    dual_margin: float,
    structural_attack: bool,
    conformal_review: bool = False,
    auto_malicious_p: float = 0.95,
    auto_benign_p: float = 0.05,
    dual_margin_high: float = 0.15,
) -> str:
    """SOC-style routing tier: auto_benign | auto_malicious | analyst_review."""
    if conformal_review:
        return "analyst_review"
    if (
        float(p_malware) >= auto_malicious_p
        and structural_attack
        and float(dual_margin) >= dual_margin_high
    ):
        return "auto_malicious"
    if float(p_malware) <= auto_benign_p and not structural_attack and float(ensemble) <= 0.40:
        return "auto_benign"
    return "analyst_review"


def final_triage(
    ensemble: float,
    low: float = 0.40,
    high: float = 0.60,
    *,
    uncertainty_gate: UncertaintyGateDecision | dict | None = None,
) -> str:
    if uncertainty_gate:
        triggered = (
            bool(uncertainty_gate.get("triggered"))
            if isinstance(uncertainty_gate, dict)
            else bool(uncertainty_gate.triggered)
        )
        if triggered:
            return "needs_analyst_review"
    if ensemble >= high:
        return "likely_malicious"
    if ensemble <= low:
        return "likely_benign"
    return "needs_analyst_review"
