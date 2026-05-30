#!/usr/bin/env python3
"""
Shared schema/types for two-model analysis outputs.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import List


HIGH_THRESHOLD = 0.60
LOW_THRESHOLD = 0.40
SCHEMA_VERSION = "2.4"


def bucket(score: float, *, low: float = LOW_THRESHOLD, high: float = HIGH_THRESHOLD) -> str:
    if score >= high:
        return "HIGH"
    if score < low:
        return "LOW"
    return "MEDIUM"


def triage_state(
    malware_score: float,
    benign_score: float,
    *,
    malware_low: float = LOW_THRESHOLD,
    malware_high: float = HIGH_THRESHOLD,
    benign_low: float = LOW_THRESHOLD,
    benign_high: float = HIGH_THRESHOLD,
) -> str:
    malware_high_hit = malware_score >= malware_high
    benign_high_hit = benign_score >= benign_high
    malware_low_hit = malware_score < malware_low
    benign_low_hit = benign_score < benign_low

    if malware_high_hit and benign_low_hit:
        return "likely_malicious"
    if malware_high_hit and benign_high_hit:
        return "needs_analyst_review"
    if malware_low_hit and benign_low_hit:
        return "anomalous_unknown"
    if malware_low_hit and benign_high_hit:
        return "likely_benign"
    return "needs_analyst_review"


def triage_state_two_model_fused(
    state_dual: str,
    state_fused: str,
    memory_injection_evidence: bool,
    *,
    uncertainty_gate_triggered: bool = False,
) -> str:
    """
    Four-way triage for two-model reports: combine dual one-class triage with
    fusion final_triage (3-way), plus injection guardrail (never likely_benign).
    """
    if uncertainty_gate_triggered:
        return "needs_analyst_review"
    if state_dual == "anomalous_unknown":
        if state_fused == "likely_malicious":
            return "likely_malicious"
        return "anomalous_unknown"

    if memory_injection_evidence:
        if state_fused == "likely_malicious":
            return "likely_malicious"
        if state_dual == "likely_malicious":
            return "likely_malicious"
        return "needs_analyst_review"

    if state_fused == "likely_malicious":
        return "likely_malicious"
    if state_fused == "likely_benign":
        if state_dual == "likely_malicious":
            return "needs_analyst_review"
        return "likely_benign"
    return "needs_analyst_review"


def triage_state_binary(prob_malware: float, threshold_low: float, threshold_high: float, high_risk: bool) -> str:
    if prob_malware >= threshold_high:
        return "likely_malicious"
    if prob_malware <= threshold_low:
        return "likely_benign"
    return "high_risk_ambiguous" if high_risk else "low_risk_ambiguous"


@dataclass
class ReasoningTypes:
    execution_chain_anomaly: bool
    memory_injection_evidence: bool
    credential_access_evidence: bool
    network_c2_evidence: bool
    benign_admin_tooling_likelihood: bool


@dataclass
class SampleAnalysis:
    sample_id: str
    folder: str
    malware_pattern_score: float
    benign_conformity_score: float
    delta_score: float
    triage_state: str
    label_from_manifest: int
    confidence_split: dict
    reasoning_types: dict
    behavioral_findings: List[dict]
    malware_model_evidence: dict
    benign_model_evidence: dict
    narrative: str
    train_eligible: bool | None = None
    uncertain: bool | None = None
    uncertain_reason: str = ""
    abstention_reason: str | None = None
    uncertainty_gate_triggered: bool | None = None
    fusion: dict | None = None
    uncertainty: dict | None = None
    attention_evidence: dict | None = None
    benign_subtype: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class BinarySampleAnalysis:
    sample_id: str
    folder: str
    malware_probability_raw: float
    malware_probability_calibrated: float
    threshold_low: float
    threshold_high: float
    triage_state: str
    behavioral_findings: List[dict]
    binary_model_evidence: dict
    narrative: str
    label_from_manifest: int = -1
    benign_subtype: str = ""
    train_eligible: bool | None = None
    uncertain: bool | None = None
    uncertain_reason: str = ""
    abstention_reason: str | None = None
    uncertainty_gate_triggered: bool | None = None
    fusion: dict | None = None
    uncertainty: dict | None = None
    attention_evidence: dict | None = None
    calibration_diagnostics: dict | None = None
    reasoning_tags: List[str] | None = None
    explainability_diversity: dict | None = None
    relation_triplets: List[dict] | None = None

    def to_dict(self) -> dict:
        return asdict(self)

