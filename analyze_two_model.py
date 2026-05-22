#!/usr/bin/env python3
"""Two-model fused analysis CLI with model-derived evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd
import torch
import torch.nn.functional as F

import numpy as np

from analysis_schema import (
    HIGH_THRESHOLD,
    LOW_THRESHOLD,
    SCHEMA_VERSION,
    ReasoningTypes,
    SampleAnalysis,
    bucket,
    triage_state,
    triage_state_two_model_fused,
)
from analyze_binary_model import _apply_feature_group_weights, build_model, explain_binary
from calibration import apply_temperature
from dataset import MalwareGraphDataset
from fusion import ensemble_score, final_triage, heuristic_risk_score
from utils.inference_align import align_pyg_data_to_binary_checkpoint
from one_class_gnn import build_model_from_payload, explain_graph, score_graph


def _clip_logits_binary(logits: torch.Tensor, clip: float) -> torch.Tensor:
    if clip is None or float(clip) <= 0:
        return logits
    c = float(clip)
    return torch.clamp(logits, -c, c)


GRAPH_ATTR_NAMES = [
    "max_score",
    "attack_steps",
    "injections",
    "c2_conns",
    "log_nodes",
    "log_edges",
    "graph_density",
    "behavioural_suspects_found",
    "lolbin_c2_found",
    "ransom_note_found",
    "log_rwx_injections",
    "triage_confidence",
    "benign_clean_software_flag",
    "benign_admin_or_security_tool_flag",
    "signal_temporal_chain_count",
    "signal_api_semantic_count",
    "signal_persistence_count",
    "signal_credential_access_count_manifest",
    "signal_privilege_escalation_count",
    "signal_svchost_lineage_anomaly_count",
    "signal_svchost_cmdline_anomaly_count",
    "signal_dll_trust_anomaly_count",
    "signal_service_orphan_count",
    "signal_lolbin_chain_count",
    "signal_c2_relation_pattern_count",
    "signal_benign_high_volume_hub_log",
    "signal_rwx_thread_context_log",
    "edge_spawned_by",
    "edge_belongs_to",
    "edge_loaded_into",
    "edge_allocated_in",
    "edge_injected_into",
    "edge_connects_from",
    "edge_connects_to",
    "edge_owned_by",
    "edge_points_to",
    "edge_loaded_in_kernel",
    "edge_intent_c2",
    "edge_intent_injection",
    "edge_intent_credential_access",
    "edge_temporal_near_creation",
    "edge_temporal_execution_chain",
    "edge_api_semantic_activity",
    "edge_parent_child_anomaly",
    "edge_persistence_behavior",
    "edge_privilege_escalation_indicator",
    "edge_svchost_lineage_anomaly",
    "edge_svchost_cmdline_anomaly",
    "edge_dll_trust_anomaly",
    "edge_c2_relation_pattern",
    "edge_service_hosts",
    "edge_service_correlation_ok",
    "edge_service_orphan",
    "edge_lolbin_execution_chain",
    "motif_ransom_decryptor_log",
    "motif_tor_tasksvc_log",
    "motif_hex_image_name_log",
    "motif_memory_per_process_log",
    "motif_lolbin_path_log",
    "motif_injection_path_log",
    "motif_persistence_path_log",
]


def _reasoning_types(malware_score: float, benign_score: float, malware_evd: dict, benign_evd: dict) -> ReasoningTypes:
    def _has_graph_attr(evd: dict, names: set[str]) -> bool:
        for item in evd.get("top_graph_attrs", []):
            idx = int(item.get("feature_index", -1))
            if 0 <= idx < len(GRAPH_ATTR_NAMES) and GRAPH_ATTR_NAMES[idx] in names:
                return True
        return False

    # Require structural injection edges (or injection-path motif), not manifest-only RWX counts.
    inj_names = {
        "edge_injected_into",
        "edge_intent_injection",
        "motif_injection_path_log",
    }
    c2_names = {"c2_conns", "lolbin_c2_found", "edge_connects_from", "edge_connects_to"}
    chain_names = {"attack_steps", "edge_spawned_by"}
    return ReasoningTypes(
        execution_chain_anomaly=_has_graph_attr(malware_evd, chain_names),
        memory_injection_evidence=_has_graph_attr(malware_evd, inj_names),
        credential_access_evidence=False,
        network_c2_evidence=_has_graph_attr(malware_evd, c2_names),
        benign_admin_tooling_likelihood=(benign_score >= 0.60 and malware_score < 0.60 and len(benign_evd.get("top_nodes", [])) > 0),
    )


def _normalize_evidence(evd: dict) -> dict:
    top_graph_attrs = []
    for item in evd.get("top_graph_attrs", []):
        idx = int(item.get("feature_index", -1))
        name = GRAPH_ATTR_NAMES[idx] if 0 <= idx < len(GRAPH_ATTR_NAMES) else f"graph_attr_{idx}"
        top_graph_attrs.append(
            {
                "feature_index": idx,
                "feature_name": name,
                "importance": float(item.get("importance", 0.0)),
            }
        )
    return {
        "distance": float(evd.get("distance", 0.0)),
        "top_nodes": evd.get("top_nodes", []),
        "edge_pairs": evd.get("edge_pairs", []),
        "top_graph_attrs": top_graph_attrs,
    }


def _build_findings(mal_evd: dict, ben_evd: dict) -> list[dict]:
    findings: list[dict] = []
    for item in mal_evd.get("top_graph_attrs", [])[:3]:
        findings.append(
            {
                "type": "malware_model_signal",
                "feature": item.get("feature_name"),
                "importance": round(float(item.get("importance", 0.0)), 6),
                "evidence": "high-contribution feature in malware one-class model",
            }
        )
    for item in ben_evd.get("top_graph_attrs", [])[:2]:
        findings.append(
            {
                "type": "benign_model_signal",
                "feature": item.get("feature_name"),
                "importance": round(float(item.get("importance", 0.0)), 6),
                "evidence": "high-contribution feature in benign one-class model",
            }
        )
    return findings


def _narrative(
    malware_score: float,
    benign_score: float,
    state: str,
    mal_evd: dict,
    ben_evd: dict,
    *,
    binary_p_effective: float | None = None,
    dual_triage: str | None = None,
    fused_three_way: str | None = None,
) -> str:
    mal_feats = [x.get("feature_name") for x in mal_evd.get("top_graph_attrs", [])[:3]]
    ben_feats = [x.get("feature_name") for x in ben_evd.get("top_graph_attrs", [])[:3]]
    base = (
        f"Triage={state}. Malware model conformity={malware_score:.3f} ({bucket(malware_score)}), "
        f"benign model conformity={benign_score:.3f} ({bucket(benign_score)}). "
        f"Malware evidence strongest on {mal_feats}. Benign evidence strongest on {ben_feats}."
    )
    if binary_p_effective is not None and dual_triage is not None and fused_three_way is not None:
        base += (
            f" Binary GNN P(malware) effective={binary_p_effective:.3f} (after fusion gate); "
            f"dual_triage={dual_triage}, fusion_3way={fused_three_way}."
        )
    return base


def _validate_fusion_args(wb: float, wd: float, wh: float, t_low: float, t_high: float) -> None:
    if wb < 0 or wd < 0 or wh < 0:
        raise SystemExit("[Analyze] fusion weights must be non-negative")
    s = wb + wd + wh
    if abs(s - 1.0) > 1e-5:
        raise SystemExit(f"[Analyze] fusion weights must sum to 1.0, got {s:.6f}")
    if not (0.0 < t_low < t_high < 1.0):
        raise SystemExit("[Analyze] require 0 < --fusion-triage-low < --fusion-triage-high < 1")


def _uncertainty_from_scores(scores: list[float]) -> dict:
    arr = np.asarray(scores, dtype=float)
    if arr.size == 0:
        return {"method": "mc_dropout", "mean": 0.0, "variance": 0.0}
    return {"method": "mc_dropout", "mean": float(arr.mean()), "variance": float(arr.var())}


def run(args):
    _validate_fusion_args(
        args.fusion_w_binary,
        args.fusion_w_dual,
        args.fusion_w_heuristic,
        args.fusion_triage_low,
        args.fusion_triage_high,
    )
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    manifest_path = Path(args.manifest)
    base_dir = Path(args.base_dir) if args.base_dir else manifest_path.parent
    df = pd.read_csv(manifest_path)
    sample_id_by_folder = {str(r["folder"]): str(r.get("sample_id", "")) for _, r in df.iterrows()}
    label_by_folder = {str(r["folder"]): int(r["label"]) for _, r in df.iterrows()}
    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=str(base_dir),
        include_uncertain=True,
        include_unknown=False,
        target="label",
    )

    malware_payload = torch.load(args.malware_model, map_location="cpu")
    benign_payload = torch.load(args.benign_model, map_location="cpu")
    malware_model, malware_center, malware_radius = build_model_from_payload(malware_payload, device)
    benign_model, benign_center, benign_radius = build_model_from_payload(benign_payload, device)
    malware_ensemble = []
    benign_ensemble = []
    for pth in (args.malware_ensemble_models or []):
        pld = torch.load(pth, map_location="cpu")
        malware_ensemble.append(build_model_from_payload(pld, device))
    for pth in (args.benign_ensemble_models or []):
        pld = torch.load(pth, map_location="cpu")
        benign_ensemble.append(build_model_from_payload(pld, device))

    binary_model_path = Path(args.binary_model)
    if not binary_model_path.is_file():
        raise SystemExit(f"[Analyze] binary model not found: {binary_model_path.resolve()}")
    binary_payload = torch.load(args.binary_model, map_location="cpu")
    binary_model = build_model(binary_payload, device)
    binary_ensemble_models: list = []
    for pth in args.binary_ensemble_models or []:
        pld = torch.load(pth, map_location="cpu")
        binary_ensemble_models.append(build_model(pld, device))

    out = []
    for idx in range(len(ds)):
        data = ds[idx]
        folder = str(getattr(data, "name", f"{idx:03d}"))

        malware_score, _ = score_graph(malware_model, malware_center, malware_radius, data, device)
        benign_score, _ = score_graph(benign_model, benign_center, benign_radius, data, device)
        mal_ens_scores = [malware_score]
        ben_ens_scores = [benign_score]
        for m, c, r in malware_ensemble:
            s, _ = score_graph(m, c, r, data, device)
            mal_ens_scores.append(s)
        for m, c, r in benign_ensemble:
            s, _ = score_graph(m, c, r, data, device)
            ben_ens_scores.append(s)
        malware_score = float(np.mean(mal_ens_scores))
        benign_score = float(np.mean(ben_ens_scores))
        mc_mal = [malware_score]
        mc_ben = [benign_score]
        if args.mc_samples > 1:
            malware_model.train()
            benign_model.train()
            for _ in range(args.mc_samples - 1):
                s1, _ = score_graph(
                    malware_model, malware_center, malware_radius, data, device, force_eval=False
                )
                s2, _ = score_graph(
                    benign_model, benign_center, benign_radius, data, device, force_eval=False
                )
                mc_mal.append(s1)
                mc_ben.append(s2)
            malware_model.eval()
            benign_model.eval()
        malware_raw = explain_graph(malware_model, malware_center, data, device)
        benign_raw = explain_graph(benign_model, benign_center, data, device)
        malware_evd = _normalize_evidence(malware_raw)
        benign_evd = _normalize_evidence(benign_raw)
        state_dual = triage_state(malware_score, benign_score)
        reasons = _reasoning_types(malware_score, benign_score, malware_evd, benign_evd)
        findings = _build_findings(malware_evd, benign_evd)

        data_bin = align_pyg_data_to_binary_checkpoint(data, binary_payload)
        d = data_bin.to(device)
        batch = torch.zeros(d.x.size(0), dtype=torch.long, device=device)
        t_bin = float(binary_payload.get("temperature", 1.0))
        lc = float(getattr(args, "logit_clip", 0.0) or 0.0)
        with torch.no_grad():
            logits_b = binary_model(
                d.x,
                d.edge_index,
                batch,
                graph_attr=_apply_feature_group_weights(getattr(d, "graph_attr", None), binary_payload),
                edge_attr=getattr(d, "edge_attr", None),
            )
            logits_b = _clip_logits_binary(logits_b, lc)
            probs_raw = F.softmax(logits_b, dim=1).detach().cpu().numpy()
            probs_cal = apply_temperature(logits_b.detach().cpu().numpy(), t_bin)
            ens_probs = [float(probs_cal[0, 1])]
            for bm in binary_ensemble_models:
                lg = bm(
                    d.x,
                    d.edge_index,
                    batch,
                    graph_attr=_apply_feature_group_weights(getattr(d, "graph_attr", None), binary_payload),
                    edge_attr=getattr(d, "edge_attr", None),
                )
                lg = _clip_logits_binary(lg, lc)
                pb = apply_temperature(lg.detach().cpu().numpy(), t_bin)
                ens_probs.append(float(pb[0, 1]))
        p_mal_raw = float(probs_raw[0, 1])
        p_mal_cal = float(np.mean(ens_probs))

        dual_high_high = (
            state_dual == "needs_analyst_review"
            and malware_score >= HIGH_THRESHOLD
            and benign_score >= HIGH_THRESHOLD
        )
        gate_on = bool(args.fusion_gate_dual_high_high)
        gate_applied = gate_on and dual_high_high
        p_mal_eff = (0.5 * p_mal_cal + 0.25) if gate_applied else p_mal_cal

        hr = heuristic_risk_score(
            {
                "c2_signal": float(reasons.network_c2_evidence),
                "injection_signal": float(reasons.memory_injection_evidence),
                "credential_access_signal": float(reasons.credential_access_evidence),
            }
        )
        ens = ensemble_score(
            p_mal_eff,
            malware_score - benign_score,
            hr,
            w_binary=args.fusion_w_binary,
            w_dual=args.fusion_w_dual,
            w_heuristic=args.fusion_w_heuristic,
        )
        state_fused = final_triage(ens, low=args.fusion_triage_low, high=args.fusion_triage_high)
        state = triage_state_two_model_fused(state_dual, state_fused, reasons.memory_injection_evidence)
        narrative = _narrative(
            malware_score,
            benign_score,
            state,
            malware_evd,
            benign_evd,
            binary_p_effective=p_mal_eff,
            dual_triage=state_dual,
            fused_three_way=state_fused,
        )
        fusion = {
            "dual_triage_state": state_dual,
            "binary_malware_probability_raw": round(p_mal_raw, 6),
            "binary_malware_probability_calibrated": round(p_mal_cal, 6),
            "binary_probability_effective": round(p_mal_eff, 6),
            "dual_high_high_gate_applied": gate_applied,
            "heuristic_risk_score": round(hr, 6),
            "ensemble_score": round(ens, 6),
            "final_triage_state": state_fused,
        }
        uncertainty = {
            "malware_model": _uncertainty_from_scores(mc_mal),
            "benign_model": _uncertainty_from_scores(mc_ben),
            "deep_ensemble": {
                "malware_size": len(mal_ens_scores),
                "malware_variance": float(np.var(mal_ens_scores)),
                "benign_size": len(ben_ens_scores),
                "benign_variance": float(np.var(ben_ens_scores)),
            },
        }
        attention_evidence = {
            "method": "edge_attention_proxy",
            "top_attended_edges": malware_evd.get("edge_pairs", [])[:5],
        }

        manifest_label = label_by_folder.get(folder, int(data.y.item()))
        out.append(
            SampleAnalysis(
                sample_id=(sample_id_by_folder.get(folder) or f"{idx+1:02d}"),
                folder=folder,
                malware_pattern_score=round(malware_score, 6),
                benign_conformity_score=round(benign_score, 6),
                delta_score=round(malware_score - benign_score, 6),
                triage_state=state,
                label_from_manifest=manifest_label,
                confidence_split={
                    "malware_evidence": bucket(malware_score),
                    "benign_baseline_match": bucket(benign_score),
                },
                reasoning_types=reasons.__dict__,
                behavioral_findings=findings,
                malware_model_evidence=malware_evd,
                benign_model_evidence=benign_evd,
                fusion=fusion,
                uncertainty=uncertainty,
                attention_evidence=attention_evidence,
                narrative=narrative,
            ).to_dict()
        )

    fusion_config = {
        "w_binary": args.fusion_w_binary,
        "w_dual": args.fusion_w_dual,
        "w_heuristic": args.fusion_w_heuristic,
        "triage_low": args.fusion_triage_low,
        "triage_high": args.fusion_triage_high,
        "gate_dual_high_high": bool(args.fusion_gate_dual_high_high),
    }
    payload = {
        "summary": {
            "schema_version": SCHEMA_VERSION,
            "samples_analyzed": len(out),
            "triage_counts": {
                "likely_malicious": sum(1 for x in out if x["triage_state"] == "likely_malicious"),
                "needs_analyst_review": sum(1 for x in out if x["triage_state"] == "needs_analyst_review"),
                "anomalous_unknown": sum(1 for x in out if x["triage_state"] == "anomalous_unknown"),
                "likely_benign": sum(1 for x in out if x["triage_state"] == "likely_benign"),
            },
            "thresholds": {"high": 0.60, "low": LOW_THRESHOLD},
            "fusion_config": fusion_config,
        },
        "samples": out,
    }
    out_path = Path(args.output_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[Analyze] wrote {out_path} ({len(out)} samples)")
    return payload


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Run two-model fused analysis")
    p.add_argument("manifest", help="Path to dataset_manifest.csv")
    p.add_argument("--base-dir", default=None, dest="base_dir")
    p.add_argument("--malware-model", default="outputs/malware_model.pt", dest="malware_model")
    p.add_argument("--benign-model", default="outputs/benign_model.pt", dest="benign_model")
    p.add_argument("--output-json", default="outputs/two_model_analysis.json", dest="output_json")
    p.add_argument("--mc-samples", type=int, default=8, dest="mc_samples")
    p.add_argument("--malware-ensemble-models", nargs="*", default=None, dest="malware_ensemble_models")
    p.add_argument("--benign-ensemble-models", nargs="*", default=None, dest="benign_ensemble_models")
    p.add_argument(
        "--binary-model",
        default="outputs/binary_model.pt",
        dest="binary_model",
        help="Supervised binary GNN checkpoint (required); fusion uses calibrated P(malware) from this model.",
    )
    p.add_argument(
        "--binary-ensemble-models",
        nargs="*",
        default=None,
        dest="binary_ensemble_models",
        help="Optional extra binary checkpoints; calibrated probabilities are averaged.",
    )
    p.add_argument("--fusion-w-binary", type=float, default=0.35, dest="fusion_w_binary", help="Fusion weight on binary P(malware)")
    p.add_argument("--fusion-w-dual", type=float, default=0.40, dest="fusion_w_dual", help="Fusion weight on normalized dual delta")
    p.add_argument("--fusion-w-heuristic", type=float, default=0.25, dest="fusion_w_heuristic", help="Fusion weight on heuristic risk")
    p.add_argument(
        "--fusion-triage-low",
        type=float,
        default=0.40,
        dest="fusion_triage_low",
        help="Ensemble score below this maps to likely_benign in fusion 3-way triage",
    )
    p.add_argument(
        "--fusion-triage-high",
        type=float,
        default=0.65,
        dest="fusion_triage_high",
        help="Ensemble score at or above this maps to likely_malicious in fusion 3-way triage",
    )
    p.add_argument(
        "--fusion-gate-dual-high-high/--no-fusion-gate-dual-high-high",
        default=True,
        action=argparse.BooleanOptionalAction,
        dest="fusion_gate_dual_high_high",
        help="When dual is needs_analyst_review and both one-class scores are HIGH, blend binary prob: 0.5*p+0.25 before ensemble.",
    )
    p.add_argument(
        "--logit-clip",
        type=float,
        default=0.0,
        dest="logit_clip",
        help="If >0, clamp binary GNN logits to [-clip, clip] before softmax/temperature.",
    )
    run(p.parse_args())

