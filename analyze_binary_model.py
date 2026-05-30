#!/usr/bin/env python3
"""Analyze samples with binary GNN + calibrated confidence and evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from analysis_schema import SCHEMA_VERSION
from calibration import apply_temperature
from dataset import (
    DEFAULT_ALLOWED_BENIGN_SUBTYPES,
    MalwareGraphDataset,
    governance_load_options,
    manifest_row_governance,
)
from fusion import ensemble_score, final_triage, heuristic_risk_score
from model import GINEMalwareClassifier
from utils.evidence_metadata import enrich_edge, enrich_node
from utils.inference_align import align_pyg_data_to_binary_checkpoint

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

FEATURE_GROUPS = {
    "generic_structure": {"log_nodes", "log_edges", "graph_density"},
    "injection_noise": {"injections", "log_rwx_injections"},
    "temporal_intent": {"signal_temporal_chain_count", "edge_temporal_near_creation", "edge_temporal_execution_chain"},
    "api_semantics": {"signal_api_semantic_count", "edge_api_semantic_activity"},
    "persistence": {"signal_persistence_count", "edge_persistence_behavior"},
    "credential_access": {"signal_credential_access_count_manifest", "edge_intent_credential_access"},
    "privilege_escalation": {"signal_privilege_escalation_count", "edge_privilege_escalation_indicator", "edge_parent_child_anomaly"},
    "lineage_anomaly": {"signal_svchost_lineage_anomaly_count", "edge_svchost_lineage_anomaly", "edge_lolbin_execution_chain"},
    "service_mismatch": {"signal_service_orphan_count", "edge_service_orphan", "edge_service_hosts"},
    "dll_trust_context": {"signal_dll_trust_anomaly_count", "edge_dll_trust_anomaly"},
    "ransom_chain_motifs": {
        "motif_ransom_decryptor_log",
        "motif_tor_tasksvc_log",
        "motif_hex_image_name_log",
        "motif_memory_per_process_log",
        "motif_lolbin_path_log",
        "motif_injection_path_log",
        "motif_persistence_path_log",
    },
}


def _apply_feature_group_weights(graph_attr: torch.Tensor | None, payload: dict) -> torch.Tensor | None:
    if graph_attr is None:
        return graph_attr
    group_weights = payload.get("feature_group_weights") or {}
    group_indices = payload.get("feature_groups") or {}
    if not group_weights or not group_indices:
        return graph_attr
    width = int(graph_attr.size(1))
    mul = torch.ones((1, width), dtype=graph_attr.dtype, device=graph_attr.device)
    for group, idxs in group_indices.items():
        w = float(group_weights.get(group, 1.0))
        for idx in idxs:
            i = int(idx)
            if 0 <= i < width:
                mul[:, i] = w
    return graph_attr * mul


def _reasoning_tags(top_graph_attrs: list[dict]) -> list[str]:
    tags = []
    names = {str(x.get("feature_name", "")) for x in top_graph_attrs}
    for group, feats in FEATURE_GROUPS.items():
        if any(n in feats for n in names):
            tags.append(group)
    return tags


def _relation_triplets(evidence: dict) -> list[dict]:
    out = []
    for e in evidence.get("edge_pairs", [])[:5]:
        out.append(
            {
                "src_node_id": int(e.get("src", -1)),
                "relation": "high_attention_edge",
                "dst_node_id": int(e.get("dst", -1)),
                "importance": float(e.get("importance", 0.0)),
            }
        )
    return out


def _clip_logits_tensor(logits: torch.Tensor, clip: float) -> torch.Tensor:
    if clip is None or float(clip) <= 0:
        return logits
    c = float(clip)
    return torch.clamp(logits, -c, c)


def build_model(payload: dict, device: torch.device) -> GINEMalwareClassifier:
    model = GINEMalwareClassifier(
        in_channels=int(payload["in_channels"]),
        hidden=int(payload["hidden"]),
        layers=int(payload["layers"]),
        dropout=float(payload["dropout"]),
        num_classes=2,
        edge_emb_dim=int(payload["edge_emb_dim"]),
    ).to(device)
    # lazy head init
    with torch.no_grad():
        dummy_x = torch.zeros((2, int(payload["in_channels"])), device=device)
        dummy_edge = torch.tensor([[0], [1]], dtype=torch.long, device=device)
        dummy_batch = torch.zeros(2, dtype=torch.long, device=device)
        dummy_edge_attr = torch.zeros(1, dtype=torch.long, device=device)
        graph_attr_dim = int(payload.get("graph_attr_dim", len(GRAPH_ATTR_NAMES)))
        dummy_ga = torch.zeros((1, graph_attr_dim), device=device)
        _ = model(dummy_x, dummy_edge, dummy_batch, graph_attr=dummy_ga, edge_attr=dummy_edge_attr)
    model.load_state_dict(payload["state_dict"], strict=True)
    model.eval()
    return model


def explain_binary(model, data, device, payload: dict) -> dict:
    d = data.clone().to(device)
    d.x = d.x.detach().requires_grad_(True)
    graph_attr = getattr(d, "graph_attr", None)
    if graph_attr is not None:
        graph_attr = graph_attr.detach().requires_grad_(True)
    batch = torch.zeros(d.x.size(0), dtype=torch.long, device=device)
    weighted_graph_attr = _apply_feature_group_weights(graph_attr, payload)
    if weighted_graph_attr is not None:
        weighted_graph_attr.retain_grad()
    logits = model(d.x, d.edge_index, batch, graph_attr=weighted_graph_attr, edge_attr=getattr(d, "edge_attr", None))
    target = logits[0, 1]
    model.zero_grad(set_to_none=True)
    target.backward()

    node_sal = (d.x.grad * d.x).abs().sum(dim=1).detach().cpu().numpy()
    top_idx = np.argsort(-node_sal)[:5]
    top_nodes = [enrich_node(d, int(i), float(node_sal[i])) for i in top_idx]

    edge_pairs = []
    if d.edge_index is not None and d.edge_index.size(1) > 0:
        src = d.edge_index[0].detach().cpu().numpy()
        dst = d.edge_index[1].detach().cpu().numpy()
        scores = []
        for edge_i, (u, v) in enumerate(zip(src.tolist(), dst.tolist())):
            s = float(node_sal[int(u)]) + float(node_sal[int(v)])
            scores.append((s, int(edge_i), int(u), int(v)))
        scores.sort(reverse=True)
        edge_pairs = [enrich_edge(d, edge_i, u, v, s) for s, edge_i, u, v in scores[:5]]

    top_graph_attrs = []
    grad_src = None
    val_src = None
    if weighted_graph_attr is not None and weighted_graph_attr.grad is not None:
        grad_src = weighted_graph_attr.grad
        val_src = weighted_graph_attr
    elif graph_attr is not None and graph_attr.grad is not None:
        grad_src = graph_attr.grad
        val_src = graph_attr
    if grad_src is not None and val_src is not None:
        ga = (grad_src * val_src).abs().detach().cpu().numpy().reshape(-1)
        idx = np.argsort(-ga)[:5]
        for i in idx:
            name = GRAPH_ATTR_NAMES[i] if 0 <= i < len(GRAPH_ATTR_NAMES) else f"graph_attr_{i}"
            top_graph_attrs.append(
                {"feature_index": int(i), "feature_name": name, "importance": float(ga[i])}
            )
    return {"top_nodes": top_nodes, "edge_pairs": edge_pairs, "top_graph_attrs": top_graph_attrs}


def triage_state_binary(p: float, t_low: float, t_high: float, high_risk: bool) -> str:
    if p >= t_high:
        return "likely_malicious"
    if p <= t_low:
        return "likely_benign"
    return "high_risk_ambiguous" if high_risk else "low_risk_ambiguous"


def run(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    payload = torch.load(args.model, map_location="cpu")
    model = build_model(payload, device)
    ensemble_models = []
    for pth in (args.ensemble_models or []):
        pld = torch.load(pth, map_location="cpu")
        ensemble_models.append(build_model(pld, device))
    t = float(payload.get("temperature", 1.0))
    t_low = float(payload.get("threshold_low", 0.35))
    t_high = float(payload.get("threshold_high", 0.65))
    max_ambiguity_width = float(payload.get("max_ambiguity_width", args.max_ambiguity_width))
    min_ambiguity_width = float(payload.get("min_ambiguity_width", args.min_ambiguity_width))
    if (t_high - t_low) > max_ambiguity_width:
        mid = 0.5 * (t_low + t_high)
        half = 0.5 * max_ambiguity_width
        t_low = max(0.0, mid - half)
        t_high = min(1.0, mid + half)
    if (t_high - t_low) < min_ambiguity_width:
        t_low = max(0.0, t_high - min_ambiguity_width)

    manifest = Path(args.manifest)
    base_dir = args.base_dir or str(manifest.parent)
    df = pd.read_csv(manifest)
    sample_id_by_folder = {str(r["folder"]): str(r.get("sample_id", "")) for _, r in df.iterrows()}
    governance_by_folder = {
        str(r["folder"]): manifest_row_governance(dict(r)) for _, r in df.iterrows()
    }
    profile = str(payload.get("graph_attr_profile", "full") or "full")
    view = str(payload.get("graph_view", "full") or "full")
    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=base_dir,
        target="label",
        graph_attr_profile=profile,
        graph_view=view,
        **governance_load_options(
            require_governance_manifest=bool(getattr(args, "require_governance_manifest", False)),
            allowed_benign_subtypes=str(
                getattr(args, "allowed_benign_subtypes", DEFAULT_ALLOWED_BENIGN_SUBTYPES)
            ),
            require_train_eligible=bool(getattr(args, "train_eligible_only", False)),
            include_uncertain=not bool(getattr(args, "exclude_uncertain", False)),
        ),
    )

    samples = []
    for i in range(len(ds)):
        data = align_pyg_data_to_binary_checkpoint(ds[i], payload)
        folder = str(getattr(data, "name", f"{i:03d}"))
        d = data.to(device)
        batch = torch.zeros(d.x.size(0), dtype=torch.long, device=device)
        lc = float(getattr(args, "logit_clip", 0.0) or 0.0)
        with torch.no_grad():
            logits = model(
                d.x,
                d.edge_index,
                batch,
                graph_attr=_apply_feature_group_weights(getattr(d, "graph_attr", None), payload),
                edge_attr=getattr(d, "edge_attr", None),
            )
            lg0 = _clip_logits_tensor(logits, lc)
            probs_raw = F.softmax(lg0, dim=1).detach().cpu().numpy()
            probs_cal = apply_temperature(lg0.detach().cpu().numpy(), t)
            ens_probs = [float(probs_cal[0, 1])]
            for m in ensemble_models:
                lg = m(
                    d.x,
                    d.edge_index,
                    batch,
                    graph_attr=_apply_feature_group_weights(getattr(d, "graph_attr", None), payload),
                    edge_attr=getattr(d, "edge_attr", None),
                )
                lg = _clip_logits_tensor(lg, lc)
                pb = apply_temperature(lg.detach().cpu().numpy(), t)
                ens_probs.append(float(pb[0, 1]))
        p_mal_raw = float(probs_raw[0, 1])
        p_mal = float(np.mean(ens_probs))
        evidence = explain_binary(model, data, device, payload)  # data already aligned to payload
        tags = _reasoning_tags(evidence["top_graph_attrs"])
        high_risk = any(
            x.get("feature_name")
            in {
                "injections",
                "c2_conns",
                "edge_injected_into",
                "edge_connects_to",
                "signal_svchost_lineage_anomaly_count",
                "signal_service_orphan_count",
                "signal_dll_trust_anomaly_count",
                "signal_lolbin_chain_count",
            }
            for x in evidence["top_graph_attrs"]
        )
        rel_triplets = _relation_triplets(evidence)
        state = triage_state_binary(p_mal, t_low, t_high, high_risk)
        mc_probs = [p_mal]
        if args.mc_samples > 1:
            model.train()
            for _ in range(args.mc_samples - 1):
                with torch.no_grad():
                    logits_mc = model(
                        d.x,
                        d.edge_index,
                        batch,
                        graph_attr=_apply_feature_group_weights(getattr(d, "graph_attr", None), payload),
                        edge_attr=getattr(d, "edge_attr", None),
                    )
                    logits_mc = _clip_logits_tensor(logits_mc, lc)
                    probs_mc = apply_temperature(logits_mc.detach().cpu().numpy(), t)
                    mc_probs.append(float(probs_mc[0, 1]))
            model.eval()
        hr = heuristic_risk_score(
            {
                "c2_signal": float(any(x.get("feature_name") in {"c2_conns", "edge_connects_to"} for x in evidence["top_graph_attrs"])),
                "injection_signal": float(any(x.get("feature_name") in {"injections", "edge_injected_into"} for x in evidence["top_graph_attrs"])),
                "credential_access_signal": float(any(x.get("feature_name") in {"edge_intent_credential_access"} for x in evidence["top_graph_attrs"])),
            }
        )
        ens = ensemble_score(binary_probability=p_mal, dual_delta=(2.0 * p_mal - 1.0), heuristic_score=hr)
        fusion = {
            "heuristic_risk_score": round(hr, 6),
            "ensemble_score": round(ens, 6),
            "final_triage_state": final_triage(ens),
        }
        uncertainty = {
            "method": "mc_dropout",
            "mean_probability": float(np.mean(mc_probs)),
            "variance_probability": float(np.var(mc_probs)),
            "deep_ensemble_size": int(len(ens_probs)),
            "deep_ensemble_variance": float(np.var(ens_probs)),
        }
        attention_evidence = {
            "method": "edge_attention_proxy",
            "top_attended_edges": evidence.get("edge_pairs", [])[:5],
        }
        findings = [
            {
                "type": "binary_model_signal",
                "feature": x.get("feature_name"),
                "importance": round(float(x.get("importance", 0.0)), 6),
                "evidence": "high-contribution feature in binary GNN",
            }
            for x in evidence["top_graph_attrs"][:5]
        ]
        gov = governance_by_folder.get(folder, {})
        samples.append(
            {
                "sample_id": sample_id_by_folder.get(folder) or f"{i+1:02d}",
                "folder": folder,
                **gov,
                "malware_probability_raw": round(p_mal_raw, 6),
                "malware_probability_calibrated": round(p_mal, 6),
                "threshold_low": t_low,
                "threshold_high": t_high,
                "triage_state": state,
                "behavioral_findings": findings,
                "binary_model_evidence": evidence,
                "fusion": fusion,
                "uncertainty": uncertainty,
                "attention_evidence": attention_evidence,
                "reasoning_tags": tags,
                "explainability_diversity": {"distinct_reasoning_groups": len(tags)},
                "relation_triplets": rel_triplets,
                "narrative": (
                    f"Binary GNN malware probability is {p_mal:.3f} (raw={p_mal_raw:.3f}). "
                    f"Triage={state}. Top factors={ [f['feature'] for f in findings[:3]] }."
                ),
            }
        )

    payload_out = {
        "summary": {
            "schema_version": SCHEMA_VERSION,
            "samples_analyzed": len(samples),
            "state_counts": {
                "likely_malicious": sum(1 for s in samples if s["triage_state"] == "likely_malicious"),
                "likely_benign": sum(1 for s in samples if s["triage_state"] == "likely_benign"),
                "high_risk_ambiguous": sum(1 for s in samples if s["triage_state"] == "high_risk_ambiguous"),
                "low_risk_ambiguous": sum(1 for s in samples if s["triage_state"] == "low_risk_ambiguous"),
            },
            "temperature": t,
            "threshold_low": t_low,
            "threshold_high": t_high,
            "ambiguity_width": float(max(0.0, t_high - t_low)),
            "band_policy": "narrow",
            "reasoning_group_coverage": {
                "temporal_intent": sum(1 for s in samples if "temporal_intent" in s.get("reasoning_tags", [])),
                "api_semantics": sum(1 for s in samples if "api_semantics" in s.get("reasoning_tags", [])),
                "persistence": sum(1 for s in samples if "persistence" in s.get("reasoning_tags", [])),
                "credential_access": sum(1 for s in samples if "credential_access" in s.get("reasoning_tags", [])),
                "privilege_escalation": sum(1 for s in samples if "privilege_escalation" in s.get("reasoning_tags", [])),
                "lineage_anomaly": sum(1 for s in samples if "lineage_anomaly" in s.get("reasoning_tags", [])),
                "service_mismatch": sum(1 for s in samples if "service_mismatch" in s.get("reasoning_tags", [])),
                "dll_trust_context": sum(1 for s in samples if "dll_trust_context" in s.get("reasoning_tags", [])),
            },
        },
        "samples": samples,
    }
    out = Path(args.output_json)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload_out, indent=2), encoding="utf-8")
    print(f"[BinaryAnalyze] wrote {out} ({len(samples)} samples)")
    return payload_out


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Analyze samples with binary GNN model")
    p.add_argument("manifest", help="Path to dataset_manifest.csv")
    p.add_argument("--base-dir", default=None, dest="base_dir")
    p.add_argument("--exclude-uncertain", action="store_true", dest="exclude_uncertain")
    p.add_argument(
        "--train-eligible-only",
        action="store_true",
        dest="train_eligible_only",
        help="Load only manifest rows with train_eligible=true.",
    )
    p.add_argument(
        "--require-governance-manifest/--no-require-governance-manifest",
        default=False,
        action=argparse.BooleanOptionalAction,
        dest="require_governance_manifest",
        help="Apply benign_subtype allowlist when loading (default: analyze all manifest rows).",
    )
    p.add_argument(
        "--allowed-benign-subtypes",
        default=DEFAULT_ALLOWED_BENIGN_SUBTYPES,
        dest="allowed_benign_subtypes",
        help="Benign subtype allowlist when --require-governance-manifest is on.",
    )
    p.add_argument("--model", default="outputs/binary_model.pt")
    p.add_argument("--output-json", default="outputs/binary_analysis.json", dest="output_json")
    p.add_argument("--mc-samples", type=int, default=8, dest="mc_samples")
    p.add_argument("--ensemble-models", nargs="*", default=None, dest="ensemble_models")
    p.add_argument("--max-ambiguity-width", type=float, default=0.12, dest="max_ambiguity_width")
    p.add_argument("--min-ambiguity-width", type=float, default=0.06, dest="min_ambiguity_width")
    p.add_argument(
        "--logit-clip",
        type=float,
        default=0.0,
        dest="logit_clip",
        help="If >0, clamp logits to [-clip, clip] before softmax/temperature (inference-only).",
    )
    run(p.parse_args())

