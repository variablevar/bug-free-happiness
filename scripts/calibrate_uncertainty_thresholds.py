#!/usr/bin/env python3
"""Grid-search uncertainty gate thresholds on a manifest split."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyze_binary_model import build_model as build_binary_model
from calibration import apply_temperature
from dataset import MalwareGraphDataset
from fusion import build_uncertainty_gate
from one_class_gnn import build_model_from_payload, score_graph
from utils.graph_attr_profile import apply_graph_attr_profile


def _load_payload(path: Path) -> dict:
    return torch.load(path, map_location="cpu", weights_only=False)


def _binary_p(model, data, payload, device, graph_attr_profile: str) -> float:
    batch = torch.zeros(data.num_nodes, dtype=torch.long, device=device)
    ga = apply_graph_attr_profile(getattr(data, "graph_attr", None), graph_attr_profile)
    if ga is not None:
        ga = ga.to(device)
    logits = model(
        data.x.to(device),
        data.edge_index.to(device),
        batch,
        graph_attr=ga,
        edge_attr=getattr(data, "edge_attr", None),
    )
    temp = float(payload.get("temperature", 1.0))
    probs = apply_temperature(logits.detach().cpu().numpy(), temp)
    return float(probs[0, 1])


def main() -> None:
    p = argparse.ArgumentParser(description="Calibrate uncertainty gate thresholds")
    p.add_argument("manifest", help="dataset_manifest.csv")
    p.add_argument("--base-dir", default=None)
    p.add_argument("--binary-model", default="outputs/binary_model.pt")
    p.add_argument("--malware-model", default="outputs/malware_model.pt")
    p.add_argument("--benign-model", default="outputs/benign_model.pt")
    p.add_argument("--val-fraction", type=float, default=0.25)
    p.add_argument("--target-review-rate", type=float, default=0.32)
    p.add_argument("--review-tolerance", type=float, default=0.08)
    p.add_argument("--output", default="outputs/uncertainty_thresholds.json")
    p.add_argument("--graph-attr-profile", default="full", dest="graph_attr_profile")
    args = p.parse_args()

    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=args.base_dir,
        include_uncertain=True,
        graph_attr_profile=args.graph_attr_profile,
    )
    if len(ds) < 4:
        raise SystemExit("[ERROR] Need at least 4 samples for calibration")

    rng = np.random.default_rng(42)
    idx = np.arange(len(ds))
    rng.shuffle(idx)
    n_val = max(2, int(round(len(ds) * args.val_fraction)))
    val_idx = set(idx[:n_val].tolist())

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    bin_payload = _load_payload(Path(args.binary_model))
    mal_payload = _load_payload(Path(args.malware_model))
    ben_payload = _load_payload(Path(args.benign_model))
    bin_model = build_binary_model(bin_payload, device)
    mal_model, mal_center, mal_radius = build_model_from_payload(mal_payload, device)
    ben_model, ben_center, ben_radius = build_model_from_payload(ben_payload, device)

    records = []
    for i, data in enumerate(ds):
        mal_s, _ = score_graph(mal_model, mal_center, mal_radius, data, device)
        ben_s, _ = score_graph(ben_model, ben_center, ben_radius, data, device)
        p_bin = _binary_p(bin_model, data, bin_payload, device, args.graph_attr_profile)
        dual_norm = max(0.0, min(1.0, (mal_s - ben_s + 1.0) / 2.0))
        records.append(
            {
                "index": i,
                "label": int(data.y.item()),
                "p_bin": p_bin,
                "dual_margin": abs(mal_s - ben_s),
                "binary_dual_gap": abs(p_bin - dual_norm),
                "mc_var": 0.0,
            }
        )

    best = None
    for disagree in [0.55, 0.65, 0.75, 999.0]:
        for margin_th in [0.05, 0.08, 0.10, 0.12]:
            for mc_th in [0.03, 0.05, 0.08]:
                n_review = 0
                n_mal_review = 0
                n_mal = 0
                for rec in records:
                    gate = build_uncertainty_gate(
                        binary_dual_gap=rec["binary_dual_gap"],
                        dual_score_margin=rec["dual_margin"],
                        mc_mal_variance=rec["mc_var"],
                        mc_ben_variance=rec["mc_var"],
                        binary_probability=rec["p_bin"],
                        disagreement_threshold=disagree,
                        dual_score_margin_threshold=margin_th,
                        mc_variance_threshold=mc_th,
                        abstention_mode="calibrated",
                    )
                    if gate.triggered:
                        n_review += 1
                    if rec["label"] == 1:
                        n_mal += 1
                        if gate.triggered:
                            n_mal_review += 1
                rate = n_review / max(len(records), 1)
                mal_recall = 1.0 - (n_mal_review / max(n_mal, 1))
                dist = abs(rate - args.target_review_rate)
                ok = dist <= args.review_tolerance
                score = (1 if ok else 0, -dist, mal_recall)
                if best is None or score > best[0]:
                    best = (
                        score,
                        {
                            "disagreement_threshold": None if disagree >= 900 else disagree,
                            "dual_score_margin_threshold": margin_th,
                            "mc_variance_threshold": mc_th,
                            "abstention_mode": "calibrated",
                            "val_review_rate": round(rate, 4),
                            "val_malware_decisive_proxy": round(mal_recall, 4),
                        },
                    )

    out = best[1] if best else {}
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(f"[calibrate_uncertainty_thresholds] wrote {out_path}")


if __name__ == "__main__":
    main()
