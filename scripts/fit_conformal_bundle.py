#!/usr/bin/env python3
"""Fit split-conformal bundle from binary val scores on a manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from analyze_binary_model import build_model
from calibration import SplitConformalBundle, apply_temperature, fit_split_conformal
from dataset import MalwareGraphDataset
from torch_geometric.data import Batch

from train_binary_model import forward_logits, split_indices


def main() -> None:
    p = argparse.ArgumentParser(description="Fit conformal bundle for fusion routing")
    p.add_argument("manifest")
    p.add_argument("--base-dir", default=None)
    p.add_argument("--binary-model", default="outputs/binary_model.pt")
    p.add_argument("--alpha", type=float, default=0.05)
    p.add_argument("--output", default="outputs/conformal_bundle.json")
    p.add_argument("--graph-attr-profile", default="no_manifest_leakage", dest="graph_attr_profile")
    args = p.parse_args()

    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=args.base_dir,
        include_uncertain=True,
        graph_attr_profile=args.graph_attr_profile,
    )
    labels = np.asarray(ds.get_labels(), dtype=int)
    keep = np.where((labels == 0) | (labels == 1))[0]
    labels = labels[keep]
    tr_idx, va_idx = split_indices(labels, 0.25, 42)
    device = torch.device("cpu")
    payload = torch.load(args.binary_model, map_location="cpu", weights_only=False)
    model = build_model(payload, device)
    model.eval()
    temp = float(payload.get("temperature", 1.0))

    probs = []
    y_val = []
    for i in va_idx:
        data = ds[int(keep[i])]
        batch = Batch.from_data_list([data]).to(device)
        logits = forward_logits(model, batch, device)
        prob = apply_temperature(logits.detach().cpu().numpy(), temp)
        probs.append(float(prob[0, 1]))
        y_val.append(int(data.y.item()))

    bundle = fit_split_conformal(np.asarray(probs), np.asarray(y_val), alpha=args.alpha)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(bundle.to_dict(), indent=2), encoding="utf-8")
    print(f"[fit_conformal_bundle] wrote {out}")


if __name__ == "__main__":
    main()
