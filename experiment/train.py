#!/usr/bin/env python3
"""
Experiment trainer: loads MalwareGraphDataset from experiment/data with benign-zone
masked graph pooling (suspect_node_mask excludes triage_zone=benign nodes).

Requires dataset_manifest.csv (run build_dataset.py on experiment/data first) or
point --manifest at extracted_data/dataset_manifest.csv after re-running the pipeline.
"""

from __future__ import annotations

import argparse
import os
import sys

import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from dataset import MalwareGraphDataset, NODE_FEAT_DIM  # noqa: E402
from model import GINEMalwareClassifier  # noqa: E402


def train_epoch(model, loader, optim, device):
    model.train()
    total = 0.0
    for batch in loader:
        batch = batch.to(device)
        optim.zero_grad()
        out = model(
            batch.x,
            batch.edge_index,
            batch.batch,
            graph_attr=getattr(batch, "graph_attr", None),
            edge_attr=getattr(batch, "edge_attr", None),
            node_mask=getattr(batch, "suspect_node_mask", None),
        )
        loss = F.cross_entropy(out, batch.y)
        loss.backward()
        optim.step()
        total += float(loss.item())
    return total / max(len(loader), 1)


@torch.no_grad()
def eval_epoch(model, loader, device):
    model.eval()
    correct = total = 0
    for batch in loader:
        batch = batch.to(device)
        pred = model(
            batch.x,
            batch.edge_index,
            batch.batch,
            graph_attr=getattr(batch, "graph_attr", None),
            edge_attr=getattr(batch, "edge_attr", None),
            node_mask=getattr(batch, "suspect_node_mask", None),
        ).argmax(dim=1)
        correct += int((pred == batch.y).sum().item())
        total += int(batch.y.size(0))
    return correct / max(total, 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--manifest",
        default=os.path.join(ROOT, "extracted_data", "dataset_manifest.csv"),
    )
    ap.add_argument("--base-dir", default=os.path.join(ROOT, "experiment", "data"))
    ap.add_argument("--epochs", type=int, default=30)
    ap.add_argument("--batch-size", type=int, default=4)
    ap.add_argument("--hidden", type=int, default=16)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--require-train-eligible", action="store_true")
    args = ap.parse_args()

    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=args.base_dir,
        require_train_eligible=args.require_train_eligible,
        include_uncertain=False,
    )
    if len(ds) == 0:
        print("[ERROR] No graphs loaded. Re-run filter → build → analyze on sample folders.")
        return 1

    loader = DataLoader(ds, batch_size=args.batch_size, shuffle=True)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model = GINEMalwareClassifier(
        in_channels=NODE_FEAT_DIM,
        hidden=args.hidden,
        layers=2,
        dropout=0.5,
        edge_emb_dim=8,
    ).to(device)
    optim = torch.optim.Adam(model.parameters(), lr=args.lr)

    print(f"[experiment] samples={len(ds)}  node_feat={NODE_FEAT_DIM}  device={device}")
    print("[experiment] Using suspect_node_mask (benign zone excluded from pooling)")

    for epoch in range(1, args.epochs + 1):
        loss = train_epoch(model, loader, optim, device)
        acc = eval_epoch(model, loader, device)
        print(f"epoch {epoch:3d}  loss={loss:.4f}  acc={acc:.3f}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
