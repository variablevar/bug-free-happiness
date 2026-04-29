#!/usr/bin/env python3
"""
evaluate.py
Evaluate a trained GNN checkpoint on a manifest-defined graph dataset.
"""

import argparse
import json
import datetime
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score, confusion_matrix
from torch_geometric.loader import DataLoader

from dataset import MalwareGraphDataset
from model import (
    GINMalwareClassifier,
    SAGEMalwareClassifier,
    GATMalwareClassifier,
    GINEMalwareClassifier,
)


def build_model(args, in_dim: int, device: torch.device):
    kwargs = dict(
        in_channels=in_dim,
        hidden=args.hidden,
        layers=args.layers,
        dropout=args.dropout,
        num_classes=2,
    )
    if args.model == "sage":
        model = SAGEMalwareClassifier(**kwargs)
    elif args.model == "gat":
        model = GATMalwareClassifier(**kwargs, heads=int(args.gat_heads))
    elif args.model == "gine":
        model = GINEMalwareClassifier(**kwargs, edge_emb_dim=int(args.edge_emb_dim))
    else:
        model = GINMalwareClassifier(**kwargs)
    return model.to(device)


@torch.no_grad()
def run_inference(model, loader, device, threshold: float):
    model.eval()
    all_labels = []
    all_probs = []
    all_preds = []
    all_names = []

    for batch in loader:
        batch = batch.to(device)
        graph_attr = getattr(batch, "graph_attr", None)
        edge_attr = getattr(batch, "edge_attr", None)
        logits = model(
            batch.x, batch.edge_index, batch.batch,
            graph_attr=graph_attr, edge_attr=edge_attr,
        )
        probs = F.softmax(logits, dim=1)[:, 1]
        preds = (probs >= threshold).long()

        names = getattr(batch, "name", None)
        if names is None:
            names = ["unknown"] * probs.size(0)

        all_labels.extend(batch.y.detach().cpu().numpy().tolist())
        all_probs.extend(probs.detach().cpu().numpy().tolist())
        all_preds.extend(preds.detach().cpu().numpy().tolist())
        all_names.extend([str(n) for n in names])

    labels = np.array(all_labels, dtype=int)
    probs = np.array(all_probs, dtype=float)
    preds = np.array(all_preds, dtype=int)
    return all_names, labels, probs, preds


def compute_metrics(labels, probs, preds):
    acc = accuracy_score(labels, preds)
    f1 = f1_score(labels, preds, zero_division=0)
    try:
        auc = roc_auc_score(labels, probs) if len(set(labels.tolist())) > 1 else 0.0
    except ValueError:
        auc = 0.0
    cm = confusion_matrix(labels, preds, labels=[0, 1])
    return acc, f1, auc, cm


def load_checkpoint(model, checkpoint_path: Path, sample, device):
    state_dict = torch.load(checkpoint_path, map_location=device)

    # Build lazy classifier head before loading state_dict.
    model.eval()
    with torch.no_grad():
        data = sample.clone().to(device)
        batch_vec = torch.zeros(data.x.size(0), dtype=torch.long, device=device)
        graph_attr = getattr(data, "graph_attr", None)
        if graph_attr is not None:
            graph_attr = graph_attr.squeeze(0).unsqueeze(0).to(device)
        edge_attr = getattr(data, "edge_attr", None)
        _ = model(
            data.x, data.edge_index, batch_vec,
            graph_attr=graph_attr, edge_attr=edge_attr,
        )

    model.load_state_dict(state_dict, strict=True)


def write_predictions_csv(path: Path, names, labels, probs, preds):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write("name,true_label,pred,prob,correct\n")
        for name, true, pred, prob in zip(names, labels, preds, probs):
            correct = int(true == pred)
            f.write(f"{name},{int(true)},{int(pred)},{float(prob):.6f},{correct}\n")


def main(args):
    if args.model == "gat" and args.hidden % int(args.gat_heads) != 0:
        raise SystemExit(
            f"[ERROR] GAT requires --hidden divisible by --gat-heads "
            f"(got hidden={args.hidden}, gat_heads={args.gat_heads})."
        )

    device = torch.device(args.device if args.device else ("cuda" if torch.cuda.is_available() else "cpu"))

    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=args.base_dir,
        include_uncertain=args.include_uncertain,
        include_unknown=args.include_unknown,
    )
    if len(ds) == 0:
        raise SystemExit("[ERROR] Dataset is empty.")

    first = ds[0]
    in_dim = first.x.size(1)
    model = build_model(args, in_dim, device)
    load_checkpoint(model, Path(args.checkpoint), first, device)

    loader = DataLoader(ds, batch_size=args.batch_size, shuffle=False)
    names, labels, probs, preds = run_inference(model, loader, device, threshold=args.threshold)

    acc, f1, auc, cm = compute_metrics(labels, probs, preds)

    print(f"[Eval] Device     : {device}")
    print(f"[Eval] Checkpoint : {args.checkpoint}")
    print(f"[Eval] Graphs     : {len(ds)}")
    print(f"[Eval] Threshold  : {args.threshold:.4f}")
    print(f"[Eval] Accuracy   : {acc:.4f}")
    print(f"[Eval] F1         : {f1:.4f}")
    print(f"[Eval] AUC        : {auc:.4f}")
    print("[Eval] Confusion  :")
    print(cm)

    if args.predictions_csv:
        pred_path = Path(args.predictions_csv)
        write_predictions_csv(pred_path, names, labels, probs, preds)
        print(f"[Eval] Predictions saved -> {pred_path}")

    if args.output_json:
        out_path = Path(args.output_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "checkpoint": args.checkpoint,
            "manifest": args.manifest,
            "model": args.model,
            "hidden": args.hidden,
            "layers": args.layers,
            "dropout": args.dropout,
            "gat_heads": int(args.gat_heads) if args.model == "gat" else None,
            "edge_emb_dim": int(args.edge_emb_dim) if args.model == "gine" else None,
            "threshold": args.threshold,
            "batch_size": args.batch_size,
            "include_uncertain": args.include_uncertain,
            "include_unknown": args.include_unknown,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "n_samples": int(len(labels)),
            "accuracy": float(acc),
            "f1": float(f1),
            "auc": float(auc),
            "confusion_matrix": cm.tolist(),
            "predictions": [
                {
                    "name": name,
                    "true_label": int(true),
                    "pred": int(pred),
                    "prob": float(prob),
                    "correct": bool(true == pred),
                }
                for name, true, pred, prob in zip(names, labels, preds, probs)
            ],
        }
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        print(f"[Eval] Results saved -> {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Evaluate a trained GNN checkpoint on a manifest dataset."
    )
    parser.add_argument("manifest", help="Path to dataset_manifest.csv")
    parser.add_argument("checkpoint", help="Path to model checkpoint (.pt)")
    parser.add_argument("--base-dir", default=None, dest="base_dir",
                        help="Base directory containing graph.pkl folders")
    parser.add_argument(
        "--model", default="gin",
        choices=["gin", "sage", "gat", "gine"],
    )
    parser.add_argument("--hidden", type=int, default=16)
    parser.add_argument("--layers", type=int, default=2)
    parser.add_argument("--dropout", type=float, default=0.5)
    parser.add_argument(
        "--gat-heads", type=int, default=4, dest="gat_heads",
        help="GAT attention heads (hidden must be divisible by this)",
    )
    parser.add_argument(
        "--edge-emb-dim", type=int, default=8, dest="edge_emb_dim",
        help="GINE edge-type embedding dim",
    )
    parser.add_argument("--threshold", type=float, default=0.5,
                        help="Decision threshold for positive class")
    parser.add_argument("--batch-size", type=int, default=8, dest="batch_size")
    parser.add_argument("--include-uncertain", action="store_true", dest="include_uncertain",
                        help="Include manifest rows marked uncertain")
    parser.add_argument("--include-unknown", action="store_true", dest="include_unknown",
                        help="Include rows with label=-1")
    parser.add_argument("--predictions-csv", default=None, dest="predictions_csv",
                        help="Optional path to save per-sample predictions CSV")
    parser.add_argument("--output-json", default=None, dest="output_json",
                        help="Optional path to save full evaluation results JSON")
    parser.add_argument("--device", default=None,
                        help="Force device (e.g. cpu, cuda). Defaults to auto")
    main(parser.parse_args())
