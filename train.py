#!/usr/bin/env python3
"""
train.py
5-fold cross-validation training + evaluation for malware GNN classifier.

Usage:
    python train.py extracted_data/dataset_manifest.csv
    python train.py extracted_data/dataset_manifest.csv --model sage
    python train.py extracted_data/dataset_manifest.csv --epochs 100 --hidden 128
"""

import os, sys, argparse, json
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset import MalwareGraphDataset
from model import GINMalwareClassifier, SAGEMalwareClassifier


def train_epoch(model, loader, optimiser, device):
    model.train()
    total_loss = 0
    for batch in loader:
        batch = batch.to(device)
        optimiser.zero_grad()
        out  = model(batch.x, batch.edge_index, batch.batch)
        loss = F.cross_entropy(out, batch.y)
        loss.backward()
        optimiser.step()
        total_loss += loss.item()
    return total_loss / len(loader)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    preds, probs, labels = [], [], []
    for batch in loader:
        batch  = batch.to(device)
        out    = model(batch.x, batch.edge_index, batch.batch)
        prob   = F.softmax(out, dim=1)[:, 1].cpu().numpy()
        pred   = out.argmax(dim=1).cpu().numpy()
        label  = batch.y.cpu().numpy()
        preds.extend(pred)
        probs.extend(prob)
        labels.extend(label)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(labels, preds, zero_division=0)
    auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
    cm  = confusion_matrix(labels, preds)
    return acc, f1, auc, cm


def run(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Train] Device: {device}")

    # Load dataset
    ds      = MalwareGraphDataset(args.manifest)
    labels  = ds.labels()
    in_dim  = ds[0].x.size(1)
    n       = len(ds)
    print(f"[Train] {n} graphs  |  feature dim={in_dim}  |  model={args.model.upper()}")

    skf     = StratifiedKFold(n_splits=args.folds, shuffle=True, random_state=42)
    indices = np.arange(n)

    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(skf.split(indices, labels), 1):
        print(f"\n── Fold {fold}/{args.folds} "
              f"(train={len(train_idx)}, test={len(test_idx)}) ──")

        train_ds = [ds[i] for i in train_idx]
        test_ds  = [ds[i] for i in test_idx]

        train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
        test_loader  = DataLoader(test_ds,  batch_size=args.batch_size, shuffle=False)

        # Build model
        if args.model == "sage":
            model = SAGEMalwareClassifier(in_dim, hidden=args.hidden,
                                          layers=args.layers, dropout=args.dropout)
        else:
            model = GINMalwareClassifier(in_dim, hidden=args.hidden,
                                         layers=args.layers, dropout=args.dropout)
        model = model.to(device)

        optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                     weight_decay=args.weight_decay)
        scheduler = torch.optim.lr_scheduler.StepLR(optimiser, step_size=30, gamma=0.5)

        best_f1, best_state = 0.0, None
        for epoch in range(1, args.epochs + 1):
            loss = train_epoch(model, train_loader, optimiser, device)
            scheduler.step()
            if epoch % 10 == 0 or epoch == args.epochs:
                acc, f1, auc, _ = evaluate(model, test_loader, device)
                print(f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                      f"acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
                if f1 >= best_f1:
                    best_f1    = f1
                    best_state = {k: v.clone() for k, v in model.state_dict().items()}

        # Final eval with best weights
        model.load_state_dict(best_state)
        acc, f1, auc, cm = evaluate(model, test_loader, device)
        print(f"  Best → acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
        print(f"  Confusion matrix:\n{cm}")

        fold_results.append({"fold": fold, "acc": acc, "f1": f1, "auc": auc})

        # Per-sample predictions for this fold
        model.eval()
        with torch.no_grad():
            for data in test_ds:
                b = data.to(device)
                out  = model(b.x, b.edge_index,
                             torch.zeros(b.num_nodes, dtype=torch.long, device=device))
                pred = out.argmax(dim=1).item()
                prob = F.softmax(out, dim=1)[0, 1].item()
                status = "✅" if pred == b.y.item() else "❌"
                print(f"    {status} {data.name:<35} "
                      f"pred={pred} true={b.y.item()} prob={prob:.3f}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print(f"  {args.folds}-FOLD CV RESULTS ({args.model.upper()})")
    print("="*60)
    accs = [r["acc"] for r in fold_results]
    f1s  = [r["f1"]  for r in fold_results]
    aucs = [r["auc"] for r in fold_results]
    print(f"  Accuracy : {np.mean(accs):.3f} ± {np.std(accs):.3f}")
    print(f"  F1       : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")
    print(f"  AUC-ROC  : {np.mean(aucs):.3f} ± {np.std(aucs):.3f}")
    print("="*60)

    # Save results
    out_path = f"results_{args.model}_{args.folds}fold.json"
    with open(out_path, "w") as f:
        json.dump({
            "model": args.model, "folds": args.folds,
            "epochs": args.epochs, "hidden": args.hidden,
            "mean_acc": np.mean(accs), "std_acc": np.std(accs),
            "mean_f1":  np.mean(f1s),  "std_f1":  np.std(f1s),
            "mean_auc": np.mean(aucs), "std_auc": np.std(aucs),
            "fold_results": fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", help="Path to dataset_manifest.csv")
    parser.add_argument("--model",        default="gin",  choices=["gin", "sage"])
    parser.add_argument("--folds",        type=int,   default=5)
    parser.add_argument("--epochs",       type=int,   default=100)
    parser.add_argument("--hidden",       type=int,   default=64)
    parser.add_argument("--layers",       type=int,   default=3)
    parser.add_argument("--dropout",      type=float, default=0.3)
    parser.add_argument("--lr",           type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4)
    parser.add_argument("--batch-size",   type=int,   default=8)
    args = parser.parse_args()
    run(args)
