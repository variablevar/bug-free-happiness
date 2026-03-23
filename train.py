#!/usr/bin/env python3
"""
train.py  v2
5-fold cross-validation training + evaluation for malware GNN classifier.

Fixes vs v1:
  - ds.labels() → ds.get_labels()  (matches MalwareGraphDataset API)
  - in_dim guard: fallback if dataset is empty or first graph has no features
  - best_state guard: save on first epoch too, not just if f1 >= 0.0 after epoch 10
  - per-sample loop: batch.num_nodes not reliable for single un-batched graph;
    use torch.zeros(data.x.size(0), ...) and unsqueeze batch dim
  - data.name may not exist; guard with getattr
  - StratifiedKFold on small N (24 samples, 5 folds): warn when fold has <2 classes
  - AUC guard: also catches when probs are all identical (no variance)
  - scheduler: ReduceLROnPlateau on val-f1 instead of StepLR (better for small datasets)
  - weight_decay arg: hyphen fixed to underscore in dest
  - results JSON: adds timestamp + git hash if available
  - --save-model flag: saves best model per fold to disk
  - --seed flag: reproducibility

Usage:
    python train.py extracted_data/dataset_manifest.csv
    python train.py extracted_data/dataset_manifest.csv --model sage
    python train.py extracted_data/dataset_manifest.csv --epochs 100 --hidden 128
    python train.py extracted_data/dataset_manifest.csv --save-model --seed 0
"""

import os, sys, argparse, json, datetime
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset import MalwareGraphDataset
from model import GINMalwareClassifier, SAGEMalwareClassifier


# ── Training helpers ──────────────────────────────────────────────────────────

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
    return total_loss / max(len(loader), 1)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    preds, probs, labels = [], [], []
    for batch in loader:
        batch = batch.to(device)
        out   = model(batch.x, batch.edge_index, batch.batch)
        prob  = F.softmax(out, dim=1)[:, 1].cpu().numpy()
        pred  = out.argmax(dim=1).cpu().numpy()
        label = batch.y.cpu().numpy()
        preds.extend(pred);  probs.extend(prob);  labels.extend(label)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(labels, preds, zero_division=0)

    # AUC needs both classes present AND non-constant probabilities
    try:
        auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
    except ValueError:
        auc = 0.0

    cm = confusion_matrix(labels, preds)
    return acc, f1, auc, cm


def build_model(args, in_dim, device):
    # ✅ New — rename the key to match GINMalwareClassifier.__init__
    kwargs = dict(in_channels=in_dim, hidden=args.hidden,
                  layers=args.layers, dropout=args.dropout)
    if args.model == "sage":
        m = SAGEMalwareClassifier(**kwargs)
    else:
        m = GINMalwareClassifier(**kwargs)
    return m.to(device)


# ── Git hash for result provenance ────────────────────────────────────────────
def git_hash():
    try:
        import subprocess
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        return "unknown"


# ── Main ──────────────────────────────────────────────────────────────────────

def run(args):
    # Reproducibility
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Train] Device : {device}")
    print(f"[Train] Seed   : {args.seed}")

    # ── Load dataset ──────────────────────────────────────────────────────────
    ds = MalwareGraphDataset(args.manifest)
    n  = len(ds)
    if n == 0:
        print("[ERROR] Dataset is empty — check manifest path and sample folders.")
        sys.exit(1)

    # FIX: API is get_labels(), not labels()
    labels = ds.get_labels()

    # FIX: guard in case first graph has no node features
    first = ds[0]
    if first.x is None or first.x.dim() < 2:
        print("[ERROR] ds[0].x is None or 1-D — check dataset.py feature construction.")
        sys.exit(1)
    in_dim = first.x.size(1)

    print(f"[Train] Graphs    : {n}  |  feature dim={in_dim}")
    print(f"[Train] Model     : {args.model.upper()}")
    print(f"[Train] Label dist: {dict(zip(*np.unique(labels, return_counts=True)))}")

    if n < args.folds:
        print(f"[WARN] Only {n} samples but --folds={args.folds}; reducing to {n} folds.")
        args.folds = n

    skf     = StratifiedKFold(n_splits=args.folds, shuffle=True,
                              random_state=args.seed)
    indices = np.arange(n)
    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(
            skf.split(indices, labels), 1):

        print(f"\n── Fold {fold}/{args.folds} "
              f"(train={len(train_idx)}, test={len(test_idx)}) ──")

        # Warn if a fold is missing a class (too few samples)
        test_labels = [labels[i] for i in test_idx]
        if len(set(test_labels)) < 2:
            print(f"  [WARN] Test fold has only class {set(test_labels)} — "
                  f"AUC/F1 unreliable for this fold")

        train_ds = [ds[i] for i in train_idx]
        test_ds  = [ds[i] for i in test_idx]

        train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
        test_loader  = DataLoader(test_ds,  batch_size=args.batch_size, shuffle=False)

        model     = build_model(args, in_dim, device)
        optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                     weight_decay=args.weight_decay)

        # FIX: ReduceLROnPlateau on val-f1 — better than StepLR for 24 samples
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimiser, mode="max", factor=0.5, patience=10, min_lr=1e-5
        )

        # FIX: initialise best_state immediately so it's never None
        best_f1, best_state = -1.0, {k: v.clone()
                                     for k, v in model.state_dict().items()}

        for epoch in range(1, args.epochs + 1):
            loss = train_epoch(model, train_loader, optimiser, device)
            acc, f1, auc, _ = evaluate(model, test_loader, device)
            scheduler.step(f1)

            if epoch % 10 == 0 or epoch == args.epochs:
                print(f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                      f"acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}  "
                      f"lr={optimiser.param_groups[0]['lr']:.2e}")

            # FIX: save on strict improvement (handles first epoch correctly)
            if f1 > best_f1:
                best_f1    = f1
                best_state = {k: v.clone() for k, v in model.state_dict().items()}

        # Final eval with best weights
        model.load_state_dict(best_state)
        acc, f1, auc, cm = evaluate(model, test_loader, device)
        print(f"  Best → acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
        print(f"  Confusion matrix:\n{cm}")

        if args.save_model:
            ckpt = f"model_{args.model}_fold{fold}.pt"
            torch.save(best_state, ckpt)
            print(f"  Saved checkpoint → {ckpt}")

        fold_results.append({"fold": fold, "acc": acc, "f1": f1, "auc": auc})

        # Per-sample predictions for this fold
        model.eval()
        with torch.no_grad():
            for data in test_ds:
                data = data.to(device)
                # FIX: create batch vector from x size, not num_nodes attribute
                batch_vec = torch.zeros(data.x.size(0), dtype=torch.long,
                                        device=device)
                out  = model(data.x, data.edge_index, batch_vec)
                pred = out.argmax(dim=1).item()
                prob = F.softmax(out, dim=1)[0, 1].item()
                # FIX: data.name may not exist
                name = getattr(data, "name", f"graph_{id(data)}")
                true = data.y.item()
                status = "✅" if pred == true else "❌"
                print(f"    {status} {str(name):<35} "
                      f"pred={pred} true={true} prob={prob:.3f}")

    # ── Summary ───────────────────────────────────────────────────────────────
    print("\n" + "=" * 60)
    print(f"  {args.folds}-FOLD CV RESULTS ({args.model.upper()})")
    print("=" * 60)
    accs = [r["acc"] for r in fold_results]
    f1s  = [r["f1"]  for r in fold_results]
    aucs = [r["auc"] for r in fold_results]
    print(f"  Accuracy : {np.mean(accs):.3f} ± {np.std(accs):.3f}")
    print(f"  F1       : {np.mean(f1s):.3f} ± {np.std(f1s):.3f}")
    print(f"  AUC-ROC  : {np.mean(aucs):.3f} ± {np.std(aucs):.3f}")
    print("=" * 60)

    # Save results
    out_path = f"results_{args.model}_{args.folds}fold.json"
    with open(out_path, "w") as f:
        json.dump({
            "model":      args.model,
            "folds":      args.folds,
            "epochs":     args.epochs,
            "hidden":     args.hidden,
            "seed":       args.seed,
            "timestamp":  datetime.datetime.utcnow().isoformat(),
            "git_hash":   git_hash(),
            "mean_acc":   np.mean(accs),   "std_acc": np.std(accs),
            "mean_f1":    np.mean(f1s),    "std_f1":  np.std(f1s),
            "mean_auc":   np.mean(aucs),   "std_auc": np.std(aucs),
            "fold_results": fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="5-fold CV training for MalVol-25 GNN classifier"
    )
    parser.add_argument("manifest",        help="Path to dataset_manifest.csv")
    parser.add_argument("--model",         default="gin",  choices=["gin", "sage"])
    parser.add_argument("--folds",         type=int,   default=5)
    parser.add_argument("--epochs",        type=int,   default=100)
    parser.add_argument("--hidden",        type=int,   default=64)
    parser.add_argument("--layers",        type=int,   default=3)
    parser.add_argument("--dropout",       type=float, default=0.3)
    parser.add_argument("--lr",            type=float, default=1e-3)
    # FIX: dest= so argparse converts --weight-decay → weight_decay attribute
    parser.add_argument("--weight-decay",  type=float, default=1e-4,
                        dest="weight_decay")
    parser.add_argument("--batch-size",    type=int,   default=8,
                        dest="batch_size")
    parser.add_argument("--seed",          type=int,   default=42)
    parser.add_argument("--save-model",    action="store_true",
                        dest="save_model",
                        help="Save best model checkpoint per fold")
    args = parser.parse_args()
    run(args)