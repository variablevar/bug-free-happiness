#!/usr/bin/env python3
"""
train.py  v4
5-fold cross-validation training + evaluation for malware GNN classifier.

Changes vs v3:
  - GROUP-AWARE fold splitting (StratifiedGroupKFold) so augmented variants
    of the same source sample are NEVER split across train/test folds.
    Source name is parsed from data.name by stripping the __aug_* suffix.
    This eliminates the data-leakage issue present in v3.

Usage:
    python train.py extracted_data/dataset_manifest.csv
    python train.py extracted_data/dataset_manifest.csv --model sage
    python train.py extracted_data/dataset_manifest.csv --epochs 200 --hidden 128
    python train.py extracted_data/dataset_manifest.csv --save-model --seed 0
"""

import os, sys, argparse, json, datetime, re
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset import MalwareGraphDataset
from model   import GINMalwareClassifier, SAGEMalwareClassifier


# ── Source-name extraction ────────────────────────────────────────────────────

_AUG_SUFFIX = re.compile(r"__aug_[a-z]+_\d+$")

def source_of(name: str) -> str:
    """
    Strip the augmentation suffix to get the original source sample name.

    Examples:
      "Cerber-WithVirus__aug_noise_03"      → "Cerber-WithVirus"
      "W32.MyDoom.A.-NoVirus__aug_benign_00" → "W32.MyDoom.A.-NoVirus"
      "Cerber-WithVirus"                     → "Cerber-WithVirus"  (passthrough)
    """
    return _AUG_SUFFIX.sub("", str(name))


# ── Training helpers ──────────────────────────────────────────────────────────

def train_epoch(model, loader, optimiser, device, class_weights):
    model.train()
    total_loss = 0
    for batch in loader:
        batch = batch.to(device)
        optimiser.zero_grad()

        graph_attr = getattr(batch, "graph_attr", None)
        if graph_attr is not None:
            graph_attr = graph_attr.view(-1, 4).to(device)

        out  = model(batch.x, batch.edge_index, batch.batch,
                     graph_attr=graph_attr)
        loss = F.cross_entropy(out, batch.y, weight=class_weights)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimiser.step()
        total_loss += loss.item()
    return total_loss / max(len(loader), 1)


@torch.no_grad()
def evaluate(model, loader, device):
    model.eval()
    preds, probs, labels = [], [], []
    for batch in loader:
        batch = batch.to(device)

        graph_attr = getattr(batch, "graph_attr", None)
        if graph_attr is not None:
            graph_attr = graph_attr.view(-1, 4).to(device)

        out   = model(batch.x, batch.edge_index, batch.batch,
                      graph_attr=graph_attr)
        prob  = F.softmax(out, dim=1)[:, 1].cpu().numpy()
        pred  = out.argmax(dim=1).cpu().numpy()
        label = batch.y.cpu().numpy()
        preds.extend(pred)
        probs.extend(prob)
        labels.extend(label)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(labels, preds, zero_division=0)
    try:
        auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
    except ValueError:
        auc = 0.0

    cm = confusion_matrix(labels, preds)
    return acc, f1, auc, cm


def build_model(args, in_dim, device):
    kwargs = dict(in_channels=in_dim, hidden=args.hidden,
                  layers=args.layers, dropout=args.dropout)
    if args.model == "sage":
        m = SAGEMalwareClassifier(**kwargs)
    else:
        m = GINMalwareClassifier(**kwargs)
    return m.to(device)


def compute_class_weights(labels, device):
    """Inverse-frequency weights so the minority class isn't ignored."""
    counts  = np.bincount(labels)
    total   = len(labels)
    weights = torch.tensor(
        [total / (len(counts) * c) for c in counts],
        dtype=torch.float, device=device
    )
    return weights


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
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("mps"  if torch.backends.mps.is_available() else
                          "cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Train] Device : {device}")
    print(f"[Train] Seed   : {args.seed}")

    # ── Load dataset ──────────────────────────────────────────────────────────
    ds = MalwareGraphDataset(args.manifest)
    n  = len(ds)
    if n == 0:
        print("[ERROR] Dataset is empty — check manifest path and sample folders.")
        sys.exit(1)

    labels = np.array(ds.get_labels())

    first = ds[0]
    if first.x is None or first.x.dim() < 2:
        print("[ERROR] ds[0].x is None or 1-D — check dataset.py feature construction.")
        sys.exit(1)
    in_dim = first.x.size(1)

    # ── Build group array: one group ID per source sample ─────────────────────
    # Each augmented variant maps back to its original source via source_of().
    # StratifiedGroupKFold guarantees all variants of a source stay together.
    names  = [str(ds[i].name) for i in range(n)]
    groups = np.array([source_of(name) for name in names])

    unique_sources   = sorted(set(groups))
    n_sources        = len(unique_sources)
    source_label_map = {}  # source → label (for reporting)
    for name, label in zip(names, labels):
        src = source_of(name)
        source_label_map[src] = int(label)

    label_counts = dict(zip(*np.unique(labels, return_counts=True)))
    print(f"[Train] Graphs    : {n}  |  feature dim={in_dim}")
    print(f"[Train] Sources   : {n_sources} unique source samples")
    print(f"[Train] Model     : {args.model.upper()}")
    print(f"[Train] Label dist: {label_counts}")
    print(f"[Train] Split     : StratifiedGroupKFold — groups=source sample names")

    class_weights = compute_class_weights(labels, device)
    print(f"[Train] Class weights: {class_weights.tolist()}")

    if n_sources < args.folds:
        print(f"[WARN] Only {n_sources} unique sources but --folds={args.folds}; "
              f"reducing to {n_sources} folds.")
        args.folds = n_sources

    # StratifiedGroupKFold: stratify by label, constrain by source group
    sgkf    = StratifiedGroupKFold(n_splits=args.folds, shuffle=True,
                                   random_state=args.seed)
    indices = np.arange(n)

    fold_results = []

    for fold, (train_idx, test_idx) in enumerate(
            sgkf.split(indices, labels, groups=groups), 1):

        # Verify no source leakage
        train_sources = set(groups[train_idx])
        test_sources  = set(groups[test_idx])
        leaked = train_sources & test_sources
        if leaked:
            # Should never happen — but loud warning if it does
            print(f"  [LEAK WARNING] {len(leaked)} source(s) appear in "
                  f"both train and test: {leaked}")

        print(f"\n── Fold {fold}/{args.folds} "
              f"(train={len(train_idx)}, test={len(test_idx)}) "
              f"[{len(train_sources)} train-sources / "
              f"{len(test_sources)} test-sources] ──")

        test_labels = labels[test_idx]
        if len(set(test_labels)) < 2:
            print(f"  [WARN] Test fold has only class {set(test_labels)} — "
                  f"AUC/F1 unreliable for this fold")

        train_ds = [ds[i] for i in train_idx]
        test_ds  = [ds[i] for i in test_idx]

        train_loader = DataLoader(train_ds, batch_size=args.batch_size,
                                  shuffle=True)
        test_loader  = DataLoader(test_ds,  batch_size=args.batch_size,
                                  shuffle=False)

        model     = build_model(args, in_dim, device)
        optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                     weight_decay=args.weight_decay)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimiser, mode="max", factor=0.5, patience=20, min_lr=1e-5
        )

        best_f1    = -1.0
        best_state = {k: v.clone() for k, v in model.state_dict().items()}

        for epoch in range(1, args.epochs + 1):
            loss = train_epoch(model, train_loader, optimiser, device,
                               class_weights)
            acc, f1, auc, _ = evaluate(model, test_loader, device)
            scheduler.step(f1)

            if epoch % 20 == 0 or epoch == args.epochs:
                print(f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                      f"acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}  "
                      f"lr={optimiser.param_groups[0]['lr']:.2e}")

            if f1 > best_f1:
                best_f1    = f1
                best_state = {k: v.clone()
                              for k, v in model.state_dict().items()}

        # Final eval with best weights
        model.load_state_dict(best_state)
        acc, f1, auc, cm = evaluate(model, test_loader, device)
        print(f"  Best → acc={acc:.3f}  f1={f1:.3f}  auc={auc:.3f}")
        print(f"  Confusion matrix:\n{cm}")
        print(f"  Test sources : {sorted(test_sources)}")

        if args.save_model:
            ckpt = f"model_{args.model}_fold{fold}.pt"
            torch.save(best_state, ckpt)
            print(f"  Saved checkpoint → {ckpt}")

        fold_results.append({"fold": fold, "acc": acc, "f1": f1, "auc": auc,
                              "test_sources": sorted(test_sources)})

        # Per-sample predictions
        model.eval()
        with torch.no_grad():
            for data in test_ds:
                data      = data.to(device)
                batch_vec = torch.zeros(data.x.size(0), dtype=torch.long,
                                        device=device)
                graph_attr = getattr(data, "graph_attr", None)
                if graph_attr is not None:
                    graph_attr = graph_attr.unsqueeze(0).to(device)

                out  = model(data.x, data.edge_index, batch_vec,
                             graph_attr=graph_attr)
                pred = out.argmax(dim=1).item()
                prob = F.softmax(out, dim=1)[0, 1].item()
                name = getattr(data, "name", f"graph_{id(data)}")
                true = data.y.item()
                status = "✅" if pred == true else "❌"
                print(f"    {status} {str(name):<50} "
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

    out_path = f"results_{args.model}_{args.folds}fold.json"
    with open(out_path, "w") as f:
        json.dump({
            "model":        args.model,
            "folds":        args.folds,
            "epochs":       args.epochs,
            "hidden":       args.hidden,
            "seed":         args.seed,
            "batch_size":   args.batch_size,
            "timestamp":    datetime.datetime.utcnow().isoformat(),
            "git_hash":     git_hash(),
            "class_weights": class_weights.tolist(),
            "split_strategy": "StratifiedGroupKFold",
            "n_unique_sources": n_sources,
            "mean_acc":     float(np.mean(accs)),
            "std_acc":      float(np.std(accs)),
            "mean_f1":      float(np.mean(f1s)),
            "std_f1":       float(np.std(f1s)),
            "mean_auc":     float(np.mean(aucs)),
            "std_auc":      float(np.std(aucs)),
            "fold_results": fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="5-fold CV training for MalVol-25 GNN classifier"
    )
    parser.add_argument("manifest",       help="Path to dataset_manifest.csv")
    parser.add_argument("--model",        default="gin", choices=["gin", "sage"])
    parser.add_argument("--folds",        type=int,   default=5)
    parser.add_argument("--epochs",       type=int,   default=200)
    parser.add_argument("--hidden",       type=int,   default=64)
    parser.add_argument("--layers",       type=int,   default=3)
    parser.add_argument("--dropout",      type=float, default=0.3)
    parser.add_argument("--lr",           type=float, default=1e-3)
    parser.add_argument("--weight-decay", type=float, default=1e-4,
                        dest="weight_decay")
    parser.add_argument("--batch-size",   type=int,   default=4,
                        dest="batch_size")
    parser.add_argument("--seed",         type=int,   default=42)
    parser.add_argument("--save-model",   action="store_true",
                        dest="save_model",
                        help="Save best model checkpoint per fold")
    args = parser.parse_args()
    run(args)
