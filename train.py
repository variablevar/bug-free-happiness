#!/usr/bin/env python3
"""
train.py  v9
Fix vs v8:
  - graph_attr per Data object is [1, 14] (dataset.py v3).
    * graph_attr_dim log now reads .shape[-1] so it prints 14, not 1.
    * Single-graph eval block: squeeze dim-0 first so unsqueeze(0) gives
      [1, 14] not [1, 1, 14] which broke the lazy head in model.py.
"""

import os, sys, argparse, json, datetime, re, types
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from sklearn.model_selection import LeaveOneGroupOut
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset        import MalwareGraphDataset
from model          import GINMalwareClassifier, SAGEMalwareClassifier
from evaluate_stats import log_prediction, run_stats


# ── Source-name extraction ────────────────────────────────────────────────────

_AUG_SUFFIX = re.compile(r"__aug_[a-z]+_\d+$")

def source_of(name: str) -> str:
    return _AUG_SUFFIX.sub("", str(name))


# ── Training helpers ──────────────────────────────────────────────────────────

def train_epoch(model, loader, optimiser, device, class_weights):
    model.train()
    total_loss = 0
    for batch in loader:
        batch = batch.to(device)
        optimiser.zero_grad()

        graph_attr = getattr(batch, "graph_attr", None)
        # DataLoader stacks [1,14] tensors along dim-0 → [B, 14]. No reshape needed.

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
        # DataLoader already gives [B, 14] — no reshape needed.

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

    cm = confusion_matrix(labels, preds, labels=[0, 1])
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
    counts  = np.bincount(labels)
    total   = len(labels)
    weights = torch.tensor(
        [total / (len(counts) * c) for c in counts],
        dtype=torch.float, device=device
    )
    return weights


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

    # ── Load dataset ────────────────────────────────────────────────────────────
    base_dir = getattr(args, "base_dir", None)
    ds = MalwareGraphDataset(args.manifest, base_dir=base_dir)
    n  = len(ds)
    if n == 0:
        print("[ERROR] Dataset is empty.")
        sys.exit(1)

    labels = np.array(ds.get_labels())

    first = ds[0]
    if first.x is None or first.x.dim() < 2:
        print("[ERROR] ds[0].x is None or 1-D.")
        sys.exit(1)
    in_dim = first.x.size(1)

    # graph_attr is [1, 14] per sample — read last dim for the true feature count
    graph_attr_dim = (
        first.graph_attr.shape[-1]
        if hasattr(first, "graph_attr") and first.graph_attr is not None
        else 0
    )

    names  = [str(ds[i].name) for i in range(n)]
    groups = np.array([source_of(name) for name in names])

    unique_sources = sorted(set(groups))
    n_sources      = len(unique_sources)

    label_counts = dict(zip(*np.unique(labels, return_counts=True)))
    print(f"[Train] Graphs      : {n}  |  node_feat={in_dim}  graph_attr={graph_attr_dim}")
    print(f"[Train] Sources     : {n_sources} unique — LOSO ({n_sources} folds)")
    print(f"[Train] Model       : {args.model.upper()}  hidden={args.hidden}  layers={args.layers}")
    print(f"[Train] Label dist  : {label_counts}")

    class_weights = compute_class_weights(labels, device)
    print(f"[Train] Class weights: {class_weights.tolist()}")

    # ── LOSO split ────────────────────────────────────────────────────────────
    logo    = LeaveOneGroupOut()
    indices = np.arange(n)

    fold_results = []
    n_folds      = n_sources

    for fold, (train_idx, test_idx) in enumerate(
            logo.split(indices, labels, groups=groups), 1):

        test_source = groups[test_idx][0]
        test_label  = int(labels[test_idx[0]])

        print(f"\n── Fold {fold:>2}/{n_folds}  "
              f"test={test_source} (label={test_label})  "
              f"train={len(train_idx)} graphs ──")

        train_ds = [ds[i] for i in train_idx]
        test_ds  = [ds[i] for i in test_idx]

        train_loader = DataLoader(train_ds, batch_size=args.batch_size,
                                  shuffle=True)
        test_loader  = DataLoader(test_ds,  batch_size=1, shuffle=False)

        model     = build_model(args, in_dim, device)
        optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                     weight_decay=args.weight_decay)
        scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
            optimiser, mode="max", factor=0.5, patience=20, min_lr=1e-5
        )

        best_f1    = -1.0
        best_acc   = -1.0
        best_state = {k: v.clone() for k, v in model.state_dict().items()}

        for epoch in range(1, args.epochs + 1):
            loss = train_epoch(model, train_loader, optimiser, device,
                               class_weights)
            train_acc, train_f1, _, _ = evaluate(model, train_loader, device)
            scheduler.step(train_f1)

            if epoch % 50 == 0 or epoch == args.epochs:
                print(f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                      f"train_acc={train_acc:.3f}  "
                      f"lr={optimiser.param_groups[0]['lr']:.2e}")

            if train_f1 > best_f1 or (train_f1 == best_f1 and train_acc > best_acc):
                best_f1    = train_f1
                best_acc   = train_acc
                best_state = {k: v.clone()
                              for k, v in model.state_dict().items()}

        # ── Final eval on the single held-out source ────────────────────────────
        model.load_state_dict(best_state)
        model.eval()
        with torch.no_grad():
            data      = test_ds[0].clone().to(device)
            batch_vec = torch.zeros(data.x.size(0), dtype=torch.long,
                                    device=device)

            graph_attr = getattr(data, "graph_attr", None)
            if graph_attr is not None:
                # dataset.py stores [1, 14]; squeeze to [14] then unsqueeze to [1, 14]
                # This avoids a double-unsqueeze producing [1, 1, 14].
                graph_attr = graph_attr.squeeze(0).unsqueeze(0).to(device)  # [1, 14]

            out  = model(data.x, data.edge_index, batch_vec,
                         graph_attr=graph_attr)
            pred = out.argmax(dim=1).item()
            prob = F.softmax(out, dim=1)[0, 1].item()
            true = data.y.item()

        correct = pred == true
        status  = "✅" if correct else "❌"
        print(f"  {status}  pred={pred}  true={true}  prob={prob:.3f}")

        log_prediction(
            source=test_source,
            pred=int(pred),
            true=int(true),
            prob=float(prob),
        )

        if args.save_model:
            ckpt = f"model_{args.model}_loso_{test_source}.pt"
            torch.save(best_state, ckpt)

        fold_results.append({
            "fold":        fold,
            "test_source": test_source,
            "true_label":  test_label,
            "pred":        int(pred),
            "prob":        round(prob, 4),
            "correct":     bool(correct),
        })

    # ── LOSO Summary ────────────────────────────────────────────────────────────
    n_correct = sum(r["correct"] for r in fold_results)
    loso_acc  = n_correct / n_folds

    mal_folds = [r for r in fold_results if r["true_label"] == 1]
    ben_folds = [r for r in fold_results if r["true_label"] == 0]
    mal_acc   = sum(r["correct"] for r in mal_folds) / max(len(mal_folds), 1)
    ben_acc   = sum(r["correct"] for r in ben_folds) / max(len(ben_folds), 1)

    print("\n" + "=" * 60)
    print(f"  LOSO RESULTS ({args.model.upper()})  —  {n_folds} folds")
    print("=" * 60)
    print(f"  Overall accuracy : {loso_acc:.3f}  ({n_correct}/{n_folds})")
    print(f"  Malware  (label=1): {mal_acc:.3f}  "
          f"({sum(r['correct'] for r in mal_folds)}/{len(mal_folds)})")
    print(f"  Benign   (label=0): {ben_acc:.3f}  "
          f"({sum(r['correct'] for r in ben_folds)}/{len(ben_folds)})")
    print("=" * 60)

    run_stats()

    out_path = f"results_{args.model}_loso.json"
    with open(out_path, "w") as f:
        json.dump({
            "model":        args.model,
            "eval":         "LOSO",
            "n_folds":      n_folds,
            "epochs":       args.epochs,
            "hidden":       args.hidden,
            "layers":       args.layers,
            "seed":         args.seed,
            "batch_size":   args.batch_size,
            "timestamp":    datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash":     git_hash(),
            "loso_acc":     round(loso_acc, 4),
            "mal_acc":      round(mal_acc, 4),
            "ben_acc":      round(ben_acc, 4),
            "fold_results": fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LOSO CV training for MalVol-25 GNN classifier"
    )
    parser.add_argument("manifest",        help="Path to dataset_manifest.csv")
    parser.add_argument("--base-dir",      default=None, dest="base_dir",
                        help="Base directory containing graph.pkl folders "
                             "(defaults to dirname of manifest)")
    parser.add_argument("--model",         default="gin", choices=["gin", "sage"])
    parser.add_argument("--epochs",        type=int,   default=300)
    parser.add_argument("--hidden",        type=int,   default=16)
    parser.add_argument("--layers",        type=int,   default=2)
    parser.add_argument("--dropout",       type=float, default=0.5)
    parser.add_argument("--lr",            type=float, default=1e-3)
    parser.add_argument("--weight-decay",  type=float, default=1e-4,
                        dest="weight_decay")
    parser.add_argument("--batch-size",    type=int,   default=8,
                        dest="batch_size")
    parser.add_argument("--seed",          type=int,   default=42)
    parser.add_argument("--save-model",    action="store_true",
                        dest="save_model")
    args = parser.parse_args()
    run(args)
