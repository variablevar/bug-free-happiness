#!/usr/bin/env python3
"""
train.py  v15
Changes vs v14:
  - --model gat | gine; --gat-heads, --edge-emb-dim; forward passes edge_attr for GINE.
  - --include-unknown for manifests containing label=-1 rows.
Prior v14: --val-fraction, --label-smoothing.
"""

import os, sys, argparse, json, datetime, re, copy
import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader
from torch_geometric.data import Data
from sklearn.model_selection import (
    LeaveOneGroupOut,
    StratifiedGroupKFold,
    train_test_split,
)
from sklearn.metrics import (accuracy_score, f1_score,
                              roc_auc_score, confusion_matrix)

from dataset        import MalwareGraphDataset
from model import (
    GINMalwareClassifier,
    SAGEMalwareClassifier,
    GATMalwareClassifier,
    GINEMalwareClassifier,
)
from evaluate_stats import log_prediction, run_stats
from utils.schema   import EXPECTED_GRAPH_ATTR_DIM

# Hardcoded — with ~29 train samples, batch_size=4 gives ~7 batches/epoch.
TRAIN_BATCH_SIZE = 4


# ── Source-name extraction ────────────────────────────────────────────────────

_AUG_SUFFIX = re.compile(r"__aug_[a-z]+_\d+$")

def source_of(name: str) -> str:
    return _AUG_SUFFIX.sub("", str(name))


def build_cv_groups(ds, n: int, names: list[str], group_by: str) -> np.ndarray:
    """Group id per sample: by graph folder name (source) or malware family."""
    group_by = str(group_by).strip().lower()
    if group_by == "family":
        return np.array(
            [
                str(getattr(ds[i], "family", None) or "unknown").strip().lower()
                for i in range(n)
            ],
            dtype=object,
        )
    if group_by == "source":
        return np.array([source_of(names[i]) for i in range(n)], dtype=object)
    raise ValueError(f"Invalid --group-by: {group_by} (use source or family)")


def build_cv_splits(
    cv: str,
    n: int,
    labels: np.ndarray,
    groups: np.ndarray,
    n_splits: int,
    seed: int,
) -> list[tuple[np.ndarray, np.ndarray]]:
    """
    Return list of (train_idx, test_idx) for one full CV pass.
    cv=loso: LeaveOneGroupOut (one held-out group per split).
    cv=stratified_group: StratifiedGroupKFold (balanced classes, no group leakage).
    """
    indices = np.arange(n)
    cv = str(cv).strip().lower()
    if cv == "loso":
        logo = LeaveOneGroupOut()
        return list(logo.split(indices, labels, groups=groups))

    if cv == "stratified_group":
        n_unique_groups = len(np.unique(groups))
        if n_unique_groups < 2:
            print(
                "[ERROR] stratified_group CV needs at least 2 distinct groups "
                "(try --group-by source)."
            )
            sys.exit(1)
        k = int(n_splits)
        k = max(2, min(k, n_unique_groups))
        last_err = None
        for attempt in range(k, 1, -1):
            try:
                sgkf = StratifiedGroupKFold(
                    n_splits=attempt,
                    shuffle=True,
                    random_state=seed,
                )
                splits = list(sgkf.split(indices, labels, groups=groups))
                if splits:
                    return splits
            except ValueError as exc:
                last_err = exc
                continue
        print(
            f"[ERROR] StratifiedGroupKFold could not build splits "
            f"(last error: {last_err}). Try --cv loso or fewer classes / more groups."
        )
        sys.exit(1)

    raise ValueError(f"Invalid --cv: {cv} (use loso or stratified_group)")


# ── Graph augmentation ────────────────────────────────────────────────────────

def augment_graph(data: Data, edge_drop_p: float = 0.15,
                  feat_mask_p: float = 0.10) -> Data:
    """
    Returns a new Data object with:
      - random edge dropping (edge_drop_p fraction removed)
      - random feature masking (feat_mask_p fraction zeroed)
    Graph-level attributes (graph_attr, y, name) are copied unchanged.
    """
    aug = copy.deepcopy(data)

    # Edge drop
    if aug.edge_index is not None and aug.edge_index.size(1) > 0:
        n_edges  = aug.edge_index.size(1)
        keep     = torch.rand(n_edges) >= edge_drop_p
        aug.edge_index = aug.edge_index[:, keep]
        ea = getattr(aug, "edge_attr", None)
        if ea is not None and ea.size(0) == n_edges:
            aug.edge_attr = ea[keep]

    # Feature mask
    if aug.x is not None:
        mask = torch.rand_like(aug.x) >= feat_mask_p
        aug.x = aug.x * mask.float()

    return aug


def build_augmented_dataset(ds_list, n_aug: int = 1) -> list:
    """
    For each graph in ds_list, add n_aug augmented copies.
    Returns original + augmented graphs.
    """
    augmented = list(ds_list)
    for data in ds_list:
        for _ in range(n_aug):
            augmented.append(augment_graph(data))
    return augmented


def _label_of(data: Data) -> int:
    y = getattr(data, "y", None)
    if y is None:
        return -1
    if hasattr(y, "item"):
        return int(y.item())
    return int(y)


def build_benign_augmented_dataset(
    ds_list,
    target_ratio: float = 1.0,
    edge_drop_p: float = 0.05,
    feat_mask_p: float = 0.05,
    max_copies_per_sample: int = 50,
) -> list:
    """
    Oversample benign class via graph augmentation until:
      benign_count >= target_ratio * malware_count

    Notes:
      - If there are 0 benign samples in a fold, no benign augmentation is possible.
      - Uses gentler perturbation defaults than generic augmentation.
    """
    if target_ratio <= 0:
        return list(ds_list)

    base = list(ds_list)
    benign = [d for d in base if _label_of(d) == 0]
    malware = [d for d in base if _label_of(d) == 1]
    benign_count = len(benign)
    malware_count = len(malware)

    if benign_count == 0 or malware_count == 0:
        return base

    target_benign = int(np.ceil(target_ratio * malware_count))
    if benign_count >= target_benign:
        return base

    needed = target_benign - benign_count
    generated = []
    idx = 0
    while len(generated) < needed:
        src = benign[idx % benign_count]
        generated.append(
            augment_graph(src, edge_drop_p=edge_drop_p, feat_mask_p=feat_mask_p)
        )
        idx += 1
        # safety brake against accidental runaway loops
        if idx > benign_count * max_copies_per_sample:
            break

    return base + generated


# ── Training helpers ──────────────────────────────────────────────────────────

def train_epoch(model, loader, optimiser, device, class_weights, label_smoothing: float = 0.0):
    model.train()
    total_loss = 0
    for batch in loader:
        batch = batch.to(device)
        graph_attr = getattr(batch, "graph_attr", None)

        if graph_attr is not None:
            assert graph_attr.dim() == 2, (
                f"[ERROR] graph_attr has unexpected shape {graph_attr.shape}. "
                f"Expected [B, D]."
            )
            assert graph_attr.size(1) == EXPECTED_GRAPH_ATTR_DIM, (
                f"[ERROR] graph_attr feature dim {graph_attr.size(1)} "
                f"!= expected {EXPECTED_GRAPH_ATTR_DIM}."
            )

        edge_attr = getattr(batch, "edge_attr", None)
        node_mask = getattr(batch, "suspect_node_mask", None)
        out  = model(
            batch.x, batch.edge_index, batch.batch,
            graph_attr=graph_attr, edge_attr=edge_attr, node_mask=node_mask,
        )
        loss = F.cross_entropy(
            out, batch.y, weight=class_weights,
            label_smoothing=float(label_smoothing),
        )
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
        optimiser.step()
        optimiser.zero_grad()
        total_loss += loss.item()
    return total_loss / max(len(loader), 1)


@torch.no_grad()
def evaluate(model, loader, device, num_classes: int = 2):
    model.eval()
    preds, probs, labels = [], [], []
    for batch in loader:
        batch = batch.to(device)
        graph_attr = getattr(batch, "graph_attr", None)

        edge_attr = getattr(batch, "edge_attr", None)
        node_mask = getattr(batch, "suspect_node_mask", None)
        out   = model(
            batch.x, batch.edge_index, batch.batch,
            graph_attr=graph_attr, edge_attr=edge_attr, node_mask=node_mask,
        )
        prob_tensor = F.softmax(out, dim=1)
        if num_classes == 2:
            prob = prob_tensor[:, 1].cpu().numpy()
        else:
            prob = prob_tensor.max(dim=1).values.cpu().numpy()
        pred  = out.argmax(dim=1).cpu().numpy()
        label = batch.y.cpu().numpy()
        preds.extend(pred)
        probs.extend(prob)
        labels.extend(label)

    acc = accuracy_score(labels, preds)
    f1  = f1_score(
        labels,
        preds,
        average=("binary" if num_classes == 2 else "macro"),
        zero_division=0,
    )
    try:
        auc = roc_auc_score(labels, probs) if len(set(labels)) > 1 else 0.0
    except ValueError:
        auc = 0.0

    all_positive = num_classes == 2 and len(preds) > 0 and all(p == 1 for p in preds)
    all_negative = num_classes == 2 and len(preds) > 0 and all(p == 0 for p in preds)
    bias_flag = all_positive or all_negative

    cm = confusion_matrix(labels, preds, labels=list(range(num_classes)))
    return acc, f1, auc, cm, bias_flag


def build_model(args, in_dim, device, num_classes: int = 2, dropout_override=None):
    dropout = dropout_override if dropout_override is not None else args.dropout
    kwargs  = dict(
        in_channels=in_dim,
        hidden=args.hidden,
        layers=args.layers,
        dropout=dropout,
        num_classes=num_classes,
    )
    if args.model == "sage":
        m = SAGEMalwareClassifier(**kwargs)
    elif args.model == "gat":
        heads = int(getattr(args, "gat_heads", 4))
        m = GATMalwareClassifier(**kwargs, heads=heads)
    elif args.model == "gine":
        edge_emb_dim = int(getattr(args, "edge_emb_dim", 8))
        m = GINEMalwareClassifier(**kwargs, edge_emb_dim=edge_emb_dim)
    else:
        m = GINMalwareClassifier(**kwargs)
    return m.to(device)


def compute_class_weights(labels, device, num_classes: int, benign_boost: float = 2.0):
    """
    Inverse-frequency weights with an additional `benign_boost` multiplier on
    the benign class (label=0) to counter positive-bias collapse.
    benign_boost=2.0 means benign misclassifications cost twice as much.
    """
    counts  = np.bincount(labels, minlength=num_classes)
    counts[counts == 0] = 1
    total   = len(labels)
    weights = np.array([total / (len(counts) * c) for c in counts],
                       dtype=np.float32)
    if num_classes == 2:
        weights[0] *= benign_boost          # extra penalty for missing benign
    weights = torch.tensor(weights, dtype=torch.float, device=device)
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


# ── Single-fold training ──────────────────────────────────────────────────────

def _split_train_val_indices(
    n_samples: int,
    labels: np.ndarray,
    val_fraction: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Return (train_idx, val_idx) into range(n_samples)."""
    idx = np.arange(n_samples)
    vf = float(val_fraction)
    if vf <= 0 or n_samples < 4:
        return idx, np.array([], dtype=int)
    uniq, cnts = np.unique(labels, return_counts=True)
    strat = labels if len(uniq) >= 2 and int(np.min(cnts)) >= 2 else None
    try:
        tr, va = train_test_split(
            idx, test_size=vf, stratify=strat, random_state=seed,
        )
        return np.asarray(tr, dtype=int), np.asarray(va, dtype=int)
    except ValueError:
        tr, va = train_test_split(idx, test_size=vf, random_state=seed)
        return np.asarray(tr, dtype=int), np.asarray(va, dtype=int)


def train_one_fold(
    args,
    train_ds,
    test_ds_fold: list,
    in_dim,
    device,
    class_weights,
    dropout_override=None,
):
    """
    Train one CV outer fold. test_ds_fold is a non-empty list of held-out Data.
    Returns (list of (pred, prob, true), best_state, bias_flag).
    """
    train_list = list(train_ds)
    val_fraction = float(getattr(args, "val_fraction", 0.0) or 0.0)
    label_smoothing = float(getattr(args, "label_smoothing", 0.0) or 0.0)

    if val_fraction > 0 and len(train_list) >= 4:
        y_arr = np.array([_label_of(d) for d in train_list], dtype=int)
        idx_tr, idx_va = _split_train_val_indices(
            len(train_list), y_arr, val_fraction, args.seed,
        )
        if len(idx_va) > 0:
            val_list = [train_list[i] for i in idx_va]
            train_list = [train_list[i] for i in idx_tr]
            print(
                f"  [Val-select] inner train={len(train_list)}  val={len(val_list)}  "
                f"fraction={val_fraction:.2f}"
            )
        else:
            val_list = []
    else:
        val_list = []

    train_ds = train_list

    # Optionally oversample benign class first.
    if getattr(args, "augment_benign", False):
        before = len(train_ds)
        train_ds = build_benign_augmented_dataset(
            train_ds,
            target_ratio=args.benign_target_ratio,
            edge_drop_p=args.benign_edge_drop,
            feat_mask_p=args.benign_feat_mask,
        )
        after = len(train_ds)
        if after > before:
            print(f"  [Augment-benign] train graphs: {before} -> {after}")
        else:
            print("  [Augment-benign] skipped (fold has no benign sample to augment)")

    # Optionally augment training data
    if getattr(args, "augment", False):
        train_ds = build_augmented_dataset(train_ds, n_aug=1)

    train_loader = DataLoader(train_ds, batch_size=TRAIN_BATCH_SIZE,
                              shuffle=True)
    val_loader = (
        DataLoader(val_list, batch_size=TRAIN_BATCH_SIZE, shuffle=False)
        if val_list else None
    )
    test_loader  = DataLoader(test_ds_fold, batch_size=1, shuffle=False)

    num_classes = int(getattr(args, "resolved_num_classes", 2))
    model     = build_model(args, in_dim, device,
                            num_classes=num_classes,
                            dropout_override=dropout_override)
    optimiser = torch.optim.Adam(model.parameters(), lr=args.lr,
                                 weight_decay=args.weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(
        optimiser, T_max=args.epochs, eta_min=1e-5
    )

    best_f1    = -1.0
    best_acc   = -1.0
    best_state = {k: v.clone() for k, v in model.state_dict().items()}

    for epoch in range(1, args.epochs + 1):
        loss = train_epoch(
            model, train_loader, optimiser, device, class_weights,
            label_smoothing=label_smoothing,
        )
        train_acc, train_f1, _, _, bias_flag = evaluate(
            model, train_loader, device, num_classes=num_classes
        )
        if val_loader is not None:
            val_acc, val_f1, _, _, _ = evaluate(
                model, val_loader, device, num_classes=num_classes
            )
            pick_f1, pick_acc = val_f1, val_acc
        else:
            val_acc = val_f1 = None
            pick_f1, pick_acc = train_f1, train_acc
        scheduler.step()

        if epoch % 10 == 0 or epoch == args.epochs:
            msg = (
                f"  Epoch {epoch:>3}  loss={loss:.4f}  "
                f"train_acc={train_acc:.3f}  "
                f"lr={optimiser.param_groups[0]['lr']:.2e}"
                + ("  ⚠️ ALL-POSITIVE" if bias_flag else "")
            )
            if val_loader is not None:
                msg += f"  val_acc={val_acc:.3f}  val_f1={val_f1:.3f}"
            print(msg)

        if pick_f1 > best_f1 or (pick_f1 == best_f1 and pick_acc > best_acc):
            best_f1    = pick_f1
            best_acc   = pick_acc
            best_state = {k: v.clone()
                          for k, v in model.state_dict().items()}

    # ── Evaluate on all held-out graphs in this fold ────────────────────────────
    model.load_state_dict(best_state)
    model.eval()
    results: list[tuple[int, float, int]] = []
    with torch.no_grad():
        for data in test_ds_fold:
            data = data.clone().to(device)
            batch_vec = torch.zeros(data.x.size(0), dtype=torch.long,
                                    device=device)

            graph_attr = getattr(data, "graph_attr", None)
            if graph_attr is not None:
                graph_attr = graph_attr.squeeze(0).unsqueeze(0).to(device)

            edge_attr = getattr(data, "edge_attr", None)
            out = model(
                data.x, data.edge_index, batch_vec,
                graph_attr=graph_attr, edge_attr=edge_attr,
            )
            pred = out.argmax(dim=1).item()
            probs = F.softmax(out, dim=1)[0]
            if num_classes == 2:
                prob = probs[1].item()
            else:
                prob = probs[pred].item()
            true = data.y.item()
            results.append((pred, prob, true))

    return results, best_state, bias_flag


# ── Main ──────────────────────────────────────────────────────────────────────

def run(args):
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[Train] Device : {device}")
    print(f"[Train] Seed   : {args.seed}")

    if args.model == "gat" and args.hidden % int(args.gat_heads) != 0:
        print(
            f"[ERROR] GAT requires --hidden divisible by --gat-heads "
            f"(got hidden={args.hidden}, gat_heads={args.gat_heads})."
        )
        sys.exit(1)

    base_dir = getattr(args, "base_dir", None)
    ds = MalwareGraphDataset(
        args.manifest,
        base_dir=base_dir,
        include_uncertain=args.include_uncertain,
        include_unknown=args.include_unknown,
        target=args.target,
    )
    n  = len(ds)
    if n == 0:
        print("[ERROR] Dataset is empty.")
        sys.exit(1)

    labels = np.array(ds.get_labels(), dtype=int)
    observed_num_classes = int(labels.max()) + 1
    num_classes = args.num_classes if args.num_classes is not None else observed_num_classes
    if observed_num_classes > num_classes:
        print(
            f"[ERROR] Observed class index requires {observed_num_classes} classes, "
            f"but --num-classes={num_classes}."
        )
        sys.exit(1)
    args.resolved_num_classes = num_classes

    first = ds[0]
    if first.x is None or first.x.dim() < 2:
        print("[ERROR] ds[0].x is None or 1-D.")
        sys.exit(1)
    in_dim = first.x.size(1)

    graph_attr_dim = (
        first.graph_attr.shape[-1]
        if hasattr(first, "graph_attr") and first.graph_attr is not None
        else 0
    )

    names  = [str(ds[i].name) for i in range(n)]
    groups = build_cv_groups(ds, n, names, args.group_by)

    unique_groups = sorted(set(groups.tolist()))
    n_groups        = len(unique_groups)

    label_counts = dict(zip(*np.unique(labels, return_counts=True)))
    benign_boost = getattr(args, "benign_boost", 2.0)

    fold_splits = build_cv_splits(
        args.cv, n, labels, groups, args.n_splits, args.seed,
    )
    for ti, (tr, te) in enumerate(fold_splits):
        if len(tr) == 0 or len(te) == 0:
            print(
                f"[ERROR] CV split {ti} has empty train or test "
                f"(train={len(tr)}, test={len(te)}). Try --group-by source."
            )
            sys.exit(1)
    n_outer_folds = len(fold_splits)

    print(f"[Train] Graphs      : {n}  |  node_feat={in_dim}  graph_attr={graph_attr_dim}")
    print(
        f"[Train] CV          : {args.cv}  group_by={args.group_by}  "
        f"groups={n_groups}  outer_folds={n_outer_folds}"
        + (f"  n_splits={args.n_splits}" if args.cv == "stratified_group" else "")
    )
    if args.cv == "loso" and args.group_by == "source":
        print(
            "[Train] Tip: --cv stratified_group --group-by family --n-splits 5  "
            "→ stratified folds, same family never in train and test together"
        )
    model_line = (
        f"{args.model.upper()}  hidden={args.hidden}  layers={args.layers}"
    )
    if args.model == "gat":
        model_line += f"  heads={args.gat_heads}"
    if args.model == "gine":
        model_line += f"  edge_emb_dim={args.edge_emb_dim}"
    print(f"[Train] Model       : {model_line}")
    print(f"[Train] Target      : {args.target}  classes={num_classes}")
    print(f"[Train] Label dist  : {label_counts}")
    print(f"[Train] Epochs      : {args.epochs}  batch_size={TRAIN_BATCH_SIZE}  lr={args.lr}")
    print(f"[Train] Augment     : {getattr(args, 'augment', False)}")
    print(f"[Train] Augment benign: {getattr(args, 'augment_benign', False)}")
    if num_classes == 2:
        print(f"[Train] Benign boost: {benign_boost}x")
    print(f"[Train] Include uncertain: {args.include_uncertain}")
    print(f"[Train] Include unknown  : {args.include_unknown}")
    vf = float(getattr(args, "val_fraction", 0.0) or 0.0)
    ls = float(getattr(args, "label_smoothing", 0.0) or 0.0)
    print(f"[Train] Val fraction   : {vf}  (checkpoint by val acc/F1 if >0)")
    print(f"[Train] Label smooth   : {ls}")

    print(
        "[Train] Class weights: computed per outer fold from training labels only "
        "(inverse frequency; benign_boost only when num_classes==2)"
    )

    fold_results: list[dict] = []

    for fold, (train_idx, test_idx) in enumerate(fold_splits, 1):
        train_labels = labels[train_idx]
        class_weights_fold = compute_class_weights(
            train_labels, device, num_classes=num_classes,
            benign_boost=benign_boost,
        )

        train_ds_fold = [ds[i] for i in train_idx]
        test_ds_fold  = [ds[i] for i in test_idx]
        test_names    = [str(d.name) for d in test_ds_fold]
        test_groups   = [str(groups[i]) for i in test_idx]

        print(
            f"\n── Outer fold {fold:>2}/{n_outer_folds}  "
            f"train={len(train_idx)}  test={len(test_idx)}  "
            f"weights={class_weights_fold.detach().cpu().tolist()} ──"
        )
        if len(test_ds_fold) <= 5:
            print(f"  Held-out: {', '.join(test_names)}")
        else:
            print(f"  Held-out ({len(test_names)}): {', '.join(test_names[:3])}, …")

        results, best_state, bias_flag = train_one_fold(
            args, train_ds_fold, test_ds_fold, in_dim, device,
            class_weights_fold,
        )

        # Retry with higher dropout if binary train collapsed and any held-out wrong
        if num_classes == 2 and bias_flag and any(
                p != t for (p, _, t) in results
        ):
            print("  ⚠️  Bias collapse detected — retrying with dropout=0.6")
            torch.manual_seed(args.seed + fold * 100)
            results, best_state, _ = train_one_fold(
                args, train_ds_fold, test_ds_fold, in_dim, device,
                class_weights_fold,
                dropout_override=0.6,
            )

        for (pred, prob, true), test_source, held_group in zip(
                results, test_names, test_groups
        ):
            correct = pred == true
            status  = "✅" if correct else "❌"
            print(
                f"  {status}  test={test_source}  group={held_group}  "
                f"pred={pred}  true={true}  prob={prob:.3f}"
            )

            log_prediction(
                source=test_source,
                pred=int(pred),
                true=int(true),
                prob=float(prob),
            )

            fold_results.append({
                "outer_fold":   fold,
                "fold":         fold,  # alias for tools expecting legacy key
                "test_source":  test_source,
                "held_group":   held_group,
                "true_label":   int(true),
                "pred":         int(pred),
                "prob":         round(prob, 4),
                "correct":      bool(correct),
            })

        if getattr(args, "save_model", False):
            if len(test_ds_fold) == 1:
                ckpt = f"model_{args.model}_{args.cv}_{test_names[0]}.pt"
            else:
                ckpt = f"model_{args.model}_{args.cv}_fold{fold}.pt"
            torch.save(best_state, ckpt)

    # ── CV summary ────────────────────────────────────────────────────────────
    n_eval = len(fold_results)
    n_correct = sum(r["correct"] for r in fold_results)
    overall_acc = n_correct / max(n_eval, 1)

    eval_label = (
        "LOSO" if args.cv == "loso" else "StratifiedGroupKFold"
    )
    print("\n" + "=" * 60)
    print(f"  CV RESULTS ({args.model.upper()})  —  {eval_label}")
    print("=" * 60)
    print(
        f"  Overall accuracy : {overall_acc:.3f}  ({n_correct}/{n_eval})  "
        f"outer_folds={n_outer_folds}"
    )
    if num_classes == 2:
        mal_folds = [r for r in fold_results if r["true_label"] == 1]
        ben_folds = [r for r in fold_results if r["true_label"] == 0]
        mal_acc   = sum(r["correct"] for r in mal_folds) / max(len(mal_folds), 1)
        ben_acc   = sum(r["correct"] for r in ben_folds) / max(len(ben_folds), 1)
        print(f"  Malware  (label=1): {mal_acc:.3f}  "
              f"({sum(r['correct'] for r in mal_folds)}/{len(mal_folds)})")
        print(f"  Benign   (label=0): {ben_acc:.3f}  "
              f"({sum(r['correct'] for r in ben_folds)}/{len(ben_folds)})")
    else:
        for cls in sorted(set(int(r["true_label"]) for r in fold_results)):
            cls_folds = [r for r in fold_results if int(r["true_label"]) == cls]
            cls_acc = sum(r["correct"] for r in cls_folds) / max(len(cls_folds), 1)
            print(
                f"  Class {cls:<2} accuracy: {cls_acc:.3f}  "
                f"({sum(r['correct'] for r in cls_folds)}/{len(cls_folds)})"
            )
    print("=" * 60)

    run_stats(target=args.target, num_classes=num_classes, cv_mode=args.cv)

    out_path = f"results_{args.model}_{args.cv}.json"
    with open(out_path, "w") as f:
        json.dump({
            "model":         args.model,
            "eval":          eval_label,
            "cv":            args.cv,
            "group_by":      args.group_by,
            "n_splits":      args.n_splits if args.cv == "stratified_group" else None,
            "n_outer_folds": n_outer_folds,
            "n_predictions": n_eval,
            "epochs":        args.epochs,
            "hidden":        args.hidden,
            "layers":        args.layers,
            "gat_heads":     int(args.gat_heads) if args.model == "gat" else None,
            "edge_emb_dim":  int(args.edge_emb_dim) if args.model == "gine" else None,
            "seed":          args.seed,
            "batch_size":    TRAIN_BATCH_SIZE,
            "target":        args.target,
            "num_classes":   num_classes,
            "benign_boost":  benign_boost,
            "augment":       getattr(args, "augment", False),
            "val_fraction":  float(getattr(args, "val_fraction", 0.0) or 0.0),
            "label_smoothing": float(getattr(args, "label_smoothing", 0.0) or 0.0),
            "timestamp":     datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "git_hash":      git_hash(),
            "overall_acc":   round(overall_acc, 4),
            "fold_results":  fold_results,
        }, f, indent=2)
    print(f"  Results saved → {out_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Grouped CV training for MalVol-25 GNN (LOSO or StratifiedGroupKFold)"
    )
    parser.add_argument("manifest",        help="Path to dataset_manifest.csv")
    parser.add_argument("--base-dir",      default=None, dest="base_dir",
                        help="Base directory containing graph.pkl folders")
    parser.add_argument(
        "--model", default="gin",
        choices=["gin", "sage", "gat", "gine"],
        help="GNN backbone: gin, sage, gat (attention), gine (edge-type aware)",
    )
    parser.add_argument(
        "--gat-heads", type=int, default=4, dest="gat_heads",
        help="GAT attention heads (hidden must be divisible by this; default 4)",
    )
    parser.add_argument(
        "--edge-emb-dim", type=int, default=8, dest="edge_emb_dim",
        help="GINE edge-type embedding dim (default 8)",
    )
    parser.add_argument("--target",        default="label", choices=["label", "risk"],
                        help="Training target: binary infection label or risk level")
    parser.add_argument("--num-classes",   type=int, default=None, dest="num_classes",
                        help="Override number of classes (auto-derived by default)")
    parser.add_argument("--epochs",        type=int,   default=120)
    parser.add_argument("--hidden",        type=int,   default=16,
                        help="GNN hidden dim (default 16; was 32)")
    parser.add_argument("--layers",        type=int,   default=2,
                        help="GNN layers (default 2; was 3)")
    parser.add_argument("--dropout",       type=float, default=0.5)
    parser.add_argument("--lr",            type=float, default=1e-3)
    parser.add_argument("--weight-decay",  type=float, default=1e-4,
                        dest="weight_decay")
    parser.add_argument("--seed",          type=int,   default=42)
    parser.add_argument("--save-model",    action="store_true",
                        dest="save_model")
    parser.add_argument("--augment",       action="store_true",
                        help="Double training set per fold via edge-drop + feature-mask augmentation")
    parser.add_argument("--augment-benign", action="store_true",
                        dest="augment_benign",
                        help="Oversample benign class per fold using graph augmentation")
    parser.add_argument("--benign-target-ratio", type=float, default=1.0,
                        dest="benign_target_ratio",
                        help="Target benign:malware ratio after benign augmentation (default 1.0)")
    parser.add_argument("--benign-edge-drop", type=float, default=0.05,
                        dest="benign_edge_drop",
                        help="Edge drop probability for benign augmentation (default 0.05)")
    parser.add_argument("--benign-feat-mask", type=float, default=0.05,
                        dest="benign_feat_mask",
                        help="Feature mask probability for benign augmentation (default 0.05)")
    parser.add_argument("--benign-boost",  type=float, default=2.0,
                        dest="benign_boost",
                        help="Extra weight multiplier for benign class (default 2.0)")
    parser.add_argument("--include-uncertain", action="store_true",
                        dest="include_uncertain",
                        help="Include manifest rows marked uncertain (default: excluded)")
    parser.add_argument("--include-unknown", action="store_true",
                        dest="include_unknown",
                        help="Include rows with label=-1 (default: excluded)")
    parser.add_argument(
        "--cv",
        default="loso",
        choices=["loso", "stratified_group"],
        help=(
            "Cross-validation: loso = leave-one-group-out (default, same as before); "
            "stratified_group = StratifiedGroupKFold (stratified held-out sets, "
            "no group appears in both train and test)"
        ),
    )
    parser.add_argument(
        "--n-splits",
        type=int,
        default=5,
        dest="n_splits",
        help="Number of folds for stratified_group CV (default 5, capped by #groups)",
    )
    parser.add_argument(
        "--group-by",
        default="source",
        choices=["source", "family"],
        dest="group_by",
        help=(
            "Group id for CV: source = graph folder name (default, matches legacy LOSO); "
            "family = manifest family (use with stratified_group to avoid family leakage)"
        ),
    )
    parser.add_argument(
        "--val-fraction",
        type=float,
        default=0.0,
        dest="val_fraction",
        help=(
            "Hold out this fraction of each outer fold's training graphs for model selection "
            "(0 = pick checkpoint by train F1, default). Try 0.15–0.2 to often improve "
            "held-out overall accuracy on small sets."
        ),
    )
    parser.add_argument(
        "--label-smoothing",
        type=float,
        default=0.0,
        dest="label_smoothing",
        help="Cross-entropy label smoothing (0–0.2; default 0). Can reduce overconfident logits.",
    )
    args = parser.parse_args()
    run(args)
