#!/usr/bin/env python3
"""Train binary GNN malware classifier with calibration artifacts."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from torch_geometric.loader import DataLoader

from calibration import (
    apply_temperature,
    auc_from_roc,
    brier_score,
    choose_thresholds_by_roc,
    expected_calibration_error,
    fit_temperature,
    ks_separation,
    reliability_curve_bins,
    roc_curve_points,
)
from analysis_schema import SCHEMA_VERSION
from dataset import MalwareGraphDataset, merge_manifest_csv_files
from model import GINEMalwareClassifier

FEATURE_GROUPS = {
    "generic_structure": [4, 5, 6],
    "injection_noise": [2, 10],
    "intent_behavior": [1, 3, 7, 8, 9, 14, 15, 16, 17, 18, 25, 26, 54, 55, 56, 57, 58, 59, 60],
}

# graph_attr indices for system-binary context signals
SYSTEM_BINARY_SIGNAL_IDXS = [19, 20, 21, 22, 23, 24]


def apply_feature_group_weights(graph_attr: torch.Tensor | None, group_weights: dict[str, float] | None) -> torch.Tensor | None:
    if graph_attr is None or group_weights is None:
        return graph_attr
    ga = graph_attr.clone()
    width = int(ga.size(1))
    for group, idxs in FEATURE_GROUPS.items():
        w = float(group_weights.get(group, 1.0))
        for idx in idxs:
            if 0 <= idx < width:
                ga[:, idx] = ga[:, idx] * w
    return ga


def split_indices(labels: np.ndarray, val_fraction: float, seed: int) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    labels = labels.astype(int)
    idx = np.arange(len(labels))
    pos = idx[labels == 1]
    neg = idx[labels == 0]
    rng.shuffle(pos)
    rng.shuffle(neg)
    n_pos_val = max(1, int(round(len(pos) * val_fraction)))
    n_neg_val = max(1, int(round(len(neg) * val_fraction)))
    val_idx = np.concatenate([pos[:n_pos_val], neg[:n_neg_val]])
    train_idx = np.setdiff1d(idx, val_idx)
    if len(train_idx) == 0 or len(val_idx) == 0:
        raise SystemExit("[ERROR] Invalid split: empty train/val")
    return train_idx, val_idx


def loader_from_list(lst: list, batch_size: int, shuffle: bool) -> DataLoader:
    return DataLoader(lst, batch_size=batch_size, shuffle=shuffle)


def forward_logits(model, batch, device, group_weights: dict[str, float] | None = None):
    batch = batch.to(device)
    graph_attr = apply_feature_group_weights(getattr(batch, "graph_attr", None), group_weights)
    return model(
        batch.x,
        batch.edge_index,
        batch.batch,
        graph_attr=graph_attr,
        edge_attr=getattr(batch, "edge_attr", None),
    )


def supervised_contrastive_loss(emb: torch.Tensor, labels: torch.Tensor, temperature: float = 0.2) -> torch.Tensor:
    if emb.size(0) < 2:
        return emb.new_tensor(0.0)
    z = F.normalize(emb, dim=1)
    sim = torch.matmul(z, z.t()) / max(temperature, 1e-6)
    mask = torch.eye(sim.size(0), device=sim.device, dtype=torch.bool)
    sim = sim.masked_fill(mask, -1e9)
    labels = labels.view(-1, 1)
    pos_mask = (labels == labels.t()) & (~mask)
    exp_sim = torch.exp(sim)
    denom = exp_sim.sum(dim=1, keepdim=True).clamp_min(1e-12)
    log_prob = sim - torch.log(denom)
    pos_count = pos_mask.sum(dim=1).clamp_min(1)
    loss = -(log_prob * pos_mask.float()).sum(dim=1) / pos_count
    valid = (pos_mask.sum(dim=1) > 0).float()
    return (loss * valid).sum() / valid.sum().clamp_min(1.0)


def precision_recall_at_threshold(probs: np.ndarray, labels: np.ndarray, threshold: float) -> tuple[float, float]:
    y = labels.astype(int)
    pred = (probs[:, 1] >= float(threshold)).astype(int)
    tp = int(np.sum((pred == 1) & (y == 1)))
    fp = int(np.sum((pred == 1) & (y == 0)))
    fn = int(np.sum((pred == 0) & (y == 1)))
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    return float(precision), float(recall)


def select_operating_threshold(
    probs: np.ndarray,
    labels: np.ndarray,
    *,
    precision_floor: float,
    recall_floor: float,
) -> float:
    p1 = probs[:, 1]
    thresholds = np.unique(np.concatenate([[0.0, 1.0], p1]))
    chosen = None
    for th in thresholds:
        pr, rc = precision_recall_at_threshold(probs, labels, float(th))
        score = (1 if pr >= precision_floor and rc >= recall_floor else 0, rc, pr, float(th))
        if chosen is None or score > chosen[0]:
            chosen = (score, float(th), pr, rc)
    return float(chosen[1]) if chosen is not None else 0.5


def pr_auc(probs: np.ndarray, labels: np.ndarray) -> float:
    p1 = probs[:, 1]
    thresholds = np.unique(np.concatenate([[0.0, 1.0], p1]))
    pr_points = []
    for th in thresholds:
        pr, rc = precision_recall_at_threshold(probs, labels, float(th))
        pr_points.append((rc, pr))
    pr_points = sorted(pr_points, key=lambda x: x[0])
    if len(pr_points) < 2:
        return 0.0
    xs = np.asarray([x for x, _ in pr_points], dtype=float)
    ys = np.asarray([y for _, y in pr_points], dtype=float)
    return float(np.trapz(ys, xs))


def eval_logits(model, loader, device, group_weights: dict[str, float] | None = None):
    model.eval()
    logits, labels = [], []
    with torch.no_grad():
        for batch in loader:
            out = forward_logits(model, batch, device, group_weights=group_weights)
            logits.append(out.detach().cpu().numpy())
            labels.append(batch.y.detach().cpu().numpy())
    if not logits:
        return np.zeros((0, 2), dtype=np.float32), np.zeros((0,), dtype=int)
    return np.concatenate(logits), np.concatenate(labels).astype(int)


def run(args):
    torch.manual_seed(args.seed)
    np.random.seed(args.seed)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"[BinaryModel] Device: {device}")

    manifest_path = args.manifest
    merged_tmp: str | None = None
    extra_manifests = [x.strip() for x in str(getattr(args, "extra_manifest", "") or "").split(",") if x.strip()]
    if extra_manifests:
        manifest_path = merge_manifest_csv_files(args.manifest, extra_manifests)
        merged_tmp = manifest_path
        print(f"[BinaryModel] Merged {len(extra_manifests)} extra manifest(s) → {manifest_path}")
    try:
        ds = MalwareGraphDataset(
            manifest_path,
            base_dir=args.base_dir,
            include_uncertain=not args.exclude_uncertain,
            include_unknown=False,
            require_train_eligible=not args.disable_strict_train_filter,
            target="label",
        )
    finally:
        if merged_tmp and merged_tmp != os.path.abspath(args.manifest) and os.path.isfile(merged_tmp):
            try:
                os.remove(merged_tmp)
            except OSError:
                pass
    labels = np.asarray(ds.get_labels(), dtype=int)
    keep = np.where((labels == 0) | (labels == 1))[0]
    ds_list = [ds[int(i)] for i in keep]
    labels = labels[keep]
    if len(ds_list) < 12:
        raise SystemExit("[ERROR] Need at least 12 labeled samples for binary training")

    tr_idx, va_idx = split_indices(labels, args.val_fraction, args.seed)
    train_ds = [ds_list[int(i)] for i in tr_idx]
    val_ds = [ds_list[int(i)] for i in va_idx]
    y_train = labels[tr_idx]
    benign = int(np.sum(y_train == 0))
    malware = int(np.sum(y_train == 1))
    if benign == 0 or malware == 0:
        raise SystemExit("[ERROR] Both classes are required in train split")
    pos_weight_auto = float(benign / max(malware, 1))

    train_loader = loader_from_list(train_ds, args.batch_size, True)
    val_loader = loader_from_list(val_ds, args.batch_size, False)
    feature_group_weights = {
        "generic_structure": float(args.weight_generic_structure),
        "injection_noise": float(args.weight_injection_noise),
        "intent_behavior": float(args.weight_intent_behavior),
    }

    in_dim = int(train_ds[0].x.size(1))
    def _metrics_at_05(probs: np.ndarray, y_true: np.ndarray) -> tuple[float, float, float]:
        pred = (probs[:, 1] >= 0.5).astype(int)
        tp = int(np.sum((pred == 1) & (y_true == 1)))
        fn = int(np.sum((pred == 0) & (y_true == 1)))
        tn = int(np.sum((pred == 0) & (y_true == 0)))
        fp = int(np.sum((pred == 1) & (y_true == 0)))
        recall = tp / max(tp + fn, 1)
        spec = tn / max(tn + fp, 1)
        f1 = (2 * tp) / max((2 * tp + fp + fn), 1)
        return float(recall), float(spec), float(f1)

    def _train_once(run_pos_weight: float, epochs: int, seed_offset: int = 0) -> dict:
        torch.manual_seed(args.seed + seed_offset)
        np.random.seed(args.seed + seed_offset)
        model = GINEMalwareClassifier(
            in_channels=in_dim,
            hidden=args.hidden,
            layers=args.layers,
            dropout=args.dropout,
            num_classes=2,
            edge_emb_dim=args.edge_emb_dim,
        ).to(device)
        opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=args.weight_decay)
        scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(1, epochs), eta_min=1e-5)
        class_weights = torch.tensor([1.0, run_pos_weight], dtype=torch.float32, device=device)
        best_val_f1 = -1.0
        best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
        stall = 0
        for epoch in range(1, epochs + 1):
            model.train()
            run_loss = 0.0
            for batch in train_loader:
                batch = batch.to(device)
                out, emb = model(
                    batch.x,
                    batch.edge_index,
                    batch.batch,
                    graph_attr=apply_feature_group_weights(getattr(batch, "graph_attr", None), feature_group_weights),
                    edge_attr=getattr(batch, "edge_attr", None),
                    return_embedding=True,
                )
                y = batch.y.to(device)
                loss_cls_vec = F.cross_entropy(
                    out,
                    y,
                    weight=class_weights,
                    reduction="none",
                    label_smoothing=float(args.label_smoothing),
                )
                sample_w = torch.ones_like(loss_cls_vec)
                ga = apply_feature_group_weights(getattr(batch, "graph_attr", None), feature_group_weights)
                if ga is not None and ga.size(1) > min(SYSTEM_BINARY_SIGNAL_IDXS):
                    sig = ga[:, SYSTEM_BINARY_SIGNAL_IDXS].sum(dim=1)
                    sample_w = sample_w + (args.system_binary_robustness_weight - 1.0) * (sig > 0).float()
                loss_cls = (loss_cls_vec * sample_w).mean()
                loss_ctr = supervised_contrastive_loss(emb, y, temperature=args.contrastive_temperature)
                loss = loss_cls + (args.contrastive_weight * loss_ctr)
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                opt.step()
                run_loss += float(loss.item())
            scheduler.step()
            val_logits_ep, val_y_ep = eval_logits(model, val_loader, device, group_weights=feature_group_weights)
            val_probs_ep = np.exp(val_logits_ep - val_logits_ep.max(axis=1, keepdims=True))
            val_probs_ep /= np.clip(val_probs_ep.sum(axis=1, keepdims=True), 1e-12, None)
            _, _, val_f1_ep = _metrics_at_05(val_probs_ep, val_y_ep)
            if val_f1_ep > best_val_f1:
                best_val_f1 = val_f1_ep
                best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}
                stall = 0
            else:
                stall += 1
            if epoch % 10 == 0 or epoch == epochs:
                print(
                    f"  Epoch {epoch:>3} loss={run_loss / max(len(train_loader),1):.4f} "
                    f"val_f1={val_f1_ep:.3f} pos_weight={run_pos_weight:.4f}"
                )
            if (
                args.early_stop_patience > 0
                and epoch >= args.early_stop_min_epochs
                and stall >= args.early_stop_patience
            ):
                print(f"  [Early-stop] no val F1 gain for {stall} epochs")
                break
        model.load_state_dict(best_state)
        val_logits_out, val_y_out = eval_logits(model, val_loader, device, group_weights=feature_group_weights)
        val_probs_out = np.exp(val_logits_out - val_logits_out.max(axis=1, keepdims=True))
        val_probs_out /= np.clip(val_probs_out.sum(axis=1, keepdims=True), 1e-12, None)
        recall, spec, f1 = _metrics_at_05(val_probs_out, val_y_out)
        return {
            "model": model,
            "val_logits": val_logits_out,
            "val_y": val_y_out,
            "best_val_f1": float(best_val_f1),
            "val_recall_at_05": recall,
            "val_specificity_at_05": spec,
            "val_f1_at_05": f1,
        }

    pos_weight_mode = str(args.pos_weight_mode).strip().lower()
    pos_weight_effective = pos_weight_auto
    sweep_summary: list[dict] = []
    if pos_weight_mode == "manual":
        pos_weight_effective = float(args.pos_weight_manual)
    elif pos_weight_mode == "sweep":
        candidates = [x.strip() for x in str(args.pos_weight_candidates).split(",") if x.strip()]
        sweep_values = []
        for c in candidates:
            try:
                v = float(c)
            except ValueError:
                continue
            if v > 0:
                sweep_values.append(v)
        if not sweep_values:
            sweep_values = [pos_weight_auto]
        best_tuple = None
        for i, sw in enumerate(sweep_values):
            print(f"[BinaryModel] sweep candidate {i+1}/{len(sweep_values)} pos_weight={sw:.4f}")
            r = _train_once(sw, epochs=max(5, int(args.sweep_epochs)), seed_offset=100 + i)
            rc = float(r["val_recall_at_05"])
            sp = float(r["val_specificity_at_05"])
            f1 = float(r["val_f1_at_05"])
            score = (1 if rc >= args.target_recall else 0, rc, sp, f1)
            sweep_summary.append(
                {"pos_weight": sw, "val_recall_at_05": rc, "val_specificity_at_05": sp, "val_f1_at_05": f1}
            )
            if best_tuple is None or score > best_tuple[0]:
                best_tuple = (score, sw)
        pos_weight_effective = float(best_tuple[1]) if best_tuple else pos_weight_auto
        print(f"[BinaryModel] sweep selected pos_weight={pos_weight_effective:.4f}")

    train_result = _train_once(pos_weight_effective, epochs=args.epochs, seed_offset=0)
    model = train_result["model"]
    val_logits, val_y = train_result["val_logits"], train_result["val_y"]
    best_val = train_result["best_val_f1"]
    ts = fit_temperature(val_logits, val_y, max_iter=200)
    val_probs_raw = apply_temperature(val_logits, 1.0)
    val_probs_cal = apply_temperature(val_logits, ts.temperature)
    t_low, t_high = choose_thresholds_by_roc(
        val_probs_cal,
        val_y,
        target_recall=args.target_recall,
        target_specificity=args.target_specificity,
        max_ambiguity_width=args.max_ambiguity_width,
        min_ambiguity_width=args.min_ambiguity_width,
        precision_floor=args.precision_floor,
        recall_floor=args.recall_floor,
    )
    t_high_soc = select_operating_threshold(
        val_probs_cal,
        val_y,
        precision_floor=args.precision_floor,
        recall_floor=args.recall_floor,
    )
    t_high = max(float(t_high), float(t_high_soc))
    if (t_high - t_low) < args.min_ambiguity_width:
        t_low = max(0.0, t_high - args.min_ambiguity_width)
    _, tpr, fpr = roc_curve_points(val_probs_cal, val_y)
    auroc = auc_from_roc(tpr, fpr)
    val_pr_auc = pr_auc(val_probs_cal, val_y)
    val_precision_at_th, val_recall_at_th = precision_recall_at_threshold(val_probs_cal, val_y, t_high)

    payload = {
        "model_type": "binary_gnn_gine",
        "state_dict": {k: v.detach().cpu() for k, v in model.state_dict().items()},
        "in_channels": in_dim,
        "hidden": args.hidden,
        "layers": args.layers,
        "dropout": args.dropout,
        "edge_emb_dim": args.edge_emb_dim,
        "graph_attr_dim": int(train_ds[0].graph_attr.size(1)),
        "temperature": ts.temperature,
        "threshold_low": t_low,
        "threshold_high": t_high,
        "target_recall": args.target_recall,
        "target_specificity": args.target_specificity,
        "precision_floor": args.precision_floor,
        "recall_floor": args.recall_floor,
        "max_ambiguity_width": args.max_ambiguity_width,
        "min_ambiguity_width": args.min_ambiguity_width,
        "pos_weight_mode": pos_weight_mode,
        "pos_weight_auto": pos_weight_auto,
        "pos_weight_effective": pos_weight_effective,
        "feature_groups": FEATURE_GROUPS,
        "feature_group_weights": feature_group_weights,
        "system_binary_robustness_weight": args.system_binary_robustness_weight,
        "schema_version": SCHEMA_VERSION,
        "label_smoothing": float(args.label_smoothing),
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    out_model = Path(args.output_model)
    out_model.parent.mkdir(parents=True, exist_ok=True)
    torch.save(payload, out_model)

    meta = {
        "manifest": args.manifest,
        "extra_manifest_csvs": extra_manifests,
        "base_dir": args.base_dir,
        "exclude_uncertain": args.exclude_uncertain,
        "strict_train_filter": (not args.disable_strict_train_filter),
        "n_train": int(len(train_ds)),
        "n_val": int(len(val_ds)),
        "n_train_benign": benign,
        "n_train_malware": malware,
        "pos_weight_mode": pos_weight_mode,
        "pos_weight_auto": pos_weight_auto,
        "pos_weight_effective": pos_weight_effective,
        "pos_weight_manual": args.pos_weight_manual if pos_weight_mode == "manual" else None,
        "pos_weight_sweep_candidates": args.pos_weight_candidates if pos_weight_mode == "sweep" else "",
        "pos_weight_sweep_summary": sweep_summary,
        "feature_groups": FEATURE_GROUPS,
        "feature_group_weights": feature_group_weights,
        "system_binary_robustness_weight": args.system_binary_robustness_weight,
        "best_val_f1": round(best_val, 6),
        "val_recall_at_05": train_result["val_recall_at_05"],
        "val_specificity_at_05": train_result["val_specificity_at_05"],
        "contrastive_weight": args.contrastive_weight,
        "contrastive_temperature": args.contrastive_temperature,
        "label_smoothing": float(args.label_smoothing),
        "temperature": ts.temperature,
        "val_nll_before": ts.val_nll_before,
        "val_nll_after": ts.val_nll_after,
        "val_brier_raw": brier_score(val_probs_raw, val_y),
        "val_brier_cal": brier_score(val_probs_cal, val_y),
        "val_ece_raw": expected_calibration_error(val_probs_raw, val_y),
        "val_ece_cal": expected_calibration_error(val_probs_cal, val_y),
        "val_ks": ks_separation(val_probs_cal, val_y),
        "val_auroc": auroc,
        "val_pr_auc": val_pr_auc,
        "val_precision_at_threshold_high": val_precision_at_th,
        "val_recall_at_threshold_high": val_recall_at_th,
        "threshold_low": t_low,
        "threshold_high": t_high,
        "max_ambiguity_width": args.max_ambiguity_width,
        "min_ambiguity_width": args.min_ambiguity_width,
        "reliability_bins_raw": reliability_curve_bins(val_probs_raw, val_y, n_bins=args.reliability_bins),
        "reliability_bins_cal": reliability_curve_bins(val_probs_cal, val_y, n_bins=args.reliability_bins),
        "schema_version": SCHEMA_VERSION,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    out_meta = Path(args.output_meta)
    out_meta.parent.mkdir(parents=True, exist_ok=True)
    out_meta.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[BinaryModel] saved: {out_model}")
    print(f"[BinaryModel] meta : {out_meta}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Train binary GNN baseline")
    p.add_argument("manifest", help="Path to dataset_manifest.csv")
    p.add_argument("--base-dir", default=None, dest="base_dir")
    p.add_argument("--exclude-uncertain", action="store_true", dest="exclude_uncertain")
    p.add_argument(
        "--disable-strict-train-filter",
        action="store_true",
        dest="disable_strict_train_filter",
        help="Allow rows with train_eligible=false (default is strict training filter on).",
    )
    p.add_argument("--hidden", type=int, default=32)
    p.add_argument("--layers", type=int, default=2)
    p.add_argument("--dropout", type=float, default=0.5)
    p.add_argument("--edge-emb-dim", type=int, default=16, dest="edge_emb_dim")
    p.add_argument("--epochs", type=int, default=120)
    p.add_argument("--batch-size", type=int, default=4, dest="batch_size")
    p.add_argument("--lr", type=float, default=3e-4)
    p.add_argument("--weight-decay", type=float, default=1e-4, dest="weight_decay")
    p.add_argument("--val-fraction", type=float, default=0.2, dest="val_fraction")
    p.add_argument("--early-stop-patience", type=int, default=25, dest="early_stop_patience")
    p.add_argument("--early-stop-min-epochs", type=int, default=40, dest="early_stop_min_epochs")
    p.add_argument("--target-recall", type=float, default=0.90, dest="target_recall")
    p.add_argument("--target-specificity", type=float, default=0.90, dest="target_specificity")
    p.add_argument("--precision-floor", type=float, default=0.55, dest="precision_floor")
    p.add_argument("--recall-floor", type=float, default=0.75, dest="recall_floor")
    p.add_argument("--max-ambiguity-width", type=float, default=0.12, dest="max_ambiguity_width")
    p.add_argument("--min-ambiguity-width", type=float, default=0.06, dest="min_ambiguity_width")
    p.add_argument("--reliability-bins", type=int, default=10, dest="reliability_bins")
    p.add_argument("--pos-weight-mode", choices=["auto", "manual", "sweep"], default="auto", dest="pos_weight_mode")
    p.add_argument("--pos-weight-manual", type=float, default=1.0, dest="pos_weight_manual")
    p.add_argument("--pos-weight-candidates", default="0.75,1.0,1.5,2.0,3.0,4.0", dest="pos_weight_candidates")
    p.add_argument("--sweep-epochs", type=int, default=25, dest="sweep_epochs")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--contrastive-weight", type=float, default=0.10, dest="contrastive_weight")
    p.add_argument("--contrastive-temperature", type=float, default=0.2, dest="contrastive_temperature")
    p.add_argument("--weight-generic-structure", type=float, default=0.85, dest="weight_generic_structure")
    p.add_argument("--weight-injection-noise", type=float, default=0.90, dest="weight_injection_noise")
    p.add_argument("--weight-intent-behavior", type=float, default=1.10, dest="weight_intent_behavior")
    p.add_argument("--system-binary-robustness-weight", type=float, default=1.05, dest="system_binary_robustness_weight")
    p.add_argument("--output-model", default="outputs/binary_model.pt", dest="output_model")
    p.add_argument("--output-meta", default="outputs/binary_model_meta.json", dest="output_meta")
    p.add_argument(
        "--extra-manifest",
        default="",
        dest="extra_manifest",
        help="Comma-separated extra manifest CSV paths merged after primary (dedupe by folder; primary wins).",
    )
    p.add_argument(
        "--label-smoothing",
        type=float,
        default=0.0,
        dest="label_smoothing",
        help="Cross-entropy label smoothing (0–0.2 typical; 0 disables).",
    )
    run(p.parse_args())

