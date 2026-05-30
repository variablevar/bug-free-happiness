# GNN Models

tags: #model #GNN #GIN #GraphSAGE #GAT #GINE

## Overview

MalVol ships three ML stacks. They share `dataset.py` for graph loading and manifest filtering but differ in training objective and inference output.

---

## A. Legacy supervised GNN (`train.py`)

Architectures in `model.py`, trained with grouped cross-validation on binary `label`:

| CLI `--model` | Role |
|---------------|------|
| `gin` | Graph Isomorphism Network-style encoder (default) |
| `sage` | GraphSAGE-style mean pooling |
| `gat` | Graph attention (`--gat-heads`, default 4) |
| `gine` | Edge-type-aware encoder (`--edge-emb-dim`) |

### Defaults

| Parameter | Default |
|-----------|---------|
| Hidden | 16 |
| Layers | 2 |
| Dropout | 0.5 |
| LR | 1e-3 |
| Epochs | 120 |
| CV | `loso` (leave-one-group-out) |

Use `--cv stratified_group --group-by family` to reduce family leakage. Graph-level manifest attributes are concatenated to the pooled embedding.

---

## B. One-class GNN heads (`one_class_gnn.py`)

Trained separately for malware-only and benign-only subsets:

- `train_malware_model.py` → `malware_pattern_score` (distance to malware manifold)
- `train_benign_model.py` → `benign_conformity_score`

Training uses a fixed center/radius deep SVDD-style objective. Checkpoints include `graph_attr_profile` and `graph_view` metadata for aligned inference.

---

## C. Binary calibrated classifier (`train_binary_model.py`)

Supervised GINE-style binary head with:

- Temperature scaling and isotonic calibration on validation split
- Threshold selection for `likely_malicious` / `likely_benign` / ambiguous bands
- Default training profile: `no_manifest_leakage` (drops manifest-derived verdict scalars from `graph_attr`)

Inference: `analyze_binary_model.py` with checkpoint-aligned `graph_attr_profile`.

---

## D. Fusion and uncertainty (`fusion.py`, `analyze_two_model.py`)

Combines:

- Calibrated binary `p_malware`
- Dual one-class scores and `delta_score`
- Heuristic risk from graph signals

**Abstention modes:** `calibrated` (default), `legacy_or`, `disabled`

**Outputs:** `triage_state`, `routing_tier`, uncertainty gate reasons, optional conformal review flags when a conformal bundle is loaded.

Thresholds can be loaded from `outputs/uncertainty_thresholds.json` after `scripts/calibrate_uncertainty_thresholds.py`.

---

## Graph attr profiles (`utils/graph_attr_profile.py`)

| Profile | Purpose |
|---------|---------|
| `full` | All manifest graph attributes |
| `no_manifest_leakage` | Drop verdict/summary scalars that leak labels |
| `structure_only` | Structural counts only |

## Graph views (`utils/subgraph_extract.py`)

| View | Purpose |
|------|---------|
| `full` | Entire behavioural graph |
| `attack_subgraph` | Focused attack-chain neighbourhood |

---

## Related notes

- [[Pipeline]]
- [[Results]]
- [[evaluation_operations]]
