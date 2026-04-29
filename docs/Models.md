# GNN Models

tags: #model #GNN #GIN #GraphSAGE #GAT #GINE

## Overview

Architectures live in `model.py` and are trained via `train.py` / evaluated via `evaluate.py`. Supported backbones:

| CLI `--model` | Role |
|---------------|--------|
| `gin` | Graph Isomorphism Network-style encoder (default); strong baseline on small structural differences. |
| `sage` | GraphSAGE-style mean pooling; scalable inductive flavour. |
| `gat` | Graph attention; use `--gat-heads` (default 4); `--hidden` must be divisible by head count. |
| `gine` | Edge-type-aware encoder; use `--edge-emb-dim` (default 8). |

## Hyperparameters (train.py defaults)

| Parameter | Default |
|-----------|---------|
| Hidden dimension | 16 |
| GNN layers | 2 |
| Dropout | 0.5 |
| Learning rate | 1e-3 |
| Weight decay | 1e-4 |
| Epochs | 120 |
| CV | `loso` (leave-one-group-out); optional `stratified_group` + `--n-splits` |
| Batch size | Fixed inside training code (not a CLI flag on `train.py`) |

`evaluate.py` uses `--batch-size` (default 8) for inference only.

## Training notes

- Class weights and optional benign augmentation / `--benign-boost` address imbalance.
- Gradient clipping is used for stability.
- Graph-level attributes from the manifest are concatenated to the pooled graph embedding.
- `--save-model` writes per-fold checkpoints; reload with matching `--model`, `--hidden`, `--layers`, `--gat-heads`, `--edge-emb-dim`.

## Related notes

- [[Pipeline]]
- [[Results]]
