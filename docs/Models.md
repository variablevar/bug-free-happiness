# GNN Models

tags: #model #GNN #GIN #GraphSAGE

## Overview

Two GNN architectures are implemented in `model.py` and trained via `train.py`:

---

## GIN — Graph Isomorphism Network

- Default model (`--model gin`)
- Uses sum aggregation — theoretically as powerful as the Weisfeiler-Lehman graph isomorphism test
- Well-suited for distinguishing structurally different graphs (malware vs benign OS graphs differ significantly in structure)
- Baseline result: **Accuracy 0.633 ± 0.163 | F1 0.743 ± 0.093 | AUC-ROC 0.644 ± 0.269**

---

## GraphSAGE

- Alternative model (`--model sage`)
- Uses mean/max neighbourhood sampling aggregation
- More scalable to larger graphs
- Results: TBD

---

## Hyperparameters

| Parameter | Default |
|---|---|
| Hidden dimension | 64 |
| GNN layers | 3 |
| Dropout | 0.3 |
| Learning rate | 1e-3 |
| Weight decay | 1e-4 |
| Batch size | 4 |
| Epochs | 200 |
| CV folds | 5 |

---

## Training Notes

- Uses **weighted loss** to handle class imbalance
- Gradient clipping applied to stabilise training
- Graph-level attributes passed as additional features
- Best checkpoint saved per fold with `--save-model`

## Related Notes

- [[Pipeline]]
- [[Results]]
