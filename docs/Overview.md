# Project Overview

tags: #overview #malware #forensics

## What is MalVol?

MalVol is an end-to-end pipeline for **ransomware and post-compromise triage** from Windows memory dumps. It combines:

- **Volatility 3** — plugin CSV extraction from `.mem` images
- **Behavioural graphs** — heterogeneous graphs (processes, DLLs, memory regions, network, drivers)
- **Rule triage** — MITRE-aligned heuristic scoring without static name lists
- **Graph neural networks** — one-class conformity, calibrated binary classification, and legacy supervised CV baselines
- **Uncertainty-aware fusion** — routes ambiguous cases to analyst review instead of forcing a verdict

## Why graphs?

Signature-heavy tools miss novel variants. A system-wide graph encodes **runtime structure** (parentage, injection, C2 edges, file staging) from the captured OS state, not a single on-disk binary hash. That supports separating malware-like activity from benign baselines when labels and training governance are chosen carefully.

## Corpora (local)

| Location | Typical size | Notes |
|----------|--------------|-------|
| `extracted_data/` | ~30 folders | Paired `*-WithVirus` / `*-NoVirus` families |
| `extracted_csvs/` | ~43 manifest rows | Primary evaluation corpus (mixed folder names) |

Exact counts depend on your local dumps and manifest. Ground truth and heuristics are joined in `dataset_manifest.csv`.

## Tech stack

| Layer | Technology |
|-------|------------|
| Memory forensics | Volatility 3 |
| Graph / ML | PyTorch Geometric, PyTorch |
| Supervised baselines | GIN, GraphSAGE, GAT, GINE (`model.py`) |
| One-class heads | `one_class_gnn.py` |
| Fusion / gates | `fusion.py`, `calibration.py` |
| Optional UI | Flask / WebSocket (`server.py`) |
| Language | Python 3.10+ |

## Inference paths

1. **Primary** — `train_stack.py` → `analyze_two_model.py` (malware + benign one-class + binary fusion)
2. **Binary baseline** — `train_binary_model.py` → `analyze_binary_model.py`
3. **Legacy CV** — `train.py` grouped cross-validation on binary labels

## Related notes

- [[Pipeline]]
- [[Models]]
- [[IOCs]]
- [[Results]]
- [[pipeline_contracts]]
- [[evaluation_operations]]
- [[graph_audit_improvement_report]]
