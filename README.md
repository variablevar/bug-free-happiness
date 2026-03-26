
---

## Dataset Manifest Format

`extracted_data/dataset_manifest.csv` must contain:

| Column | Description |
|---|---|
| `folder` | Sample directory name (e.g. `WannaCry-WithVirus`) |
| `label` | `1` = malware, `0` = benign |
| `family` | Malware family name (e.g. `WannaCry`) |
| `max_score` | Peak heuristic score from graph\_summary.py |
| `attack_steps` | Number of attack chain steps detected |
| `injections` | Count of malfind RWX regions |
| `c2_conns` | Count of external ESTABLISHED connections |

---

## Installation

```bash
git clone https://github.com/variablevar/bug-free-happiness.git
cd bug-free-happiness
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install torch torch-geometric pandas numpy scikit-learn
```

Volatility 3 is required for the data extraction scripts:
```bash
pip install volatility3
```

---

## Usage

### Full pipeline (from memory dump)
```bash
# Step 1 — triage each dump folder
python filter_malicious.py extracted_data/WannaCry-WithVirus/

# Step 2 — build graph
python build_graph.py extracted_data/WannaCry-WithVirus/

# Step 3 — behavioural heuristics
python graph_summary.py extracted_data/WannaCry-WithVirus/
```

### Training
```bash
# GIN (default)
python train.py extracted_data/dataset_manifest.csv

# GraphSAGE
python train.py extracted_data/dataset_manifest.csv --model sage

# Custom hyperparameters
python train.py extracted_data/dataset_manifest.csv \
    --epochs 200 --hidden 128 --layers 3 \
    --batch-size 4 --lr 1e-3 --dropout 0.3

# Save best checkpoint per fold
python train.py extracted_data/dataset_manifest.csv --save-model

# Multiple seeds for reliable results
for seed in 0 1 2; do
  python train.py extracted_data/dataset_manifest.csv --seed $seed
done
```

### CLI Reference
| Argument | Default | Description |
|---|---|---|
| `manifest` | — | Path to `dataset_manifest.csv` |
| `--model` | `gin` | `gin` or `sage` |
| `--folds` | `5` | Number of CV folds |
| `--epochs` | `200` | Training epochs per fold |
| `--hidden` | `64` | Hidden dimension |
| `--layers` | `3` | GNN layers |
| `--dropout` | `0.3` | Dropout rate |
| `--lr` | `1e-3` | Learning rate |
| `--weight-decay` | `1e-4` | Adam weight decay |
| `--batch-size` | `4` | Batch size |
| `--seed` | `42` | Random seed |
| `--save-model` | `False` | Save best checkpoint per fold |

---

## Results (MalVol-25, seed=42)

| Model | Accuracy | F1 | AUC-ROC |
|---|---|---|---|
| GIN (v2, baseline) | 0.633 ± 0.163 | 0.743 ± 0.093 | 0.644 ± 0.269 |
| GIN (v3, weighted + clipped + graph\_attr) | TBD | TBD | TBD |
| GraphSAGE | TBD | TBD | TBD |

> ⚠️ Dataset contains 30 samples (15 malware / 15 benign). Metrics have high variance
> by design — run multiple seeds and average for reliable reporting.

---

## Behavioural Heuristics (graph_summary.py)

The heuristic engine scores each graph across 5 dimensions:

| Tactic | MITRE | Signal |
|---|---|---|
| Initial Access / Execution | T1218, T1566 | LOLBin usage, script extensions in args |
| Defense Evasion / Injection | T1055 | malfind RWX + MZ header, shared shellcode stub |
| Command & Control | T1071 | ESTABLISHED connections to external IPs |
| Credential Access | T1003.001 | Full LSASS handle access (0x1fffff) |
| Execution / Impact | T1486 | High-score processes, ransomware note args |

Verdict levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`

---

## Limitations

- **Small dataset (30 samples)** — results have high variance; aim for 60–100+ for reliable CV
- **Node features are shallow** — one-hot + numeric; future work: pretrained embeddings on Windows API/DLL names
- **No family-aware splitting** — `WithVirus`/`NoVirus` pairs from the same family may leak across folds
- **CPU only tested** — CUDA path untested but implemented

---

## Related Work

| Paper | Method | Difference |
|---|---|---|
| MDGraph (Expert Systems 2024) | doc2vec + GraphSAGE on FCG | Code structure graph; requires binary |
| ProcGCN (PMC 2024) | BoW + DGCNN on FCG from process dump | Single-process FCG; requires IDA Pro |
| **This work** | GIN/SAGE on heterogeneous OS behavioural graph | System-wide runtime artefacts; no binary needed |

---

## Future Work

- [ ] Expand dataset to 100+ samples
- [ ] Add pretrained DLL/process name embeddings as node features
- [ ] Family-aware stratified splitting to prevent leakage
- [ ] Combined FCG + behavioural graph (process nodes carry code-structure subgraph)
- [ ] Explainability: GNNExplainer to identify which nodes/edges drive classification
- [ ] Real-time scoring: integrate with live Volatility memory acquisition