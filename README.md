# MalVol — Memory Forensics Behavioural Graphs & ML Triage

Automated analysis of Windows memory dumps using **Volatility 3**, rule-based behavioural triage, and graph neural networks. Samples are modelled as heterogeneous OS behaviour graphs; ML heads produce calibrated triage states with explicit abstention when evidence is ambiguous.

---

## What this repository provides

| Layer | Role |
|-------|------|
| **Extraction** | Run Volatility plugins over `.mem` images → per-sample CSVs |
| **Graph + rules** | Build behavioural graphs, score IOCs, emit structured forensic reports |
| **Manifest** | Join labels, graph stats, triage signals, and pipeline health in `dataset_manifest.csv` |
| **ML (primary)** | Dual one-class GNNs (malware + benign) fused with a calibrated binary head |
| **ML (legacy)** | Supervised GNN cross-validation (`train.py`) for separability experiments |
| **Evaluation** | Orchestrated inference, subset metrics, gate ablation, geometry diagnostics |

---

## Quick start

```bash
git clone https://github.com/variablevar/bug-free-happiness.git
cd bug-free-happiness
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Install [Volatility 3](https://github.com/volatilityfoundation/volatility3) so the `vol` CLI is on your `PATH`.

Optional dashboard:

```bash
python server.py
```

---

## Repository layout

```text
datasets/
├── README.md
├── requirements.txt
├── auto_vol.py              # Volatility batch extraction
├── build_graph.py           # Behavioural graph + graph_attr.json
├── filter_malicious.py      # Rule triage → filtered_malicious.json
├── analyze_graph.py         # Attack chain → analysis_report.json
├── build_dataset.py         # Corpus manifest builder
├── dataset.py               # PyG dataset loader
├── train_stack.py           # Train malware + benign one-class models
├── train_malware_model.py
├── train_benign_model.py
├── train_binary_model.py    # Calibrated binary GNN
├── analyze_two_model.py     # Fused triage inference
├── analyze_binary_model.py
├── evaluate.py              # Run two-model + binary + merged summary
├── fusion.py                # Uncertainty gates & ensemble scoring
├── calibration.py
├── train.py                 # Legacy supervised GNN CV (GIN/SAGE/GAT/GINE)
├── model.py / one_class_gnn.py
├── utils/
│   ├── graph_attr_profile.py
│   └── subgraph_extract.py
├── scripts/                 # See scripts/README.md
├── docs/                    # Obsidian vault + pipeline contracts
├── memory_dumps/            # Local only (not in git)
├── extracted_data/          # ~30 paired WithVirus/NoVirus samples
├── extracted_csvs/          # Primary manifest corpus (~43 rows)
└── outputs/                 # Models, analysis JSON, diagnostics
```

Memory images and malware binaries are **not** shipped. Store `.mem` files locally or via Git LFS.

---

## End-to-end pipeline

### 1. Extract forensic artefacts

Place dumps under `memory_dumps/`, then:

```bash
python auto_vol.py
```

Output: `extracted_data/<SampleName>/*.csv` (or your chosen output tree).

### 2. Build graphs and triage (per sample or corpus)

**Single folder** (after CSVs exist):

```bash
python build_graph.py extracted_data/WannaCry-WithVirus/
python filter_malicious.py extracted_data/WannaCry-WithVirus/
python build_graph.py extracted_data/WannaCry-WithVirus/
python analyze_graph.py extracted_data/WannaCry-WithVirus/
```

**Full corpus + manifest:**

```bash
python build_dataset.py
# or with explicit base:
python build_dataset.py --base-dir extracted_csvs
```

Stable step order is documented in [docs/pipeline_contracts.md](docs/pipeline_contracts.md).

### 3. Train ML models

Primary stack (dual one-class):

```bash
python train_stack.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
```

Or train heads separately:

```bash
python train_malware_model.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
python train_benign_model.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
```

Binary calibrated classifier (recommended `no_manifest_leakage` profile):

```bash
python train_binary_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --graph-attr-profile no_manifest_leakage \
  --epochs 120 --hidden 32 --layers 2
```

Legacy supervised GNN (grouped CV):

```bash
python train.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --model gin
```

### 4. Run evaluation

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
```

Writes by default:

- `outputs/two_model_analysis.json`
- `outputs/binary_analysis.json`
- `outputs/evaluate_merged_analysis.json`

Optional diagnostics:

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --gate-ablation
python scripts/calibrate_uncertainty_thresholds.py
python scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json
```

Calibrated two-model inference (explicit):

```bash
python analyze_two_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --abstention-mode calibrated \
  --output-json outputs/two_model_analysis.json
```

### 5. Per-sample reports

```bash
python scripts/generate_sample_reports.py --base-dir extracted_csvs \
  --analysis-json outputs/two_model_analysis.json

python scripts/generate_sample_reports.py --base-dir extracted_data
```

Creates `REPORT.md` in each folder that has `analysis_report.json`.

---

## Data directories

| Path | Contents |
|------|----------|
| `extracted_data/` | Paired ransomware-family WithVirus / NoVirus runs (~30 folders) |
| `extracted_csvs/` | Extended manifest corpus (~43 labelled rows) |
| `outputs/` | Checkpoints (`*.pt`), meta JSON, analysis and diagnostic outputs |

For folders not named `*-WithVirus` / `*-NoVirus`, use `build_dataset.py --default-label-for-unmatched` or a `--labels-csv` with `folder,label[,family]`.

---

## Manifest and label governance

Key columns (see [docs/pipeline_contracts.md](docs/pipeline_contracts.md)):

- `label` — `1` malware, `0` benign, `-1` unknown (excluded from one-class trainers)
- `uncertain`, `uncertain_reason` — heuristic ambiguity flags
- `benign_subtype` — e.g. `clean_benign`, `hard_benign_admin_tooling`, `ambiguous_novirus_control`
- `train_eligible` — strict training filter when governance manifest is required
- `graph_attr`, `signal_*`, pipeline flags (`filter_ok`, `graph_ok`, `analyze_ok`)

Author hard-benign overrides in `extracted_csvs/hard_benign_labels.csv` (see `hard_benign_labels.example.csv`), then:

```bash
python scripts/apply_hard_benign_labels.py extracted_csvs/dataset_manifest.csv \
  --labels-csv extracted_csvs/hard_benign_labels.csv
```

`NoVirus` family controls are **not** a substitute for clean benign training data unless you explicitly pass `--include-ambiguous-benign-controls` to the benign trainer (experimental only).

---

## Two-model triage stack

| Component | Output |
|-----------|--------|
| Malware one-class GNN | `malware_pattern_score` |
| Benign one-class GNN | `benign_conformity_score` |
| Binary GNN + calibration | `p_malware` (temperature / isotonic in checkpoint meta) |
| `fusion.py` | `triage_state`, `routing_tier`, uncertainty gates |

**Triage states:** `likely_malicious`, `likely_benign`, `needs_analyst_review`, `anomalous_unknown`

**Abstention modes** (`--abstention-mode`):

- `calibrated` — layered gates; binary disagreement only in mid-confidence band (default)
- `legacy_or` — earlier OR-combined gates
- `disabled` — diagnostic only; not for production routing

**Graph attr profiles** (`--graph-attr-profile`): `full`, `no_manifest_leakage`, `structure_only`

**Graph views** (`--graph-view`): `full`, `attack_subgraph`

Artifacts default to `outputs/malware_model.pt`, `outputs/benign_model.pt`, `outputs/binary_model.pt`, and matching `*_meta.json` files.

---

## Binary baseline (separability)

```bash
python analyze_binary_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --model outputs/binary_model.pt \
  --output-json outputs/binary_analysis.json
```

**States:** `likely_malicious`, `likely_benign`, `high_risk_ambiguous`, `low_risk_ambiguous`

Calibration metrics (Brier, ECE, KS, AUROC) are stored in `outputs/binary_model_meta.json`.

---

## Behavioural heuristics

`filter_malicious.py` scores processes using behavioural signals (LOLBin abuse, injection, C2-style edges, credential access, staging paths, lineage anomalies, etc.) — not static malware name lists. Full signal tables: [docs/IOCs.md](docs/IOCs.md).

---

## Documentation index

| Document | Description |
|----------|-------------|
| [docs/Overview.md](docs/Overview.md) | System overview |
| [docs/Pipeline.md](docs/Pipeline.md) | Stage-by-stage pipeline |
| [docs/Models.md](docs/Models.md) | GNN architectures and ML stacks |
| [docs/IOCs.md](docs/IOCs.md) | IOC categories and MITRE mapping |
| [docs/Results.md](docs/Results.md) | Metrics and output artifacts |
| [docs/Future Work.md](docs/Future%20Work.md) | Roadmap |
| [docs/pipeline_contracts.md](docs/pipeline_contracts.md) | File-level contracts |
| [docs/evaluation_operations.md](docs/evaluation_operations.md) | Evaluation runs and ablations |
| [docs/graph_audit_improvement_report.md](docs/graph_audit_improvement_report.md) | Graph corpus audit |
| [scripts/README.md](scripts/README.md) | Helper scripts index |

Open `docs/` as an [Obsidian](https://obsidian.md) vault for wiki-linked notes (`[[Pipeline]]`, etc.).

---

## Limitations

- **Small sample counts** — metrics vary sharply across seeds and folds; prefer multiple seeds and grouped CV.
- **Group leakage** — default LOSO groups by folder; use `--cv stratified_group --group-by family` when families repeat.
- **Ambiguous benign controls** — many `NoVirus` graphs carry high rule-based verdicts; treat as controls, not clean benign unless labelled otherwise.
- **Features** — hand-engineered node/edge attributes; learned embeddings remain future work.

---

## Development

```bash
python -m pytest tests/
find . -type d -name __pycache__ -prune -exec rm -rf {} +
```

Generated paths (`extracted_data/`, `extracted_csvs/`, `outputs/`) may be large; see `.gitignore` for local policy.
