# MalVol — Ransomware Detection via Memory Forensics & Graph Neural Networks

> **MSc Cybersecurity Dissertation Project**  
> Automated ransomware detection from Windows memory dumps using Volatility 3 forensics and graph neural networks (GIN, GraphSAGE, GAT, GINE).

---

## Overview

MalVol is an end-to-end pipeline that:

1. **Extracts** forensic artefacts from Windows memory dumps using **Volatility 3** (pslist, psscan, malfind, filescan, netscan, and many more plugins).
2. **Analyses** memory-resident Indicators of Compromise (IOCs): code injection, hidden processes, suspicious files, C2-style network activity.
3. **Scores** each sample with a rule-based triage engine (`filter_malicious.py`) that reads the behavioural graph (`graph.pkl`) and writes `filtered_malicious.json`.
4. **Rebuilds** the graph with enrichment (`build_graph.py`): `graph.pkl`, `graph.json`, and `graph_attr.json` (legacy 5-float `graph_attr` plus full `graph_attr_map`).
5. **Analyses** attack chains and reports (`analyze_graph.py` → `analysis_report.json`).
6. **Trains** a graph-level classifier (`train.py`) with **leave-one-group-out** or **stratified group** cross-validation.

The dissertation corpus (MalVol-25) is on the order of tens of paired WithVirus / NoVirus samples; exact counts depend on your local `memory_dumps/` and manifest.

---

## Repository structure

```text
datasets/
├── README.md
├── requirements.txt
├── auto_vol.py
├── build_graph.py
├── filter_malicious.py
├── analyze_graph.py
├── build_dataset.py
├── dataset.py
├── model.py
├── train.py
├── evaluate.py
├── parity_checks.py
├── graphml_to_formats.py
├── memory_triage.py
├── server.py
├── socket_server.py
├── scripts/ioc/          # IOC corpus scripts
├── scripts/tools/
├── ioc_analysis/
├── utils/
├── docs/                 # Obsidian notes + pipeline_contracts.md
├── notebook/             # e.g. train.ipynb (Colab-friendly)
├── memory_dumps/         # local only
├── extracted_data/
├── extracted_csvs/
└── outputs/
```

Memory images and malware binaries are **not** shipped in the repo. Use Git LFS or local storage for `.mem` files.

### Root hygiene

Ignored or generated paths include `__pycache__/`, `extracted_data/`, `extracted_csvs/`, `outputs/`. To clear bytecode:

```bash
find . -type d -name "__pycache__" -prune -exec rm -rf {} + && find . -type f -name "*.pyc" -delete
```

---

## Installation

```bash
git clone https://github.com/variablevar/bug-free-happiness.git
cd bug-free-happiness
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Install Volatility 3 so the `vol` CLI is available (see [Volatility 3](https://github.com/volatilityfoundation/volatility3)).

### Dashboard (optional)

```bash
python server.py
```

Then open the app in the browser. For a narrative of stages and scripts, see [docs/Pipeline.md](docs/Pipeline.md) and [docs/pipeline_contracts.md](docs/pipeline_contracts.md).

---

## Pipeline

### Step 1 — Volatility extraction

Place memory images under `memory_dumps/`, then:

```bash
python auto_vol.py
```

Per-sample plugin CSVs land under `extracted_data/<SampleName>/`.

### Step 2 — IOC analysis (optional reporting)

```bash
python scripts/ioc/code_injection_analysis.py
python scripts/ioc/hidden_proc_analysis.py
python scripts/ioc/filescan_analysis.py
python scripts/ioc/network_analysis.py
python scripts/ioc/analysis_corpus.py
```

Shared helpers live under `ioc_analysis/`.

### Step 3–5 — Filter, graph, analyse (per sample)

`build_dataset.py` orchestrates a stable order (see `docs/pipeline_contracts.md`):

1. Ensure `graph.pkl` exists (bootstrap via `build_graph.py` if needed).
2. Run `filter_malicious.py` on `graph.pkl` → `filtered_malicious.json`.
3. Run `build_graph.py` again to persist graphs and `graph_attr.json`.
4. Run `analyze_graph.py` → `analysis_report.json`.

For a **single** folder after extraction:

```bash
python build_graph.py extracted_data/WannaCry-WithVirus/
python filter_malicious.py extracted_data/WannaCry-WithVirus/
python build_graph.py extracted_data/WannaCry-WithVirus/
python analyze_graph.py extracted_data/WannaCry-WithVirus/
```

Full corpus + manifest:

```bash
python build_dataset.py
```

Manifest path defaults to `extracted_data/dataset_manifest.csv` (or the base you pass in).

For folders that are not named `…-WithVirus` / `…-NoVirus` (e.g. BCCC benign dumps under `extracted_csvs/`), set manifest labels with `--default-label-for-unmatched 0` or a `--labels-csv` with `folder,label[,family]`; see `python build_dataset.py --help`.

### Manifest columns (high level)

Besides `sample_id`, `folder`, `label` (`1` malware, `0` benign, `-1` unknown), `family`, graph counts, verdict-style fields (`max_score`, `attack_steps`, …), the manifest includes:

- `graph_attr` — JSON list of graph-level floats consumed by `dataset.py` (dimension matches the loader).
- `label_signals_top`, `label_signals_json` — serialised triage / label signals for inspection and tooling.
- Typed `signal_*` columns (counts / scores) for spreadsheets and ablations.
- `uncertain`, `uncertain_reason` — heuristic curation flags; one-class trainers include these rows by default. Use `--exclude-uncertain` on train commands to drop them.
- `filter_ok`, `graph_ok`, `analyze_ok`, `error` — pipeline health.

Training includes `uncertain` rows by default. Rows with `label=-1` are excluded from both one-class trainers.

---

## Two-model analysis stack

This repository now uses an explainability-first stack instead of one binary classifier:

- **Model A: malware one-class GNN** (`train_malware_model.py`) outputs `malware_pattern_score`.
- **Model B: benign one-class GNN** (`train_benign_model.py`) outputs `benign_conformity_score`.
- **Fusion analyzer** (`analyze_two_model.py`) combines both into a triage state and model-derived evidence.

### Train the two models

```bash
# Train both models with one command (wrapper)
python train.py extracted_csvs/dataset_manifest.csv

# Or train each model separately
python train_malware_model.py extracted_csvs/dataset_manifest.csv \
  --hidden 32 --layers 2 --out-dim 64 --epochs 120

python train_benign_model.py extracted_csvs/dataset_manifest.csv \
  --hidden 32 --layers 2 --out-dim 64 --epochs 120
```

Artifacts are written under `outputs/` by default:

- `outputs/malware_model.pt`
- `outputs/malware_model_meta.json`
- `outputs/benign_model.pt`
- `outputs/benign_model_meta.json`

### Run fused analysis

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv

# equivalent direct command:
python analyze_two_model.py extracted_csvs/dataset_manifest.csv \
  --malware-model outputs/malware_model.pt \
  --benign-model outputs/benign_model.pt \
  --output-json outputs/two_model_analysis.json
```

Per-sample JSON includes:

- `malware_pattern_score`
- `benign_conformity_score`
- `delta_score`
- `triage_state` (`likely_malicious`, `needs_analyst_review`, `anomalous_unknown`, `likely_benign`)
- `confidence_split`
- `reasoning_types`:
  - `execution_chain_anomaly`
  - `memory_injection_evidence`
  - `credential_access_evidence`
  - `network_c2_evidence`
  - `benign_admin_tooling_likelihood`
- `behavioral_findings`
- `malware_model_evidence` (top nodes, edge pairs, top graph attributes, distance)
- `benign_model_evidence` (top nodes, edge pairs, top graph attributes, distance)
- `narrative`

Use `python train.py --help`, `python train_malware_model.py --help`, and
`python analyze_two_model.py --help` for full options.

---

## Binary GNN baseline (separability)

Use this path to force direct malware-vs-benign separation and reduce ambiguity.

```bash
# Train binary GNN + calibration artifacts
python train_binary_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --epochs 120 \
  --hidden 32 --layers 2 --edge-emb-dim 16 \
  --val-fraction 0.2 \
  --target-recall 0.90 --target-specificity 0.90 \
  --output-model outputs/binary_model.pt \
  --output-meta outputs/binary_model_meta.json

# Analyze with calibrated probabilities and 4-state triage
python analyze_binary_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --model outputs/binary_model.pt \
  --output-json outputs/binary_analysis.json
```

Binary output states:

- `likely_malicious` (`p_malware >= threshold_high`)
- `likely_benign` (`p_malware <= threshold_low`)
- `high_risk_ambiguous` (between thresholds + risky signals present)
- `low_risk_ambiguous` (between thresholds without risky signals)

Calibration + separability metrics are written in `outputs/binary_model_meta.json`:

- temperature scaling (`temperature`, `val_nll_before`, `val_nll_after`)
- calibration quality (`val_brier_*`, `val_ece_*`)
- class separation (`val_ks`, `val_auroc`)

---

## Notebooks

`notebook/train.ipynb` is set up for local runs and Google Colab (install cell, optional Drive mount, path to manifest). Point `ROOT` at this repo before `pip install -r requirements.txt`.

---

## Behavioural heuristics (MITRE-style)

`filter_malicious.py` combines process- and graph-level signals (injections, C2-style edges, credential access patterns, staging, ransomware-note style indicators, lineage and stage coverage, benign-context discounts, etc.). Full logic lives in the script and in `_meta` sections of `filtered_malicious.json` / `graph_attr.json`.

---

## Limitations

- **Small N** — metrics vary sharply between seeds and splits; report mean ± std over seeds where possible.
- **Group leakage** — default LOSO groups by folder; use `--cv stratified_group --group-by family` when families repeat across folders.
- **Heuristic vs label noise** — benign captures with strong signals may be flagged `uncertain`; training includes them by default; use `--exclude-uncertain` to hold out.
- **Features** — node features are hand-engineered categoricals and numerics; embeddings are future work.

---

## Related work (high level)

| Work | Idea | Contrast |
|------|------|----------|
| MDGraph-style FCG methods | Code / document features on static graphs | MalVol uses **runtime** memory artefacts, not disassembly of a single binary |
| ProcGCN-style process graphs | Often single-process or static | MalVol builds a **system-wide** heterogeneous behavioural graph from Volatility |

---

## Academic context

This repository supports dissertation work on: MalVol-25-style corpora, automated Volatility extraction, IOC quantification, and GNNs on heterogeneous OS behaviour graphs.

Further reading in-repo: [docs/Overview.md](docs/Overview.md), [docs/Models.md](docs/Models.md), [docs/Pipeline.md](docs/Pipeline.md), [docs/pipeline_contracts.md](docs/pipeline_contracts.md).
