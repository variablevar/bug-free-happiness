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

### Manifest columns (high level)

Besides `sample_id`, `folder`, `label` (`1` malware, `0` benign, `-1` unknown), `family`, graph counts, verdict-style fields (`max_score`, `attack_steps`, …), the manifest includes:

- `graph_attr` — JSON list of graph-level floats consumed by `dataset.py` (dimension matches the loader).
- `label_signals_top`, `label_signals_json` — serialised triage / label signals for inspection and tooling.
- Typed `signal_*` columns (counts / scores) for spreadsheets and ablations.
- `uncertain`, `uncertain_reason` — rows you may want to hold out of training (default in `dataset.py`).
- `filter_ok`, `graph_ok`, `analyze_ok`, `error` — pipeline health.

Training excludes `uncertain` rows and `label=-1` unless you pass `--include-uncertain` / `--include-unknown` to `train.py` or `evaluate.py`. If you include unknown labels while using binary cross-entropy on `label`, ensure your training code does not assume only `{0,1}` (e.g. remap or use a third class).

---

## Training and evaluation

Training uses **grouped** cross-validation (not IID shuffled folds):

- `--cv loso` — leave-one-group-out (default). Groups default to sample folder names (`--group-by source`).
- `--cv stratified_group` — `StratifiedGroupKFold` with `--n-splits` (default 5), useful with `--group-by family` to reduce family leakage.

Internal training batches use a fixed small batch size in code (there is **no** `--batch-size` on `train.py`). **`evaluate.py`** accepts `--batch-size` for inference.

Examples:

```bash
# Default: GIN, LOSO, 120 epochs, hidden 16, 2 layers, dropout 0.5
python train.py extracted_data/dataset_manifest.csv

python train.py extracted_data/dataset_manifest.csv --model sage
python train.py extracted_data/dataset_manifest.csv --model gat --hidden 32 --gat-heads 4
python train.py extracted_data/dataset_manifest.csv --model gine --edge-emb-dim 8

# Stratified folds by family
python train.py extracted_data/dataset_manifest.csv \
  --cv stratified_group --group-by family --n-splits 5

# Validation holdout inside each outer train split (model selection)
python train.py extracted_data/dataset_manifest.csv --val-fraction 0.15

python train.py extracted_data/dataset_manifest.csv --save-model
python train.py extracted_data/dataset_manifest.csv --include-uncertain
python train.py extracted_data/dataset_manifest.csv --label-smoothing 0.05
```

Evaluate a saved checkpoint (flags must match the architecture used at train time):

```bash
python evaluate.py extracted_data/dataset_manifest.csv outputs/best_fold0.pt \
  --model gin --predictions-csv preds.csv --output-json eval.json
```

### `train.py` CLI (summary)

| Argument | Default | Description |
|----------|---------|-------------|
| `manifest` | — | Path to `dataset_manifest.csv` |
| `--base-dir` | manifest dir | Root containing per-sample folders |
| `--model` | `gin` | `gin`, `sage`, `gat`, `gine` |
| `--gat-heads` | `4` | GAT heads (`--hidden` must be divisible) |
| `--edge-emb-dim` | `8` | GINE edge-type embedding dim |
| `--target` | `label` | `label` or `risk` |
| `--epochs` | `120` | Epochs per outer fold |
| `--hidden` | `16` | Hidden dimension |
| `--layers` | `2` | Message-passing layers |
| `--dropout` | `0.5` | Dropout |
| `--lr` | `1e-3` | Learning rate |
| `--weight-decay` | `1e-4` | AdamW weight decay |
| `--cv` | `loso` | `loso` or `stratified_group` |
| `--n-splits` | `5` | Folds for `stratified_group` |
| `--group-by` | `source` | `source` (folder) or `family` |
| `--val-fraction` | `0` | Fraction of outer-train graphs for validation |
| `--label-smoothing` | `0` | CE label smoothing |
| `--save-model` | off | Save best checkpoint per fold |
| `--include-uncertain` | off | Include uncertain manifest rows |
| `--include-unknown` | off | Include `label=-1` |
| `--augment` / `--augment-benign` | off | Graph augmentation options |
| `--benign-*` | see `--help` | Benign oversampling / loss weighting |

Run `python train.py --help` for the full list.

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
- **Heuristic vs label noise** — benign captures with strong signals are flagged `uncertain`; default training drops them unless `--include-uncertain`.
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
