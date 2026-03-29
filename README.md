# MalVol — Ransomware Detection via Memory Forensics & Graph Neural Networks

> **MSc Cybersecurity Dissertation Project**
> Automated ransomware detection from Windows memory dumps using Volatility 3 forensics and Graph Neural Networks (GIN / GraphSAGE).

---

## Overview

MalVol is an end-to-end pipeline that:

1. **Extracts** forensic artefacts from Windows memory dumps using **Volatility 3** (pslist, psscan, malfind, filescan, netscan, and 12+ more plugins)
2. **Analyses** memory-resident Indicators of Compromise (IOCs) — code injection, hidden processes, suspicious files, C2 network activity
3. **Builds** a heterogeneous OS behavioural graph per sample (processes, DLLs, network connections, files as nodes)
4. **Trains** a Graph Neural Network (GIN or GraphSAGE) on the resulting graphs to classify samples as **malware** or **benign**
5. **Scores** new samples in real time via a heuristic engine mapped to MITRE ATT&CK tactics

The project evaluates **24 real-world malware samples** across multiple ransomware families (e.g. WannaCry) in WithVirus / NoVirus paired dumps.

---

## Repository Structure

```text
bug-free-happiness/
├── auto_vol.py               # Parallel Volatility 3 extraction over all memory dumps
├── analysis_corpus.py        # Full corpus statistics & combined IOC view
├── analyze_graph.py          # Graph-level analysis and visualisation
├── build_dataset.py          # Construct dataset_manifest.csv from extracted_data/
├── build_graph.py            # Build heterogeneous behavioural graphs (PyG format)
├── code_injection_analysis.py# malfind RWX / MZ header IOC analysis
├── hidden_proc_analysis.py   # psscan vs pslist hidden process detection
├── filescan_analysis.py      # Suspicious file staging detection
├── network_analysis.py       # Non-standard / C2 network connection analysis
├── filter_malicious.py       # Per-sample malicious artefact filtering & scoring
├── memory_triage.py          # High-level triage across dump corpus
├── dataset.py                # PyG Dataset class wrapping extracted graphs
├── model.py                  # GIN and GraphSAGE model definitions
├── train.py                  # 5-fold cross-validated training loop
├── test_train.py             # Unit tests for training pipeline
├── script.py                 # Utility / batch processing script
├── server.py                 # Flask/FastAPI server (dashboard backend)
├── socket_server.py          # WebSocket server for live scoring
├── results_gin_5fold.json    # GIN baseline 5-fold CV results
├── requirements.txt          # Python dependencies
├── PIPELINE_README.md        # Quick-start guide for the dashboard flow
└── extracted_data/           # Volatility CSVs per sample (not included — see below)
    └── <Family>-WithVirus/
        ├── windows_pslist.csv
        ├── windows_psscan.csv
        ├── windows_malfind.csv
        ├── windows_filescan.csv
        └── ...
    └── <Family>-NoVirus/
```

> ⚠️ Memory images and ransomware samples are **not included** for safety and licensing reasons. Raw dumps are too large to ship in a repository.

---

## Installation

```bash
git clone https://github.com/variablevar/bug-free-happiness.git
cd bug-free-happiness
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Volatility 3 must be installed and available as the `vol` command:

```bash
pip install volatility3
```

### Quick Start (Dashboard)

```bash
python server.py
```

Then open the dashboard in your browser. See [PIPELINE_README.md](PIPELINE_README.md) for full dashboard instructions.

---

## Pipeline

### Step 1 — Volatility 3 Extraction

Place Windows memory images in `memory_dumps/` following the naming convention:

```text
memory_dumps/
    WannaCry-WithVirus.mem
    WannaCry-NoVirus.mem
    ...
```

Run parallel extraction across all dumps (17+ plugins):

```bash
python auto_vol.py
```

This writes per-sample CSVs into `extracted_data/<Family>-WithVirus/` and `extracted_data/<Family>-NoVirus/`.

### Step 2 — IOC Analysis

Run individual analysis scripts to compute IOC metrics per sample and per family:

```bash
python code_injection_analysis.py    # Code injection (malfind RWX + MZ header)
python hidden_proc_analysis.py       # Hidden processes (psscan vs pslist)
python filescan_analysis.py          # Suspicious file staging
python network_analysis.py           # C2-like network connections
python analysis_corpus.py            # Full corpus combined view
```

Each script outputs clean CSVs and Markdown-ready tables suitable for reports or papers.

### Step 3 — Graph Construction

Build heterogeneous behavioural graphs (PyTorch Geometric format):

```bash
python build_graph.py extracted_data/WannaCry-WithVirus/
```

Processes, DLLs, network connections, and files become nodes; edges encode relationships (parent–child, loaded-by, connected-to, wrote).

### Step 4 — Dataset Manifest

```bash
python build_dataset.py
```

Produces `extracted_data/dataset_manifest.csv`:

| Column | Description |
|---|---|
| `folder` | Sample directory name (e.g. `WannaCry-WithVirus`) |
| `label` | `1` = malware, `0` = benign |
| `family` | Malware family name |
| `max_score` | Peak heuristic score |
| `attack_steps` | Number of attack chain steps detected |
| `injections` | Count of malfind RWX regions |
| `c2_conns` | Count of external ESTABLISHED connections |

### Step 5 — Train GNN

```bash
# GIN (default, 5-fold CV)
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

#### CLI Reference

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

## Behavioural Heuristics (MITRE ATT&CK)

The heuristic engine in `filter_malicious.py` scores each graph across 5 MITRE ATT&CK dimensions:

| Tactic | MITRE | Signal |
|---|---|---|
| Initial Access / Execution | T1218, T1566 | LOLBin usage, script extensions in args |
| Defense Evasion / Injection | T1055 | malfind RWX + MZ header, shared shellcode stub |
| Command & Control | T1071 | ESTABLISHED connections to external IPs |
| Credential Access | T1003.001 | Full LSASS handle access (0x1fffff) |
| Execution / Impact | T1486 | High-score processes, ransomware note args |

Verdict levels: `CRITICAL` · `HIGH` · `MEDIUM` · `LOW`

---

## Indicators of Compromise (IOCs)

The pipeline detects four categories of memory-resident IOCs:

- **Code injection** — suspicious executable memory regions identified by `windows.malfind` (RWX pages with MZ headers)
- **Hidden processes** — objects in `psscan` not visible in `pslist`, indicating process hiding/rootkit behaviour
- **Suspicious file staging** — executables and payloads discovered via `windows.filescan`
- **Non-standard network activity** — outbound C2-like connections identified via `windows.netscan`

---

## Limitations

- **Small dataset (30 samples)** — results have high variance; aim for 60–100+ for reliable CV
- **Shallow node features** — one-hot + numeric; future work: pretrained embeddings on Windows API/DLL names
- **No family-aware splitting** — WithVirus/NoVirus pairs from the same family may leak across folds
- **CPU only tested** — CUDA path is implemented but untested

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

---

## Academic Context

This repository supports an **MSc Cybersecurity dissertation** on automated ransomware detection using Volatility 3 memory forensics, focusing on:

- Building a labelled ransomware memory corpus (MalVol-25)
- Automating Volatility 3 extraction at scale across 17+ plugins
- Quantifying memory-based IOCs for ransomware detection
- Applying Graph Neural Networks to heterogeneous OS behavioural graphs
