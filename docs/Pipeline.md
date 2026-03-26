# Pipeline

tags: #pipeline #volatility #graph

The MalVol pipeline has 5 stages:

---

## Stage 1 — Volatility 3 Extraction

**Script:** `auto_vol.py`

Runs 17+ Volatility 3 plugins in parallel over all memory dumps in `memory_dumps/`. Outputs per-sample CSVs into `extracted_data/`.

```bash
python auto_vol.py
```

Plugins include: `pslist`, `psscan`, `malfind`, `filescan`, `netscan`, `dlllist`, `handles`, and more.

---

## Stage 2 — IOC Analysis

**Scripts:** `code_injection_analysis.py`, `hidden_proc_analysis.py`, `filescan_analysis.py`, `network_analysis.py`, `analysis_corpus.py`

Computes IOC metrics per sample and per family. Exports CSVs and Markdown tables.

```bash
python code_injection_analysis.py
python hidden_proc_analysis.py
python filescan_analysis.py
python network_analysis.py
python analysis_corpus.py
```

See [[IOCs]] for details on each indicator.

---

## Stage 3 — Graph Construction

**Script:** `build_graph.py`

Builds a heterogeneous OS behavioural graph per sample in PyTorch Geometric format.

- **Nodes:** processes, DLLs, network connections, files
- **Edges:** parent–child, loaded-by, connected-to, wrote

```bash
python build_graph.py extracted_data/WannaCry-WithVirus/
```

---

## Stage 4 — Dataset Manifest

**Script:** `build_dataset.py`

Produces `extracted_data/dataset_manifest.csv` with per-sample labels and heuristic scores.

```bash
python build_dataset.py
```

---

## Stage 5 — GNN Training

**Script:** `train.py`

5-fold cross-validated training with GIN or GraphSAGE.

```bash
python train.py extracted_data/dataset_manifest.csv
python train.py extracted_data/dataset_manifest.csv --model sage
```

See [[Models]] for architecture details and [[Results]] for benchmark numbers.
