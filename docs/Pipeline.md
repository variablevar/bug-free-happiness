# Pipeline

tags: #pipeline #volatility #graph

The MalVol pipeline has these major stages:

---

## Stage 1 — Volatility 3 extraction

**Script:** `auto_vol.py`

Runs many Volatility 3 plugins in parallel over memory dumps in `memory_dumps/`. Writes per-sample CSVs into `extracted_data/<Sample>/`.

```bash
python auto_vol.py
```

Plugins include `pslist`, `psscan`, `malfind`, `filescan`, `netscan`, `dlllist`, `handles`, and more.

---

## Stage 2 — IOC analysis (optional / reporting)

**Scripts:** `scripts/ioc/code_injection_analysis.py`, `hidden_proc_analysis.py`, `filescan_analysis.py`, `network_analysis.py`, `analysis_corpus.py`

Computes IOC-style metrics per sample and family. Exports CSVs and Markdown-friendly tables.

```bash
python scripts/ioc/code_injection_analysis.py
python scripts/ioc/hidden_proc_analysis.py
python scripts/ioc/filescan_analysis.py
python scripts/ioc/network_analysis.py
python scripts/ioc/analysis_corpus.py
```

See [[IOCs]] for indicator categories.

---

## Stage 3 — Graph construction and triage

**Scripts:** `build_graph.py`, `filter_malicious.py`, `analyze_graph.py`

1. **`build_graph.py`** — Builds a heterogeneous behavioural graph per sample (NetworkX → `graph.pkl`, plus `graph.json`). After filtering, a second pass writes **`graph_attr.json`**: legacy 5-float `graph_attr` and full **`graph_attr_map`** from triage metadata.

2. **`filter_malicious.py`** — Reads **`graph.pkl`**, writes `filtered_malicious.json` (rule hits, `_meta.graph_attr`, `_meta.label_signals`).

3. **`analyze_graph.py`** — Reads the graph and artefacts; writes `analysis_report.json`.

`build_dataset.py` runs these in a fixed order (bootstrap graph if missing → filter → graph → analyse). See `docs/pipeline_contracts.md` for file contracts.

Single-folder example:

```bash
python build_graph.py extracted_data/WannaCry-WithVirus/
python filter_malicious.py extracted_data/WannaCry-WithVirus/
python build_graph.py extracted_data/WannaCry-WithVirus/
python analyze_graph.py extracted_data/WannaCry-WithVirus/
```

---

## Stage 4 — Dataset manifest

**Script:** `build_dataset.py`

Produces `extracted_data/dataset_manifest.csv` with labels, graph stats, verdict fields, `graph_attr`, `label_signals_json`, typed `signal_*` columns, `uncertain` / `uncertain_reason`, and step flags (`filter_ok`, `graph_ok`, `analyze_ok`).

```bash
python build_dataset.py
```

---

## Stage 5 — GNN training and evaluation

**Scripts:** `train.py`, `evaluate.py`

Grouped CV (default LOSO on sample folders; optional stratified group K-fold by family). Models: `gin`, `sage`, `gat`, `gine`.

```bash
python train.py extracted_data/dataset_manifest.csv
python train.py extracted_data/dataset_manifest.csv --model sage
python train.py extracted_data/dataset_manifest.csv --cv stratified_group --group-by family

python evaluate.py extracted_data/dataset_manifest.csv path/to/checkpoint.pt --model gin
```

See [[Models]] for architecture notes.
