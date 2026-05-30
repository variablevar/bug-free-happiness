# Pipeline

tags: #pipeline #volatility #graph

The MalVol pipeline has these major stages:

---

## Stage 1 — Volatility 3 extraction

**Script:** `auto_vol.py`

Runs Volatility 3 plugins in parallel over memory dumps in `memory_dumps/`. Writes per-sample CSVs into `extracted_data/<Sample>/` (or your configured output tree).

```bash
python auto_vol.py
```

Plugins include `pslist`, `psscan`, `malfind`, `filescan`, `netscan`, `dlllist`, `handles`, and more.

---

## Stage 2 — IOC analysis (optional / reporting)

**Scripts:** `scripts/ioc/code_injection_analysis.py`, `hidden_proc_analysis.py`, `filescan_analysis.py`, `network_analysis.py`, `analysis_corpus.py`

Computes IOC-style metrics per sample and family. Exports CSVs and summary tables.

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

3. **`analyze_graph.py`** — Reads the graph and artefacts; writes `analysis_report.json` (attack chain, entry points, IOC sections).

`build_dataset.py` runs these in a fixed order (bootstrap graph if missing → filter → graph → analyse). See [[pipeline_contracts]] for file contracts.

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

Produces `dataset_manifest.csv` with labels, graph stats, verdict fields, `graph_attr`, `label_signals_json`, typed `signal_*` columns, `uncertain` / `uncertain_reason`, governance fields when enabled, and step flags (`filter_ok`, `graph_ok`, `analyze_ok`).

**Uncertainty (default):** `-NoVirus` folders still get `benign_subtype=ambiguous_novirus_control`, but that alone no longer sets `uncertain=True`. Rows become uncertain only on pipeline failure, other label-quality flags, or strong suspect-zone disagreement (`CRITICAL` verdict, or ≥18 suspect PIDs with `max_score` ≥100). Use `--strict-novirus-controls` to restore the old “all NoVirus controls uncertain” behaviour.

```bash
python build_dataset.py
python build_dataset.py --base-dir extracted_csvs
python build_dataset.py extracted_data --skip-existing
python build_dataset.py extracted_data --strict-novirus-controls
```

---

## Stage 5 — Per-sample reports (optional)

**Script:** `scripts/generate_sample_reports.py`

Writes human-readable `REPORT.md` per folder from `analysis_report.json` and optional ML JSON.

```bash
python scripts/generate_sample_reports.py --base-dir extracted_csvs \
  --analysis-json outputs/two_model_analysis.json
```

---

## Stage 6 — ML training

### Primary: dual one-class stack

```bash
python train_stack.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
```

Or separately: `train_malware_model.py`, `train_benign_model.py`.

Key flags:

- `--graph-attr-profile` — `full`, `no_manifest_leakage`, `structure_only`
- `--graph-view` — `full`, `attack_subgraph`
- `--exclude-uncertain` — drop manifest uncertain rows
- `--require-governance-manifest` — enforce `train_eligible` / subtype columns

### Binary calibrated classifier

```bash
python train_binary_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --graph-attr-profile no_manifest_leakage
```

### Legacy supervised GNN CV

```bash
python train.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --model gin
python train.py extracted_csvs/dataset_manifest.csv --cv stratified_group --group-by family
```

See [[Models]] for architecture notes.

---

## Stage 7 — Evaluation and diagnostics

**Script:** `evaluate.py` (orchestrates two-model + binary + merged JSON)

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --gate-ablation
```

Supporting scripts:

- `scripts/calibrate_uncertainty_thresholds.py`
- `scripts/fit_conformal_bundle.py`
- `scripts/diagnose_triage_geometry.py`
- `scripts/apply_hard_benign_labels.py`

See [[evaluation_operations]] for ablation matrix and reproducibility commands.

---

## Related

- [[Models]]
- [[Results]]
- [[pipeline_contracts]]
