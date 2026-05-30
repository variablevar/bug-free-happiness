# Scripts

Helper and diagnostic scripts for the MalVol pipeline. Core stages (`auto_vol.py`, `build_graph.py`, etc.) live at the repository root.

## IOC and corpus profiling

| Script | Purpose |
|--------|---------|
| `ioc/code_injection_analysis.py` | malfind / injection IOC metrics |
| `ioc/hidden_proc_analysis.py` | psscan vs pslist hidden process detection |
| `ioc/filescan_analysis.py` | Suspicious file staging paths |
| `ioc/network_analysis.py` | External connection / C2-style activity |
| `ioc/analysis_corpus.py` | Aggregate IOC tables across corpus |
| `ioc/upload_sessions_batch.py` | Batch session upload helper |
| `corpus_profile.py` | Corpus-level graph/stat summary |
| `vol3_model_scan.py` | Volatility 3 plugin scan utility |

## Dataset governance

| Script | Purpose |
|--------|---------|
| `apply_hard_benign_labels.py` | Merge `hard_benign_labels.csv` into manifest (`benign_subtype`, `train_eligible`) |

## Training and calibration support

| Script | Purpose |
|--------|---------|
| `calibrate_uncertainty_thresholds.py` | Fit gates → `outputs/uncertainty_thresholds.json` |
| `fit_conformal_bundle.py` | Optional conformal review bundle for two-model path |

## Evaluation and diagnostics

| Script | Purpose |
|--------|---------|
| `diagnose_triage_geometry.py` | Score overlap / margin report from analysis JSON |
| `per_process_fp_report.py` | Per-process false-positive style breakdown |
| `tabular_baselines.py` | Non-GNN baseline comparisons |

## Reporting

| Script | Purpose |
|--------|---------|
| `generate_sample_reports.py` | Write `REPORT.md` per sample from `analysis_report.json` |
| `export_dissertation_figure_data.py` | Export numeric series for external LaTeX figures (optional) |

## LaTeX helpers (optional)

Not required for core pipeline operation:

- `generate_analysis_latex.py`
- `generate_eval_latex.py`
- `generate_dissertation_figures.py`
- `count_dissertation_words.sh`

## Tools

| Script | Purpose |
|--------|---------|
| `tools/csvs.py` | CSV utilities |

## Typical workflows

```bash
# Per-sample markdown reports
python scripts/generate_sample_reports.py --base-dir extracted_csvs \
  --analysis-json outputs/two_model_analysis.json

# Threshold calibration after retrain
python scripts/calibrate_uncertainty_thresholds.py

# Geometry diagnostic
python scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json

# Apply benign subtype overrides
python scripts/apply_hard_benign_labels.py extracted_csvs/dataset_manifest.csv \
  --labels-csv extracted_csvs/hard_benign_labels.csv
```

See [docs/evaluation_operations.md](../docs/evaluation_operations.md) and [docs/Pipeline.md](../docs/Pipeline.md).
