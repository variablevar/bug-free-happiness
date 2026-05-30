# Evaluation Operations

Operational guide for reproducing triage metrics, ablations, and diagnostics on a local manifest.

## Standard evaluation run

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
python scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json
python scripts/per_process_fp_report.py outputs/two_model_analysis.json
```

Outputs:

- `outputs/two_model_analysis.json`
- `outputs/binary_analysis.json`
- `outputs/evaluate_merged_analysis.json`
- `outputs/triage_geometry_report.json` (after diagnose script)

## Gate ablation

Compare abstention presets without manual re-runs:

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --gate-ablation
```

Writes `outputs/gate_ablation.csv` and preset-specific JSON files under `outputs/`.

Calibrate thresholds first when using `calibrated` mode:

```bash
python scripts/calibrate_uncertainty_thresholds.py
```

## Ablation matrix

| Experiment | graph_attr | graph_view | abstention | Notes |
|------------|------------|------------|------------|-------|
| Baseline | full | full | legacy_or | `outputs/two_model_analysis_legacy_or.json` if saved |
| Calibrated gates | full | full | calibrated | Default production-style routing |
| No leakage | no_manifest_leakage | full | calibrated | Retrain `train_binary_model.py` first |
| Subgraph | no_manifest_leakage | attack_subgraph | calibrated | Retrain all heads with `--graph-view attack_subgraph` |

Example calibrated inference:

```bash
python analyze_two_model.py extracted_csvs/dataset_manifest.csv \
  --base-dir extracted_csvs \
  --abstention-mode calibrated \
  --output-json outputs/two_model_analysis_calibrated.json
```

## Benign subtype slices

`evaluate.py` merged summary includes `subset_metrics` when manifest rows carry `benign_subtype`:

- `clean_benign`
- `hard_benign_admin_tooling`
- `ambiguous_novirus_control`
- `malware_labelled`
- `uncertain_benign`

Populate labels via `hard_benign_labels.csv` and `scripts/apply_hard_benign_labels.py`.

## Evaluation scope

This stack targets **uncertainty-aware behavioural triage** on memory-forensics graphs with ambiguous benign controls — not bulk malware labeling benchmarks (e.g. VirusTotal-scale static detection).

Report:

- decisive coverage vs review routing
- family-paired ambiguity where applicable
- calibration quality on the binary head (Brier, ECE in `binary_model_meta.json`)

## Optional figure export

LaTeX figure tables (optional, separate tree):

```bash
python scripts/export_dissertation_figure_data.py
```

Not required for core pipeline operation.

## Related

- [[Results]]
- [[graph_audit_improvement_report]]
- [[pipeline_contracts]]
