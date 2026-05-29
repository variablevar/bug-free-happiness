# Research Evaluation Report (auto-generated template)

Regenerate metrics after each ablation run:

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
python scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --gate-ablation
python scripts/export_dissertation_figure_data.py
python scripts/per_process_fp_report.py outputs/two_model_analysis.json
```

## Ablation matrix

| Experiment | graph_attr | graph_view | abstention | Review rate | Decisive coverage |
|------------|------------|------------|------------|-------------|-------------------|
| Baseline | full | full | legacy_or | see `outputs/two_model_analysis_legacy_or.json` | |
| Calibrated gates | full | full | calibrated | see `outputs/two_model_analysis_calibrated.json` | |
| No leakage | no_manifest_leakage | full | calibrated | retrain binary first | |
| Subgraph | no_manifest_leakage | attack_subgraph | calibrated | retrain all heads | |

See `outputs/gate_ablation.csv` and `outputs/triage_geometry_report.json` for latest numbers.

## Benign subtype slices

`evaluate.py` merged output includes `subset_metrics` for:

- `clean_benign`
- `hard_benign_admin_tooling`
- `ambiguous_novirus_control`
- `malware_labelled`

## Dissertation framing

Uncertainty-aware behavioral triage under ambiguous benign labels in memory-forensics graphs — not endpoint detection SOTA on VirusTotal.
