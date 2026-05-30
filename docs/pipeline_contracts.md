# Pipeline Artifact Contracts

This document defines the file-level contracts used by the dataset pipeline.
It is the stability reference for safe refactors.

## Canonical Per-Sample Outputs

- `graph.pkl`
  - Producer: `build_graph.py`
  - Consumers: `filter_malicious.py`, `analyze_graph.py`, `dataset.py`
  - Contract: pickle containing a NetworkX graph (`nx.Graph` or subclass).
  - Node attrs: `triage_zone` (`suspect`|`benign`|`neutral`), `raw_is_suspicious`, `benign_reasons`; `is_suspicious` is 1 only when `triage_zone == suspect`.

- `filtered_malicious.json`
  - Producer: `filter_malicious.py`
  - Consumer: `build_graph.py`
  - Contract keys:
    - `_meta.suspicious_pids` (list[int]) — suspect-zone PIDs only
    - `_meta.suspect_zone_pids` (alias of suspicious_pids)
    - `_meta.benign_zone_pids` (list[int])
    - `_meta.benign_zone_reasons` (dict[str, list[str]])
    - `benign_context_processes` (list, audit)
    - `_meta.graph_attr` (dict)
      - `max_process_score`
      - `attack_steps`
      - `high_severity_injections`
      - `lolbin_c2_connections`
      - `ransom_note_signal`
    - `_meta.label_signals` (dict)

- `graph.json`
  - Producer: `build_graph.py`
  - Consumer: optional tooling/inspection
  - Contract: node-link JSON for the same graph represented by `graph.pkl`.

- `graph_attr.json`
  - Producer: `build_graph.py`
  - Consumers: `build_dataset.py`, `analyze_graph.py`
  - Contract keys:
    - `graph_attr` (list[float], len=5) — legacy tensor aligned with the first five summary scalars
    - `graph_attr_map` (dict) — full expanded graph-level attributes from filter/triage (`_meta.graph_attr`)
    - `label_signals` (dict)

- `analysis_report.json`
  - Producer: `analyze_graph.py`
  - Consumer: `build_dataset.py`
  - Contract keys (minimum):
    - `attack_chain.max_process_score`
    - `attack_chain.steps`
    - `attack_chain.overall_verdict`
    - `injections`
    - `network`

## Dataset-Level Output

- `dataset_manifest.csv`
  - Producer: `build_dataset.py`
  - Consumers: `dataset.py`, training scripts
  - Contract columns:
    - identity: `sample_id`, `folder`, `label`, `family`
    - graph stats: `nodes`, `edges`
    - signals: `max_score`, `attack_steps`, `injections`, `c2_conns`, `verdict`
    - attrs: `graph_attr`, `label_signals_top`, `label_signals_json`
    - typed signals: `signal_behavioural_suspects_found`, `signal_lolbin_c2_found`, `signal_ransom_note_found`, `signal_rwx_injections`, `signal_hidden_processes`, `signal_top_suspect_score`, `signal_triage_confidence`, `signal_stage_coverage_score`, `signal_lineage_depth_p95`, `signal_nonrwx_exec_count`, `signal_credential_access_count`, `signal_num_attack_motifs`
    - triage: `uncertain`, `uncertain_reason`
    - pipeline health: `filter_ok`, `graph_ok`, `analyze_ok`, `error`

## Canonical Step Orchestration

Stable execution order in `build_dataset.py`:

1. Ensure `graph.pkl` exists before filtering.
   - If missing, run `build_graph.py` as a bootstrap pass.
2. Run `filter_malicious.py`.
3. Run `build_graph.py` (normal pass) to persist enrichment (`graph_attr`, labels).
4. Run `analyze_graph.py`.

This preserves compatibility with the current filter input dependency and graph
enrichment behavior while keeping all final outputs unchanged.

## Per-sample human report

- `REPORT.md`
  - Producer: `scripts/generate_sample_reports.py`
  - Inputs: `analysis_report.json`, optional `dataset_manifest.csv`, optional `outputs/two_model_analysis.json`
  - Contract: markdown summary (identity, graph scale, attack chain, IOC counts, artifact checklist, optional ML triage row)

## Manifest governance columns (when enabled)

Optional columns used by strict trainers and evaluation slices:

- `benign_subtype` — `clean_benign`, `hard_benign_admin_tooling`, `ambiguous_novirus_control`, etc.
- `train_eligible` — `true` / `false` for one-class training filters
- `label_quality_flag`, `label_quality_reason` — curation metadata
- `uncertain` / `uncertain_reason` — default (post benign-zone): `ambiguous_novirus_control` alone does **not** set `uncertain=True`; pipeline failures and `benign_label_critical_verdict` / `benign_label_high_suspect_zone` (label=0 with hot suspect-zone stats) may. Use `build_dataset.py --strict-novirus-controls` to restore folder-name uncertainty for NoVirus controls.

Author overrides via `hard_benign_labels.csv` + `scripts/apply_hard_benign_labels.py`.

## ML model artifacts (`outputs/`)

- `malware_model.pt`, `benign_model.pt`, `binary_model.pt`
  - Producers: `train_malware_model.py`, `train_benign_model.py`, `train_binary_model.py`
  - Consumers: `analyze_two_model.py`, `analyze_binary_model.py`
  - Contract: PyTorch state dict + embedded training metadata

- `malware_model_meta.json`, `benign_model_meta.json`, `binary_model_meta.json`
  - Contract keys (minimum):
    - `schema_version`
    - `graph_attr_profile` — `full` | `no_manifest_leakage` | `structure_only`
    - `graph_view` — `full` | `attack_subgraph`
    - binary meta additionally: `temperature`, calibration metrics, threshold fields

## ML analysis outputs

- `two_model_analysis.json`
  - Producer: `analyze_two_model.py` (or `evaluate.py`)
  - Contract:
    - top-level `summary` with triage rates and optional `subset_metrics`
    - `samples[]` with `folder`, `triage_state`, `malware_pattern_score`, `benign_conformity_score`, `delta_score`, `routing_tier`, evidence blocks

- `binary_analysis.json`
  - Producer: `analyze_binary_model.py`
  - Contract: per-sample `triage_state`, `p_malware`, calibration-aligned features

- `evaluate_merged_analysis.json`
  - Producer: `evaluate.py`
  - Contract: joins two-model and binary rows per `folder`

- `uncertainty_thresholds.json`
  - Producer: `scripts/calibrate_uncertainty_thresholds.py`
  - Consumer: `analyze_two_model.py` when present

- `gate_ablation.csv`, `triage_geometry_report.json`
  - Producers: `evaluate.py --gate-ablation`, `scripts/diagnose_triage_geometry.py`

## Graph attr profile semantics

Applied at load time via `utils/graph_attr_profile.py`:

| Profile | Effect |
|---------|--------|
| `full` | Use all manifest graph attributes |
| `no_manifest_leakage` | Zero or drop verdict-derived scalars |
| `structure_only` | Keep structural counts only |

Training and inference must use the same profile recorded in checkpoint meta.
