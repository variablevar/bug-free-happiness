# Pipeline Artifact Contracts

This document defines the file-level contracts used by the dataset pipeline.
It is the stability reference for safe refactors.

## Canonical Per-Sample Outputs

- `graph.pkl`
  - Producer: `build_graph.py`
  - Consumers: `filter_malicious.py`, `analyze_graph.py`, `dataset.py`
  - Contract: pickle containing a NetworkX graph (`nx.Graph` or subclass).

- `filtered_malicious.json`
  - Producer: `filter_malicious.py`
  - Consumer: `build_graph.py`
  - Contract keys:
    - `_meta.suspicious_pids` (list[int])
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
    - `graph_attr` (list[float], len=5)
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
    - attrs: `graph_attr`, `label_signals_top`
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
