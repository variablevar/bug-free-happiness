# Future Work

tags: #future #improvements #roadmap

## Completed (in repo)

- [x] Dual one-class + binary fusion stack (`train_stack.py`, `analyze_two_model.py`)
- [x] Calibrated abstention gates (`fusion.py`, `--abstention-mode calibrated`)
- [x] Graph attr leakage profiles (`utils/graph_attr_profile.py`)
- [x] Attack subgraph view (`utils/subgraph_extract.py`)
- [x] Gate ablation harness (`evaluate.py --gate-ablation`)
- [x] Triage geometry diagnostics (`scripts/diagnose_triage_geometry.py`)
- [x] Conformal bundle hooks (`scripts/fit_conformal_bundle.py`)
- [x] Hard-benign label tooling (`scripts/apply_hard_benign_labels.py`)
- [x] Per-sample `REPORT.md` generation (`scripts/generate_sample_reports.py`)
- [x] Family-aware grouped CV (`train.py --cv stratified_group`)

## Short term

- [ ] **Populate `hard_benign_labels.csv`** with real `clean_benign` and `hard_benign_admin_tooling` rows
- [ ] **Retrain binary head** with `no_manifest_leakage` on full `extracted_csvs` and recalibrate thresholds
- [ ] **Expand corpus to 100+ samples** — reduce CV variance and stabilize one-class manifolds
- [ ] **CUDA validation** — GPU path exists but needs systematic testing at scale

## Medium term

- [ ] **Pretrained node embeddings** — replace sparse categorical features
- [ ] **Combined FCG + behavioural graph** — attach static call-structure subgraphs to process nodes
- [ ] **Hyperparameter search** — Optuna or Ray Tune across heads and fusion weights

## Long term

- [ ] **GNNExplainer / attribution** — tie model scores to specific nodes and edges in analyst UI
- [ ] **Live acquisition integration** — score graphs from on-the-fly memory capture
- [ ] **Multi-class family classification** — beyond binary triage
- [ ] **Federated training** — cross-org learning without sharing raw dumps

## Related notes

- [[Results]]
- [[Models]]
- [[graph_audit_improvement_report]]
