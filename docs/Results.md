# Results

tags: #results #benchmarks #evaluation

## Where metrics live

After running `evaluate.py`, inspect:

| Artifact | Contents |
|----------|----------|
| `outputs/two_model_analysis.json` | Per-sample fused triage, scores, evidence |
| `outputs/binary_analysis.json` | Binary path states and `p_malware` |
| `outputs/evaluate_merged_analysis.json` | Combined summary + `subset_metrics` |
| `outputs/gate_ablation.csv` | Abstention preset comparison (`--gate-ablation`) |
| `outputs/triage_geometry_report.json` | Score overlap / margin diagnostics |
| `outputs/binary_model_meta.json` | Calibration (Brier, ECE, KS, AUROC) |

Regenerate diagnostics:

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
python scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json
```

See [[evaluation_operations]] for the full ablation matrix.

---

## Triage metrics (primary stack)

Report these for production-style evaluation:

- **decisive_coverage** — fraction in `likely_malicious` or `likely_benign`
- **review_routing_rate** — fraction in `needs_analyst_review`
- **abstention_coverage** — ambiguous / review states combined
- **subset_metrics** — broken down by `benign_subtype` when manifest columns exist

Do not rely on plain accuracy alone when many benign controls are heuristic-high.

---

## Legacy supervised GNN baseline (seed=42, grouped CV)

Historical reference on ~30-sample paired corpus (`extracted_data/`), leave-one-group-out:

| Model | Accuracy | F1 | AUC-ROC |
|-------|----------|-----|---------|
| GIN (v2, baseline) | 0.633 ± 0.163 | 0.743 ± 0.093 | 0.644 ± 0.269 |
| GIN (v3, weighted + graph_attr) | run locally | run locally | run locally |
| GraphSAGE / GAT / GINE | run locally | run locally | run locally |

High variance is expected at this sample size — use multiple seeds and grouped CV.

---

## How to reproduce legacy CV

```bash
python train.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --seed 42
```

Checkpoint evaluation:

```bash
python evaluate.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs
```

Multi-seed loop:

```bash
for seed in 0 1 2 3 4; do
  python train.py extracted_csvs/dataset_manifest.csv --base-dir extracted_csvs --seed $seed
done
```

---

## Related notes

- [[Models]]
- [[evaluation_operations]]
- [[Future Work]]
