# Results

tags: #results #benchmarks #evaluation

## MalVol-25 Benchmark (seed=42, 5-fold CV)

| Model | Accuracy | F1 | AUC-ROC |
|---|---|---|---|
| GIN (v2, baseline) | 0.633 ± 0.163 | 0.743 ± 0.093 | 0.644 ± 0.269 |
| GIN (v3, weighted + clipped + graph_attr) | TBD | TBD | TBD |
| GraphSAGE | TBD | TBD | TBD |

> ⚠️ Dataset is small (30 samples). High variance is expected — run multiple seeds and average.

---

## Interpreting the Numbers

- **F1 (0.743)** is the most meaningful metric given the binary classification task and small dataset
- **AUC-ROC (0.644)** suggests the model is learning a real signal but needs more data to generalise
- **Accuracy (0.633)** is above random (0.5) but unstable across folds due to dataset size

---

## How to Reproduce

```bash
python train.py extracted_data/dataset_manifest.csv --seed 42
```

For multi-seed averaging:

```bash
for seed in 0 1 2 3 4; do
  python train.py extracted_data/dataset_manifest.csv --seed $seed
done
```

## Related Notes

- [[Models]]
- [[Future Work]]
