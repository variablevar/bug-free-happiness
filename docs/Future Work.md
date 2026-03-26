# Future Work

tags: #future #improvements #roadmap

## Short Term

- [ ] **Expand dataset to 100+ samples** — most critical improvement; will dramatically reduce CV variance
- [ ] **Family-aware stratified splitting** — prevent WithVirus/NoVirus pairs from the same family leaking across folds
- [ ] **CUDA testing** — GPU path is implemented but untested; needed for larger datasets

## Medium Term

- [ ] **Pretrained node embeddings** — replace one-hot DLL/process name features with embeddings pretrained on Windows API call sequences
- [ ] **Combined FCG + behavioural graph** — process nodes carry a code-structure subgraph from function call graph analysis
- [ ] **Hyperparameter search** — automated tuning with Optuna or Ray Tune

## Long Term

- [ ] **GNNExplainer integration** — identify which nodes/edges drive the malware classification for interpretability
- [ ] **Real-time scoring** — integrate with live Volatility memory acquisition for on-the-fly detection
- [ ] **Multi-class classification** — extend beyond binary to family-level classification (WannaCry vs LockBit vs REvil etc.)
- [ ] **Federated learning** — train across organisations without sharing raw memory dumps

## Related Notes

- [[Results]]
- [[Models]]
