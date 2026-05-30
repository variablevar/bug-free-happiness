# Graph Audit Improvement Report

## Executive Summary

The current dataset and model stack support an uncertainty-aware triage workflow more naturally than a hard malware-vs-benign decision. The core reason is not just model quality; it is dataset structure. In the checked-in corpus, `14/15` benign-labelled rows are already marked `uncertain=True`, and many `NoVirus` control graphs carry `HIGH` or `CRITICAL` rule-based verdicts. A binary classifier therefore learns against overlapping classes, while the two-model path is better aligned with the real question: "does this graph look malware-like, benign-like, or too ambiguous to decide automatically?"

This report references both corpora:

- **`extracted_data/`** — ~30 paired `*-WithVirus` / `*-NoVirus` families (primary graph-audit statistics below)
- **`extracted_csvs/`** — ~43 manifest rows with full per-folder `graph.pkl` / `analysis_report.json` (primary ML evaluation corpus)

Training and evaluation typically use `extracted_csvs/dataset_manifest.csv` with `--base-dir extracted_csvs`.

## Scope And Evidence Base

Files reviewed for this report:

- `extracted_data/dataset_manifest.csv`
- `extracted_data/*/graph.json`
- `dataset.py`
- `one_class_gnn.py`
- `train_malware_model.py`
- `train_benign_model.py`
- `analyze_two_model.py`
- `fusion.py`
- `outputs/binary_analysis.json`
- `outputs/two_model_analysis.json`

Corpus summary from the checked-in artifacts:

- `30` manifest rows
- `30` matching `graph.json` files under `extracted_data/*`
- `15` benign-labelled rows and `15` malware-labelled rows
- `14/15` benign-labelled rows marked `uncertain=True`
- identical verdict mix on both labels: `8 HIGH`, `6 CRITICAL`, `1 LOW`

One implementation detail matters immediately for model improvement work:

- the inspectable graph artifacts are available as `graph.json`
- the loader in `dataset.py` trains from `graph.pkl`
- the manifest row drives folder resolution, then `dataset.py` loads `graph.pkl` from `<base_dir>/<folder>/graph.pkl`

That means graph audits can inspect `graph.json`, but any model improvement must account for what is actually consumed from `graph.pkl` and the feature projection built in `dataset.py`.

## Key Findings

### 1. The benign class is not a clean benign distribution

The strongest issue is label ambiguity. In the current manifest, nearly every benign-labelled row is already marked uncertain, and many benign control graphs are at least as suspicious as their malware-labelled pair.

Paired-family overlap from `dataset_manifest.csv`:

- benign `max_score >= malware` in `10/15` families
- benign `injections >= malware` in `11/15`
- benign `c2_conns >= malware` in `7/15`
- benign `signal_top_suspect_score >= malware` in `15/15`

Representative reversals:

- `DeriaLock-NoVirus`: `max_score=31`, `injections=9`, `c2_conns=66`
- `DeriaLock-WithVirus`: `max_score=13`, `injections=2`, `c2_conns=8`
- `PowerLoader-NoVirus`: `max_score=39`, `c2_conns=39`
- `PowerLoader-WithVirus`: `max_score=14`, `c2_conns=13`
- `DLLHijacking-NoVirus`: `max_score=52`, `injections=18`
- `DLLHijacking-WithVirus`: `max_score=22`, `injections=8`

Why it matters:

- a hard binary boundary is structurally mismatched to this corpus
- the benign one-class model is being asked to model a class that is already contaminated by malware-like behaviour
- the project should describe these rows as ambiguous or control-condition benign, not clean negatives

### 2. The graphs are dominated by memory structure, not high-value semantics

Aggregate graph counts across all `30` checked-in `graph.json` files show that the corpus is overwhelmingly driven by memory-region structure:

- node totals:
  - `memory_region`: `412,133`
  - `thread`: `33,685`
  - `dll`: `29,826`
  - `process`: `2,731`
  - `network_conn`: `2,480`
  - `ip_address`: `425`
- edge totals:
  - `allocated_in`: `411,793`
  - `loaded_into`: `123,468`
  - `belongs_to`: `33,675`
  - `connects_from`: `1,865`
  - `connects_to`: `570`
  - `injected_into`: `340`

Why it matters:

- the current feature space is exposed to enormous volume from `memory_region`, `allocated_in`, and `loaded_into`
- this creates pressure for the model to learn graph size, memory pressure, or allocation density as shortcuts
- the most interpretable malicious relations are much rarer, so they risk being diluted by bulk structure

### 3. Rare semantic motifs look more discriminative than bulk graph counts

Suspicious-node rates are much sharper for a few semantic node types than for the memory-heavy majority:

- `ip_address`: suspicious rate `1.0`
- `handle`: suspicious rate `1.0`
- `network_conn`: suspicious rate `0.2298`
- `process`: suspicious rate `0.1472`
- `thread`: suspicious rate `0.1084`
- `memory_region`: suspicious rate `0.0021`

The suspicion metadata is also sparse:

- `6,217` suspicious nodes have `null` suspicion reasons
- `286` have `"[]"`
- only `101` explicitly carry `"['rwx_injection']"`

Why it matters:

- the durable malware signal appears to live in sparse relations such as injection, credential access, and network/C2 context
- the model should lean more on semantically rich but rare motifs instead of raw graph mass
- richer motif-aware features are likely to improve both discrimination and explanation quality

### 4. Some samples are structurally out-of-distribution

`W32.MyDoom.A.-NoVirus` and `W32.MyDoom.A.-WithVirus` are clear outliers in the manifest:

- `86` nodes / `7` edges
- `164` nodes / `10` edges
- both have `LOW` verdicts and zero injection-related signals

These are radically smaller than the rest of the corpus, where most samples are in the thousands to tens of thousands of nodes.

Why it matters:

- they represent a different graph regime, not just another family instance
- treating them as ordinary members of the benign/malware manifolds can distort one-class centers and thresholds
- they should be handled as out-of-distribution or at least evaluated separately

### 5. There are signs of repeated or templated graph structure

At least one exact structural fingerprint collision exists in the checked-in graph summaries:

- `DLLHijacking-NoVirus`
- `RedTail-NoVirus`

These two graphs share the same node/edge totals, the same node-type counts, the same edge-type counts, and the same suspicious-node count.

Why it matters:

- repeated scaffolding can make generalization look stronger than it really is
- the model may learn dataset templates rather than malware/benign behaviour
- family-aware evaluation should remain explicit in reporting

### 6. Uncertainty must stay operational in fusion

`analyze_two_model.py` and `fusion.py` now support layered abstention (`--abstention-mode calibrated` by default): MC variance, ensemble disagreement, dual-margin gates, and binary–dual disagreement in mid-confidence bands. Legacy `legacy_or` and diagnostic `disabled` modes remain for ablation.

Why it matters:

- review routing should reflect measured ambiguity, not fixed score bands alone
- gate presets are comparable via `evaluate.py --gate-ablation` → `outputs/gate_ablation.csv`

### 7. One-class training is especially fragile on this dataset

The one-class trainers include uncertain rows by default via `include_uncertain=not args.exclude_uncertain`. In addition, `one_class_gnn.py` initializes the center from early embeddings, optimizes against that fixed center, and only recomputes the scoring center after training.

Why it matters:

- benign contamination widens the learned benign region
- small-data one-class learning becomes sensitive to initialization and sample mix
- training and inference are not optimized against exactly the same center/radius definition

## What Current Evaluation Outputs Show

Inspect the latest run under `outputs/` (counts vary by checkpoint and abstention preset).

Typical pattern on ambiguous corpora:

- **Binary path** (`outputs/binary_analysis.json`) — tends to over-commit to `likely_malicious` when manifest leakage or calibration collapse is present
- **Two-model path** (`outputs/two_model_analysis.json`) — routes more mass to `needs_analyst_review` / `anomalous_unknown`, matching overlapping benign controls

Interpretation:

- use **triage metrics** (decisive coverage, review rate) rather than accuracy alone
- recalibrate after `no_manifest_leakage` binary retrain and threshold fitting (`scripts/calibrate_uncertainty_thresholds.py`)
- regenerate geometry report: `scripts/diagnose_triage_geometry.py outputs/two_model_analysis.json`

## Prioritized Improvements

### Priority 1: Fix data governance before changing model architecture

Recommended actions:

1. regenerate or extend the main manifest so `train_eligible`, `benign_subtype`, `label_quality_flag`, and `label_quality_reason` are live fields in the active dataset, not dormant schema
2. split benign data into at least three groups:
   - clean benign
   - hard benign / admin-tooling
   - ambiguous `NoVirus` controls from malware families
3. exclude or down-weight ambiguous benign rows by default during benign one-class training

Why this is first:

- the current training target is ill-defined
- no architecture change will fully solve contaminated class boundaries

Primary files:

- `build_dataset.py`
- `dataset.py`
- `train_benign_model.py`
- `train_malware_model.py`

### Priority 2: Make rare semantic graph motifs count more than graph bulk

Recommended actions:

1. rebalance graph-level features so `memory_region` and allocation-heavy counts do not dominate
2. promote relation features tied to:
   - `injected_into`
   - `connects_to`
   - `connects_from`
   - credential-access patterns
   - suspicious handle / process lineage context
3. track out-of-distribution graph regimes explicitly instead of forcing them into the same one-class boundary

Why this is second:

- the graph already contains rich signals, but the current projection risks drowning them in bulk structure

Primary files:

- `dataset.py`
- `utils/graph_motif_signals.py`
- `build_graph.py`

### Priority 3: Turn reported uncertainty into actual abstention logic

Recommended actions:

1. gate `likely_benign` and `likely_malicious` on model disagreement or variance, not only score bands
2. reserve decisive states for low-variance cases
3. route high-variance or contamination-prone cases to `needs_analyst_review`

Why this is third:

- the code already computes the raw ingredients for uncertainty-aware triage
- using them directly is higher leverage than adding another classifier head

Primary files:

- `analyze_two_model.py`
- `fusion.py`
- `analysis_schema.py`

### Priority 4: Make one-class training internally consistent and more robust

Recommended actions:

1. revisit center/radius learning so training and inference optimize against the same target
2. calibrate conformity thresholds on held-out data instead of treating `0.40` / `0.60` as stable confidence bands
3. evaluate whether benign training should use contamination-robust objectives or explicit hard-negative handling

Why this is fourth:

- even a cleaner dataset still needs more stable one-class optimization on small samples

Primary files:

- `one_class_gnn.py`
- `train_benign_model.py`
- `train_malware_model.py`

### Priority 5: Evaluate the system as triage, not just classification

Recommended actions:

1. report abstention coverage, analyst-review routing, and family-paired ambiguity
2. compare results with and without uncertain benign rows
3. keep family-paired evaluation explicit in all summary tables and subset_metrics

Why this matters:

- the strongest claim this corpus supports is triage quality under uncertainty
- a plain accuracy framing overstates what the labels can justify

Primary files:

- `evaluate.py`
- `analyze_two_model.py`
- `scripts/diagnose_triage_geometry.py`
- [[evaluation_operations]]

## Implementation status

| Priority | Theme | Status | Modules |
|----------|-------|--------|---------|
| 1 | Data governance | Partial | `dataset.py`, `scripts/apply_hard_benign_labels.py`, `train_*_model.py` flags |
| 2 | Semantic motifs vs bulk | Partial | `utils/graph_motif_signals.py`, `dataset.py`, `build_graph.py` |
| 3 | Operational abstention | Implemented | `fusion.py`, `analyze_two_model.py`, `evaluate.py --gate-ablation` |
| 4 | One-class robustness | Partial | `one_class_gnn.py`, `scripts/calibrate_uncertainty_thresholds.py` |
| 5 | Triage-first evaluation | Implemented | `evaluate.py` subset_metrics, `scripts/diagnose_triage_geometry.py` |

**Remaining operational gaps:**

- populate `hard_benign_labels.csv` with real clean/hard-benign rows
- retrain binary head with `no_manifest_leakage` on full `extracted_csvs`
- optional conformal bundle: `scripts/fit_conformal_bundle.py`

## Bottom Line

The current repository already points toward the right modeling direction: separate malware conformity from benign conformity, then fuse the outputs into triage states. The main improvement opportunity is not to force a sharper binary verdict. It is to make the uncertainty story real at every level: cleaner benign governance, stronger semantic graph features, explicit out-of-distribution handling, and triage logic that abstains when the evidence is genuinely mixed.
