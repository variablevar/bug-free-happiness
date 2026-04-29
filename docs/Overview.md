# Project Overview

tags: #overview #malware #forensics

## What is MalVol?

MalVol is an end-to-end ransomware-research pipeline built for an **MSc Cybersecurity dissertation**. It combines:

- **Volatility 3** memory forensics to extract artefacts from Windows memory dumps
- **Graph construction** to model OS behaviour as a heterogeneous graph (processes, DLLs, network, files)
- **Graph neural networks** (GIN, GraphSAGE, GAT, GINE) to classify samples or rank risk, with **grouped** cross-validation (LOSO or stratified-by-group folds)

## Why graphs?

Signature-heavy tools miss novel variants. A graph over the whole captured OS state encodes **behavioural structure** (parentage, loads, connections, file writes) rather than a single file hash, which can help separate malware-style activity from benign baselines when labels and groups are chosen carefully.

## Dataset

Corpus size is **local**: it depends on `memory_dumps/` and the built manifest. Typical dissertation scale is tens of paired WithVirus / NoVirus folders. Ground truth and heuristics are joined in `dataset_manifest.csv` (see [[Pipeline]] and `docs/pipeline_contracts.md`).

## Tech stack

| Layer | Technology |
|-------|------------|
| Memory forensics | Volatility 3 |
| Graph / ML | PyTorch Geometric, PyTorch |
| Models | GIN, GraphSAGE, GAT, GINE (`model.py`) |
| Optional UI | Flask / WebSocket (`server.py`) |
| Language | Python 3.10+ |

## Related notes

- [[Pipeline]]
- [[Models]]
- [[IOCs]]
