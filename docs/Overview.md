# Project Overview

tags: #overview #malware #forensics

## What is MalVol?

MalVol is an end-to-end ransomware detection system built for an **MSc Cybersecurity dissertation**. It combines:

- **Volatility 3** memory forensics to extract artefacts from Windows memory dumps
- **Graph construction** to model OS behaviour as a heterogeneous graph
- **Graph Neural Networks** (GIN / GraphSAGE) to classify samples as malware or benign

## Why Graphs?

Traditional signature-based AV tools miss novel ransomware variants. By modelling the entire OS state — processes, DLLs, network connections, files — as a graph, the model learns **behavioural patterns** rather than static signatures. This means it can potentially detect unknown ransomware that behaves similarly to known families.

## Dataset

- **30 samples** (15 malware / 15 benign)
- Real-world ransomware families (e.g. WannaCry)
- Paired WithVirus / NoVirus memory dumps per family
- Labelled via `dataset_manifest.csv`

## Tech Stack

| Layer | Technology |
|---|---|
| Memory Forensics | Volatility 3 |
| Graph Library | PyTorch Geometric |
| ML Models | GIN, GraphSAGE |
| Server | Flask / WebSocket |
| Language | Python 3.10+ |

## Related Notes

- [[Pipeline]]
- [[Models]]
- [[IOCs]]
