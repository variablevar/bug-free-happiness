# Automated Ransomware Detection with Volatility 3

This project implements an automated, parallelised memory forensics pipeline using **Volatility 3** to detect ransomware activity from Windows memory dumps. It was developed as part of an MSc Cybersecurity dissertation and evaluates **24 real-world malware samples** (WithVirus/NoVirus pairs) across multiple ransomware families.

## If you are here from the dashboard follow here

```bash
git clone https://github.com/variablevar/bug-free-happiness.git
cd bug-free-happiness

# optional
python -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
python server.py
```

## Features

- Parallel **Volatility 3** CSV extraction for large memory corpora
- Support for 17+ Windows plugins (e.g. `pslist`, `psscan`, `malfind`, `filescan`, `netscan`)
- Automated IOC extraction and comparison for:
  - Code injection (`malfind`)
  - Hidden processes (`psscan` vs `pslist`)
  - Suspicious file staging (`filescan`)
  - Non-standard network activity (`netscan`)
- WithVirus vs NoVirus differential analysis
- Export of clean CSVs and Markdown-ready tables for reports

## Repository Structure,

Typical data layout (not included in this repo):

```text
memory_dumps/
└── <Family>-WithVirus.raw / .mem / .dmp
└── <Family>-NoVirus.raw   / .mem / .dmp

extracted_data/
└── <Family>-WithVirus/
    ├── windows_pslist.csv
    ├── windows_psscan.csv
    ├── windows_malfind.csv
    ├── windows_filescan.csv
    └── ...
└── <Family>-NoVirus/
    └── ...
```

## Requirements

- Python 3.10+
- Volatility 3 installed and in `PATH` (`vol` command)

Install Python dependencies:

```bash
pip install -r requirements.txt
```


## Usage

### 1. Prepare memory dumps

Place your Windows memory images in:

```text
memory_dumps/
    sample1-WithVirus.mem
    sample1-NoVirus.mem
    ...
```

### 2. Run Volatility 3 extraction

This will run all configured plugins over all dumps in parallel and write CSVs to `extracted_data/`:

```bash
python auto_vol.py
```

### 3. Run IOC analysis scripts

Example for malfind (code injection) analysis:

```bash
# Code injection (malfind) analysis
python code_injection_analysis.py

# Hidden process (psscan vs pslist) analysis
python hidden_proc_analysis.py

# Suspicious file (filescan) analysis
python filescan_analysis.py

# Network IOC (netscan) analysis
python network_analysis.py

# Full corpus statistics / combined view
python analysis_corpus.py
```

These scripts:

- Load the real CSVs from `extracted_data/`
- Compute IOC metrics per sample and per family
- Perform basic statistics (mean, standard deviation, t-test, effect size)
- Export CSVs and Markdown tables ready for reports/papers

## Indicators of Compromise (IOCs)

The analysis focuses on memory-resident IOCs commonly associated with ransomware:

- **Code injection**: suspicious executable pages identified by `windows.malfind`
- **Hidden processes**: objects present in `psscan` but missing from `pslist`
- **Suspicious files**: executables and payloads found via `windows.filescan`
- **Non-standard ports**: outbound C2-like connections via `windows.netscan`

The scripts are designed so you can adapt thresholds and scoring logic for your own datasets.

## Notes and Limitations

- Memory images and ransomware samples are **not** included for safety and licensing reasons, or more likely the images size are too high  
- Paths and naming conventions in the scripts assume a `<Family>-WithVirus` / `<Family>-NoVirus` style; adjust as needed.
- Results depend on correct Volatility symbol resolution for each Windows build.

## Academic Context

This repository supports an MSc Cybersecurity dissertation on **automated ransomware detection using Volatility 3 memory forensics**, focusing on:

- Building a labelled ransomware memory corpus
- Automating Volatility 3 extraction at scale
- Quantifying memory-based IOCs for ransomware detection