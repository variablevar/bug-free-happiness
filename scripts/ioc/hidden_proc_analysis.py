#!/usr/bin/env python3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from scipy import stats

from ioc_analysis.common import (
    configuration_from_dir,
    ensure_outputs_dir,
    iter_sample_dirs,
    paired_by_family,
    sample_name_from_dir,
    split_config,
)

DATA_DIR = BASE_DIR / "extracted_data"


def _pid_set(csv_path: Path):
    if not csv_path.exists():
        return set()
    return set(pd.read_csv(csv_path)["PID"].astype(str))


def detect_hidden_processes(img_dir: Path):
    pslist_pids = _pid_set(img_dir / "windows_pslist.csv")
    psscan_pids = _pid_set(img_dir / "windows_psscan.csv")
    hidden_pids = psscan_pids - pslist_pids
    suspicious_names = []
    csv = img_dir / "windows_psscan.csv"
    if hidden_pids and csv.exists():
        df = pd.read_csv(csv)
        hidden = df[df["PID"].astype(str).isin(hidden_pids)]
        suspicious_names = hidden["ImageFileName"].dropna().unique().tolist()
    return {
        "hidden_count": len(hidden_pids),
        "total_psscan": len(psscan_pids),
        "total_pslist": len(pslist_pids),
        "hidden_names": ", ".join(suspicious_names[:5]),
    }


def analyze_hidden_processes_corpus():
    results = []
    for img_dir in iter_sample_dirs(DATA_DIR):
        sample_name = sample_name_from_dir(img_dir)
        with_virus = configuration_from_dir(img_dir) == "WithVirus"
        analysis = detect_hidden_processes(img_dir)
        results.append(
            {
                "Ransomware Family": sample_name,
                "Configuration": "WithVirus" if with_virus else "NoVirus",
                "Hidden Procs": analysis["hidden_count"],
                "Total PSSCAN": analysis["total_psscan"],
                "Total PSLIST": analysis["total_pslist"],
                "Suspicious Names": analysis["hidden_names"],
            }
        )

    df = pd.DataFrame(results)
    with_virus_df, no_virus_df = split_config(df)
    paired = paired_by_family(df, ["Hidden Procs"])
    comp_df = pd.DataFrame(
        [
            {
                "Ransomware Family": r["Ransomware Family"],
                "WithVirus Hidden": r["Hidden Procs_with"],
                "NoVirus Hidden": r["Hidden Procs_no"],
                "Differential": f"+{r['Hidden Procs_with'] - r['Hidden Procs_no']}",
            }
            for _, r in paired.iterrows()
        ]
    )

    print("## 6.3 HIDDEN PROCESS DETECTION (PSSCAN vs PSLIST)")
    print(comp_df.to_markdown(index=False))
    with_mean = with_virus_df["Hidden Procs"].mean()
    no_mean = no_virus_df["Hidden Procs"].mean()
    print(f"WithVirus mean={with_mean:.2f} NoVirus mean={no_mean:.2f}")
    if len(with_virus_df) == len(no_virus_df):
        t_stat, p_value = stats.ttest_rel(with_virus_df["Hidden Procs"], no_virus_df["Hidden Procs"])
        print(f"t={t_stat:.3f}, p={p_value:.4f}")

    ensure_outputs_dir(str(BASE_DIR / "outputs"))
    comp_df.to_csv(BASE_DIR / "outputs" / "hidden_processes_table.csv", index=False)
    df.to_csv(BASE_DIR / "outputs" / "hidden_processes_full.csv", index=False)


if __name__ == "__main__":
    analyze_hidden_processes_corpus()

