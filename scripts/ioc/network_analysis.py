#!/usr/bin/env python3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pandas as pd

from ioc_analysis.common import (
    configuration_from_dir,
    ensure_outputs_dir,
    iter_sample_dirs,
    paired_by_family,
    sample_name_from_dir,
    split_config,
)

DATA_DIR = BASE_DIR / "extracted_data"


def load_netscan(img_dir: Path):
    csv_file = img_dir / "windows_netscan.csv"
    if not csv_file.exists():
        return {"connections": 0, "susp_ports": 0, "c2_hits": 0}
    df = pd.read_csv(csv_file)
    suspicious = df[(df["LocalPort"] > 10000) | (df["ForeignAddr"].str.contains(r"\.ru|\.top|\.xyz|tor|onion", na=False))]
    return {
        "connections": len(df),
        "susp_ports": len(df[df["LocalPort"].isin([80, 443, 4444, 8080, 9001])]),
        "c2_hits": len(suspicious),
    }


def analyze_netscan_corpus():
    rows = []
    for img_dir in iter_sample_dirs(DATA_DIR):
        m = load_netscan(img_dir)
        rows.append(
            {
                "Ransomware Family": sample_name_from_dir(img_dir),
                "Configuration": configuration_from_dir(img_dir),
                "Total Connections": m["connections"],
                "Suspicious Ports": m["susp_ports"],
                "C2 Hits": m["c2_hits"],
            }
        )
    df = pd.DataFrame(rows)
    with_virus_df, no_virus_df = split_config(df)
    paired = paired_by_family(df, ["C2 Hits"])
    comp_df = pd.DataFrame(
        [
            {
                "Ransomware Family": r["Ransomware Family"],
                "WithVirus C2": r["C2 Hits_with"],
                "NoVirus C2": r["C2 Hits_no"],
                "Differential": f"+{r['C2 Hits_with'] - r['C2 Hits_no']}",
            }
            for _, r in paired.iterrows()
        ]
    )
    print("## 6.5 NETWORK ACTIVITY AND C2 DETECTION (NETSCAN)")
    print(comp_df.to_markdown(index=False))
    print(f"WithVirus mean={with_virus_df['C2 Hits'].mean():.2f}, NoVirus mean={no_virus_df['C2 Hits'].mean():.2f}")
    ensure_outputs_dir(str(BASE_DIR / "outputs"))
    comp_df.to_csv(BASE_DIR / "outputs" / "netscan_analysis_table.csv", index=False)


if __name__ == "__main__":
    analyze_netscan_corpus()

