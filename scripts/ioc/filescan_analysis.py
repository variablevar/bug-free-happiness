#!/usr/bin/env python3
import re
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
SUSP_PATH_PATTERNS = [
    r".*\\temp\\.*\.exe", r".*\\appdata\\.*\.exe", r".*\\windows\\temp\\",
    r"readme\.txt", r"\.crypt", r"\.locked", r"!!!_DECRYPT_!!!", r"wanacry",
    r"\.scr$", r"\.pif$", r"decrypt\.html",
]
TEMP_EXE_PATTERN = re.compile(r"(temp|appdata|windows\\temp).*(\.exe|\.scr|\.pif|\.dll)$", re.IGNORECASE)


def load_filescan_suspicious(img_dir: Path):
    csv_file = img_dir / "windows_filescan.csv"
    if not csv_file.exists():
        return {"suspicious_count": 0, "deleted_count": 0, "susp_names": ""}
    df = pd.read_csv(csv_file)
    suspicious = 0
    deleted = 0
    names = []
    for _, row in df.iterrows():
        fname = str(row.get("Name", "")).lower()
        details = str(row.get("Details", row.get("Type", ""))).lower()
        if any(re.search(p, fname) for p in SUSP_PATH_PATTERNS) or TEMP_EXE_PATTERN.search(fname):
            suspicious += 1
            names.append(fname[:50])
        if "file_deleted" in details or "deleted" in details:
            deleted += 1
    return {"suspicious_count": suspicious, "deleted_count": deleted, "susp_names": ", ".join(set(names[:6]))}


def analyze_filescan_corpus():
    rows = []
    for img_dir in iter_sample_dirs(DATA_DIR):
        a = load_filescan_suspicious(img_dir)
        rows.append(
            {
                "Ransomware Family": sample_name_from_dir(img_dir),
                "Configuration": configuration_from_dir(img_dir),
                "Suspicious Files": a["suspicious_count"],
                "Deleted Files": a["deleted_count"],
                "Suspicious Names": a["susp_names"],
            }
        )
    df = pd.DataFrame(rows)
    with_virus_df, no_virus_df = split_config(df)
    paired = paired_by_family(df, ["Suspicious Files"])
    comp_df = pd.DataFrame(
        [
            {
                "Ransomware Family": r["Ransomware Family"],
                "WithVirus Suspicious": r["Suspicious Files_with"],
                "NoVirus Suspicious": r["Suspicious Files_no"],
                "Differential": f"+{r['Suspicious Files_with'] - r['Suspicious Files_no']}",
            }
            for _, r in paired.iterrows()
        ]
    )
    print("## 6.4 SUSPICIOUS FILE ANALYSIS (FILESCAN)")
    print(comp_df.to_markdown(index=False))
    print(
        f"WithVirus hits={len(with_virus_df[with_virus_df['Suspicious Files'] > 0])} "
        f"NoVirus hits={len(no_virus_df[no_virus_df['Suspicious Files'] > 0])}"
    )
    ensure_outputs_dir(str(BASE_DIR / "outputs"))
    comp_df.to_csv(BASE_DIR / "outputs" / "filescan_analysis_table.csv", index=False)
    df.to_csv(BASE_DIR / "outputs" / "filescan_full.csv", index=False)


if __name__ == "__main__":
    analyze_filescan_corpus()

