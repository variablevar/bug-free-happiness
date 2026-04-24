#!/usr/bin/env python3
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pandas as pd

from ioc_analysis.csv_loader import load_windows_plugin_csv
from ioc_analysis.common import ensure_outputs_dir

DATA_DIR = BASE_DIR / "extracted_data"
SAMPLES = [
    "Cerber", "Dharma", "InfinityCrypt", "PowerLoader", "W32.MyDoom",
    "DLLHijacking", "GandCrab", "Locky.AZ", "RedTail", "WannaCry",
    "DeriaLock", "GoldenEye", "LuckyLcoker", "SporaRansomware", "Win32.BlackWorm",
]


def compare_samples():
    results = {}
    for sample in SAMPLES:
        with_virus = DATA_DIR / f"{sample}-WithVirus"
        no_virus = DATA_DIR / f"{sample}-NoVirus"
        if not (with_virus.exists() and no_virus.exists()):
            continue
        pslist_v = load_windows_plugin_csv(with_virus, "pslist")
        pslist_nv = load_windows_plugin_csv(no_virus, "pslist")
        malfind_v = load_windows_plugin_csv(with_virus, "malfind")
        filescan_v = load_windows_plugin_csv(with_virus, "filescan")
        iocs = {
            "new_processes": len(pslist_v) - len(pslist_nv),
            "injected_code": len(malfind_v),
            "suspicious_files": len(filescan_v[filescan_v["Name"].str.contains(r"\.(exe|dll|pif)$", na=False)]),
            "hidden_procs": len(load_windows_plugin_csv(with_virus, "psscan")) - len(pslist_v),
        }
        results[sample] = iocs
    df_results = pd.DataFrame(results).T
    ensure_outputs_dir(str(BASE_DIR / "outputs"))
    out_path = BASE_DIR / "outputs" / "ransomware_iocs.csv"
    df_results.to_csv(out_path)
    print("\n📊 Master IOCs:", df_results)
    print(f"\n✅ Exported: {out_path}")


if __name__ == "__main__":
    compare_samples()

