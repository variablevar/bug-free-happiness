#!/usr/bin/env python3
"""
MSc Memory Forensics: Analyze ALL ransomware CSVs
Compares WithVirus vs NoVirus → Indicators of Compromise
"""

import pandas as pd
from pathlib import Path
import json

DATA_DIR = Path("extracted_data")
SAMPLES = [
    "Cerber",              "Dharma",              "InfinityCrypt",       "PowerLoader",         "W32.MyDoom",
    "DLLHijacking",        "GandCrab",            "Locky.AZ",            "RedTail",             "WannaCry",
    "DeriaLock",           "GoldenEye",           "LuckyLcoker",         "SporaRansomware",     "Win32.BlackWorm",
] 

def load_csv(img_dir: Path, plugin: str) -> pd.DataFrame:
    csv_file = img_dir / f"windows_{plugin.replace('.', '_')}.csv"
    return pd.read_csv(csv_file) if csv_file.exists() else pd.DataFrame()

def compare_samples():
    """Compare WithVirus vs NoVirus for key IOCs."""
    results = {}
    
    for sample in SAMPLES:
        with_virus = DATA_DIR / f"{sample}-WithVirus"
        no_virus = DATA_DIR / f"{sample}-NoVirus"
        
        if not (with_virus.exists() and no_virus.exists()):
            continue
        
        print(f"\n🔬 Analyzing {sample}...")
        
        # Key forensics comparisons
        pslist_v = load_csv(with_virus, "pslist")
        pslist_nv = load_csv(no_virus, "pslist")
        
        malfind_v = load_csv(with_virus, "malfind")
        filescan_v = load_csv(with_virus, "filescan")
        
        iocs = {
            "new_processes": len(pslist_v) - len(pslist_nv),
            "injected_code": len(malfind_v),
            "suspicious_files": len(filescan_v[filescan_v['Name'].str.contains(r'\.(exe|dll|pif)$', na=False)]),
            "hidden_procs": len(load_csv(with_virus, "psscan")) - len(pslist_v)
        }
        results[sample] = iocs
    
    # Export master report
    df_results = pd.DataFrame(results).T
    df_results.to_csv("outputs/ransomware_iocs.csv")
    print("\n📊 Master IOCs:", df_results)

if __name__ == "__main__":
    compare_samples()
