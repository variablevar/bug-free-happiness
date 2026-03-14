#!/usr/bin/env python3
"""
Chapter 6.5 Network Activity and C2 Detection (netscan)
Processes windows.netscan.csv → Table 6.4 + C2 IOC statistics
Exact methodology matching prior chapters (6.2-6.4)
"""

import pandas as pd
from pathlib import Path
import numpy as np
from scipy import stats

DATA_DIR = Path("extracted_data")


def load_netscan(img_dir: Path) -> dict:
    """Load windows.netscan.csv → network metrics."""
    csv_file = img_dir / "windows_netscan.csv"
    if not csv_file.exists():
        return {'connections': 0, 'susp_ports': 0, 'c2_hits': 0}
    
    df = pd.read_csv(csv_file)
    
    total_conns = len(df)
    susp_ports = len(df[df['LocalPort'].isin([80, 443, 4444, 8080, 9001])])
    
    # C2-like: non-RFC ports, .onion, known bad TLDs
    suspicious = df[
        (df['LocalPort'] > 10000) | 
        (df['ForeignAddr'].str.contains(r'\.ru|\.top|\.xyz|tor|onion', na=False))
    ]
    c2_hits = len(suspicious)
    
    return {
        'connections': total_conns,
        'susp_ports': susp_ports,
        'c2_hits': c2_hits
    }


def get_sample_name(img_dir: Path) -> str:
    return img_dir.name.replace('-WithVirus', '').replace('-NoVirus', '')


def analyze_netscan_corpus():
    """Generate Chapter 6.5 table + stats."""
    
    results = []
    for img_dir in DATA_DIR.iterdir():
        if img_dir.is_dir():
            sample_name = get_sample_name(img_dir)
            with_virus = "WithVirus" in img_dir.name
            metrics = load_netscan(img_dir)
            
            results.append({
                'Ransomware Family': sample_name,
                'Configuration': 'WithVirus' if with_virus else 'NoVirus',
                'Total Connections': metrics['connections'],
                'Suspicious Ports': metrics['susp_ports'],
                'C2 Hits': metrics['c2_hits']
            })
    
    df = pd.DataFrame(results)
    with_virus_df = df[df['Configuration'] == 'WithVirus']
    no_virus_df = df[df['Configuration'] == 'NoVirus']
    
    # Comparison table
    comp_table = []
    for sample in with_virus_df['Ransomware Family'].unique():
        try:
            w_c2 = with_virus_df[with_virus_df['Ransomware Family'] == sample]['C2 Hits'].iloc[0]
            nv_c2 = no_virus_df[no_virus_df['Ransomware Family'] == sample]['C2 Hits'].iloc[0]
            comp_table.append({
                'Ransomware Family': sample,
                'WithVirus C2': w_c2,
                'NoVirus C2': nv_c2,
                'Differential': f"+{w_c2-nv_c2}"
            })
        except IndexError:
            continue
    
    comp_df = pd.DataFrame(comp_table)
    
    # Stats
    c2_mean_w = with_virus_df['C2 Hits'].mean()
    c2_mean_nv = no_virus_df['C2 Hits'].mean()
    
    print("## 6.5 NETWORK ACTIVITY AND C2 DETECTION (NETSCAN)")
    print("\n**Key Findings:**")
    print(f"C2 connections in {len(with_virus_df[with_virus_df['C2 Hits'] > 0])} WithVirus samples.")
    
    print("\n**C2 Prevalence by Family:**")
    print(comp_df.to_markdown(index=False))
    
    print("\n**Statistical Summary:**")
    print(f"• Mean C2 hits WithVirus: {c2_mean_w:.1f}")
    print(f"• Mean C2 hits NoVirus: {c2_mean_nv:.1f}")
    
    comp_df.to_csv("outputs/netscan_analysis_table.csv", index=False)
    print(f"\n✅ Exported: outputs/netscan_analysis_table.csv")


if __name__ == "__main__":
    print("🌐 Analyzing netscan for 6.5...")
    analyze_netscan_corpus()
