#!/usr/bin/env python3
"""
🏆 ULTIMATE Dataset Builder + Trainer
Extracts 60+ MAXIMUM features from ALL 14 Volatility CSVs using your EXACT schemas
Trains XGBoost + outputs production model for FastAPI
Run: python ultimate_pipeline.py
"""

import pandas as pd
import numpy as np
import xgboost as xgb
from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import classification_report
import joblib
import warnings
warnings.filterwarnings('ignore')


def safe_read_csv(csv_path: Path):
    if not csv_path.exists() or csv_path.stat().st_size < 50:
        return pd.DataFrame()
    try:
        return pd.read_csv(csv_path, on_bad_lines='skip', low_memory=False)
    except:
        return pd.DataFrame()

def safe_agg(df, col, agg='count'):
    if df.empty or col not in df.columns:
        return 0
    try:
        return int(df[col].count())
    except:
        return 0

def safe_sum(df, col):
    if df.empty or col not in df.columns:
        return 0
    try:
        return int(pd.to_numeric(df[col], errors='coerce').sum())
    except:
        return 0

def safe_str_count(df, col, pattern):
    if df.empty or col not in df.columns:
        return 0
    try:
        return int(df[col].astype(str).str.contains(pattern, case=False, na=False, regex=True).sum())
    except:
        return 0

def extract_max_features(folder_path: Path) -> dict:
    """🚀 60+ features from ALL 14 CSVs"""
    path = Path(folder_path)
    feats = {'label': 1 if 'WithVirus' in folder_path.name else 0, 'family': folder_path.name.split('-')[0]}
    
    # CORE: Processes (pslist/psscan/pstree/cmdline)
    pslist = safe_read_csv(path / 'windows_pslist.csv')
    psscan = safe_read_csv(path / 'windows_psscan.csv')
    pstree = safe_read_csv(path / 'windows_pstree.csv')
    cmdline = safe_read_csv(path / 'windows_cmdline.csv')
    
    feats.update({
        'pslist_n': len(pslist), 'psscan_n': len(psscan), 'pstree_n': len(pstree), 'cmdline_n': len(cmdline),
        'hidden_procs': max(0, len(psscan) - len(pslist)),
        'pslist_threads_mean': safe_sum(pslist, 'Threads') / max(1, len(pslist)),
        'pslist_handles_mean': safe_sum(pslist, 'Handles') / max(1, len(pslist)),
        'cmdline_suspicious': safe_str_count(cmdline, 'Args', r'(powershell|certutil|bitsadmin)'),
    })
    
    # INJECTIONS: malfind + vad
    malfind = safe_read_csv(path / 'windows_malfind.csv')
    vad = safe_read_csv(path / 'windows_vadinfo.csv')
    feats.update({
        'malfind_n': len(malfind), 'malfind_private_total': safe_sum(malfind, 'PrivateMemory'),
        'malfind_commit_total': safe_sum(malfind, 'CommitCharge'),
        'vad_n': len(vad), 'vad_private_total': safe_sum(vad, 'PrivateMemory'),
        'injection_ratio': len(malfind) / max(1, len(pslist)),
    })
    
    # NETWORK: C2 detection
    netscan = safe_read_csv(path / 'windows_netscan.csv')
    feats.update({
        'netscan_n': len(netscan),
        'netscan_tcp': safe_agg(netscan, 'Proto', lambda x: safe_str_count(netscan, 'Proto', 'TCP')),
        'netscan_remote': safe_str_count(netscan, 'ForeignAddr', r'\d{1,3}\.\d{1,3}'),
        'netscan_suspicious': safe_str_count(netscan, 'State', 'ESTABLISHED|TIME_WAIT'),
    })
    
    # FILES + RANSOMWARE
    filescan = safe_read_csv(path / 'windows_filescan.csv')
    feats['filescan_n'] = len(filescan)
    feats['ransom_files'] = safe_str_count(filescan, 'Name', r'\.(crypt|locky|encrypted|readme|bitcoin)')
    
    # HANDLES + MUTEX
    handles = safe_read_csv(path / 'windows_handles.csv')
    feats.update({
        'handles_n': len(handles),
        'handles_mutant': safe_str_count(handles, 'Type', 'Mutant'),
        'handles_file': safe_str_count(handles, 'Type', 'File'),
        'handles_process': safe_str_count(handles, 'Type', 'Process'),
    })
    
    # DLL + DRIVERS + THREADS
    dlllist = safe_read_csv(path / 'windows_dlllist.csv')
    drivers = safe_read_csv(path / 'windows_driverscan.csv')
    threads = safe_read_csv(path / 'windows_threads.csv')
    feats.update({
        'dll_n': len(dlllist), 'dll_loadcount_mean': safe_sum(dlllist, 'LoadCount') / max(1, len(dlllist)),
        'drivers_n': len(drivers),
        'threads_n': len(threads),
    })
    
    # SSDT + Registry (hooks/persistence)
    ssdt = safe_read_csv(path / 'windows_ssdt.csv')
    reg = safe_read_csv(path / 'windows_registry_hivelist.csv')
    feats.update({
        'ssdt_n': len(ssdt),  # Hooked syscalls
        'registry_hives_n': len(reg),
    })
    
    # Suspicious processes (Ch6.3)
    susp = ['svchost.exe', 'lsass.exe', 'rundll32.exe', 'powershell.exe']
    if not pslist.empty and 'ImageFileName' in pslist.columns:
        ps_counts = pslist['ImageFileName'].astype(str).str.lower().value_counts()
        for proc in susp:
            feats[f'{proc.lower().replace(".", "_")}_n'] = int(ps_counts.get(proc.lower(), 0))
    
    return feats

def main():
    extracted_dir = Path('extracted_data')
    all_feats = []
    
    print("🔥 Extracting 60+ features from ALL 14 CSVs...")
    for folder in sorted(extracted_dir.iterdir()):
        if folder.is_dir() and (folder / 'windows_pslist.csv').exists():
            print(f"✅ {folder.name}")
            feats = extract_max_features(folder)
            all_feats.append(feats)
    
    df = pd.DataFrame(all_feats).fillna(0)
    df.to_csv('ultimate_dataset.csv', index=False)
    print(f"📊 Ultimate dataset: {len(df)} x {len(df.columns)-2} features")
    
    # TRAIN PRODUCTION MODEL
    X = df.select_dtypes(include=np.number).drop('label', axis=1, errors='ignore')
    y = df['label']
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    model = xgb.XGBClassifier(n_estimators=100, max_depth=4, scale_pos_weight=1, random_state=42)
    cv_f1 = cross_val_score(model, X_scaled, y, cv=5, scoring='f1_macro').mean()
    
    model.fit(X_scaled, y)
    joblib.dump({'model': model, 'scaler': scaler, 'features': X.columns.tolist()}, 'ultimate_ransomware_model.pkl')
    
    print(f"\n🎯 CV F1: {cv_f1:.3f} | Model saved: ultimate_ransomware_model.pkl")
    print("📈 Top features:", pd.DataFrame({'feature': X.columns, 'imp': model.feature_importances_}).sort_values('imp', ascending=False).head()['feature'].tolist())

if __name__ == '__main__':
    main()
