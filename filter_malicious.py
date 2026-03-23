#!/usr/bin/env python3
"""
Script 1: filter_malicious.py
Loads all Volatility CSVs, applies triage rules, and outputs
filtered_malicious.json — only the rows/entities flagged as suspicious.
Usage: python filter_malicious.py <csv_folder>
"""

import os, sys, re, json, glob
import pandas as pd

# ── Helpers ───────────────────────────────────────────────────────────────────
def find(folder, pattern):
    hits = glob.glob(os.path.join(folder, pattern))
    return hits[0] if hits else None

def load(folder, pattern):
    p = find(folder, pattern)
    if p:
        try:
            df = pd.read_csv(p, low_memory=False)
            print(f"  [OK] {os.path.basename(p)}: {len(df)} rows")
            return df
        except Exception as e:
            print(f"  [WARN] {pattern}: {e}")
    else:
        print(f"  [MISSING] {pattern}")
    return pd.DataFrame()

PRIVATE_IP = re.compile(
    r"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|::1|0\\.0\\.0\\.0|\\*)"
)
LEGIT_NET  = {"svchost.exe","System","dns.exe","MsMpEng.exe",
              "chrome.exe","firefox.exe","msedge.exe","iexplore.exe"}
LEGIT_SSDT = {"ntoskrnl","win32k"}
EXPECTED_PARENTS = {
    "smss.exe":     ["system"],
    "csrss.exe":    ["smss.exe"],
    "wininit.exe":  ["smss.exe"],
    "lsass.exe":    ["wininit.exe"],
    "services.exe": ["wininit.exe"],
    "svchost.exe":  ["services.exe"],
    "explorer.exe": ["userinit.exe","winlogon.exe"],
}
CMDLINE_RULES = {
    r"-enc\\b|-encodedcommand":                           "EncodedPowerShell",
    r"iex|invoke-expression|downloadstring|downloadfile": "FilelessExec",
    r"mshta|wscript|cscript|regsvr32":                   "LOLBin",
    r"\\\\temp\\\\|\\\\appdata\\\\|users\\\\public\\\\":  "SuspiciousPath",
    r"bypass|windowstyle\\s+hidden":                     "EvasionFlag",
    r"net\\s+user|net\\s+localgroup|whoami|mimikatz":    "ReconTool",
}

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    folder = os.path.abspath(folder)
    print(f"\\n[*] Loading CSVs from: {folder}")

    pslist  = load(folder, "windows_pslist*.csv")
    psscan  = load(folder, "windows_psscan*.csv")
    pstree  = load(folder, "windows_pstree*.csv")
    malfind = load(folder, "windows_malfind*.csv")
    ssdt    = load(folder, "windows_ssdt*.csv")
    netscan = load(folder, "windows_netscan*.csv")
    cmdline = load(folder, "windows_cmdline*.csv")
    dlllist = load(folder, "windows_dlllist*.csv")
    handles = load(folder, "windows_handles*.csv")
    threads = load(folder, "windows_threads*.csv")
    vadinfo = load(folder, "windows_vadinfo*.csv")
    drvscan = load(folder, "windows_driverscan*.csv")

    suspicious_pids = set()
    result = {
        "suspicious_processes": [],
        "hidden_processes":     [],
        "malfind_regions":      [],
        "ssdt_hooks":           [],
        "network_suspicious":   [],
        "cmdline_suspicious":   [],
        "dll_suspicious":       [],
        "handle_suspicious":    [],
        "thread_suspicious":    [],
        "vad_suspicious":       [],
        "driver_suspicious":    [],
        "abnormal_parents":     [],
    }

    # 1. Hidden processes
    if not pslist.empty and not psscan.empty:
        pl_pids = set(pslist["PID"].dropna().astype(int))
        ps_pids = set(psscan["PID"].dropna().astype(int))
        for pid in ps_pids - pl_pids:
            row = psscan[psscan["PID"]==pid].iloc[0].to_dict()
            row["_reason"] = "hidden_from_pslist"
            result["hidden_processes"].append(row)
            suspicious_pids.add(int(pid))

    # 2. Malfind RWX
    if not malfind.empty:
        rwx = malfind[malfind["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)]
        for _, r in rwx.iterrows():
            row = r.to_dict()
            row["_has_mz"] = "MZ" in str(r.get("Hexdump","")) or "4d5a" in str(r.get("Hexdump","")).lower()
            row["_severity"] = "Critical" if row["_has_mz"] else "High"
            result["malfind_regions"].append(row)
            suspicious_pids.add(int(r["PID"]))

    # 3. SSDT hooks
    if not ssdt.empty:
        hooked = ssdt[~ssdt["Module"].str.lower().str.strip().isin(LEGIT_SSDT)]
        for _, r in hooked.iterrows():
            row = r.to_dict(); row["_severity"] = "Critical"
            result["ssdt_hooks"].append(row)

    # 4. Abnormal parent-child
    if not pstree.empty:
        pid_to_name = dict(zip(pstree["PID"].dropna().astype(int),
                               pstree["ImageFileName"].str.lower().str.strip()))
        for _, r in pstree.iterrows():
            proc = str(r["ImageFileName"]).lower().strip()
            try:
                pid  = int(r["PID"]); ppid = int(r["PPID"])
            except: continue
            if proc in EXPECTED_PARENTS:
                parent = pid_to_name.get(ppid, "unknown").lower()
                if parent not in EXPECTED_PARENTS[proc]:
                    row = r.to_dict()
                    row["_actual_parent"] = parent
                    row["_expected"]      = EXPECTED_PARENTS[proc]
                    row["_severity"]      = "High"
                    result["abnormal_parents"].append(row)
                    suspicious_pids.add(pid)

    # 5. Suspicious network
    if not netscan.empty:
        for _, r in netscan.iterrows():
            foreign = str(r.get("ForeignAddr",""))
            state   = str(r.get("State",""))
            owner   = str(r.get("Owner",""))
            if state=="ESTABLISHED" and not PRIVATE_IP.match(foreign):
                row = r.to_dict()
                row["_severity"] = "Critical" if owner not in LEGIT_NET else "Medium"
                result["network_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except: pass

    # 6. Cmdline
    if not cmdline.empty:
        for _, r in cmdline.iterrows():
            args = str(r.get("Args","")).lower()
            triggered = []
            for pat, label in CMDLINE_RULES.items():
                if re.search(pat, args, re.IGNORECASE):
                    triggered.append(label)
            if triggered:
                row = r.to_dict()
                row["_triggered_rules"] = triggered
                row["_severity"] = "Critical" if any(x in triggered for x in
                    ["EncodedPowerShell","FilelessExec","ReconTool"]) else "High"
                result["cmdline_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except: pass

    # 7. Suspicious DLLs
    if not dlllist.empty:
        sus = dlllist[dlllist["Path"].str.contains(
            r"\\\\temp\\\\|\\\\appdata\\\\|users\\\\public", case=False, na=False)]
        for _, r in sus.iterrows():
            row = r.to_dict(); row["_severity"] = "High"
            result["dll_suspicious"].append(row)
            suspicious_pids.add(int(r["PID"]))

    # 8. Handles → lsass full access
    if not handles.empty:
        HIGH_ACCESS = {"0x1fffff","0x1f0fff","0x143a"}
        lsass_h = handles[(handles["Type"]=="Process") &
                          (handles["Name"].str.contains("lsass", case=False, na=False))]
        for _, r in lsass_h.iterrows():
            if str(r.get("GrantedAccess","")).lower() in HIGH_ACCESS:
                row = r.to_dict(); row["_severity"] = "Critical"
                result["handle_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except: pass

    # 9. Suspicious threads
    if not threads.empty:
        sus = threads[threads["StartPath"].str.contains(
            r"\\\\temp\\\\|\\\\appdata\\\\|public", case=False, na=False)]
        for _, r in sus.iterrows():
            row = r.to_dict(); row["_severity"] = "High"
            result["thread_suspicious"].append(row)
            suspicious_pids.add(int(r["PID"]))

    # 10. VAD RWX private
    if not vadinfo.empty:
        vad_rwx = vadinfo[(vadinfo["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)) &
                          (vadinfo["PrivateMemory"]==1) &
                          (vadinfo["File"].isna() | (vadinfo["File"].str.strip()==""))]
        for _, r in vad_rwx.iterrows():
            row = r.to_dict(); row["_severity"] = "High"
            result["vad_suspicious"].append(row)
            suspicious_pids.add(int(r["PID"]))

    # 11. Drivers with no service key
    if not drvscan.empty:
        sus = drvscan[drvscan["Service Key"].isna() | (drvscan["Service Key"].str.strip()=="")]
        for _, r in sus.iterrows():
            row = r.to_dict(); row["_severity"] = "Medium"
            result["driver_suspicious"].append(row)

    # 12. Suspicious processes (cross-ref by collected PIDs)
    if not pstree.empty:
        for pid in suspicious_pids:
            rows = pstree[pstree["PID"]==pid]
            if not rows.empty:
                result["suspicious_processes"].append(rows.iloc[0].to_dict())

    # Output
    result["_meta"] = {
        "total_suspicious_pids": len(suspicious_pids),
        "suspicious_pids": sorted(list(suspicious_pids)),
    }

    out_path = os.path.join(folder, "filtered_malicious.json")
    # Convert NaN to None for JSON serialization
    def clean(obj):
        if isinstance(obj, dict):
            return {k: clean(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [clean(i) for i in obj]
        if isinstance(obj, float) and str(obj) == "nan":
            return None
        return obj

    with open(out_path, "w") as f:
        json.dump(clean(result), f, indent=2, default=str)

    print(f"\\n[✅] Suspicious PIDs found: {len(suspicious_pids)}")
    for k, v in result.items():
        if k.startswith("_"): continue
        print(f"  {k}: {len(v)} entries")
    print(f"\\n[💾] Saved: {out_path}")

if __name__ == "__main__":
    main()