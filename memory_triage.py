#!/usr/bin/env python3
"""
Memory Forensics Triage Script
Usage: python triage.py <folder_with_csvs>
       python triage.py .   (if CSVs are in current directory)
"""

import pandas as pd
import numpy as np
import re, json, sys, os, glob
import plotly.graph_objects as go

# ── File discovery ─────────────────────────────────────────────────────────────
FILE_MAP = {
    "pslist":    ["windows_pslist*.csv"],
    "psscan":    ["windows_psscan*.csv"],
    "pstree":    ["windows_pstree*.csv"],
    "cmdline":   ["windows_cmdline*.csv"],
    "malfind":   ["windows_malfind*.csv"],
    "ssdt":      ["windows_ssdt*.csv"],
    "netscan":   ["windows_netscan*.csv"],
    "dlllist":   ["windows_dlllist*.csv"],
    "handles":   ["windows_handles*.csv"],
    "threads":   ["windows_threads*.csv"],
    "filescan":  ["windows_filescan*.csv"],
    "drvscan":   ["windows_driverscan*.csv"],
    "hivelist":  ["windows_registry_hivelist*.csv"],
    "vadinfo":   ["windows_vadinfo*.csv"],
    "sysinfo":   ["windows_info*.csv"],
}

def find_csv(folder, patterns):
    for pat in patterns:
        hits = glob.glob(os.path.join(folder, pat))
        if hits:
            return hits[0]
    return None

def safe_read(path):
    if path and os.path.exists(path):
        try:
            return pd.read_csv(path, low_memory=False)
        except Exception as e:
            print(f"  [WARN] Could not read {path}: {e}")
    return pd.DataFrame()

def load_all(folder):
    dfs = {}
    for key, patterns in FILE_MAP.items():
        path = find_csv(folder, patterns)
        df = safe_read(path)
        dfs[key] = df
        status = f"{len(df)} rows" if not df.empty else "MISSING"
        print(f"  {'[OK]' if not df.empty else '[MISSING]'} {key}: {status}")
    return dfs

# ── Detection modules ──────────────────────────────────────────────────────────
findings = []

def add(category, severity, pid, process, detail):
    findings.append({"Category": category, "Severity": severity,
                     "PID": pid, "Process": process, "Detail": detail})

def check_malfind(df):
    if df.empty: return
    rwx = df[df["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)]
    for _, r in rwx.iterrows():
        has_mz = "MZ" in str(r.get("Hexdump","")) or "4d5a" in str(r.get("Hexdump","")).lower()
        sev = "Critical" if has_mz else "High"
        add("Malfind: RWX Region", sev, r["PID"], r["Process"],
            f"RWX @ {r['Start VPN']} {'[MZ header]' if has_mz else ''} | {str(r.get('Disasm',''))[:80]}")

def check_ssdt(df):
    if df.empty: return
    legit = ["ntoskrnl", "win32k"]
    hooked = df[~df["Module"].str.lower().str.strip().isin(legit)]
    for _, r in hooked.iterrows():
        add("SSDT Hook", "Critical", "N/A", "kernel",
            f"SSDT[{r['Index']}] hooked by {r['Module']} @ {r['Address']} ({r['Symbol']})")

def check_hidden_processes(pslist, psscan):
    if pslist.empty or psscan.empty: return
    pl_pids = set(pslist["PID"].dropna().astype(int))
    ps_pids = set(psscan["PID"].dropna().astype(int))
    for pid in ps_pids - pl_pids:
        row = psscan[psscan["PID"] == pid].iloc[0]
        add("Hidden Process", "Critical", pid, row["ImageFileName"],
            f"PID {pid} ({row['ImageFileName']}) in psscan but NOT in pslist")

def check_parent_child(pstree):
    if pstree.empty: return
    expected = {
        "smss.exe":     ["system"],
        "csrss.exe":    ["smss.exe"],
        "wininit.exe":  ["smss.exe"],
        "lsass.exe":    ["wininit.exe"],
        "services.exe": ["wininit.exe"],
        "svchost.exe":  ["services.exe"],
        "explorer.exe": ["userinit.exe", "winlogon.exe"],
    }
    pid_to_name = dict(zip(pstree["PID"].dropna().astype(int),
                           pstree["ImageFileName"].str.lower().str.strip()))
    for _, row in pstree.iterrows():
        proc = str(row["ImageFileName"]).lower().strip()
        pid  = int(row["PID"])  if not pd.isna(row["PID"])  else None
        ppid = int(row["PPID"]) if not pd.isna(row["PPID"]) else None
        if proc in expected and ppid is not None:
            parent = pid_to_name.get(ppid, "unknown").lower()
            if parent not in expected[proc]:
                add("Abnormal Parent-Child", "High", pid, proc,
                    f"{proc} (PID {pid}) parent={parent} (PPID {ppid}), expected {expected[proc]}")

def check_cmdline(df):
    if df.empty: return
    patterns = {
        r"-enc\b|-encodedcommand":                          ("Encoded PowerShell",    "Critical"),
        r"iex|invoke-expression|downloadstring|downloadfile":("Fileless Execution",    "Critical"),
        r"mshta|wscript|cscript|regsvr32":                   ("LOLBin",                "High"),
        r"\\temp\\|\\appdata\\|users\\public\\":  ("Temp/Public Execution", "High"),
        r"bypass|windowstyle\s+hidden":                     ("Evasion Flag",          "High"),
        r"net\s+user|net\s+localgroup|whoami|mimikatz":    ("Recon/CredTool",        "Critical"),
    }
    for _, r in df.iterrows():
        args = str(r.get("Args","")).lower()
        proc = str(r.get("Process",""))
        pid  = r.get("PID","?")
        for pat, (label, sev) in patterns.items():
            if re.search(pat, args, re.IGNORECASE):
                add(f"Cmdline: {label}", sev, pid, proc,
                    f"{proc} (PID {pid}): {str(r.get('Args',''))[:120]}")

def check_network(df):
    if df.empty: return
    legit = {"svchost.exe","lsass.exe","System","dns.exe","MsMpEng.exe",
             "iexplore.exe","chrome.exe","firefox.exe","msedge.exe","outlook.exe"}
    private = re.compile(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0)")
    for _, r in df.iterrows():
        foreign = str(r.get("ForeignAddr",""))
        state   = str(r.get("State",""))
        owner   = str(r.get("Owner",""))
        pid     = r.get("PID","?")
        fport   = r.get("ForeignPort",0)
        if state == "ESTABLISHED" and not private.match(foreign) and foreign not in ["*","0.0.0.0",""]:
            sev = "Critical" if owner not in legit else "Medium"
            add("Network: External Connection", sev, pid, owner,
                f"{owner} (PID {pid}) → {foreign}:{fport} [ESTABLISHED]")

def check_dll(df):
    if df.empty: return
    sus = df[df["Path"].str.contains(r"\\temp\\|\\appdata\\|users\\public",
                                     case=False, na=False)]
    for _, r in sus.iterrows():
        add("DLL: Suspicious Path", "High", r["PID"], r["Process"],
            f"DLL from suspicious path: {r['Path']}")

def check_handles(df):
    if df.empty: return
    high_access = {"0x1fffff","0x1f0fff","0x143a"}
    lsass_h = df[(df["Type"]=="Process") &
                 (df["Name"].str.contains("lsass", case=False, na=False))]
    for _, r in lsass_h.iterrows():
        if str(r.get("GrantedAccess","")).lower() in high_access:
            add("Handle: lsass Full Access", "Critical", r["PID"], r["Process"],
                f"{r['Process']} (PID {r['PID']}) → lsass, GrantedAccess={r['GrantedAccess']}")

def check_threads(df):
    if df.empty: return
    sus = df[df["StartPath"].str.contains(r"\\temp\\|\\appdata\\|public",
                                          case=False, na=False)]
    for _, r in sus.iterrows():
        add("Thread: Suspicious StartPath", "High", r["PID"], str(r.get("StartPath",""))[:40],
            f"Thread in PID {r['PID']} starts from {r['StartPath']}")

def check_vad(df):
    if df.empty: return
    rwx = df[(df["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)) &
             (df["PrivateMemory"] == 1) &
             (df["File"].isna() | (df["File"].str.strip() == ""))]
    for _, r in rwx.iterrows():
        add("VAD: RWX Private No File", "High", r["PID"], r["Process"],
            f"RWX private anon VAD @ {r['Start VPN']}-{r['End VPN']} in {r['Process']} PID={r['PID']}")

def check_drivers(df):
    if df.empty: return
    sus = df[df["Service Key"].isna() | (df["Service Key"].str.strip() == "")]
    for _, r in sus.iterrows():
        add("Driver: No Service Key", "Medium", "N/A", str(r.get("Driver Name","")),
            f"Driver '{r['Driver Name']}' at {r['Start']} has no Service Key")

def check_filescan(df):
    if df.empty: return
    sus = df[df["Name"].str.contains(
        r"\\temp\\.*\.(exe|dll|bat|ps1|vbs)|\\users\\public\\.*\.(exe|dll)|recycle",
        case=False, na=False)]
    for _, r in sus.iterrows():
        add("Filescan: Suspicious File", "Medium", "N/A", "filesystem",
            f"Suspicious file in memory: {r['Name']}")

# ── Charts ─────────────────────────────────────────────────────────────────────
def save_charts(df, out_folder):
    try:
        sev_order = ["Critical","High","Medium","Low"]
        colors    = ["#d62728","#ff7f0e","#ffbb78","#aec7e8"]
        sev_counts = df["Severity"].value_counts().reindex(sev_order).fillna(0).astype(int).reset_index()
        sev_counts.columns = ["Severity","Count"]

        fig1 = go.Figure(go.Bar(x=sev_counts["Severity"], y=sev_counts["Count"],
                                marker_color=colors, text=sev_counts["Count"], textposition="outside"))
        fig1.update_layout(title_text="Triage Findings by Severity")
        fig1.update_xaxes(title_text="Severity")
        fig1.update_yaxes(title_text="Count")
        fig1.write_image(os.path.join(out_folder, "findings_by_severity.png"))

        cat_counts = df.groupby("Category").size().reset_index(name="Count").sort_values("Count")
        cat_counts["Short"] = cat_counts["Category"].str[:40]
        fig2 = go.Figure(go.Bar(y=cat_counts["Short"], x=cat_counts["Count"],
                                orientation="h", text=cat_counts["Count"], textposition="outside",
                                marker_color="#1f77b4"))
        fig2.update_layout(title_text="Findings by Category", height=600)
        fig2.update_xaxes(title_text="Count")
        fig2.update_yaxes(title_text="Category")
        fig2.write_image(os.path.join(out_folder, "findings_by_category.png"))

        pid_df = df[df["PID"].astype(str) != "N/A"].copy()
        pid_df["Label"] = pid_df["Process"].astype(str) + " (" + pid_df["PID"].astype(str) + ")"
        top = pid_df.groupby("Label").size().reset_index(name="Count").sort_values("Count", ascending=False).head(10)
        fig3 = go.Figure(go.Bar(y=top["Label"], x=top["Count"], orientation="h",
                                text=top["Count"], textposition="outside", marker_color="#9467bd"))
        fig3.update_layout(title_text="Top Suspicious PIDs", height=500)
        fig3.update_xaxes(title_text="Count")
        fig3.update_yaxes(title_text="Process (PID)")
        fig3.write_image(os.path.join(out_folder, "top_pids.png"))
        print("  Charts saved.")
    except Exception as e:
        print(f"  [WARN] Charts failed: {e}")

# ── Print report ───────────────────────────────────────────────────────────────
def print_report(df):
    sev_order = ["Critical","High","Medium","Low"]
    print("\n" + "="*70)
    print("  MEMORY FORENSICS TRIAGE REPORT")
    print("="*70)
    for sev in sev_order:
        sub = df[df["Severity"]==sev]
        if sub.empty: continue
        print(f"\n{'🔴' if sev=='Critical' else '🟠' if sev=='High' else '🟡'} {sev.upper()} ({len(sub)} findings)")
        print("-"*70)
        for _, r in sub.iterrows():
            print(f"  [{r['Category']}] PID={r['PID']} | {r['Process']}")
            print(f"    → {r['Detail']}")
    print("\n" + "="*70)
    print(f"  TOTAL: {len(df)} findings across {df['Category'].nunique()} categories")
    print("="*70)

# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        print(f"[ERROR] Folder not found: {folder}")
        sys.exit(1)

    print(f"\n[*] Loading CSVs from: {folder}")
    dfs = load_all(folder)

    print("\n[*] Running detection modules...")
    check_malfind(dfs["malfind"])
    check_ssdt(dfs["ssdt"])
    check_hidden_processes(dfs["pslist"], dfs["psscan"])
    check_parent_child(dfs["pstree"])
    check_cmdline(dfs["cmdline"])
    check_network(dfs["netscan"])
    check_dll(dfs["dlllist"])
    check_handles(dfs["handles"])
    check_threads(dfs["threads"])
    check_vad(dfs["vadinfo"])
    check_drivers(dfs["drvscan"])
    check_filescan(dfs["filescan"])

    if not findings:
        print("\n[✓] No suspicious findings detected.")
        return

    df_out = pd.DataFrame(findings)
    df_out["Severity"] = pd.Categorical(df_out["Severity"],
                                        categories=["Critical","High","Medium","Low"], ordered=True)
    df_out = df_out.sort_values("Severity")

    # Save CSV report
    out_csv = os.path.join(folder, "triage_report.csv")
    df_out.to_csv(out_csv, index=False)
    print(f"\n[*] Report saved: {out_csv}")

    # Save charts
    print("[*] Generating charts...")
    save_charts(df_out, folder)

    # Print to terminal
    print_report(df_out)

if __name__ == "__main__":
    main()
