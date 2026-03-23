#!/usr/bin/env python3
"""
filter_malicious.py  (MalVol-25 aware, v3 — behaviour-based, 0-day ready)
Loads Volatility CSVs, applies behaviour-based triage (no hardcoded names),
and outputs filtered_malicious.json.

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

def clean(obj):
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean(i) for i in obj]
    if isinstance(obj, float) and str(obj) in ("nan", "inf", "-inf"):
        return None
    return obj

def col(df, candidates):
    """Return first matching column name from candidates list."""
    for c in candidates:
        if c in df.columns:
            return c
    # case-insensitive fallback
    low = {x.lower(): x for x in df.columns}
    for c in candidates:
        if c.lower() in low:
            return low[c.lower()]
    return None


# ── Constants ─────────────────────────────────────────────────────────────────
PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|\*|-$)"
)

# Browsers / update agents — allowed to make external connections
LEGIT_NET_OWNERS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "svchost.exe", "system", "dns.exe", "msmpeng.exe", "onedrive.exe",
    "microsoftedgeupdate.exe", "wuauclt.exe", "taskhostw.exe",
}

# LOLBins — should NEVER make external network connections
LOLBIN_NET = {
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "certutil.exe", "powershell.exe",
    "cmd.exe", "bitsadmin.exe", "wmic.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
}

# Windows processes that legitimately hold full lsass handles
LSASS_WHITELIST = {
    "csrss.exe", "wininit.exe", "lsass.exe", "werfault.exe",
    "services.exe", "winlogon.exe", "taskmgr.exe", "msmpeng.exe",
    "msseces.exe", "antimalware service executable",
}

LEGIT_SSDT = {"ntoskrnl", "win32k"}

EXPECTED_PARENTS = {
    "smss.exe":     ["system"],
    "csrss.exe":    ["smss.exe"],
    "wininit.exe":  ["smss.exe"],
    "lsass.exe":    ["wininit.exe"],
    "services.exe": ["wininit.exe"],
    "svchost.exe":  ["services.exe"],
    "explorer.exe": ["userinit.exe", "winlogon.exe"],
}

HIGH_ACCESS_MASKS = {"0x1fffff", "0x1f0fff", "0x143a"}

RANSOM_NOTE_RE = re.compile(
    r"readme|recover|decrypt|ransom|creadthis|help_recover|how_to|your_files",
    re.IGNORECASE,
)

SHELLCODE_EB_RE = re.compile(r"(eb\s+[0-9a-f]{2}\s+){3,}", re.IGNORECASE)

CMDLINE_RULES = {
    r"-enc\b|-encodedcommand":                            "EncodedPowerShell",
    r"iex|invoke-expression|downloadstring|downloadfile": "FilelessExec",
    r"mshta|wscript|cscript|regsvr32":                   "LOLBin",
    r"\\\\temp\\\\|\\\\appdata\\\\|users\\\\public\\\\":  "SuspiciousPath",
    r"bypass|windowstyle\s+hidden":                       "EvasionFlag",
    r"net\s+user|net\s+localgroup|whoami|mimikatz":       "ReconTool",
    RANSOM_NOTE_RE.pattern:                               "RansomNote",
}

# Suspicion scoring thresholds
SUSPICION_THRESHOLD = 4   # score >= 4  → flagged
SEV_CRITICAL        = 9   # score >= 9  → Critical
SEV_HIGH            = 6   # score >= 6  → High  (else Medium)


# ── Behaviour-based process scorer (0-day ready) ──────────────────────────────
def score_process(pid, malfind_pids, net_lolbin_pids, handle_pids,
                  abnormal_pids, cmdline_pids, hidden_pids):
    score   = 0
    reasons = []

    if pid in hidden_pids:
        score += 5; reasons.append("hidden_from_pslist")

    if pid in malfind_pids:
        score += 4; reasons.append("rwx_injection")

    if pid in net_lolbin_pids:
        score += 4; reasons.append("lolbin_network")

    if pid in handle_pids:
        score += 3; reasons.append("lsass_full_access")

    if pid in abnormal_pids:
        score += 3; reasons.append("abnormal_parent")

    if pid in cmdline_pids:
        score += 2; reasons.append("suspicious_cmdline")

    # Combo bonuses
    if "rwx_injection" in reasons and "lolbin_network" in reasons:
        score += 3; reasons.append("inject_then_c2_combo")

    if "hidden_from_pslist" in reasons and len(reasons) > 1:
        score += 2; reasons.append("hidden_plus_activity")

    if "rwx_injection" in reasons and "lsass_full_access" in reasons:
        score += 2; reasons.append("inject_plus_lsass_dump")

    return score, reasons


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(f"\n[*] Loading CSVs from: {folder}")

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
        "behavioural_suspects": [],   # replaces hardcoded ransomware names
    }

    # ── 1. Hidden processes ───────────────────────────────────────────────────
    if not pslist.empty and not psscan.empty:
        pl_pids = set(pslist["PID"].dropna().astype(int))
        ps_pids = set(psscan["PID"].dropna().astype(int))
        for pid in ps_pids - pl_pids:
            row = psscan[psscan["PID"] == pid].iloc[0].to_dict()
            row["_reason"] = "hidden_from_pslist"
            result["hidden_processes"].append(row)
            suspicious_pids.add(int(pid))

    # ── 2. Malfind RWX regions ────────────────────────────────────────────────
    if not malfind.empty:
        rwx = malfind[malfind["Protection"].str.contains(
            "PAGE_EXECUTE_READWRITE", na=False)]
        for _, r in rwx.iterrows():
            hexdump = str(r.get("Hexdump", ""))
            disasm  = str(r.get("Disasm",  ""))
            has_mz        = "MZ" in hexdump or "4d5a" in hexdump.lower()
            has_shellcode = bool(SHELLCODE_EB_RE.search(disasm))
            row = r.to_dict()
            row["_has_mz"]        = has_mz
            row["_has_shellcode"] = has_shellcode
            row["_severity"]      = (
                "Critical" if has_mz else
                "High"     if has_shellcode else
                "Medium"
            )
            result["malfind_regions"].append(row)
            try: suspicious_pids.add(int(r["PID"]))
            except Exception: pass

    # ── 3. SSDT hooks ─────────────────────────────────────────────────────────
    if not ssdt.empty:
        mod_col = col(ssdt, ["Module", "Owner", "Symbol"])
        if mod_col:
            hooked = ssdt[~ssdt[mod_col].str.lower().str.strip().str.contains(
                "|".join(LEGIT_SSDT), na=False)]
            for _, r in hooked.iterrows():
                row = r.to_dict(); row["_severity"] = "Critical"
                result["ssdt_hooks"].append(row)

    # ── 4. Abnormal parent-child ──────────────────────────────────────────────
    if not pstree.empty:
        name_col = col(pstree, ["Process", "ImageFileName", "Name"])
        if name_col:
            pid_to_name = dict(zip(
                pstree["PID"].dropna().astype(int),
                pstree[name_col].str.lower().str.strip()
            ))
            abnormal_pids_local = set()
            for _, r in pstree.iterrows():
                proc = str(r.get(name_col, "")).lower().strip()
                try:
                    pid  = int(r["PID"])
                    ppid = int(r["PPID"])
                except Exception:
                    continue
                if proc in EXPECTED_PARENTS:
                    parent = pid_to_name.get(ppid, "unknown").lower()
                    if parent not in EXPECTED_PARENTS[proc]:
                        row = r.to_dict()
                        row["_actual_parent"] = parent
                        row["_expected"]      = EXPECTED_PARENTS[proc]
                        row["_severity"]      = "High"
                        result["abnormal_parents"].append(row)
                        suspicious_pids.add(pid)
                        abnormal_pids_local.add(pid)

    # ── 5. Suspicious network ─────────────────────────────────────────────────
    net_lolbin_pids_local = set()
    if not netscan.empty:
        for _, r in netscan.iterrows():
            foreign = str(r.get("ForeignAddr", "")).strip()
            state   = str(r.get("State",       "")).strip()
            owner   = str(r.get("Owner",       "")).strip().lower()
            if state != "ESTABLISHED":
                continue
            is_public      = foreign not in ("", "-", "*") and \
                             not PRIVATE_IP.match(foreign)
            is_lolbin      = owner in LOLBIN_NET
            is_non_browser = is_public and owner not in LEGIT_NET_OWNERS

            if is_lolbin or is_non_browser:
                row = r.to_dict()
                row["_is_lolbin_c2"] = is_lolbin
                row["_severity"]     = "Critical" if is_lolbin else "High"
                result["network_suspicious"].append(row)
                try:
                    pid = int(r["PID"])
                    suspicious_pids.add(pid)
                    if is_lolbin:
                        net_lolbin_pids_local.add(pid)
                except Exception:
                    pass

    # ── 6. Cmdline rules ──────────────────────────────────────────────────────
    cmdline_pids_local = set()
    if not cmdline.empty:
        args_col = col(cmdline, ["Args", "Cmdline", "CommandLine"])
        if args_col:
            for _, r in cmdline.iterrows():
                args = str(r.get(args_col, "")).lower()
                triggered = [label for pat, label in CMDLINE_RULES.items()
                             if re.search(pat, args, re.IGNORECASE)]
                if triggered:
                    row = r.to_dict()
                    row["_triggered_rules"] = triggered
                    row["_severity"] = (
                        "Critical" if any(x in triggered for x in
                            ["EncodedPowerShell", "FilelessExec",
                             "ReconTool", "RansomNote"])
                        else "High"
                    )
                    result["cmdline_suspicious"].append(row)
                    try:
                        pid = int(r["PID"])
                        suspicious_pids.add(pid)
                        cmdline_pids_local.add(pid)
                    except Exception:
                        pass

    # ── 7. Suspicious DLLs ────────────────────────────────────────────────────
    if not dlllist.empty:
        path_col = col(dlllist, ["Path", "FullPath", "Mapped Path"])
        if path_col:
            sus = dlllist[dlllist[path_col].str.contains(
                r"\\temp\\|\\appdata\\|users\\public",
                case=False, na=False)]
            for _, r in sus.iterrows():
                row = r.to_dict(); row["_severity"] = "High"
                result["dll_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except Exception: pass

    # ── 8. Handles → unexpected lsass full access ─────────────────────────────
    handle_pids_local = set()
    if not handles.empty:
        name_col_h  = col(handles, ["Process", "ImageFile", "Name"])
        type_col_h  = col(handles, ["Type"])
        hname_col_h = col(handles, ["HandleName", "Name", "Detail"])
        ga_col_h    = col(handles, ["GrantedAccess", "Granted Access"])

        if all([type_col_h, hname_col_h, ga_col_h]):
            lsass_h = handles[
                (handles[type_col_h] == "Process") &
                (handles[hname_col_h].str.contains("lsass", case=False, na=False))
            ]
            for _, r in lsass_h.iterrows():
                access    = str(r.get(ga_col_h, "")).lower().strip()
                proc_name = str(r.get(name_col_h, "")).lower().strip() \
                            if name_col_h else ""
                if access not in HIGH_ACCESS_MASKS:
                    continue
                if proc_name in LSASS_WHITELIST:
                    continue
                row = r.to_dict(); row["_severity"] = "Critical"
                result["handle_suspicious"].append(row)
                try:
                    pid = int(r["PID"])
                    suspicious_pids.add(pid)
                    handle_pids_local.add(pid)
                except Exception:
                    pass

    # ── 9. Suspicious threads ─────────────────────────────────────────────────
    if not threads.empty:
        path_col_t = col(threads, ["StartPath", "Start Address"])
        if path_col_t:
            sus = threads[threads[path_col_t].str.contains(
                r"\\temp\\|\\appdata\\|public", case=False, na=False)]
            for _, r in sus.iterrows():
                row = r.to_dict(); row["_severity"] = "High"
                result["thread_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except Exception: pass

    # ── 10. VAD RWX private ───────────────────────────────────────────────────
    if not vadinfo.empty:
        file_col_v = col(vadinfo, ["File", "Mapped File", "Filename"])
        if file_col_v and "Protection" in vadinfo.columns \
                       and "PrivateMemory" in vadinfo.columns:
            vad_rwx = vadinfo[
                (vadinfo["Protection"].str.contains(
                    "PAGE_EXECUTE_READWRITE", na=False)) &
                (vadinfo["PrivateMemory"] == 1) &
                (vadinfo[file_col_v].isna() |
                 vadinfo[file_col_v].astype(str).str.strip().isin(
                     ["", "N/A", "nan", "Disabled"]))
            ]
            for _, r in vad_rwx.iterrows():
                row = r.to_dict(); row["_severity"] = "High"
                result["vad_suspicious"].append(row)
                try: suspicious_pids.add(int(r["PID"]))
                except Exception: pass

    # ── 11. Drivers with no service key ──────────────────────────────────────
    if not drvscan.empty:
        svc_col = col(drvscan, ["Service Key", "ServiceKey", "Service"])
        if svc_col:
            sus = drvscan[
                drvscan[svc_col].isna() |
                (drvscan[svc_col].astype(str).str.strip() == "")
            ]
            for _, r in sus.iterrows():
                row = r.to_dict(); row["_severity"] = "Medium"
                result["driver_suspicious"].append(row)

    # ── 12. Behaviour-based process scoring (0-day ready) ────────────────────
    # Scores every process purely on WHAT IT DOES, not what it's named.
    # A 0-day named svchost.exe still gets caught if it injects + calls C2.
    malfind_pids_set  = {int(r["PID"]) for r in result["malfind_regions"]}
    hidden_pids_set   = {int(r["PID"]) for r in result["hidden_processes"]}
    abnormal_pids_set = set(suspicious_pids) & \
                        {int(r["PID"]) for r in result["abnormal_parents"]}

    df_procs = pstree if not pstree.empty else pslist
    name_col_p = col(df_procs, ["Process", "ImageFileName", "Name"])

    seen_scored = set()
    for _, r in df_procs.iterrows():
        try:
            pid = int(r["PID"])
        except Exception:
            continue
        if pid in seen_scored:
            continue
        seen_scored.add(pid)

        proc_name = str(r.get(name_col_p, "")).lower().strip() \
                    if name_col_p else ""

        score, reasons = score_process(
            pid,
            malfind_pids_set,
            net_lolbin_pids_local,
            handle_pids_local,
            abnormal_pids_set,
            cmdline_pids_local,
            hidden_pids_set,
        )

        if score >= SUSPICION_THRESHOLD:
            row = r.to_dict()
            row["_suspicion_score"] = score
            row["_reasons"]         = reasons
            row["_severity"]        = (
                "Critical" if score >= SEV_CRITICAL else
                "High"     if score >= SEV_HIGH      else
                "Medium"
            )
            result["behavioural_suspects"].append(row)
            suspicious_pids.add(pid)

    # ── 13. Collect all suspicious processes for summary ─────────────────────
    if not df_procs.empty and name_col_p:
        seen = set()
        for pid in suspicious_pids:
            rows = df_procs[df_procs["PID"] == pid]
            if not rows.empty and pid not in seen:
                result["suspicious_processes"].append(rows.iloc[0].to_dict())
                seen.add(pid)

    # ── 14. Build graph_attr for dataset.py ───────────────────────────────────
    graph_attr = {
        "max_process_score": max(
            (r["_suspicion_score"] for r in result["behavioural_suspects"]),
            default=0
        ),
        "attack_steps": sum([
            1 if result["malfind_regions"]      else 0,
            1 if result["network_suspicious"]   else 0,
            1 if result["handle_suspicious"]    else 0,
            1 if result["hidden_processes"]     else 0,
            1 if result["abnormal_parents"]     else 0,
        ]),
        "high_severity_injections": sum(
            1 for r in result["malfind_regions"]
            if r.get("_severity") in ("Critical", "High")
        ),
        "lolbin_c2_connections": sum(
            1 for r in result["network_suspicious"]
            if r.get("_is_lolbin_c2")
        ),
        "ransom_note_signal": 1 if any(
            "RansomNote" in r.get("_triggered_rules", [])
            for r in result["cmdline_suspicious"]
        ) else 0,
    }

    label_signals = {
        "behavioural_suspects_found": len(result["behavioural_suspects"]) > 0,
        "lolbin_c2_found":            graph_attr["lolbin_c2_connections"] > 0,
        "ransom_note_found":          graph_attr["ransom_note_signal"] == 1,
        "rwx_injections":             len(result["malfind_regions"]),
        "hidden_processes":           len(result["hidden_processes"]),
        "top_suspect_score":          graph_attr["max_process_score"],
    }

    result["_meta"] = {
        "total_suspicious_pids": len(suspicious_pids),
        "suspicious_pids":       sorted(list(suspicious_pids)),
        "graph_attr":            graph_attr,
        "label_signals":         label_signals,
    }

    # ── Output ────────────────────────────────────────────────────────────────
    out_path = os.path.join(folder, "filtered_malicious.json")
    with open(out_path, "w") as f:
        json.dump(clean(result), f, indent=2, default=str)

    print(f"\n[✅] Suspicious PIDs: {len(suspicious_pids)}")
    for k, v in result.items():
        if k.startswith("_"):
            continue
        print(f"  {k}: {len(v)} entries")

    print(f"\n  graph_attr (for dataset.py):")
    for k, v in graph_attr.items():
        print(f"    {k}: {v}")

    print(f"\n  label_signals:")
    for k, v in label_signals.items():
        print(f"    {k}: {v}")

    print(f"\n[💾] Saved: {out_path}")


if __name__ == "__main__":
    main()