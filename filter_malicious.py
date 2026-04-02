#!/usr/bin/env python3
"""
filter_malicious.py  (MalVol-25 aware, v4 — graph.pkl input, 0-day ready)

Drops the CSV pipeline entirely. Reads the NetworkX graph produced by
build_graph.py (graph.pkl) and applies the same behaviour-based triage.

Node types consumed:
  process       — pid, ppid, label, in_pslist, in_psscan, heuristic_score,
                  suspicion_reasons, args, session_id, wow64
  memory_region — pid, protection, private_memory, backing_file,
                  has_mz_header, has_shellcode, disasm, source (malfind/vadinfo)
  network_conn  — pid, owner, foreign_addr, foreign_port, state,
                  is_external, is_lolbin_c2, proto
  handle        — pid, handle_type, name, granted_access, is_suspicious
  thread        — pid, tid, start_address, start_path, is_suspicious
  driver        — driver_name, service_key
  ssdt          — symbol, module, address

Usage:
  python filter_malicious.py <graph.pkl|sample_folder>
Output:
  filtered_malicious.json  (same folder as graph.pkl)
"""

import os, sys, re, json, math, pickle
import networkx as nx


# ── Constants ─────────────────────────────────────────────────────────────────
PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|\*|-$)"
)

LEGIT_NET_OWNERS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "svchost.exe", "system", "dns.exe", "msmpeng.exe", "onedrive.exe",
    "microsoftedgeupdate.exe", "wuauclt.exe", "taskhostw.exe",
}

LOLBIN_NET = {
    "mshta.exe", "wscript.exe", "cscript.exe", "regsvr32.exe",
    "rundll32.exe", "msiexec.exe", "certutil.exe", "powershell.exe",
    "cmd.exe", "bitsadmin.exe", "wmic.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
}

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
    r"-enc\b|-encodedcommand":                             "EncodedPowerShell",
    r"iex|invoke-expression|downloadstring|downloadfile":  "FilelessExec",
    r"mshta|wscript|cscript|regsvr32":                    "LOLBin",
    r"\\\\temp\\\\|\\\\appdata\\\\|users\\\\public\\\\":   "SuspiciousPath",
    r"bypass|windowstyle\s+hidden":                        "EvasionFlag",
    r"net\s+user|net\s+localgroup|whoami|mimikatz":        "ReconTool",
    RANSOM_NOTE_RE.pattern:                                "RansomNote",
}

SUSPICION_THRESHOLD = 4
SEV_CRITICAL        = 9
SEV_HIGH            = 6


# ── Helpers ───────────────────────────────────────────────────────────────────
def safe_int(v, default=0):
    try: return int(v)
    except Exception: return default

def safe_str(v):
    return "" if (v is None or (isinstance(v, float) and math.isnan(v))) else str(v)

def clean(obj):
    if isinstance(obj, dict):
        return {k: clean(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [clean(i) for i in obj]
    if isinstance(obj, float) and str(obj) in ("nan", "inf", "-inf"):
        return None
    return obj

def nodes_of_type(G, t):
    return [(n, d) for n, d in G.nodes(data=True) if d.get("node_type") == t]

def load_graph(path):
    if os.path.isdir(path):
        candidate = os.path.join(path, "graph.pkl")
        if not os.path.exists(candidate):
            print(f"[ERROR] graph.pkl not found in {path}"); sys.exit(1)
        path = candidate
    if not os.path.exists(path):
        print(f"[ERROR] Not found: {path}"); sys.exit(1)
    with open(path, "rb") as f:
        G = pickle.load(f)
    if not isinstance(G, nx.Graph):
        print("[ERROR] Pickle does not contain a NetworkX graph."); sys.exit(1)
    return G, os.path.dirname(os.path.abspath(path))


# ── Behaviour-based process scorer ────────────────────────────────────────────
def score_process(pid, malfind_pids, net_lolbin_pids, handle_pids,
                  abnormal_pids, cmdline_pids, hidden_pids):
    score, reasons = 0, []
    if pid in hidden_pids:      score += 5; reasons.append("hidden_from_pslist")
    if pid in malfind_pids:     score += 4; reasons.append("rwx_injection")
    if pid in net_lolbin_pids:  score += 4; reasons.append("lolbin_network")
    if pid in handle_pids:      score += 3; reasons.append("lsass_full_access")
    if pid in abnormal_pids:    score += 3; reasons.append("abnormal_parent")
    if pid in cmdline_pids:     score += 2; reasons.append("suspicious_cmdline")
    if "rwx_injection" in reasons and "lolbin_network" in reasons:
        score += 3; reasons.append("inject_then_c2_combo")
    if "hidden_from_pslist" in reasons and len(reasons) > 1:
        score += 2; reasons.append("hidden_plus_activity")
    if "rwx_injection" in reasons and "lsass_full_access" in reasons:
        score += 2; reasons.append("inject_plus_lsass_dump")
    return score, reasons


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    G, out_dir = load_graph(path)
    print(f"\n[*] Loaded graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

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
        "behavioural_suspects": [],
    }

    # ── Build pid → name map from process nodes ───────────────────────────────
    pid_to_name = {}
    for _, d in nodes_of_type(G, "process"):
        pid_to_name[safe_int(d.get("pid", 0))] = safe_str(d.get("label", "")).lower()

    # ── 1. Hidden processes (in_psscan=1 but in_pslist=0) ────────────────────
    hidden_pids_set = set()
    for _, d in nodes_of_type(G, "process"):
        if safe_int(d.get("in_pslist", 1)) == 0 and safe_int(d.get("in_psscan", 1)) == 1:
            pid = safe_int(d.get("pid", 0))
            result["hidden_processes"].append({
                "pid":         pid,
                "name":        d.get("label", ""),
                "ppid":        d.get("ppid"),
                "create_time": d.get("create_time", ""),
                "_reason":     "hidden_from_pslist",
            })
            hidden_pids_set.add(pid)
            suspicious_pids.add(pid)

    # ── 2. Memory regions: malfind RWX ───────────────────────────────────────
    malfind_pids_set = set()
    for _, d in nodes_of_type(G, "memory_region"):
        prot   = safe_str(d.get("protection", ""))
        source = safe_str(d.get("source", ""))
        is_rwx = "EXECUTE_READWRITE" in prot.upper() or source == "malfind"
        if not is_rwx:
            continue
        pid       = safe_int(d.get("pid", 0))
        disasm    = safe_str(d.get("disasm", ""))
        has_mz    = bool(safe_int(d.get("has_mz_header", 0)))
        has_shell = bool(safe_int(d.get("has_shellcode", 0))) \
                    or bool(SHELLCODE_EB_RE.search(disasm))
        row = {
            "pid":          pid,
            "process_name": pid_to_name.get(pid, "?"),
            "start_vpn":    d.get("start_vpn", ""),
            "end_vpn":      d.get("end_vpn", ""),
            "protection":   prot,
            "source":       source,
            "private":      bool(safe_int(d.get("private_memory", 0))),
            "backing_file": d.get("backing_file", ""),
            "has_mz":       has_mz,
            "has_shellcode": has_shell,
            "disasm":       disasm[:120],
            "_severity":    "Critical" if has_mz else "High" if has_shell else "Medium",
        }
        result["malfind_regions"].append(row)
        malfind_pids_set.add(pid)
        suspicious_pids.add(pid)

    # ── 3. VAD RWX private (no backing file) ─────────────────────────────────
    for _, d in nodes_of_type(G, "memory_region"):
        prot    = safe_str(d.get("protection", ""))
        source  = safe_str(d.get("source", ""))
        private = safe_int(d.get("private_memory", 0))
        bf      = safe_str(d.get("backing_file", "")).strip()
        if source != "vadinfo": continue
        if "EXECUTE_READWRITE" not in prot.upper(): continue
        if not private: continue
        if bf and bf not in ("", "N/A", "nan", "Disabled"): continue
        pid = safe_int(d.get("pid", 0))
        result["vad_suspicious"].append({
            "pid":         pid,
            "process_name": pid_to_name.get(pid, "?"),
            "start_vpn":   d.get("start_vpn", ""),
            "protection":  prot,
            "backing_file": bf,
            "_severity":   "High",
        })
        suspicious_pids.add(pid)

    # ── 4. SSDT hooks ─────────────────────────────────────────────────────────
    for _, d in nodes_of_type(G, "ssdt"):
        module = safe_str(d.get("module", "")).lower().strip()
        if not any(leg in module for leg in LEGIT_SSDT):
            result["ssdt_hooks"].append({
                "symbol":   d.get("symbol", ""),
                "module":   module,
                "address":  d.get("address", ""),
                "_severity": "Critical",
            })

    # ── 5. Abnormal parent-child ──────────────────────────────────────────────
    abnormal_pids_set = set()
    for _, d in nodes_of_type(G, "process"):
        name = safe_str(d.get("label", "")).lower().strip()
        if name not in EXPECTED_PARENTS:
            continue
        pid    = safe_int(d.get("pid", 0))
        ppid   = safe_int(d.get("ppid", 0))
        parent = pid_to_name.get(ppid, "unknown")
        if parent not in EXPECTED_PARENTS[name]:
            result["abnormal_parents"].append({
                "pid":             pid,
                "name":            d.get("label", ""),
                "ppid":            ppid,
                "actual_parent":   parent,
                "expected_parent": EXPECTED_PARENTS[name],
                "_severity":       "High",
            })
            abnormal_pids_set.add(pid)
            suspicious_pids.add(pid)

    # ── 6. Suspicious network connections ────────────────────────────────────
    net_lolbin_pids_local = set()
    for _, d in nodes_of_type(G, "network_conn"):
        state   = safe_str(d.get("state", "")).strip()
        if state != "ESTABLISHED":
            continue
        foreign = safe_str(d.get("foreign_addr", "")).strip()
        owner   = safe_str(d.get("owner", "")).strip().lower()
        is_ext  = bool(safe_int(d.get("is_external", 0)))
        is_pub  = is_ext and foreign not in ("", "-", "*") \
                  and not PRIVATE_IP.match(foreign)
        is_lolbin     = owner in LOLBIN_NET
        is_non_browser = is_pub and owner not in LEGIT_NET_OWNERS
        if not (is_lolbin or is_non_browser):
            continue
        pid = safe_int(d.get("pid", 0))
        result["network_suspicious"].append({
            "pid":           pid,
            "process_name":  pid_to_name.get(pid, "?"),
            "owner":         owner,
            "foreign_addr":  foreign,
            "foreign_port":  d.get("foreign_port"),
            "state":         state,
            "proto":         d.get("proto", ""),
            "is_lolbin_c2":  is_lolbin,
            "_is_lolbin_c2": is_lolbin,
            "_severity":     "Critical" if is_lolbin else "High",
        })
        suspicious_pids.add(pid)
        if is_lolbin:
            net_lolbin_pids_local.add(pid)

    # ── 7. Cmdline rules ──────────────────────────────────────────────────────
    cmdline_pids_local = set()
    for _, d in nodes_of_type(G, "process"):
        args = safe_str(d.get("args", "")).lower()
        if not args:
            continue
        triggered = [label for pat, label in CMDLINE_RULES.items()
                     if re.search(pat, args, re.IGNORECASE)]
        if not triggered:
            continue
        pid = safe_int(d.get("pid", 0))
        result["cmdline_suspicious"].append({
            "pid":              pid,
            "name":             d.get("label", ""),
            "args":             d.get("args", ""),
            "_triggered_rules": triggered,
            "_severity": (
                "Critical" if any(x in triggered for x in
                    ["EncodedPowerShell", "FilelessExec", "ReconTool", "RansomNote"])
                else "High"
            ),
        })
        suspicious_pids.add(pid)
        cmdline_pids_local.add(pid)

    # ── 8. Handles → unexpected lsass full access ─────────────────────────────
    handle_pids_local = set()
    for _, d in nodes_of_type(G, "handle"):
        htype  = safe_str(d.get("handle_type", ""))
        hname  = safe_str(d.get("name", "")).lower()
        access = safe_str(d.get("granted_access", "")).lower().strip()
        if "process" not in htype.lower(): continue
        if "lsass" not in hname: continue
        if access not in HIGH_ACCESS_MASKS: continue
        pid       = safe_int(d.get("pid", 0))
        proc_name = pid_to_name.get(pid, "")
        if proc_name in LSASS_WHITELIST: continue
        result["handle_suspicious"].append({
            "pid":            pid,
            "holder_process": proc_name,
            "target":         d.get("name", ""),
            "handle_type":    htype,
            "granted_access": access,
            "_severity":      "Critical",
        })
        handle_pids_local.add(pid)
        suspicious_pids.add(pid)

    # ── 9. Suspicious threads ─────────────────────────────────────────────────
    for _, d in nodes_of_type(G, "thread"):
        if not safe_int(d.get("is_suspicious", 0)):
            continue
        start_path = safe_str(d.get("start_path", "")).lower()
        if any(p in start_path for p in ["\\temp\\", "\\appdata\\", "public"]):
            pid = safe_int(d.get("pid", 0))
            result["thread_suspicious"].append({
                "pid":           pid,
                "process_name":  pid_to_name.get(pid, "?"),
                "tid":           d.get("tid"),
                "start_address": d.get("start_address", ""),
                "start_path":    start_path,
                "_severity":     "High",
            })
            suspicious_pids.add(pid)

    # ── 10. Drivers with no service key ──────────────────────────────────────
    for _, d in nodes_of_type(G, "driver"):
        svc = safe_str(d.get("service_key", "")).strip()
        if not svc or svc in ("N/A", "nan"):
            result["driver_suspicious"].append({
                "driver_name": d.get("driver_name", ""),
                "service_key": svc,
                "start":       d.get("start"),
                "size":        d.get("size"),
                "_severity":   "Medium",
            })

    # ── 11. DLLs loaded from suspicious paths ────────────────────────────────
    for _, d in nodes_of_type(G, "dll"):
        dll_path = safe_str(d.get("path", "")).lower()
        if any(p in dll_path for p in ["\\temp\\", "\\appdata\\", "users\\public"]):
            pid = safe_int(d.get("pid", 0))
            result["dll_suspicious"].append({
                "pid":          pid,
                "process_name": pid_to_name.get(pid, "?"),
                "path":         d.get("path", ""),
                "name":         d.get("name", ""),
                "_severity":    "High",
            })
            suspicious_pids.add(pid)

    # ── 12. Behaviour-based process scoring (0-day ready) ────────────────────
    seen_scored = set()
    for _, d in nodes_of_type(G, "process"):
        pid = safe_int(d.get("pid", 0))
        if pid in seen_scored:
            continue
        seen_scored.add(pid)
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
            result["behavioural_suspects"].append({
                "pid":              pid,
                "name":             d.get("label", ""),
                "ppid":             d.get("ppid"),
                "parent_name":      pid_to_name.get(safe_int(d.get("ppid", 0)), "?"),
                "create_time":      d.get("create_time", ""),
                "args":             d.get("args", ""),
                "wow64":            bool(safe_int(d.get("wow64", 0))),
                "in_pslist":        bool(safe_int(d.get("in_pslist", 1))),
                "_suspicion_score": score,
                "_reasons":         reasons,
                "_severity": (
                    "Critical" if score >= SEV_CRITICAL else
                    "High"     if score >= SEV_HIGH      else
                    "Medium"
                ),
            })
            suspicious_pids.add(pid)

    # ── 13. Collect suspicious process summary ────────────────────────────────
    seen = set()
    for _, d in nodes_of_type(G, "process"):
        pid = safe_int(d.get("pid", 0))
        if pid in suspicious_pids and pid not in seen:
            result["suspicious_processes"].append({
                "pid":         pid,
                "name":        d.get("label", ""),
                "ppid":        d.get("ppid"),
                "create_time": d.get("create_time", ""),
                "args":        d.get("args", ""),
                "in_pslist":   bool(safe_int(d.get("in_pslist", 1))),
                "in_psscan":   bool(safe_int(d.get("in_psscan", 1))),
            })
            seen.add(pid)

    # ── 14. Build graph_attr ──────────────────────────────────────────────────
    graph_attr = {
        "max_process_score": max(
            (r["_suspicion_score"] for r in result["behavioural_suspects"]),
            default=0
        ),
        "attack_steps": sum([
            1 if result["malfind_regions"]    else 0,
            1 if result["network_suspicious"] else 0,
            1 if result["handle_suspicious"]  else 0,
            1 if result["hidden_processes"]   else 0,
            1 if result["abnormal_parents"]   else 0,
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
    out_path = os.path.join(out_dir, "filtered_malicious.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(clean(result), f, indent=2, default=str)

    print(f"\n[\u2705] Suspicious PIDs: {len(suspicious_pids)}")
    for k, v in result.items():
        if k.startswith("_"): continue
        print(f"  {k}: {len(v)} entries")

    print(f"\n  graph_attr (for dataset.py):")
    for k, v in graph_attr.items():
        print(f"    {k}: {v}")

    print(f"\n  label_signals:")
    for k, v in label_signals.items():
        print(f"    {k}: {v}")

    print(f"\n[\U0001f4be] Saved: {out_path}")


if __name__ == "__main__":
    main()
