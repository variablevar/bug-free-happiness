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
from dataclasses import dataclass
import networkx as nx
from utils.parsing import safe_int, safe_str
from utils.graph_io import load_graph_from_path
from utils.rules import (
    PRIVATE_IP_RE as PRIVATE_IP,
    LOLBIN_NET,
    LSASS_WHITELIST,
    HIGH_ACCESS_MASKS,
)


# ── Constants ─────────────────────────────────────────────────────────────────
LEGIT_NET_OWNERS = {
    "chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe",
    "svchost.exe", "system", "dns.exe", "msmpeng.exe", "onedrive.exe",
    "microsoftedgeupdate.exe", "wuauclt.exe", "taskhostw.exe",
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

RULE_WEIGHTS = {
    "hidden_from_pslist": 5.0,
    "rwx_injection": 4.0,
    "nonrwx_exec_private": 3.5,
    "thread_start_private_exec": 3.0,
    "reflective_pe_like": 3.0,
    "hollowing_like": 4.0,
    "lolbin_network": 4.0,
    "rare_external_network": 2.5,
    "slow_beacon_profile": 2.5,
    "lsass_full_access": 3.0,
    "sensitive_handle_access": 2.0,
    "abnormal_parent": 3.0,
    "suspicious_cmdline": 2.0,
    "inject_then_c2_combo": 3.0,
    "hidden_plus_activity": 2.0,
    "inject_plus_lsass_dump": 2.0,
    "browser_expected_traffic": -2.0,
    "windows_update_profile": -1.5,
    "av_expected_activity": -1.5,
    "svchost_expected_service_net": -1.0,
}

STAGE_ORDER = [
    "initial_execution",
    "memory_manipulation",
    "credential_or_discovery",
    "c2_or_lateral",
    "impact_or_persistence",
]


# ── Helpers ───────────────────────────────────────────────────────────────────
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


@dataclass
class RuleHit:
    rule_id: str
    stage: str
    weight: float
    confidence: float
    quality: float
    evidence: str


def _basename_lower(v):
    return os.path.basename(safe_str(v).lower().replace("\\", "/"))


def _lineage_depth(pid, ppid_map, max_depth=12):
    depth = 0
    current = safe_int(pid, 0)
    seen = set()
    while depth < max_depth and current not in seen and current > 0:
        seen.add(current)
        parent = safe_int(ppid_map.get(current, 0), 0)
        if parent <= 0:
            break
        current = parent
        depth += 1
    return depth


def _severity_from_score(score):
    if score >= SEV_CRITICAL:
        return "Critical"
    if score >= SEV_HIGH:
        return "High"
    return "Medium"


def _build_attack_stages(pid_hits):
    stages = []
    for stage in STAGE_ORDER:
        stage_hits = [h for h in pid_hits if h.stage == stage]
        if not stage_hits:
            continue
        stages.append({
            "stage_id": stage,
            "evidence_count": len(stage_hits),
            "rules": sorted(set(h.rule_id for h in stage_hits)),
            "evidence_sample": [h.evidence for h in stage_hits[:3]],
        })
    return stages


def _ordered_stage_transitions(stages):
    if not stages:
        return 0
    idx_map = {s: i for i, s in enumerate(STAGE_ORDER)}
    ordered = 0
    prev = -1
    for stage in [s["stage_id"] for s in stages]:
        cur = idx_map.get(stage, -1)
        if cur > prev:
            ordered += 1
            prev = cur
    return ordered


def _build_root_cause(pid, pid_to_name, pid_hits):
    if pid is None:
        return {}
    hits = pid_hits.get(pid, [])
    if not hits:
        return {}
    top = sorted(hits, key=lambda h: (h.weight * h.confidence * h.quality), reverse=True)[:3]
    return {
        "pid": pid,
        "name": pid_to_name.get(pid, "?"),
        "why": [f"{h.rule_id}:{h.evidence}" for h in top],
    }

def load_graph(path):
    try:
        return load_graph_from_path(path)
    except (FileNotFoundError, TypeError) as exc:
        print(f"[ERROR] {exc}")
        sys.exit(1)


# ── Behaviour-based process scorer ────────────────────────────────────────────
def score_process(pid, pid_hits):
    hits = pid_hits.get(pid, [])
    raw = 0.0
    reasons = []
    stages = set()
    for h in hits:
        raw += h.weight * h.confidence * h.quality
        reasons.append(h.rule_id)
        stages.add(h.stage)

    # corroboration-aware combo bonuses
    if "rwx_injection" in reasons and "lolbin_network" in reasons:
        raw += RULE_WEIGHTS["inject_then_c2_combo"]
        reasons.append("inject_then_c2_combo")
    if "hidden_from_pslist" in reasons and len(set(reasons)) > 1:
        raw += RULE_WEIGHTS["hidden_plus_activity"]
        reasons.append("hidden_plus_activity")
    if "rwx_injection" in reasons and "lsass_full_access" in reasons:
        raw += RULE_WEIGHTS["inject_plus_lsass_dump"]
        reasons.append("inject_plus_lsass_dump")

    # require multi-family corroboration for peak severity confidence
    family_count = len(stages)
    if family_count >= 3:
        raw += 1.5
    elif family_count == 1 and raw >= SEV_HIGH:
        raw -= 1.5

    score = max(0, int(round(raw)))
    confidence = max(0.05, min(0.99, 1 - math.exp(-raw / 10.0)))
    return score, sorted(set(reasons)), confidence


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    G, out_dir = load_graph(path)
    print(f"\n[*] Loaded graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")

    suspicious_pids = set()
    pid_hits = {}
    evidence_graph = {"nodes": set(), "edges": set()}
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
    ppid_map = {}
    for _, d in nodes_of_type(G, "process"):
        pid_to_name[safe_int(d.get("pid", 0))] = safe_str(d.get("label", "")).lower()
        ppid_map[safe_int(d.get("pid", 0))] = safe_int(d.get("ppid", 0))

    def add_hit(pid, rule_id, stage, evidence, confidence=1.0, quality=1.0):
        pid = safe_int(pid, 0)
        if pid <= 0:
            return
        hit = RuleHit(
            rule_id=rule_id,
            stage=stage,
            weight=float(RULE_WEIGHTS.get(rule_id, 1.0)),
            confidence=float(confidence),
            quality=float(quality),
            evidence=safe_str(evidence)[:220],
        )
        pid_hits.setdefault(pid, []).append(hit)

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
            add_hit(pid, "hidden_from_pslist", "memory_manipulation", "in_psscan=1,in_pslist=0", 0.95, 1.0)

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
        add_hit(pid, "rwx_injection", "memory_manipulation", f"{source}:{prot}", 0.90, 1.0)
        if has_mz and safe_str(d.get("backing_file", "")).strip() in ("", "N/A", "nan", "Disabled"):
            add_hit(pid, "reflective_pe_like", "memory_manipulation", "mz_header+no_backing", 0.85, 1.0)

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
        add_hit(pid, "nonrwx_exec_private", "memory_manipulation", f"vad:{prot}", 0.80, 0.9)

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
            add_hit(pid, "abnormal_parent", "initial_execution", f"{parent}->{name}", 0.9, 1.0)

    # ── 6. Suspicious network connections ────────────────────────────────────
    net_lolbin_pids_local = set()
    pid_net_ips = {}
    pid_net_rows = {}
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
        pid_net_rows[pid] = pid_net_rows.get(pid, 0) + 1
        pid_net_ips.setdefault(pid, set()).add(foreign)
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
            add_hit(pid, "lolbin_network", "c2_or_lateral", f"{owner}->{foreign}:{d.get('foreign_port')}", 0.9, 1.0)
        elif is_non_browser:
            add_hit(pid, "rare_external_network", "c2_or_lateral", f"{owner}->{foreign}:{d.get('foreign_port')}", 0.75, 0.9)

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
        add_hit(pid, "suspicious_cmdline", "initial_execution", "|".join(triggered[:3]), 0.8, 0.9)

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
        add_hit(pid, "lsass_full_access", "credential_or_discovery", f"{proc_name}:{access}", 0.9, 1.0)

    # Additional sensitive handle patterns (non-LSASS)
    for _, d in nodes_of_type(G, "handle"):
        hname = safe_str(d.get("name", "")).lower()
        if not any(x in hname for x in ["\\sam", "\\security", "\\system"]):
            continue
        pid = safe_int(d.get("pid", 0))
        add_hit(pid, "sensitive_handle_access", "credential_or_discovery", hname[:120], 0.65, 0.8)

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
            add_hit(pid, "thread_start_private_exec", "memory_manipulation", start_path[:120], 0.8, 0.9)

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
        # low-and-slow profile (many outbound rows, low LOLBin evidence)
        uniq_ips = {ip for ip in pid_net_ips.get(pid, set()) if ip and ip not in ("-", "*")}
        if len(uniq_ips) >= 3 and pid not in net_lolbin_pids_local:
            add_hit(pid, "slow_beacon_profile", "c2_or_lateral", f"unique_ips={len(uniq_ips)}", 0.7, 0.8)

        # benign context discounts with guardrails
        pname = pid_to_name.get(pid, "")
        if pname in {"chrome.exe", "firefox.exe", "msedge.exe"} and len(uniq_ips) >= 2:
            add_hit(pid, "browser_expected_traffic", "c2_or_lateral", pname, 1.0, 1.0)
        if pname in {"msmpeng.exe"} and pid not in malfind_pids_set:
            add_hit(pid, "av_expected_activity", "memory_manipulation", pname, 1.0, 1.0)
        if pname in {"wuauclt.exe", "microsoftedgeupdate.exe", "onedrive.exe"}:
            add_hit(pid, "windows_update_profile", "c2_or_lateral", pname, 1.0, 1.0)
        if pname == "svchost.exe" and pid not in malfind_pids_set:
            add_hit(pid, "svchost_expected_service_net", "c2_or_lateral", pname, 1.0, 1.0)

        score, reasons, confidence = score_process(pid, pid_hits)
        if score >= SUSPICION_THRESHOLD:
            if ("rwx_injection" in reasons) or ("thread_start_private_exec" in reasons):
                exec_tech = "injection_like"
            elif ("nonrwx_exec_private" in reasons and "abnormal_parent" in reasons):
                exec_tech = "hollowing_like"
            elif "reflective_pe_like" in reasons:
                exec_tech = "reflective_like"
            elif "nonrwx_exec_private" in reasons:
                exec_tech = "unknown_memory_exec"
            else:
                exec_tech = "n/a"
            result["behavioural_suspects"].append({
                "PID":              pid,  # compat for build_graph.py legacy parser
                "pid":              pid,
                "name":             d.get("label", ""),
                "ppid":             d.get("ppid"),
                "parent_name":      pid_to_name.get(safe_int(d.get("ppid", 0)), "?"),
                "create_time":      d.get("create_time", ""),
                "args":             d.get("args", ""),
                "wow64":            bool(safe_int(d.get("wow64", 0))),
                "in_pslist":        bool(safe_int(d.get("in_pslist", 1))),
                "lineage_depth":    _lineage_depth(pid, ppid_map),
                "attack_stages":    sorted({h.stage for h in pid_hits.get(pid, [])}),
                "execution_technique": exec_tech,
                "rule_hits":        [h.__dict__ for h in pid_hits.get(pid, [])[:12]],
                "_suspicion_score": score,
                "_reasons":         reasons,
                "_confidence":      round(confidence, 4),
                "_severity":        _severity_from_score(score),
            })
            suspicious_pids.add(pid)
            evidence_graph["nodes"].add(f"process_{pid}")

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
    # graph-level motifs / stats
    proc_nodes = nodes_of_type(G, "process")
    proc_count = max(len(proc_nodes), 1)
    suspicious_component_ratio = len(suspicious_pids) / proc_count
    lineage_depths = [_lineage_depth(p["pid"], ppid_map) for p in result["behavioural_suspects"] if p.get("pid")]
    lineage_depth_p95 = sorted(lineage_depths)[max(0, int(0.95 * (len(lineage_depths) - 1)))] if lineage_depths else 0
    motif_proc_mem_thread = 0
    for _, t in nodes_of_type(G, "thread"):
        pid = safe_int(t.get("pid", 0))
        if pid in malfind_pids_set:
            motif_proc_mem_thread += 1
    proc_degree = []
    for n, d in proc_nodes:
        proc_degree.append(G.in_degree(n) + G.out_degree(n))
    if proc_degree:
        mean_deg = sum(proc_degree) / len(proc_degree)
        std_deg = (sum((x - mean_deg) ** 2 for x in proc_degree) / len(proc_degree)) ** 0.5
        proc_degree_zmax = ((max(proc_degree) - mean_deg) / std_deg) if std_deg > 0 else 0.0
    else:
        proc_degree_zmax = 0.0
    try:
        proc_graph = G.subgraph([n for n, _ in proc_nodes]).to_undirected()
        btw = nx.betweenness_centrality(proc_graph, k=min(32, max(4, proc_graph.number_of_nodes() - 1)))
        btw_vals = sorted(btw.values())
        proc_betweenness_p95 = btw_vals[max(0, int(0.95 * (len(btw_vals) - 1)))] if btw_vals else 0.0
    except Exception:
        proc_betweenness_p95 = 0.0

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

    max_attack_steps = float(len(STAGE_ORDER))
    all_hits = [h for hs in pid_hits.values() for h in hs]
    attack_stages = _build_attack_stages(all_hits)
    ordered_transitions = _ordered_stage_transitions(attack_stages)
    stage_coverage_score = len(attack_stages) / max_attack_steps if max_attack_steps else 0.0
    triage_confidence = max((r.get("_confidence", 0.0) for r in result["behavioural_suspects"]), default=0.0)
    root_pid = result["behavioural_suspects"][0]["pid"] if result["behavioural_suspects"] else None
    root_cause_process = _build_root_cause(root_pid, pid_to_name, pid_hits)

    graph_attr.update({
        "suspect_rate": round(len(result["behavioural_suspects"]) / proc_count, 6),
        "hidden_rate": round(len(result["hidden_processes"]) / proc_count, 6),
        "inject_rate": round(len(result["malfind_regions"]) / proc_count, 6),
        "external_conn_rate": round(len(result["network_suspicious"]) / proc_count, 6),
        "largest_suspicious_component_ratio": round(suspicious_component_ratio, 6),
        "lineage_depth_p95": lineage_depth_p95,
        "lolbin_chain_count": len(net_lolbin_pids_local),
        "nonrwx_exec_count": len(result["vad_suspicious"]),
        "credential_access_count": len(result["handle_suspicious"]),
        "triage_confidence": round(triage_confidence, 6),
        "stage_coverage_score": round(stage_coverage_score, 6),
        "proc_degree_zmax": round(float(proc_degree_zmax), 6),
        "proc_betweenness_p95": round(float(proc_betweenness_p95), 6),
        "num_attack_motifs": motif_proc_mem_thread,
    })

    label_signals = {
        "behavioural_suspects_found": int(len(result["behavioural_suspects"]) > 0),
        "lolbin_c2_found":            int(graph_attr["lolbin_c2_connections"] > 0),
        "ransom_note_found":          int(graph_attr["ransom_note_signal"] == 1),
        "rwx_injections":             len(result["malfind_regions"]),
        "hidden_processes":           len(result["hidden_processes"]),
        "top_suspect_score":          graph_attr["max_process_score"],
        "triage_confidence":          round(triage_confidence, 6),
        "stage_coverage_score":       round(stage_coverage_score, 6),
        "lineage_depth_p95":          lineage_depth_p95,
        "nonrwx_exec_count":          len(result["vad_suspicious"]),
        "credential_access_count":    len(result["handle_suspicious"]),
        "num_attack_motifs":          motif_proc_mem_thread,
    }

    result["_meta"] = {
        "total_suspicious_pids": len(suspicious_pids),
        "suspicious_pids":       sorted(list(suspicious_pids)),
        "graph_attr":            graph_attr,
        "label_signals":         label_signals,
        "triage_confidence":     round(triage_confidence, 6),
        "attack_stages":         attack_stages,
        "attack_stage_classification": {
            "stages_seen": len(attack_stages),
            "ordered_transitions": ordered_transitions,
            "sequence_quality": round((ordered_transitions / max_attack_steps) if max_attack_steps else 0.0, 6),
        },
        "root_cause_process":    root_cause_process,
        "evidence_graph":        {
            "nodes": sorted(evidence_graph["nodes"]),
            "edges": sorted(evidence_graph["edges"]),
        },
        "model_features": {
            **graph_attr,
        },
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
