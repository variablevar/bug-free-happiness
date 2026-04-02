#!/usr/bin/env python3
"""
analyze_graph.py  v3  (MalVol-25 aware — behaviour-based, 0-day ready)

Fixes vs v2:
  - session_id key (was "session")
  - in_pslist/in_psscan stored as int 0/1 — all bool checks updated
  - pid_to_name uses int keys throughout (no str/int mismatch)
  - entry_pids set uses safe int cast (no None comparison crash)
  - heuristic_score from build_graph used as baseline, not overwritten
  - LOLBINS path checks use os.sep-agnostic matching
  - SUSPICIOUS_PATHS uses forward slash (matches safe_str output)
  - graph_attr loaded from graph_attr.json and included in report
  - analyze_credentials fixed: reads correct node fields from v2 graph
  - shared-stub detection uses first 60 chars of disasm (strip whitespace)
  - overall verdict logic improved for 0-day (no name dependency)
  - load_graph reads graph.pkl (pickle) instead of graph.json

Usage:
  python analyze_graph.py <graph.pkl|folder>
Output:
  analysis_report.json  (same folder as graph.pkl)
"""

import json, sys, os, collections, math, pickle
from networkx.readwrite import json_graph
import networkx as nx


# ═══════════════════════════════════════════════════════════════════════
# CONSTANTS  (no hardcoded malware names)
# ═══════════════════════════════════════════════════════════════════════

LOLBINS = {
    "mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe",
    "certutil.exe","bitsadmin.exe","msiexec.exe","installutil.exe",
    "ieexec.exe","msconfig.exe","pcalua.exe","schtasks.exe","at.exe",
    "cmd.exe","powershell.exe","pwsh.exe","wmic.exe","odbcconf.exe",
    "xwizard.exe","regasm.exe","regsvcs.exe","msbuild.exe","cmstp.exe",
}

# Forward-slash paths (safe_str normalises separators in build_graph output)
SUSPICIOUS_PATHS = [
    "/temp/", "/tmp/", "/appdata/", "/public/",
    "/downloads/", "/recycle", "/programdata/",
    "\\temp\\", "\\appdata\\", "\\public\\",   # keep backslash variants too
]

SUSPICIOUS_PARENTS = {
    "lsass.exe":    {"cmd.exe","powershell.exe","wscript.exe","mshta.exe"},
    "svchost.exe":  {"explorer.exe","cmd.exe","powershell.exe"},
    "services.exe": {"cmd.exe","powershell.exe","explorer.exe"},
}

HIGH_ACCESS_MASKS = {"0x1fffff","0x1f0fff","0x143a"}

ENCODED_PATTERNS = [
    "-enc","-encodedcommand","frombase64","invoke-expression",
    "iex(","bypass","hidden","downloadstring","webclient",
]

RANSOM_PATTERNS = [
    "_r_e_a_d","decrypt","ransom","readme","!!!","creadthis",
    "your_files","recover","howto","help_restore",
]

# Processes that legitimately have no backing path
NO_PATH_OK = {"system", "registry"}


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def safe(v):
    if v is None: return None
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)): return None
    return v

def safe_int(v, default=0):
    try: return int(v)
    except Exception: return default

def label_severity(score):
    if score >= 12: return "CRITICAL"
    if score >= 7:  return "HIGH"
    if score >= 3:  return "MEDIUM"
    return "LOW"

def nodes_of_type(G, t):
    return [(n, d) for n, d in G.nodes(data=True) if d.get("node_type") == t]

def load_graph(path):
    """Accept a graph.pkl file or a sample folder containing graph.pkl."""
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
        print(f"[ERROR] Pickle does not contain a NetworkX graph."); sys.exit(1)
    return G, os.path.dirname(os.path.abspath(path))

def load_graph_attr(folder):
    """Load graph_attr.json written by build_graph.py v2."""
    p = os.path.join(folder, "graph_attr.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {"graph_attr": [0.0, 0.0, 0.0, 0.0, 0.0], "label_signals": {}}


# ═══════════════════════════════════════════════════════════════════════
# HEURISTICS
# ═══════════════════════════════════════════════════════════════════════

def heuristic_process(n, d, G, pid_to_name):
    # Start from the score already computed by build_graph (behaviour-based)
    # and add analysis-layer signals on top.
    score   = safe_int(d.get("heuristic_score", 0))
    reasons = list(d.get("suspicion_reasons", "").strip("[]'").split("', '")
                   if d.get("suspicion_reasons","").strip("[]") else [])
    reasons = [r for r in reasons if r]   # drop empty strings

    name   = str(d.get("label","")).lower()
    args   = str(d.get("args","")).lower()
    path   = str(d.get("path","")).lower()
    ppid   = safe_int(d.get("ppid", 0))
    parent = pid_to_name.get(ppid, "").lower()

    # LOLBin
    if any(lb in name for lb in LOLBINS) and "lolbin" not in reasons:
        score += 2; reasons.append("lolbin")

    # Suspicious path
    if any(p in path for p in SUSPICIOUS_PATHS) and not any("suspicious-path" in r for r in reasons):
        score += 3; reasons.append(f"suspicious-path:{path[:40]}")

    # Encoded / obfuscated cmdline
    if any(p in args for p in ENCODED_PATTERNS) and "encoded-cmdline" not in reasons:
        score += 4; reasons.append("encoded-cmdline")

    # Script-file argument
    for ext in [".hta",".vbs",".js",".ps1",".bat",".cmd",".jse",".vbe",".wsf"]:
        if ext in args and not any("script-arg" in r for r in reasons):
            score += 2; reasons.append(f"script-arg{ext}"); break

    # Ransom note in args
    if any(x in args for x in RANSOM_PATTERNS) and "ransom-note-arg" not in reasons:
        score += 4; reasons.append("ransom-note-arg")

    # Abnormal parent
    for child_kw, bad_parents in SUSPICIOUS_PARENTS.items():
        if child_kw in name and any(bp in parent for bp in bad_parents):
            tag = f"abnormal-parent:{parent}->{name}"
            if tag not in reasons:
                score += 5; reasons.append(tag)

    # No on-disk path (fileless)
    if (not path or path in ("-","")) and name not in NO_PATH_OK \
            and "no-path" not in reasons:
        score += 1; reasons.append("no-path")

    # External C2 connections (predecessors that are network_conn nodes)
    ext_conns = [nb for nb in G.predecessors(n)
                 if G.nodes[nb].get("is_external")
                 and G.nodes[nb].get("node_type") == "network_conn"]
    if ext_conns and not any("c2-conn" in r for r in reasons):
        score += len(ext_conns); reasons.append(f"{len(ext_conns)}x-c2-conn")

    # Injected memory (malfind → this process)
    inj = [nb for nb in G.predecessors(n)
           if G.nodes[nb].get("node_type") == "memory_region"
           and G.nodes[nb].get("source") == "malfind"]
    if inj and not any("injected-mem" in r for r in reasons):
        score += len(inj) * 3; reasons.append(f"{len(inj)}x-injected-mem")

    # Unexpected lsass handle
    sus_handles = [nb for nb in G.predecessors(n)
                   if G.nodes[nb].get("node_type") == "handle"
                   and G.nodes[nb].get("is_suspicious")]
    if sus_handles and "lsass-full-access" not in reasons:
        score += 6; reasons.append("lsass-full-access")

    # WoW64 process with already-suspicious score
    if safe_int(d.get("wow64",0)) and score > 3 and "wow64-suspicious" not in reasons:
        score += 1; reasons.append("wow64-suspicious")

    # Hidden process  (FIX: in_pslist stored as int 0/1)
    if safe_int(d.get("in_pslist", 1)) == 0 and "hidden-process" not in reasons:
        score += 8; reasons.append("hidden-process")

    # High in-degree (hub node = injected-into or C2 pivot)
    in_deg = G.in_degree(n)
    if in_deg > 50 and not any(x in name for x in
            ["system","svchost","explorer","chrome",
             "searchindexer","spoolsv","lsass"]):
        tag = f"high-in-degree{in_deg}"
        if not any("high-in-degree" in r for r in reasons):
            score += 2; reasons.append(tag)

    # Spawned a LOLBin child
    children = [G.nodes[nb] for nb in G.successors(n)
                if G.nodes[nb].get("node_type") == "process"]
    if any(any(lb in str(c.get("label","")).lower() for lb in LOLBINS)
           for c in children) and "spawned-lolbin-child" not in reasons:
        score += 2; reasons.append("spawned-lolbin-child")

    return score, reasons


def heuristic_memory(d):
    score = 0; reasons = []
    prot   = str(d.get("protection",""))
    src    = str(d.get("source",""))
    has_mz = bool(d.get("has_mz_header", False))  # may be int 0/1 or bool
    disasm = str(d.get("disasm","")).lower()
    private= safe_int(d.get("private_memory", 0))
    fname  = str(d.get("backing_file","")).strip()

    if src == "malfind":
        score += 4; reasons.append("malfind-rwx")
    if "execute_readwrite" in prot.lower():
        score += 2; reasons.append("rwx")
    if has_mz or safe_int(d.get("has_mz_header",0)):
        score += 5; reasons.append("mz-header-injected-pe")
    if private and fname in ("","N/A","nan"):
        score += 1; reasons.append("private-no-backing-file")
    # Shellcode opcode patterns
    for pat in ["eb ","ff d0","ff e0","call eax","jmp esp","push ebp"]:
        if pat in disasm:
            score += 2; reasons.append(f"shellcode-opcode:{pat.strip()}"); break
    return score, reasons


def heuristic_network(d):
    score = 0; reasons = []
    state  = str(d.get("state",""))
    fport  = safe_int(d.get("foreign_port", 0))
    owner  = str(d.get("owner","")).lower()

    if safe_int(d.get("is_external", 0)):
        score += 2; reasons.append("external-ip")
    if state == "ESTABLISHED":
        score += 1; reasons.append("established")
    if fport in [4444,1337,31337,8080,8443,9090,6667,1234]:
        score += 4; reasons.append(f"suspicious-port:{fport}")
    if any(lb in owner for lb in LOLBINS):
        score += 4; reasons.append(f"lolbin-network:{owner}")
    if fport == 80 and "chrome" not in owner and "firefox" not in owner \
            and "edge" not in owner:
        score += 1; reasons.append("http-non-browser")
    if safe_int(d.get("is_lolbin_c2", 0)):
        if "lolbin-c2" not in reasons:
            score += 3; reasons.append("lolbin-c2")
    return score, reasons


# ═══════════════════════════════════════════════════════════════════════
# ANALYSIS SECTIONS
# ═══════════════════════════════════════════════════════════════════════

def analyze_summary(G):
    node_types = collections.Counter(d.get("node_type","?")
                                     for _,d in G.nodes(data=True))
    edge_types = collections.Counter(d.get("edge_type","?")
                                     for _,_,d in G.edges(data=True))
    sus        = [(n,d) for n,d in G.nodes(data=True)
                  if safe_int(d.get("is_suspicious",0))]
    sus_types  = collections.Counter(d.get("node_type","?") for _,d in sus)
    return {
        "nodes_total":        G.number_of_nodes(),
        "edges_total":        G.number_of_edges(),
        "is_directed":        G.is_directed(),
        "suspicious_total":   len(sus),
        "node_types":         dict(node_types),
        "edge_types":         dict(edge_types),
        "suspicious_by_type": dict(sus_types),
    }


def analyze_processes(G):
    # FIX: pid_to_name uses int keys (d.get("pid") returns int from build_graph v2)
    pid_to_name = {safe_int(d.get("pid",0)): str(d.get("label","?"))
                   for _, d in nodes_of_type(G, "process")}
    rows = []
    for n, d in nodes_of_type(G, "process"):
        score, reasons = heuristic_process(n, d, G, pid_to_name)
        rows.append({
            "node_id":            n,
            "name":               d.get("label",""),
            "pid":                safe(d.get("pid")),
            "ppid":               safe(d.get("ppid")),
            "parent_name":        pid_to_name.get(safe_int(d.get("ppid",0)), "?"),
            "session":            safe(d.get("session_id","")),   # FIX: was "session"
            "wow64":              bool(safe_int(d.get("wow64",0))),
            "in_pslist":          bool(safe_int(d.get("in_pslist",1))),
            "in_psscan":          bool(safe_int(d.get("in_psscan",1))),
            "create_time":        d.get("create_time",""),
            "args":               d.get("args",""),
            "path":               d.get("path",""),
            "degree_in":          G.in_degree(n),
            "degree_out":         G.out_degree(n),
            "is_suspicious_flag": bool(safe_int(d.get("is_suspicious",0))),
            "heuristic_score":    score,
            "severity":           label_severity(score),
            "reasons":            reasons,
        })
    return sorted(rows, key=lambda x: x["heuristic_score"], reverse=True)


def analyze_hidden(G):
    # FIX: in_pslist is int 0/1, not bool
    return [
        {
            "name":        d.get("label",""),
            "pid":         safe(d.get("pid")),
            "ppid":        safe(d.get("ppid")),
            "create_time": d.get("create_time",""),
            "severity":    "CRITICAL",
            "reason":      "present in psscan but absent from pslist — DKOM hiding",
        }
        for _, d in nodes_of_type(G, "process")
        if safe_int(d.get("in_pslist", 1)) == 0
    ]


def analyze_entry_points(G):
    pid_to_name = {safe_int(d.get("pid",0)): str(d.get("label","?"))
                   for _, d in nodes_of_type(G, "process")}
    results = []
    for n, d in nodes_of_type(G, "process"):
        name  = str(d.get("label","")).lower()
        args  = str(d.get("args","")).lower()
        score = 0; signals = []

        if any(lb in name for lb in LOLBINS):
            score += 2; signals.append("lolbin")

        has_ext_net = any(
            safe_int(G.nodes[nb].get("is_external", 0))
            for nb in list(G.predecessors(n)) + list(G.successors(n))
            if G.nodes[nb].get("node_type") in ("network_conn","ip_address")
        )
        if has_ext_net:
            score += 2; signals.append("external-network")

        for ext in [".hta",".vbs",".js",".ps1",".bat",".jse",".vbe",".wsf"]:
            if ext in args:
                score += 2; signals.append(f"script:{ext}"); break

        if any(p in args for p in ENCODED_PATTERNS):
            score += 3; signals.append("encoded/obfuscated-args")

        if any(x in args for x in RANSOM_PATTERNS):
            score += 3; signals.append("ransom-note-reference")

        if score >= 2:
            results.append({
                "name":        d.get("label",""),
                "pid":         safe(d.get("pid")),
                "ppid":        safe(d.get("ppid")),
                "parent":      pid_to_name.get(safe_int(d.get("ppid",0)), "?"),
                "entry_score": score,
                "signals":     signals,
                "severity":    label_severity(score * 2),
                "args":        d.get("args",""),
                "create_time": d.get("create_time",""),
            })
    return sorted(results, key=lambda x: x["entry_score"], reverse=True)


def analyze_network(G):
    results = []
    for n, d in nodes_of_type(G, "network_conn"):
        score, reasons = heuristic_network(d)
        if score > 0:
            results.append({
                "proto":           d.get("proto",""),
                "local_addr":      d.get("local_addr",""),
                "local_port":      safe(d.get("local_port")),
                "foreign_addr":    d.get("foreign_addr",""),
                "foreign_port":    safe(d.get("foreign_port")),
                "state":           d.get("state",""),
                "owner":           d.get("owner",""),
                "is_external":     bool(safe_int(d.get("is_external",0))),
                "is_lolbin_c2":    bool(safe_int(d.get("is_lolbin_c2",0))),
                "heuristic_score": score,
                "severity":        label_severity(score),
                "reasons":         reasons,
            })
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)


def analyze_injections(G):
    pid_to_name = {safe_int(d.get("pid",0)): str(d.get("label","?"))
                   for _, d in nodes_of_type(G, "process")}

    # Detect shared shellcode stub (same first 60 chars of disasm = same campaign/packer)
    mal_disasms = [str(d.get("disasm","")).strip()[:60]
                   for _, d in nodes_of_type(G, "memory_region")
                   if d.get("source") == "malfind"]
    shared_stub = len(set(mal_disasms)) == 1 and len(mal_disasms) > 1

    results = []
    for n, d in nodes_of_type(G, "memory_region"):
        score, reasons = heuristic_memory(d)
        if score > 0:
            pid = safe_int(d.get("pid",0))
            if shared_stub and d.get("source") == "malfind":
                reasons.append("shared-stub-across-processes")
            results.append({
                "pid":             safe(d.get("pid")),
                "process_name":    pid_to_name.get(pid, "?"),
                "start_vpn":       d.get("start_vpn",""),
                "end_vpn":         d.get("end_vpn",""),
                "protection":      d.get("protection",""),
                "private":         bool(safe_int(d.get("private_memory",0))),
                "backing_file":    d.get("backing_file",""),
                "has_mz_header":   bool(safe_int(d.get("has_mz_header",0))),
                "has_shellcode":   bool(safe_int(d.get("has_shellcode",0))),
                "disasm":          str(d.get("disasm",""))[:120],
                "source":          d.get("source",""),
                "heuristic_score": score,
                "severity":        label_severity(score),
                "reasons":         reasons,
            })
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)


def analyze_credentials(G):
    # FIX: handle nodes in v2 graph store pid as int; use safe_int throughout
    pid_to_name = {safe_int(d.get("pid",0)): str(d.get("label","?"))
                   for _, d in nodes_of_type(G, "process")}
    results = []
    for n, d in nodes_of_type(G, "handle"):
        access  = str(d.get("granted_access","")).lower().strip()
        pid     = safe_int(d.get("pid",0))
        is_full = access in HIGH_ACCESS_MASKS
        results.append({
            "holder_process": pid_to_name.get(pid, "?"),
            "holder_pid":     safe(d.get("pid")),
            "target":         d.get("name",""),
            "handle_type":    d.get("handle_type",""),
            "granted_access": access,
            "is_full_access": is_full,
            "severity":       "CRITICAL" if is_full else "HIGH",
            "reason":         "Full process access to lsass — T1003 credential dumping"
                              if is_full else "Elevated lsass access",
        })
    return results


def analyze_drivers(G):
    results = []
    for n, d in nodes_of_type(G, "driver"):
        svckey = str(d.get("service_key","")).strip()
        score  = 0; reasons = []
        if not svckey or svckey in ("","N/A","nan"):
            score += 5; reasons.append("no-service-key (phantom/rootkit driver)")
        if score > 0:
            results.append({
                "driver_name":     d.get("driver_name",""),
                "service_key":     svckey,
                "start":           safe(d.get("start")),
                "size":            safe(d.get("size")),
                "heuristic_score": score,
                "severity":        label_severity(score),
                "reasons":         reasons,
            })
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)


def analyze_attack_chain(G, processes, entry_points, injections,
                          credentials, network):
    steps = []

    # Step 1 — Initial Access / Execution
    if entry_points:
        e = entry_points[0]
        steps.append({
            "step":     1,
            "tactic":   "Initial Access / Execution",
            "mitre":    "T1218 / T1566",
            "detail":   f"{e['name']} PID {e['pid']} via {', '.join(e['signals'])}",
            "evidence": e["args"][:120],
        })

    # Step 2 — Process Injection
    injected_procs = list({i["process_name"] for i in injections
                           if i.get("source") == "malfind"})
    if injected_procs:
        shared = any("shared-stub" in str(i.get("reasons","")) for i in injections)
        steps.append({
            "step":     2,
            "tactic":   "Defense Evasion / Process Injection",
            "mitre":    "T1055",
            "detail":   f"Shellcode in {len(injected_procs)} process(es): "
                        f"{', '.join(injected_procs)}"
                        + (" [identical stub = same campaign]" if shared else ""),
            "evidence": injections[0].get("disasm","")[:80] if injections else "",
        })

    # Step 3 — C2
    c2 = [n for n in network
          if safe_int(n.get("is_external",0)) and n.get("state") == "ESTABLISHED"]
    if c2:
        steps.append({
            "step":     3,
            "tactic":   "Command & Control",
            "mitre":    "T1071",
            "detail":   f"{len(c2)} ESTABLISHED C2 connection(s) to "
                        f"{len({n['foreign_addr'] for n in c2})} unique IP(s) "
                        f"via {', '.join({n['owner'] for n in c2})}",
            "evidence": str(sorted({n['foreign_addr'] for n in c2})[:4]),
        })

    # Step 4 — Credential Access
    if credentials:
        steps.append({
            "step":     4,
            "tactic":   "Credential Access",
            "mitre":    "T1003.001",
            "detail":   "lsass accessed with FULL rights by "
                        f"{', '.join(set(c['holder_process'] for c in credentials))}",
            "evidence": f"GrantedAccess {credentials[0]['granted_access']}",
        })

    # Step 5 — Impact / secondary high-score process
    sys_procs = {
        "system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
        "services.exe","lsass.exe","lsm.exe","svchost.exe",
        "spoolsv.exe","dwm.exe","taskhost.exe","taskhostw.exe",
    }
    # FIX: entry_pids uses safe int cast; skip None pids
    entry_pids = {safe_int(e["pid"]) for e in entry_points if e["pid"] is not None}
    for p in processes:
        if p["pid"] is None: continue
        if (p["heuristic_score"] >= 7
                and str(p["name"]).lower() not in sys_procs
                and safe_int(p["pid"]) not in entry_pids):
            steps.append({
                "step":     5,
                "tactic":   "Execution / Impact",
                "mitre":    "T1486",
                "detail":   f"High-score process: {p['name']} (PID {p['pid']}) "
                            f"score={p['heuristic_score']} parent={p['parent_name']}",
                "evidence": p.get("args","")[:80],
            })
            break

    # Verdict
    has_injection  = len(injected_procs) > 0
    has_c2         = len(c2) > 0
    has_creds      = len(credentials) > 0
    has_hidden     = any(safe_int(d.get("in_pslist",1)) == 0
                         for _, d in G.nodes(data=True)
                         if d.get("node_type") == "process")
    max_score      = max((p["heuristic_score"] for p in processes), default=0)

    if (has_injection and has_c2 and has_creds) or (has_hidden and max_score >= 10):
        verdict = "CRITICAL — Active malware: injection + C2 + credential access detected"
    elif len(steps) >= 3 or (has_injection and has_c2):
        verdict = "HIGH — Multiple malicious behaviours detected"
    elif len(steps) >= 2 or max_score >= 7:
        verdict = "MEDIUM — Suspicious activity detected"
    else:
        verdict = "LOW — No significant threats identified"

    return {
        "steps":             steps,
        "overall_verdict":   verdict,
        "max_process_score": max_score,
    }


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    G, out_dir = load_graph(path)
    graph_attr  = load_graph_attr(out_dir)

    print(f"[*] Loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print(f"[*] graph_attr: {graph_attr.get('graph_attr')}")
    print("[*] Running behavioural heuristics...")

    processes   = analyze_processes(G)
    entry_pts   = analyze_entry_points(G)
    network     = analyze_network(G)
    injections  = analyze_injections(G)
    credentials = analyze_credentials(G)
    chain       = analyze_attack_chain(G, processes, entry_pts,
                                       injections, credentials, network)

    report = {
        "meta":             {
            "tool":    "analyze_graph.py v3",
            "source":  path,
            "version": "3.0",
        },
        "summary":          analyze_summary(G),
        "attack_chain":     chain,
        "entry_points":     entry_pts,
        "processes":        processes,
        "hidden_processes": analyze_hidden(G),
        "network":          network,
        "injections":       injections,
        "credentials":      credentials,
        "drivers":          analyze_drivers(G),
        # graph_attr tensor for dataset.py — 5 floats ready to use
        "graph_attr":       graph_attr.get("graph_attr", [0.0]*5),
        "label_signals":    graph_attr.get("label_signals", {}),
    }

    out_path = os.path.join(out_dir, "analysis_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    # ── Console summary ───────────────────────────────────────────────────────
    w = 57
    print(f"\n{'='*w}")
    print(f"  VERDICT  : {chain['overall_verdict']}")
    print(f"  Steps    : {len(chain['steps'])}")
    print(f"  Max score: {chain['max_process_score']}")
    if entry_pts:
        print(f"  Entry    : {entry_pts[0]['name']} (score {entry_pts[0]['entry_score']})")
    inj_procs = {i['process_name'] for i in injections if i.get('source') == 'malfind'}
    print(f"  Injected : {len(inj_procs)} process(es) — {', '.join(list(inj_procs)[:3])}")
    c2_count = len([n for n in network
                    if safe_int(n.get('is_external',0)) and n.get('state') == 'ESTABLISHED'])
    print(f"  C2 conns : {c2_count}")
    print(f"  Creds    : {'YES — ' + str(len(credentials)) + ' handle(s)' if credentials else 'None detected'}")
    print(f"  Hidden   : {len(analyze_hidden(G))} process(es)")
    print(f"  graph_attr tensor: {graph_attr.get('graph_attr')}")
    print(f"{'='*w}")
    print(f"\n[✅] Report: {out_path}")


if __name__ == "__main__":
    main()
