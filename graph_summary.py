#!/usr/bin/env python3
"""
analyze_graph.py  v2
Loads graph.json → exports a structured JSON analysis report.
No hardcoded malware names. Detection is purely behavioural.

Usage:
  python analyze_graph.py <graph.json|folder>
  python analyze_graph.py .          # looks for graph.json in cwd
Output:
  analysis_report.json  (same folder as graph.json)
"""

import json, sys, os, collections, math
from networkx.readwrite import json_graph
import networkx as nx

# ═══════════════════════════════════════════════════════════════════════
# BEHAVIOURAL HEURISTICS  (zero hardcoded malware names)
# ═══════════════════════════════════════════════════════════════════════

LOLBINS = {
    "mshta.exe","wscript.exe","cscript.exe","regsvr32.exe",
    "rundll32.exe","certutil.exe","bitsadmin.exe","msiexec.exe",
    "installutil.exe","ieexec.exe","msconfig.exe","pcalua.exe",
    "schtasks.exe","at.exe","cmd.exe","powershell.exe","pwsh.exe",
    "wmic.exe","odbcconf.exe","xwizard.exe","appsyncpublishingtool.exe",
}

SUSPICIOUS_PATHS = ["\\\\temp\\\\","\\\\tmp\\\\","\\\\appdata\\\\","\\\\public\\\\",
                    "\\\\downloads\\\\","\\\\recycle","\\\\programdata\\\\"]

SUSPICIOUS_PARENTS = {
    "lsass.exe":    {"cmd.exe","powershell.exe","wscript.exe","mshta.exe"},
    "svchost.exe":  {"explorer.exe","cmd.exe","powershell.exe"},
    "services.exe": {"cmd.exe","powershell.exe","explorer.exe"},
}

HIGH_ACCESS_MASKS = {"0x1fffff","0x1f0fff","0x143a"}

ENCODED_PATTERNS = ["-enc","-encodedcommand","frombase64","invoke-expression",
                    "iex(","bypass","hidden","downloadstring","webclient"]


def heuristic_process(n, d, G, pid_to_name):
    score = 0; reasons = []
    name   = str(d.get("label","")).lower()
    args   = str(d.get("args","")).lower()
    path   = str(d.get("path","")).lower()
    ppid   = d.get("ppid","")
    parent = pid_to_name.get(ppid, "").lower()

    if any(lb in name for lb in LOLBINS):
        score += 2; reasons.append("lolbin")
    if any(p in path for p in SUSPICIOUS_PATHS):
        score += 3; reasons.append(f"suspicious-path:{path[:40]}")
    if any(p in args for p in ENCODED_PATTERNS):
        score += 4; reasons.append("encoded-cmdline")
    for ext in [".hta",".vbs",".js",".ps1",".bat",".cmd",".jse",".vbe",".wsf"]:
        if ext in args:
            score += 2; reasons.append(f"script-arg:{ext}"); break
    if any(x in args for x in ["_r_e_a_d","decrypt","ransom","readme","!!!","---"]):
        score += 4; reasons.append("ransom-note-arg")
    for child_kw, bad_parents in SUSPICIOUS_PARENTS.items():
        if child_kw in name and any(bp in parent for bp in bad_parents):
            score += 5; reasons.append(f"abnormal-parent:{parent}->{name}")
    if not path or path in ["-",""]:
        score += 1; reasons.append("no-path")

    ext_conns = [nb for nb in G.predecessors(n)
                 if G.nodes[nb].get("is_external") and
                 G.nodes[nb].get("node_type") == "network_conn"]
    if ext_conns:
        score += len(ext_conns); reasons.append(f"{len(ext_conns)}x-c2-conn")

    inj = [nb for nb in G.predecessors(n)
           if G.nodes[nb].get("node_type") == "memory_region" and
           G.nodes[nb].get("source") == "malfind"]
    if inj:
        score += len(inj) * 3; reasons.append(f"{len(inj)}x-injected-mem")

    handles = [nb for nb in G.predecessors(n)
               if G.nodes[nb].get("node_type") == "handle" and
               G.nodes[nb].get("is_suspicious")]
    if handles:
        score += 6; reasons.append("lsass-full-access")

    if d.get("wow64") and score > 3:
        score += 1; reasons.append("wow64-suspicious")
    if not d.get("in_pslist", True):
        score += 8; reasons.append("hidden-process")

    in_deg = G.in_degree(n)
    if in_deg > 50 and not any(x in name for x in
                                ["system","svchost","explorer","chrome",
                                 "searchindexer","spoolsv","lsass"]):
        score += 2; reasons.append(f"high-in-degree:{in_deg}")

    children = [G.nodes[nb] for nb in G.successors(n)
                if G.nodes[nb].get("node_type") == "process"]
    if any(any(lb in str(c.get("label","")).lower() for lb in LOLBINS) for c in children):
        score += 2; reasons.append("spawned-lolbin-child")

    return score, reasons


def heuristic_memory(d):
    score = 0; reasons = []
    prot   = d.get("protection","")
    src    = d.get("source","")
    has_mz = d.get("has_mz_header", False)
    disasm = str(d.get("disasm","")).lower()
    private= d.get("private_memory", 0)
    fname  = d.get("backing_file","")

    if src == "malfind":
        score += 4; reasons.append("malfind-rwx")
    if "execute_readwrite" in prot.lower():
        score += 2; reasons.append("rwx")
    if has_mz:
        score += 5; reasons.append("mz-header-injected-pe")
    if private and not fname:
        score += 1; reasons.append("private-no-backing-file")
    for pat in ["eb ","ff d0","ff e0","call eax","jmp esp","push ebp"]:
        if pat in disasm:
            score += 2; reasons.append(f"shellcode-opcode:{pat.strip()}"); break
    return score, reasons


def heuristic_network(d):
    score = 0; reasons = []
    state  = d.get("state","")
    fport  = d.get("foreign_port", 0)
    owner  = str(d.get("owner","")).lower()

    if d.get("is_external"):
        score += 2; reasons.append("external-ip")
    if state == "ESTABLISHED":
        score += 1; reasons.append("established")
    if fport in [4444,1337,31337,8080,8443,9090]:
        score += 4; reasons.append(f"suspicious-port:{fport}")
    if any(lb in owner for lb in LOLBINS):
        score += 4; reasons.append(f"lolbin-network:{owner}")
    if fport == 80 and "chrome" not in owner and "firefox" not in owner:
        score += 1; reasons.append("http-non-browser")
    return score, reasons


# ═══════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════

def load_graph(path):
    if os.path.isdir(path):
        path = os.path.join(path, "graph.json")
    if not os.path.exists(path):
        print(f"[ERROR] Not found: {path}"); sys.exit(1)
    with open(path) as f:
        data = json.load(f)
    G = json_graph.node_link_graph(data, edges="links", directed=True)
    return G, os.path.dirname(os.path.abspath(path))

def nodes_of_type(G, t):
    return [(n, d) for n, d in G.nodes(data=True) if d.get("node_type") == t]

def safe(v):
    if v is None: return None
    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)): return None
    return v

def label_severity(score):
    if score >= 12: return "CRITICAL"
    if score >= 7:  return "HIGH"
    if score >= 3:  return "MEDIUM"
    return "LOW"


# ═══════════════════════════════════════════════════════════════════════
# ANALYSIS SECTIONS
# ═══════════════════════════════════════════════════════════════════════

def analyze_summary(G):
    node_types = collections.Counter(d.get("node_type","?") for _, d in G.nodes(data=True))
    edge_types = collections.Counter(d.get("edge_type","?") for _, _, d in G.edges(data=True))
    sus        = [(n,d) for n,d in G.nodes(data=True) if d.get("is_suspicious")]
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
    pid_to_name = {d.get("pid"): d.get("label","?")
                   for _, d in nodes_of_type(G, "process")}
    rows = []
    for n, d in nodes_of_type(G, "process"):
        score, reasons = heuristic_process(n, d, G, pid_to_name)
        rows.append({
            "node_id":            n,
            "name":               d.get("label",""),
            "pid":                safe(d.get("pid")),
            "ppid":               safe(d.get("ppid")),
            "parent_name":        pid_to_name.get(d.get("ppid",""), "?"),
            "session":            safe(d.get("session")),
            "wow64":              d.get("wow64", False),
            "in_pslist":          d.get("in_pslist", True),
            "in_psscan":          d.get("in_psscan", True),
            "create_time":        d.get("create_time",""),
            "args":               d.get("args",""),
            "path":               d.get("path",""),
            "degree_in":          G.in_degree(n),
            "degree_out":         G.out_degree(n),
            "is_suspicious_flag": d.get("is_suspicious", False),
            "heuristic_score":    score,
            "severity":           label_severity(score),
            "reasons":            reasons,
        })
    return sorted(rows, key=lambda x: x["heuristic_score"], reverse=True)

def analyze_hidden(G):
    return [{"name": d.get("label",""), "pid": safe(d.get("pid")),
             "ppid": safe(d.get("ppid")), "create_time": d.get("create_time",""),
             "severity": "CRITICAL",
             "reason": "present in psscan but absent from pslist — DKOM hiding"}
            for _, d in nodes_of_type(G, "process") if not d.get("in_pslist", True)]

def analyze_entry_points(G):
    pid_to_name = {d.get("pid"): d.get("label","?")
                   for _, d in nodes_of_type(G, "process")}
    results = []
    for n, d in nodes_of_type(G, "process"):
        name = str(d.get("label","")).lower()
        args = str(d.get("args","")).lower()
        score = 0; signals = []

        if any(lb in name for lb in LOLBINS):
            score += 2; signals.append("lolbin")
        if any(G.nodes[nb].get("is_external") for nb in
               list(G.predecessors(n)) + list(G.successors(n))):
            score += 2; signals.append("external-network")
        for ext in [".hta",".vbs",".js",".ps1",".bat",".jse",".vbe"]:
            if ext in args:
                score += 2; signals.append(f"script:{ext}"); break
        if any(x in args for x in ENCODED_PATTERNS):
            score += 3; signals.append("encoded/obfuscated-args")
        if any(x in args for x in ["_r_e_a_d","ransom","decrypt","!!!"]):
            score += 3; signals.append("ransom-note-reference")

        if score >= 2:
            results.append({"name": d.get("label",""), "pid": safe(d.get("pid")),
                            "ppid": safe(d.get("ppid")),
                            "parent": pid_to_name.get(d.get("ppid",""), "?"),
                            "entry_score": score, "signals": signals,
                            "severity": label_severity(score * 2),
                            "args": d.get("args",""), "create_time": d.get("create_time","")})
    return sorted(results, key=lambda x: x["entry_score"], reverse=True)

def analyze_network(G):
    results = []
    for n, d in nodes_of_type(G, "network_conn"):
        score, reasons = heuristic_network(d)
        if score > 0:
            results.append({
                "proto": d.get("proto",""), "local_addr": d.get("local_addr",""),
                "local_port": safe(d.get("local_port")),
                "foreign_addr": d.get("foreign_addr",""),
                "foreign_port": safe(d.get("foreign_port")),
                "state": d.get("state",""), "owner": d.get("owner",""),
                "is_external": d.get("is_external", False),
                "heuristic_score": score, "severity": label_severity(score),
                "reasons": reasons,
            })
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)

def analyze_injections(G):
    pid_to_name = {d.get("pid"): d.get("label","?")
                   for _, d in nodes_of_type(G, "process")}
    all_disasms = [str(d.get("disasm",""))[:60]
                   for _, d in nodes_of_type(G, "memory_region")
                   if d.get("source") == "malfind"]
    shared_stub = len(set(all_disasms)) == 1 and len(all_disasms) > 1
    results = []
    for n, d in nodes_of_type(G, "memory_region"):
        score, reasons = heuristic_memory(d)
        if score > 0:
            pid = d.get("pid","")
            if shared_stub and d.get("source") == "malfind":
                reasons.append("shared-stub-across-processes")
            results.append({
                "pid": safe(pid), "process_name": pid_to_name.get(pid,"?"),
                "start_vpn": d.get("start_vpn",""), "end_vpn": d.get("end_vpn",""),
                "protection": d.get("protection",""),
                "private": bool(d.get("private_memory",0)),
                "backing_file": d.get("backing_file",""),
                "has_mz_header": d.get("has_mz_header", False),
                "disasm": str(d.get("disasm",""))[:120],
                "source": d.get("source",""),
                "heuristic_score": score, "severity": label_severity(score),
                "reasons": reasons,
            })
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)

def analyze_credentials(G):
    pid_to_name = {d.get("pid"): d.get("label","?")
                   for _, d in nodes_of_type(G, "process")}
    results = []
    for n, d in nodes_of_type(G, "handle"):
        access  = str(d.get("granted_access","")).lower()
        is_full = access in HIGH_ACCESS_MASKS
        if "lsass" in str(d.get("name","")).lower() or is_full:
            pid = d.get("pid","")
            results.append({
                "holder_process": pid_to_name.get(pid,"?"), "holder_pid": safe(pid),
                "target": d.get("name",""), "handle_type": d.get("handle_type",""),
                "granted_access": access, "is_full_access": is_full,
                "severity": "CRITICAL" if is_full else "HIGH",
                "reason": "Full process access to lsass — T1003 credential dumping",
            })
    return results

def analyze_drivers(G):
    results = []
    for n, d in nodes_of_type(G, "driver"):
        svckey = d.get("service_key","")
        score = 0; reasons = []
        if not svckey:
            score += 5; reasons.append("no-service-key (phantom/rootkit driver)")
        if score > 0:
            results.append({"driver_name": d.get("driver_name",""),
                            "service_key": svckey, "start": safe(d.get("start")),
                            "size": safe(d.get("size")), "heuristic_score": score,
                            "severity": label_severity(score), "reasons": reasons})
    return sorted(results, key=lambda x: x["heuristic_score"], reverse=True)

def analyze_attack_chain(G, processes, entry_points, injections, credentials, network):
    steps = []
    if entry_points:
        e = entry_points[0]
        steps.append({"step": 1, "tactic": "Initial Access / Execution",
                      "mitre": "T1218 / T1566",
                      "detail": f"{e['name']} (PID {e['pid']}) via {', '.join(e['signals'])}",
                      "evidence": e["args"][:120]})

    injected_pids = list({i["process_name"] for i in injections if i.get("source") == "malfind"})
    if injected_pids:
        shared = any("shared-stub" in str(i.get("reasons","")) for i in injections)
        steps.append({"step": 2, "tactic": "Defense Evasion / Process Injection",
                      "mitre": "T1055",
                      "detail": f"Shellcode in {len(injected_pids)} process(es): "
                                f"{', '.join(injected_pids)}"
                                + (" [identical stub = same campaign]" if shared else ""),
                      "evidence": injections[0].get("disasm","")[:80] if injections else ""})

    c2 = [n for n in network if n.get("is_external") and n.get("state") == "ESTABLISHED"]
    if c2:
        steps.append({"step": 3, "tactic": "Command & Control", "mitre": "T1071",
                      "detail": f"{len(c2)} ESTABLISHED connections to "
                                f"{len({n['foreign_addr'] for n in c2})} IPs "
                                f"via {', '.join({n['owner'] for n in c2})}",
                      "evidence": str(list({n['foreign_addr'] for n in c2})[:4])})

    if credentials:
        steps.append({"step": 4, "tactic": "Credential Access", "mitre": "T1003.001",
                      "detail": f"lsass accessed with FULL rights by "
                                f"{', '.join(set(c['holder_process'] for c in credentials))}",
                      "evidence": f"GrantedAccess: {credentials[0]['granted_access']}"})

    sys_procs = {"system","smss.exe","csrss.exe","wininit.exe","winlogon.exe",
                 "services.exe","lsass.exe","lsm.exe","svchost.exe",
                 "spoolsv.exe","dwm.exe"}
    entry_pids = {e["pid"] for e in entry_points}
    for p in processes:
        if (p["heuristic_score"] >= 7 and
                str(p["name"]).lower() not in sys_procs and
                p["pid"] not in entry_pids):
            steps.append({"step": 5, "tactic": "Execution / Impact", "mitre": "T1486",
                          "detail": f"High-score: {p['name']} (PID {p['pid']}) "
                                    f"score={p['heuristic_score']} parent={p['parent_name']}",
                          "evidence": p.get("args","")[:80]})
            break

    verdict = (
        "CRITICAL — Active malware: injection + C2 + credential access detected"
        if len(steps) >= 4 else
        "HIGH — Multiple malicious behaviours detected" if len(steps) >= 2 else
        "MEDIUM — Suspicious activity detected" if steps else
        "LOW — No significant threats identified"
    )
    return {"steps": steps, "overall_verdict": verdict,
            "max_process_score": max((p["heuristic_score"] for p in processes), default=0)}


# ═══════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    G, out_dir = load_graph(path)
    print(f"[*] Loaded: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    print("[*] Running behavioural heuristics...")

    processes   = analyze_processes(G)
    entry_pts   = analyze_entry_points(G)
    network     = analyze_network(G)
    injections  = analyze_injections(G)
    credentials = analyze_credentials(G)
    chain       = analyze_attack_chain(G, processes, entry_pts,
                                       injections, credentials, network)

    report = {
        "meta":             {"tool": "analyze_graph.py v2", "source": path, "version": "2.0"},
        "summary":          analyze_summary(G),
        "attack_chain":     chain,
        "entry_points":     entry_pts,
        "processes":        processes,
        "hidden_processes": analyze_hidden(G),
        "network":          network,
        "injections":       injections,
        "credentials":      credentials,
        "drivers":          analyze_drivers(G),
    }

    out_path = os.path.join(out_dir, "analysis_report.json")
    with open(out_path, "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[✅] Report saved: {out_path}")
    print(f"\n{'='*55}")
    print(f"  VERDICT : {chain['overall_verdict']}")
    print(f"  Steps   : {len(chain['steps'])}")
    print(f"  Max score:{chain['max_process_score']}")
    if entry_pts:
        print(f"  Entry   : {entry_pts[0]['name']} (score {entry_pts[0]['entry_score']})")
    print(f"  Injected: {len({i['process_name'] for i in injections if i.get('source')=='malfind'})}")
    print(f"  C2 conn : {len([n for n in network if n.get('is_external') and n.get('state')=='ESTABLISHED'])}")
    print(f"  Creds   : {'YES' if credentials else 'No'}")
    print(f"{'='*55}")

if __name__ == "__main__":
    main()
