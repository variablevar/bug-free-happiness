#!/usr/bin/env python3

import os, sys, json, glob, pickle, re, math
import pandas as pd
import networkx as nx
from networkx.readwrite import json_graph

PRIVATE_IP = re.compile(
    r"^(10\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|192\\.168\\.|127\\.|::1|0\\.0\\.0\\.0|\\*)"
)

# ── XML safety ────────────────────────────────────────────────────────────────
_BAD_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

def _xml_safe(v):
    if not isinstance(v, str):
        v = str(v)
    v = v.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    return _BAD_XML.sub("", v)[:500]


# ── Helpers ───────────────────────────────────────────────────────────────────
def find(folder, pattern):
    hits = glob.glob(os.path.join(folder, pattern))
    return hits[0] if hits else None

def load(folder, pattern):
    p = find(folder, pattern)
    if p:
        try:
            return pd.read_csv(p, low_memory=False)
        except Exception:
            pass
    return pd.DataFrame()

def safe_str(v):
    if not isinstance(v, str):
        try:
            if pd.isna(v):
                return ""
        except (TypeError, ValueError):
            pass
        v = str(v)
    return _xml_safe(v)


def safe_int(v, default=0):
    try:
        return int(v)
    except Exception:
        return default

def safe_float(v, default=None):
    try:
        f = float(v)
        return None if math.isnan(f) or math.isinf(f) else f
    except Exception:
        return default

# ── Node ID helpers ───────────────────────────────────────────────────────────
def pid_node(pid):   return f"process_{pid}"
def tid_node(tid):   return f"thread_{tid}"
def dll_node(path):  return f"dll_{hash(path) & 0xFFFFFF}"
def mem_node(vpn, pid): return f"mem_{pid}_{vpn}"
def net_node(offset): return f"net_{offset}"
def ip_node(addr):   return f"ip_{addr.replace('.','_').replace(':','_')}"
def drv_node(name):  return f"driver_{hash(name) & 0xFFFFFF}"
kernel_node = "kernel_system"

# ── NaN-safe JSON encoder ─────────────────────────────────────────────────────
class NaNSafeEncoder(json.JSONEncoder):
    def iterencode(self, o, _one_shot=False):
        for chunk in super().iterencode(o, _one_shot):
            chunk = chunk.replace(": NaN",       ": null")
            chunk = chunk.replace(":NaN",        ":null")
            chunk = chunk.replace(": Infinity",  ": null")
            chunk = chunk.replace(":Infinity",   ":null")
            chunk = chunk.replace(": -Infinity", ": null")
            chunk = chunk.replace(":-Infinity",  ":null")
            yield chunk

# ── GraphML sanitiser ─────────────────────────────────────────────────────────
def sanitize_for_graphml(G):
    H = G.copy()
    for _, data in H.nodes(data=True):
        for k, v in list(data.items()):
            if v is None:                data[k] = ""
            elif isinstance(v, bool):    data[k] = int(v)
            elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                                         data[k] = ""
            elif isinstance(v, (list, dict, set)): data[k] = _xml_safe(str(v))
            elif isinstance(v, str):     data[k] = _xml_safe(v)
    for _, _, data in H.edges(data=True):
        for k, v in list(data.items()):
            if v is None:                data[k] = ""
            elif isinstance(v, bool):    data[k] = int(v)
            elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                                         data[k] = ""
            elif isinstance(v, (list, dict, set)): data[k] = _xml_safe(str(v))
            elif isinstance(v, str):     data[k] = _xml_safe(v)
    return H


# ── Build Graph ───────────────────────────────────────────────────────────────
def build(folder):
    G = nx.DiGraph()

    pslist  = load(folder, "windows_pslist*.csv")
    psscan  = load(folder, "windows_psscan*.csv")
    pstree  = load(folder, "windows_pstree*.csv")
    malfind = load(folder, "windows_malfind*.csv")
    netscan = load(folder, "windows_netscan*.csv")
    cmdline = load(folder, "windows_cmdline*.csv")
    dlllist = load(folder, "windows_dlllist*.csv")
    handles = load(folder, "windows_handles*.csv")
    threads = load(folder, "windows_threads*.csv")
    vadinfo = load(folder, "windows_vadinfo*.csv")
    drvscan = load(folder, "windows_driverscan*.csv")

    mal_path = os.path.join(folder, "filtered_malicious.json")
    suspicious_pids = set()
    if os.path.exists(mal_path):
        with open(mal_path) as f:
            mal = json.load(f)
        suspicious_pids = set(mal.get("_meta", {}).get("suspicious_pids", []))
        print(f"  [*] Suspicious PIDs from filter: {suspicious_pids}")

    # Kernel node
    G.add_node(kernel_node, node_type="kernel", label="KERNEL")

    # Process nodes
    proc_df = pstree if not pstree.empty else pslist
    pid_to_row = {}
    for _, r in proc_df.iterrows():
        try:
            pid = int(r["PID"])
        except Exception:
            continue
        nid = pid_node(pid)
        pid_to_row[pid] = r
        is_sus = pid in suspicious_pids
        G.add_node(nid,
            node_type="process",
            label=safe_str(r.get("ImageFileName", "")),
            pid=pid,
            ppid=safe_int(r.get("PPID", 0)),
            threads=safe_int(r.get("Threads", 0)),
            handles=safe_int(r.get("Handles", 0)),
            session=safe_float(r.get("SessionId")),
            wow64=int(bool(r.get("Wow64", False))),
            create_time=safe_str(r.get("CreateTime", "")),
            exit_time=safe_str(r.get("ExitTime", "")),
            cmd=safe_str(r.get("Cmd", "")),
            path=safe_str(r.get("Path", "")),
            is_suspicious=int(is_sus),
            in_pslist=int(pid in set(pslist["PID"].dropna().astype(int)) if not pslist.empty else True),
            in_psscan=int(pid in set(psscan["PID"].dropna().astype(int)) if not psscan.empty else True),
        )

    # Cmdline args → process nodes
    if not cmdline.empty:
        for _, r in cmdline.iterrows():
            try:
                pid = int(r["PID"])
            except Exception:
                continue
            nid = pid_node(pid)
            if G.has_node(nid):
                G.nodes[nid]["args"] = safe_str(r.get("Args", ""))

    # Process → Process (spawned_by)
    for pid, r in pid_to_row.items():
        try:
            ppid = int(r["PPID"])
        except Exception:
            continue
        src = pid_node(pid)
        dst = pid_node(ppid)
        if G.has_node(src) and G.has_node(dst):
            try:
                ct = pd.Timestamp(r.get("CreateTime", ""))
                pt_row = pid_to_row.get(ppid)
                delta = (ct - pd.Timestamp(pt_row.get("CreateTime", ""))).total_seconds() if pt_row is not None else 0.0
            except Exception:
                delta = 0.0
            G.add_edge(src, dst, edge_type="spawned_by", time_delta_seconds=delta)

    # Thread nodes
    if not threads.empty:
        for _, r in threads.iterrows():
            try:
                tid = int(r["TID"])
                pid = int(r["PID"])
            except Exception:
                continue
            nid = tid_node(tid)
            sp  = safe_str(r.get("StartPath", ""))
            w32 = safe_str(r.get("Win32StartPath", ""))
            is_sus = any(x in sp.lower() for x in ["temp","appdata","public"]) or sp == "" or w32 == ""
            G.add_node(nid,
                node_type="thread", label=f"TID:{tid}",
                tid=tid, pid=pid,
                start_address=safe_str(r.get("StartAddress", "")),
                start_path=sp, win32_start_path=w32,
                create_time=safe_str(r.get("CreateTime", "")),
                is_suspicious=int(is_sus),
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type="belongs_to",
                    start_path_suspicious=int(is_sus),
                    start_path_empty=int(sp == ""),
                )

    # DLL nodes
    if not dlllist.empty:
        for _, r in dlllist.iterrows():
            try:
                pid = int(r["PID"])
            except Exception:
                continue
            path = safe_str(r.get("Path", ""))
            name = safe_str(r.get("Name", ""))
            key  = path if path else name
            nid  = dll_node(key)
            sus  = any(x in path.lower() for x in ["temp","appdata","public"]) or path == ""
            if not G.has_node(nid):
                G.add_node(nid,
                    node_type="dll", label=name,
                    name=name, path=path, is_suspicious=int(sus),
                )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type="loaded_into",
                    load_time=safe_str(r.get("LoadTime", "")),
                    load_count=safe_int(r.get("LoadCount", 0)),
                    path_suspicious=int(sus),
                    path_empty=int(path == ""),
                )

    # VAD memory regions
    if not vadinfo.empty:
        for _, r in vadinfo.iterrows():
            try:
                pid = int(r["PID"])
            except Exception:
                continue
            vpn   = safe_str(r.get("Start VPN", ""))
            nid   = mem_node(vpn, pid)
            prot  = safe_str(r.get("Protection", ""))
            priv  = safe_int(r.get("PrivateMemory", 0))
            fname = safe_str(r.get("File", ""))
            sus   = "EXECUTE" in prot and priv == 1 and fname == ""
            G.add_node(nid,
                node_type="memory_region", label=f"MEM:{vpn}",
                pid=pid, start_vpn=vpn,
                end_vpn=safe_str(r.get("End VPN", "")),
                protection=prot, private_memory=priv,
                commit_charge=safe_int(r.get("CommitCharge", 0)),
                backing_file=fname,
                is_rwx=int("PAGE_EXECUTE_READWRITE" in prot),
                is_suspicious=int(sus),
                source="vadinfo",
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type="allocated_in",
                    is_rwx=int("PAGE_EXECUTE_READWRITE" in prot),
                    private=int(priv),
                    has_backing_file=int(fname != ""),
                )

    # Malfind injected regions
    if not malfind.empty:
        rwx = malfind[malfind["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)]
        for _, r in rwx.iterrows():
            try:
                pid = int(r["PID"])
            except Exception:
                continue
            vpn  = safe_str(r.get("Start VPN", ""))
            nid  = mem_node(f"mal_{vpn}", pid)
            hexd = safe_str(r.get("Hexdump", ""))
            has_mz = "MZ" in hexd or "4d5a" in hexd.lower()
            G.add_node(nid,
                node_type="memory_region", label=f"INJECT:{vpn}",
                pid=pid, start_vpn=vpn,
                end_vpn=safe_str(r.get("End VPN", "")),
                protection=safe_str(r.get("Protection", "")),
                private_memory=safe_int(r.get("PrivateMemory", 0)),
                commit_charge=safe_int(r.get("CommitCharge", 0)),
                has_mz_header=int(has_mz),
                disasm=safe_str(r.get("Disasm", ""))[:200],
                is_rwx=1, is_suspicious=1,
                source="malfind",
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type="injected_into",
                    has_mz_header=int(has_mz),
                    is_rwx=1,
                )

    # Network connections
    if not netscan.empty:
        for _, r in netscan.iterrows():
            offset  = safe_str(r.get("Offset", ""))
            foreign = safe_str(r.get("ForeignAddr", ""))
            state   = safe_str(r.get("State", ""))
            owner   = safe_str(r.get("Owner", ""))
            fport   = safe_int(r.get("ForeignPort", 0))
            proto   = safe_str(r.get("Proto", ""))
            is_ext  = (state == "ESTABLISHED"
                       and not PRIVATE_IP.match(foreign)
                       and foreign not in ["*", "", "0.0.0.0"])
            net_nid = net_node(offset)
            G.add_node(net_nid,
                node_type="network_conn", label=f"{proto}->{foreign}:{fport}",
                proto=proto,
                local_addr=safe_str(r.get("LocalAddr", "")),
                local_port=safe_int(r.get("LocalPort", 0)),
                foreign_addr=foreign, foreign_port=fport,
                state=state, owner=owner,
                is_external=int(is_ext), is_suspicious=int(is_ext),
            )
            try:
                pid  = int(r["PID"])
                pnid = pid_node(pid)
                if G.has_node(pnid):
                    G.add_edge(net_nid, pnid, edge_type="connects_from", state=state)
            except Exception:
                pass
            if is_ext and foreign not in ["*", ""]:
                ip_nid = ip_node(foreign)
                if not G.has_node(ip_nid):
                    G.add_node(ip_nid,
                        node_type="ip_address", label=foreign,
                        address=foreign, is_external=1,
                    )
                G.add_edge(net_nid, ip_nid, edge_type="connects_to", port=fport, proto=proto)

    # Handle nodes (lsass credential access)
    if not handles.empty:
        HIGH_ACCESS = {"0x1fffff", "0x1f0fff", "0x143a"}
        for _, r in handles.iterrows():
            try:
                pid = int(r["PID"])
            except Exception:
                continue
            htype  = safe_str(r.get("Type", ""))
            hname  = safe_str(r.get("Name", ""))
            access = safe_str(r.get("GrantedAccess", "")).lower()
            hval   = safe_str(r.get("HandleValue", ""))
            is_sus = (htype == "Process" and "lsass" in hname.lower() and access in HIGH_ACCESS)
            if is_sus:
                h_nid = f"handle_{pid}_{hval}"
                G.add_node(h_nid,
                    node_type="handle", label=f"HANDLE:{htype}",
                    pid=pid, handle_type=htype,
                    granted_access=access, name=hname,
                    is_suspicious=1,
                )
                pnid = pid_node(pid)
                if G.has_node(pnid):
                    G.add_edge(h_nid, pnid,
                        edge_type="owned_by",
                        granted_access=access, handle_type=htype,
                    )
                for lp, lr in pid_to_row.items():
                    if "lsass" in safe_str(lr.get("ImageFileName", "")).lower():
                        target_nid = pid_node(lp)
                        if G.has_node(target_nid):
                            G.add_edge(h_nid, target_nid,
                                edge_type="points_to",
                                granted_access=access,
                                is_full_access=int(access == "0x1fffff"),
                            )
                        break

    # Driver nodes
    if not drvscan.empty:
        for _, r in drvscan.iterrows():
            name   = safe_str(r.get("Driver Name", ""))
            svckey = safe_str(r.get("Service Key", ""))
            nid    = drv_node(name)
            raw_size  = safe_str(r.get("Size", ""))
            raw_start = safe_str(r.get("Start", ""))
            try:
                size_int = int(raw_size, 16) if raw_size.startswith("0x") else int(raw_size)
            except Exception:
                size_int = 0
            try:
                start_int = int(raw_start, 16) if raw_start.startswith("0x") else int(raw_start)
            except Exception:
                start_int = 0
            G.add_node(nid,
                node_type="driver", label=name,
                driver_name=name, service_key=svckey,
                start=start_int, size=size_int,
                is_suspicious=int(svckey == ""),
            )
            G.add_edge(nid, kernel_node,
                edge_type="loaded_in_kernel",
                has_service_key=int(svckey != ""),
            )

    print(f"\\n[OK] Graph built:")
    print(f"  Nodes: {G.number_of_nodes()}")
    print(f"  Edges: {G.number_of_edges()}")
    node_types = {}
    for _, d in G.nodes(data=True):
        t = d.get("node_type", "unknown")
        node_types[t] = node_types.get(t, 0) + 1
    for t, c in sorted(node_types.items()):
        print(f"    {t}: {c}")
    edge_types = {}
    for u, v, d in G.edges(data=True):
        t = d.get("edge_type", "unknown")
        edge_types[t] = edge_types.get(t, 0) + 1
    for t, c in sorted(edge_types.items()):
        print(f"  edge/{t}: {c}")
    return G

# ── Save ──────────────────────────────────────────────────────────────────────
def save_graph(G, folder):
    os.makedirs(folder, exist_ok=True)
    saved = []

    # ── Step 1: JSON first (forces all attrs through NaNSafeEncoder + default=str)
    def replace_none(obj):
        """Recursively replace None (JSON null) with empty string."""
        if isinstance(obj, dict):
            return {k: replace_none(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [replace_none(i) for i in obj]
        elif obj is None:
            return ""
        return obj

    json_path = os.path.join(folder, "graph.json")
    data = json_graph.node_link_data(G, edges="links")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2, cls=NaNSafeEncoder, default=str))
    saved.append(("JSON", json_path))

    clean = replace_none(json.loads(json.dumps(data, cls=NaNSafeEncoder, default=str)))
    G_clean = json_graph.node_link_graph(clean, edges="links", directed=True)

    # ── Step 3: GraphML + GEXF from the clean graph (no None, no bad chars)
    # path = os.path.join(folder, "graph.graphml")
    # nx.write_graphml(G_clean, path)
    # saved.append(("GraphML", path))

    # path = os.path.join(folder, "graph.gexf")
    # nx.write_gexf(G_clean, path)
    # saved.append(("GEXF", path))

    # ── Step 4: Pickle the original G (preserves Python types for ML pipeline)
    path = os.path.join(folder, "graph.pkl")
    with open(path, "wb") as f:
        pickle.dump(G, f)
    saved.append(("Pickle", path))

    print("\n[SAVED] Graph files:")
    for fmt, p in saved:
        print(f"  {fmt:<10} {os.path.basename(p)}  ({os.path.getsize(p)/1024:.1f} KB)")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "."
    folder = os.path.abspath(folder)
    print(f"\\n[*] Building graph from: {folder}")
    G = build(folder)
    save_graph(G, folder)
    print("\\n[Done]")

if __name__ == "__main__":
    main()