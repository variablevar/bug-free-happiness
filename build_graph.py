#!/usr/bin/env python3
"""
build_graph.py  (MalVol-25 aware, v2 — behaviour-based, 0-day ready)

Confirmed column names from actual CSVs:
  pslist/psscan : PID, PPID, ImageFileName, Threads, Handles, SessionId,
                  Wow64, CreateTime, ExitTime
  pstree        : same as pslist (also has Offset(V))
  vadinfo       : PID, Process, Start VPN, End VPN, Protection,
                  CommitCharge, PrivateMemory, File  (NOT "backing_file")
  malfind       : PID, Process, Start VPN, End VPN, Protection,
                  CommitCharge, PrivateMemory, Hexdump, Disasm
  threads       : PID, TID, StartAddress, StartPath, Win32StartAddress,
                  Win32StartPath, CreateTime, ExitTime
  netscan       : Offset, Proto, LocalAddr, LocalPort, ForeignAddr,
                  ForeignPort, State, PID, Owner, Created
  handles       : PID, Offset, Type, Name, GrantedAccess, HandleValue
  dlllist       : PID, Process, Base, InLoad, InMem, InInit,
                  Path, LoadTime, LoadCount
  drvscan       : Offset, Start, Size, Service Key, Driver Name, Name

Usage:
  python build_graph.py <csv_folder>
  # filtered_malicious.json must exist in same folder (run filter_malicious.py first)
"""

import os, sys, json, glob, pickle, re, math
import pandas as pd
import networkx as nx
from networkx.readwrite import json_graph

PRIVATE_IP = re.compile(
    r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|::1|0\.0\.0\.0|\*)"
)
SHELLCODE_EB_RE = re.compile(r"(eb\s+[0-9a-f]{2}\s+){3,}", re.IGNORECASE)

LOLBIN_NET = {
    "mshta.exe","wscript.exe","cscript.exe","regsvr32.exe","rundll32.exe",
    "msiexec.exe","certutil.exe","powershell.exe","cmd.exe","bitsadmin.exe",
    "wmic.exe","installutil.exe","regasm.exe","regsvcs.exe","msbuild.exe",
}

LSASS_WHITELIST = {
    "csrss.exe","wininit.exe","lsass.exe","werfault.exe","services.exe",
    "winlogon.exe","taskmgr.exe","msmpeng.exe",
}

HIGH_ACCESS = {"0x1fffff","0x1f0fff","0x143a"}

_BAD_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

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

def _xml_safe(v):
    if not isinstance(v, str):
        v = str(v)
    v = v.encode("utf-8", errors="replace").decode("utf-8", errors="replace")
    return _BAD_XML.sub("", v)[:500]

def safe_str(v, maxlen=500):
    if v is None: return ""
    try:
        if pd.isna(v): return ""
    except (TypeError, ValueError):
        pass
    s = str(v).strip()
    if s in ("nan","N/A","NaT","None","-"): return ""
    return _xml_safe(s)[:maxlen]

def safe_int(v, default=0):
    try: return int(v)
    except Exception: return default

def safe_float(v, default=0.0):
    try:
        f = float(v)
        return default if (math.isnan(f) or math.isinf(f)) else f
    except Exception: return default

def col(df, candidates):
    """Return first matching column (case-insensitive fallback)."""
    for c in candidates:
        if c in df.columns: return c
    low = {x.lower(): x for x in df.columns}
    for c in candidates:
        if c.lower() in low: return low[c.lower()]
    return None

# ── Node ID helpers ───────────────────────────────────────────────────────────
def pid_node(pid):        return f"process_{pid}"
def tid_node(tid):        return f"thread_{tid}"
def dll_node(path):       return f"dll_{hash(path) & 0xFFFFFF}"
def mem_node(vpn, pid):   return f"mem_{pid}_{vpn}"
def net_node(offset):     return f"net_{offset}"
def ip_node(addr):        return f"ip_{re.sub(r'[.:]','_',addr)}"
def drv_node(name):       return f"driver_{hash(name) & 0xFFFFFF}"
KERNEL_NODE = "kernel_system"

# ── NaN-safe JSON encoder ─────────────────────────────────────────────────────
class NaNSafeEncoder(json.JSONEncoder):
    def iterencode(self, o, _one_shot=False):
        for chunk in super().iterencode(o, _one_shot):
            for bad, good in [("NaN","null"),("Infinity","null"),("-Infinity","null")]:
                chunk = chunk.replace(f": {bad}", ": null").replace(f":{bad}", ":null")
            yield chunk

def replace_none(obj):
    if isinstance(obj, dict):  return {k: replace_none(v) for k,v in obj.items()}
    if isinstance(obj, list):  return [replace_none(i) for i in obj]
    if obj is None:            return ""
    return obj

def sanitize_for_graphml(G):
    H = G.copy()
    for _, data in H.nodes(data=True):
        for k, v in list(data.items()):
            if v is None: data[k] = ""
            elif isinstance(v, bool): data[k] = int(v)
            elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)): data[k] = ""
            elif isinstance(v, (list,dict,set)): data[k] = _xml_safe(str(v))
            elif isinstance(v, str): data[k] = _xml_safe(v)
    for _,_,data in H.edges(data=True):
        for k, v in list(data.items()):
            if v is None: data[k] = ""
            elif isinstance(v, bool): data[k] = int(v)
            elif isinstance(v, float) and (math.isnan(v) or math.isinf(v)): data[k] = ""
            elif isinstance(v, (list,dict,set)): data[k] = _xml_safe(str(v))
            elif isinstance(v, str): data[k] = _xml_safe(v)
    return H

# ── Build ─────────────────────────────────────────────────────────────────────
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

    # ── Load filtered_malicious.json ──────────────────────────────────────────
    mal_path = os.path.join(folder, "filtered_malicious.json")
    suspicious_pids  = set()
    pid_suspicion    = {}   # pid -> {"score": int, "reasons": [...]}
    graph_attr_meta  = {}
    label_signals    = {}

    if os.path.exists(mal_path):
        with open(mal_path) as f:
            mal = json.load(f)
        meta = mal.get("_meta", {})
        suspicious_pids = set(meta.get("suspicious_pids", []))
        graph_attr_meta = meta.get("graph_attr", {})
        label_signals   = meta.get("label_signals", {})
        # Build per-pid suspicion score map from behavioural_suspects
        for entry in mal.get("behavioural_suspects", []):
            try:
                pid = int(entry["PID"])
                pid_suspicion[pid] = {
                    "score":   entry.get("_suspicion_score", 0),
                    "reasons": entry.get("_reasons", []),
                }
            except Exception:
                pass
        print(f"  [*] Suspicious PIDs: {len(suspicious_pids)}")
        print(f"  [*] graph_attr: {graph_attr_meta}")
    else:
        print("  [WARN] filtered_malicious.json not found — run filter_malicious.py first")

    # ── PID sets for quick lookup ─────────────────────────────────────────────
    pl_pids = set(pslist["PID"].dropna().astype(int)) if not pslist.empty else set()
    ps_pids = set(psscan["PID"].dropna().astype(int)) if not psscan.empty else set()

    # ── Kernel node ───────────────────────────────────────────────────────────
    G.add_node(KERNEL_NODE, node_type="kernel", label="KERNEL",
               heuristic_score=0, is_suspicious=0)

    # ── Process nodes (uses confirmed column: ImageFileName) ──────────────────
    # pslist has: PID, PPID, ImageFileName, Threads, Handles,
    #             SessionId, Wow64, CreateTime, ExitTime
    proc_df  = pslist if not pslist.empty else pstree
    pid_to_row = {}

    for _, r in proc_df.iterrows():
        try: pid = int(r["PID"])
        except Exception: continue

        pid_to_row[pid] = r
        nid     = pid_node(pid)
        is_sus  = pid in suspicious_pids
        sus_inf = pid_suspicion.get(pid, {"score": 0, "reasons": []})
        name    = safe_str(r.get("ImageFileName", ""))

        G.add_node(nid,
            node_type        = "process",
            label            = name,
            pid              = pid,
            ppid             = safe_int(r.get("PPID", 0)),
            name             = name,
            threads          = safe_int(r.get("Threads", 0)),
            handles          = safe_int(r.get("Handles", 0)),
            session_id       = safe_str(r.get("SessionId", "")),
            wow64            = int(str(r.get("Wow64","False")).lower() == "true"),
            create_time      = safe_str(r.get("CreateTime", "")),
            exit_time        = safe_str(r.get("ExitTime", "")),
            in_pslist        = int(pid in pl_pids),
            in_psscan        = int(pid in ps_pids),
            is_suspicious    = int(is_sus),
            heuristic_score  = sus_inf["score"],
            suspicion_reasons= str(sus_inf["reasons"]),
        )

    # ── Cmdline args → enrich process nodes ──────────────────────────────────
    # cmdline columns: PID, Process, Args
    if not cmdline.empty:
        args_col = col(cmdline, ["Args","Cmdline","CommandLine"])
        if args_col:
            for _, r in cmdline.iterrows():
                try: pid = int(r["PID"])
                except Exception: continue
                nid = pid_node(pid)
                if G.has_node(nid):
                    G.nodes[nid]["args"] = safe_str(r.get(args_col, ""), maxlen=300)

    # ── Process → Process (spawned_by) ────────────────────────────────────────
    for pid, r in pid_to_row.items():
        try: ppid = int(r["PPID"])
        except Exception: continue
        src, dst = pid_node(pid), pid_node(ppid)
        if not (G.has_node(src) and G.has_node(dst)): continue
        try:
            ct   = pd.Timestamp(r.get("CreateTime",""))
            pt_r = pid_to_row.get(ppid)
            delta = (ct - pd.Timestamp(pt_r.get("CreateTime",""))).total_seconds() \
                    if pt_r is not None else 0.0
            if math.isnan(delta) or math.isinf(delta): delta = 0.0
        except Exception:
            delta = 0.0
        G.add_edge(src, dst, edge_type="spawned_by", time_delta_seconds=round(delta, 2))

    # ── Thread nodes ──────────────────────────────────────────────────────────
    # threads columns: PID, TID, StartAddress, StartPath, Win32StartAddress,
    #                  Win32StartPath, CreateTime, ExitTime
    if not threads.empty:
        for _, r in threads.iterrows():
            try:
                tid = int(r["TID"])
                pid = int(r["PID"])
            except Exception: continue
            nid = tid_node(tid)
            sp  = safe_str(r.get("StartPath",""))
            w32 = safe_str(r.get("Win32StartPath",""))
            is_sus = any(x in sp.lower() for x in ["temp","appdata","public"]) \
                     or (sp == "" and pid not in {4})   # PID 4 = System, always has blank path
            G.add_node(nid,
                node_type        = "thread",
                label            = f"TID:{tid}",
                tid              = tid,
                pid              = pid,
                start_address    = safe_str(r.get("StartAddress","")),
                start_path       = sp,
                win32_start_path = w32,
                create_time      = safe_str(r.get("CreateTime","")),
                is_suspicious    = int(is_sus),
                heuristic_score  = 2 if is_sus else 0,
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type            = "belongs_to",
                    start_path_suspicious= int(is_sus),
                    start_path_empty     = int(sp == ""),
                )

    # ── DLL nodes ────────────────────────────────────────────────────────────
    # dlllist columns: PID, Process, Base, Path, LoadTime, LoadCount, ...
    if not dlllist.empty:
        path_c = col(dlllist, ["Path","FullPath","Mapped Path"])
        name_c = col(dlllist, ["Name","DllName"])
        for _, r in dlllist.iterrows():
            try: pid = int(r["PID"])
            except Exception: continue
            path = safe_str(r.get(path_c,"")) if path_c else ""
            name = safe_str(r.get(name_c,"")) if name_c else os.path.basename(path)
            key  = path if path else name
            nid  = dll_node(key)
            sus  = any(x in path.lower() for x in ["temp","appdata","public"]) or path == ""
            if not G.has_node(nid):
                G.add_node(nid,
                    node_type       = "dll",
                    label           = name,
                    name            = name,
                    path            = path,
                    is_suspicious   = int(sus),
                    heuristic_score = 2 if sus else 0,
                )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type       = "loaded_into",
                    load_count      = safe_int(r.get("LoadCount",0)),
                    path_suspicious = int(sus),
                    path_empty      = int(path == ""),
                )

    # ── VAD memory regions ────────────────────────────────────────────────────
    # vadinfo columns: PID, Process, Start VPN, End VPN, Tag, Protection,
    #                  CommitCharge, PrivateMemory, Parent, File, File output
    if not vadinfo.empty:
        for _, r in vadinfo.iterrows():
            try: pid = int(r["PID"])
            except Exception: continue
            vpn   = safe_str(r.get("Start VPN",""))        # ← correct column name
            nid   = mem_node(vpn, pid)
            prot  = safe_str(r.get("Protection",""))
            priv  = safe_int(r.get("PrivateMemory",0))
            fname = safe_str(r.get("File",""))              # ← correct column name
            is_rwx= int("PAGE_EXECUTE_READWRITE" in prot)
            sus   = is_rwx == 1 and priv == 1 and fname == ""
            G.add_node(nid,
                node_type       = "memory_region",
                label           = f"MEM:{vpn}",
                pid             = pid,
                start_vpn       = vpn,
                end_vpn         = safe_str(r.get("End VPN","")),   # ← correct column name
                protection      = prot,
                private_memory  = priv,
                commit_charge   = safe_int(r.get("CommitCharge",0)),
                backing_file    = fname,
                is_rwx          = is_rwx,
                is_suspicious   = int(sus),
                heuristic_score = 4 if sus else 0,
                source          = "vadinfo",
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type        = "allocated_in",
                    is_rwx           = is_rwx,
                    private          = priv,
                    has_backing_file = int(fname != ""),
                )

    # ── Malfind injected regions ──────────────────────────────────────────────
    # malfind columns: PID, Process, Start VPN, End VPN, Protection,
    #                  CommitCharge, PrivateMemory, Hexdump, Disasm
    if not malfind.empty:
        rwx = malfind[malfind["Protection"].str.contains("PAGE_EXECUTE_READWRITE", na=False)]
        for _, r in rwx.iterrows():
            try: pid = int(r["PID"])
            except Exception: continue
            vpn    = safe_str(r.get("Start VPN",""))
            nid    = mem_node(f"mal_{vpn}", pid)
            hexd   = safe_str(r.get("Hexdump",""))
            disasm = safe_str(r.get("Disasm",""), maxlen=200)
            has_mz        = "MZ" in hexd or "4d5a" in hexd.lower()
            has_shellcode = bool(SHELLCODE_EB_RE.search(disasm))
            score  = 9 if has_mz else (7 if has_shellcode else 5)
            G.add_node(nid,
                node_type       = "memory_region",
                label           = f"INJECT:{vpn}",
                pid             = pid,
                start_vpn       = vpn,
                end_vpn         = safe_str(r.get("End VPN","")),
                protection      = safe_str(r.get("Protection","")),
                private_memory  = safe_int(r.get("PrivateMemory",0)),
                commit_charge   = safe_int(r.get("CommitCharge",0)),
                has_mz_header   = int(has_mz),
                has_shellcode   = int(has_shellcode),
                disasm          = disasm,
                is_rwx          = 1,
                is_suspicious   = 1,
                heuristic_score = score,
                source          = "malfind",
            )
            pnid = pid_node(pid)
            if G.has_node(pnid):
                G.add_edge(nid, pnid,
                    edge_type      = "injected_into",
                    has_mz_header  = int(has_mz),
                    has_shellcode  = int(has_shellcode),
                    is_rwx         = 1,
                )

    # ── Network connections ───────────────────────────────────────────────────
    # netscan columns: Offset, Proto, LocalAddr, LocalPort, ForeignAddr,
    #                  ForeignPort, State, PID, Owner, Created
    if not netscan.empty:
        for _, r in netscan.iterrows():
            offset  = safe_str(r.get("Offset",""))
            foreign = safe_str(r.get("ForeignAddr",""))
            state   = safe_str(r.get("State",""))
            owner   = safe_str(r.get("Owner","")).lower()
            fport   = safe_int(r.get("ForeignPort",0))
            proto   = safe_str(r.get("Proto",""))
            is_ext  = (state == "ESTABLISHED"
                       and foreign not in ("","*","0.0.0.0","-")
                       and not PRIVATE_IP.match(foreign))
            is_lolbin_c2 = owner in LOLBIN_NET and state == "ESTABLISHED"
            net_nid = net_node(offset)
            sus_score = 8 if is_lolbin_c2 else (3 if is_ext else 0)
            G.add_node(net_nid,
                node_type       = "network_conn",
                label           = f"{proto}->{foreign}:{fport}",
                proto           = proto,
                local_addr      = safe_str(r.get("LocalAddr","")),
                local_port      = safe_int(r.get("LocalPort",0)),
                foreign_addr    = foreign,
                foreign_port    = fport,
                state           = state,
                owner           = owner,
                is_external     = int(is_ext),
                is_lolbin_c2    = int(is_lolbin_c2),
                is_suspicious   = int(is_ext or is_lolbin_c2),
                heuristic_score = sus_score,
            )
            try:
                pid  = int(r["PID"])
                pnid = pid_node(pid)
                if G.has_node(pnid):
                    G.add_edge(net_nid, pnid,
                        edge_type    = "connects_from",
                        state        = state,
                        is_lolbin_c2 = int(is_lolbin_c2),
                    )
            except Exception: pass
            if (is_ext or is_lolbin_c2) and foreign not in ("*",""):
                ip_nid = ip_node(foreign)
                if not G.has_node(ip_nid):
                    G.add_node(ip_nid,
                        node_type       = "ip_address",
                        label           = foreign,
                        address         = foreign,
                        is_external     = 1,
                        is_suspicious   = 1,
                        heuristic_score = sus_score,
                    )
                G.add_edge(net_nid, ip_nid,
                    edge_type = "connects_to",
                    port      = fport,
                    proto     = proto,
                )

    # ── Handle nodes (unexpected lsass access) ────────────────────────────────
    # handles columns: PID, Offset, Type, Name, GrantedAccess, HandleValue
    # FIX: whitelist normal Windows procs so clean snapshots aren't over-flagged
    if not handles.empty:
        type_c   = col(handles, ["Type"])
        name_c   = col(handles, ["Name","HandleName","Detail"])
        ga_c     = col(handles, ["GrantedAccess","Granted Access"])
        hval_c   = col(handles, ["HandleValue","Handle"])
        proc_c   = col(handles, ["Process","ImageFile"])

        if all([type_c, name_c, ga_c]):
            lsass_h = handles[
                (handles[type_c] == "Process") &
                (handles[name_c].str.contains("lsass", case=False, na=False))
            ]
            for _, r in lsass_h.iterrows():
                access = safe_str(r.get(ga_c,"")).lower()
                if access not in HIGH_ACCESS: continue
                # Whitelist normal Windows processes
                proc_name = safe_str(r.get(proc_c,"")).lower() if proc_c else ""
                if proc_name in LSASS_WHITELIST: continue
                try: pid = int(r["PID"])
                except Exception: continue
                hval  = safe_str(r.get(hval_c,"")) if hval_c else ""
                h_nid = f"handle_{pid}_{hval}"
                G.add_node(h_nid,
                    node_type       = "handle",
                    label           = f"HANDLE:lsass_access",
                    pid             = pid,
                    handle_type     = "Process",
                    granted_access  = access,
                    name            = safe_str(r.get(name_c,"")),
                    is_suspicious   = 1,
                    heuristic_score = 8,
                )
                pnid = pid_node(pid)
                if G.has_node(pnid):
                    G.add_edge(h_nid, pnid,
                        edge_type      = "owned_by",
                        granted_access = access,
                    )
                # Edge to lsass process node
                for lp, lr in pid_to_row.items():
                    if "lsass" in safe_str(lr.get("ImageFileName","")).lower():
                        target = pid_node(lp)
                        if G.has_node(target):
                            G.add_edge(h_nid, target,
                                edge_type      = "points_to",
                                granted_access = access,
                                is_full_access = int(access == "0x1fffff"),
                            )
                        break

    # ── Driver nodes ──────────────────────────────────────────────────────────
    # drvscan columns: Offset, Start, Size, Service Key, Driver Name, Name
    if not drvscan.empty:
        dname_c  = col(drvscan, ["Driver Name","Name","DriverName"])
        svckey_c = col(drvscan, ["Service Key","ServiceKey"])
        size_c   = col(drvscan, ["Size"])
        start_c  = col(drvscan, ["Start"])
        for _, r in drvscan.iterrows():
            name   = safe_str(r.get(dname_c,"")) if dname_c else ""
            svckey = safe_str(r.get(svckey_c,"")) if svckey_c else ""
            nid    = drv_node(name)
            raw_size  = safe_str(r.get(size_c,"")) if size_c else ""
            raw_start = safe_str(r.get(start_c,"")) if start_c else ""
            try: size_int  = int(raw_size,  16) if raw_size.startswith("0x")  else int(raw_size)
            except Exception: size_int = 0
            try: start_int = int(raw_start, 16) if raw_start.startswith("0x") else int(raw_start)
            except Exception: start_int = 0
            sus = svckey == ""
            G.add_node(nid,
                node_type       = "driver",
                label           = name,
                driver_name     = name,
                service_key     = svckey,
                start           = start_int,
                size            = size_int,
                is_suspicious   = int(sus),
                heuristic_score = 3 if sus else 0,
            )
            G.add_edge(nid, KERNEL_NODE,
                edge_type        = "loaded_in_kernel",
                has_service_key  = int(svckey != ""),
            )

    # ── Summary ───────────────────────────────────────────────────────────────
    print(f"\n[OK] Graph: {G.number_of_nodes()} nodes, {G.number_of_edges()} edges")
    ntypes = {}
    for _, d in G.nodes(data=True):
        t = d.get("node_type","?")
        ntypes[t] = ntypes.get(t,0) + 1
    for t,c in sorted(ntypes.items()):
        print(f"  node/{t}: {c}")
    etypes = {}
    for _,_,d in G.edges(data=True):
        t = d.get("edge_type","?")
        etypes[t] = etypes.get(t,0) + 1
    for t,c in sorted(etypes.items()):
        print(f"  edge/{t}: {c}")

    return G, graph_attr_meta, label_signals


# ── Save ──────────────────────────────────────────────────────────────────────
def save_graph(G, folder, graph_attr_meta, label_signals):
    os.makedirs(folder, exist_ok=True)

    # JSON
    json_path = os.path.join(folder, "graph.json")
    data = json_graph.node_link_data(G, edges="links")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(data, indent=2, cls=NaNSafeEncoder, default=str))
    print(f"  [JSON]   {json_path}  ({os.path.getsize(json_path)/1024:.1f} KB)")

    # Pickle (for ML pipeline)
    pkl_path = os.path.join(folder, "graph.pkl")
    with open(pkl_path, "wb") as f:
        pickle.dump(G, f)
    print(f"  [PKL]    {pkl_path}  ({os.path.getsize(pkl_path)/1024:.1f} KB)")

    # graph_attr.json — ready for dataset.py to read directly
    # Maps to: torch.tensor([max_process_score, attack_steps,
    #                         high_severity_injections, lolbin_c2_connections,
    #                         ransom_note_signal], dtype=torch.float)
    ga_path = os.path.join(folder, "graph_attr.json")
    ga_out = {
        "graph_attr": [
            float(graph_attr_meta.get("max_process_score",       0)),
            float(graph_attr_meta.get("attack_steps",            0)),
            float(graph_attr_meta.get("high_severity_injections",0)),
            float(graph_attr_meta.get("lolbin_c2_connections",   0)),
            float(graph_attr_meta.get("ransom_note_signal",      0)),
        ],
        "label_signals": label_signals,
    }
    with open(ga_path, "w") as f:
        json.dump(ga_out, f, indent=2)
    print(f"  [ATTR]   {ga_path}")
    print(f"           graph_attr tensor: {ga_out['graph_attr']}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    folder = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(f"\n[*] Building graph from: {folder}")
    G, graph_attr_meta, label_signals = build(folder)
    print("\n[*] Saving...")
    save_graph(G, folder, graph_attr_meta, label_signals)
    print("\n[Done]")


if __name__ == "__main__":
    main()