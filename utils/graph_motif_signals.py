#!/usr/bin/env python3
"""
Graph-level motif signals for malware-vs-benign differentiation.

Computed from NetworkX graph.pkl (same object as training). Values are
log1p-scaled counts/ratios suitable for concatenation after manifest + edge-type
features. Family-agnostic proxies (not only WannaCry); may still correlate
with ransomware families present in the dataset — use with caps and group
weighting during training.

FP note: hex-like process basenames can appear on legitimate packed tools;
counts are capped before log1p.
"""

from __future__ import annotations

import math
import os
import re
from typing import Any

# Tail length appended after manifest block + edge log-counts (N_EDGE_TYPES); see dataset.GRAPH_ATTR_DIM.
MOTIF_FEATURE_COUNT = 7

# Generic decryptor / ransom-adjacent UI or file naming (case-insensitive).
_RANSOM_NAME_RE = re.compile(
    r"(wanadecrypt|@.*decrypt|decryptor|help_decrypt|how_decrypt|readme|read_me|"
    r"howto\.|_recover_|restore_files|your_files|\.locked|_locked|crypt\d{0,3}|"
    r"ransom|teerac|cerber|gandcrab|locky|dharma|maze|ryuk)",
    re.IGNORECASE,
)

# Tor helper / ransomware service host naming.
_TOR_TASK_RE = re.compile(
    r"(\\tor\\|/tor/|taskhsvc|tor\\task|\\\\tor\\\\)",
    re.IGNORECASE,
)

# Short image-like names that are mostly hex (e.g. random dropper names). Strict to limit FP.
_HEX_NAME_RE = re.compile(r"^[a-f0-9]{12,40}$", re.IGNORECASE)

_HEX_NAME_CAP = 5

_LOL_SPAWN_NAMES = frozenset(
    {
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "mshta.exe",
        "wscript.exe",
        "cscript.exe",
        "forfiles.exe",
        "certutil.exe",
        "bitsadmin.exe",
    }
)

_PATH_CAP = 20


def _proc_name_lower(G: Any, nid: Any) -> str:
    d = G.nodes[nid]
    return str(d.get("name", d.get("label", "")) or "").lower()


def _motif_lolbin_spawn_paths(G: Any) -> int:
    """Capped count: spawned_by edges where child or parent basename is a LOLBin."""
    n = 0
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "spawned_by":
            continue
        if str(G.nodes[u].get("node_type", "")) != "process":
            continue
        c = _proc_name_lower(G, u)
        p = _proc_name_lower(G, v)
        if c in _LOL_SPAWN_NAMES or p in _LOL_SPAWN_NAMES:
            n += 1
            if n >= _PATH_CAP:
                return _PATH_CAP
    return n


def _motif_injection_intent_pairs(G: Any) -> int:
    """Capped count: process P with intent_injection P→M and injected_into M→P (malfind-style)."""
    intent_mem: dict[Any, set[Any]] = {}
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") == "intent_injection":
            intent_mem.setdefault(u, set()).add(v)
    n = 0
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "injected_into":
            continue
        mem, proc = u, v
        if proc in intent_mem and mem in intent_mem[proc]:
            n += 1
            if n >= _PATH_CAP:
                return _PATH_CAP
    return n


def _motif_persistence_edges(G: Any) -> int:
    """Capped count of persistence_behavior edges (DLL / API persistence hooks)."""
    n = 0
    for _, _, ed in G.edges(data=True):
        if ed.get("edge_type") == "persistence_behavior":
            n += 1
            if n >= _PATH_CAP:
                return _PATH_CAP
    return n


def _proc_text(data: dict[str, Any]) -> str:
    parts = [
        str(data.get("label", "") or ""),
        str(data.get("name", "") or ""),
        str(data.get("args", "") or ""),
        str(data.get("path", "") or ""),
    ]
    return " ".join(parts).lower()


def _basename_lower(label: str) -> str:
    base = os.path.basename(label.replace("\\", "/").strip())
    return base.lower().split(".")[0] if base else ""


def graph_differentiation_signals(G: Any) -> list[float]:
    """
    Return exactly MOTIF_FEATURE_COUNT floats:
      [0] log1p(ransom_naming_hits)
      [1] log1p(tor_tasksvc_hits)
      [2] log1p(hex_like_process_names capped)
      [3] log1p(memory_regions_per_process)
      [4] log1p(LOLBin spawn-chain hits, capped)
      [5] log1p(injection intent↔malfind pair hits, capped)
      [6] log1p(persistence_behavior edges, capped)
    """
    n_proc = 0
    n_mem = 0
    ransom_hits = 0
    tor_task_hits = 0
    hex_hits = 0

    for _nid, data in G.nodes(data=True):
        nt = str(data.get("node_type", "") or "")
        if nt == "process":
            n_proc += 1
            text = _proc_text(data)
            if _RANSOM_NAME_RE.search(text):
                ransom_hits += 1
            if _TOR_TASK_RE.search(text) or _TOR_TASK_RE.search(str(data.get("label", ""))):
                tor_task_hits += 1
            base = _basename_lower(str(data.get("label", data.get("name", ""))))
            if base and _HEX_NAME_RE.match(base):
                hex_hits += 1
        elif nt == "memory_region":
            n_mem += 1

    hex_capped = min(hex_hits, _HEX_NAME_CAP)
    ratio = n_mem / max(n_proc, 1)
    lol_paths = _motif_lolbin_spawn_paths(G)
    inj_pairs = _motif_injection_intent_pairs(G)
    persist_hits = _motif_persistence_edges(G)

    return [
        float(math.log1p(ransom_hits)),
        float(math.log1p(tor_task_hits)),
        float(math.log1p(hex_capped)),
        float(math.log1p(ratio)),
        float(math.log1p(lol_paths)),
        float(math.log1p(inj_pairs)),
        float(math.log1p(persist_hits)),
    ]
