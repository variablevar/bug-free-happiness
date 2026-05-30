#!/usr/bin/env python3
"""
dataset.py  v3
==============
Fix vs v2:
  - graph_attr stored as shape [1, 14] instead of [14].
    PyG DataLoader concatenates tensors along dim-0, so [1,14] per graph
    correctly stacks to [B, 14].  A plain [14] was being concatenated to
    [B*14] and then mis-shaped inside model.forward().

All other feature engineering is unchanged from v2.
"""

import json
import os
import math
import pickle
import re
from collections import Counter

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data, Dataset
from utils.graph_attr_profile import apply_graph_attr_profile
from utils.graph_motif_signals import MOTIF_FEATURE_COUNT, graph_differentiation_signals
from utils.schema import EXPECTED_GRAPH_ATTR_DIM
from utils.subgraph_extract import extract_attack_subgraph
from utils.triage_zone import node_triage_zone

# ── Vocabularies ───────────────────────────────────────────────────────────
NODE_TYPES = [
    "process", "thread", "dll", "memory_region",
    "network_conn", "ip_address", "handle", "driver", "kernel",
]
NODE_TYPE_IDX = {t: i for i, t in enumerate(NODE_TYPES)}

EDGE_TYPES = [
    "spawned_by", "belongs_to", "loaded_into", "allocated_in",
    "injected_into", "connects_from", "connects_to",
    "owned_by", "points_to", "loaded_in_kernel",
    "intent_c2", "intent_injection", "intent_credential_access", "temporal_near_creation",
    "temporal_execution_chain", "api_semantic_activity", "parent_child_anomaly",
    "persistence_behavior", "privilege_escalation_indicator",
    "svchost_lineage_anomaly", "svchost_cmdline_anomaly", "dll_trust_anomaly",
    "c2_relation_pattern", "service_hosts", "service_correlation_ok", "service_orphan",
    "lolbin_execution_chain",
]
EDGE_TYPE_IDX  = {t: i for i, t in enumerate(EDGE_TYPES)}
N_EDGE_TYPES   = len(EDGE_TYPES)

# ── Feature layout ───────────────────────────────────────────────────────────
#  [0:9]   one-hot node type          (9 dims)
#  [9:21]  semantic/context attrs     (12 dims, includes triage zone flags)
#  [21:32] per-node edge-role counts  (11 dims)
NODE_FEAT_DIM = 9 + 13 + 11

# Graph-level attrs:
#   4  base manifest counts
#   23 additional manifest/derived risk signals (includes hub / RWX–thread context logs)
#   N edge-type log-counts
#   MOTIF_FEATURE_COUNT graph-derived differentiation tail (see graph_motif_signals)
# = (27 + N_EDGE_TYPES + MOTIF_FEATURE_COUNT) dims total
GRAPH_ATTR_DIM = 27 + N_EDGE_TYPES + MOTIF_FEATURE_COUNT

MIN_NODES = 10

# ── Helpers ───────────────────────────────────────────────────────────────────

def _log1p(v) -> float:
    try:
        return math.log1p(max(float(v), 0.0))
    except (TypeError, ValueError):
        return 0.0


def _build_per_node_edge_roles(G):
    n_injected_into  = {}
    n_connects_to    = {}
    n_connects_from  = {}
    degree_out       = {}
    degree_in        = {}
    n_persistence    = {}
    n_cred_access    = {}
    n_priv_esc       = {}
    n_svchost_anom   = {}
    n_service_mismatch = {}
    n_c2_pattern = {}

    for u, v, edata in G.edges(data=True):
        etype = edata.get("edge_type", "")
        degree_out[u] = degree_out.get(u, 0) + 1
        degree_in[v]  = degree_in.get(v, 0)  + 1
        if etype == "injected_into":
            n_injected_into[v] = n_injected_into.get(v, 0) + 1
        elif etype == "connects_to":
            n_connects_to[u]   = n_connects_to.get(u, 0)   + 1
        elif etype == "connects_from":
            n_connects_from[u] = n_connects_from.get(u, 0) + 1
        elif etype == "persistence_behavior":
            n_persistence[u] = n_persistence.get(u, 0) + 1
        elif etype == "intent_credential_access":
            n_cred_access[u] = n_cred_access.get(u, 0) + 1
        elif etype == "privilege_escalation_indicator":
            n_priv_esc[u] = n_priv_esc.get(u, 0) + 1
        elif etype in {"svchost_lineage_anomaly", "svchost_cmdline_anomaly"}:
            n_svchost_anom[u] = n_svchost_anom.get(u, 0) + 1
        elif etype in {"service_orphan", "service_hosts"}:
            n_service_mismatch[u] = n_service_mismatch.get(u, 0) + 1
        elif etype in {"c2_relation_pattern", "intent_c2"}:
            n_c2_pattern[u] = n_c2_pattern.get(u, 0) + 1

    return (
        n_injected_into, n_connects_to, n_connects_from, degree_out, degree_in,
        n_persistence, n_cred_access, n_priv_esc, n_svchost_anom, n_service_mismatch, n_c2_pattern
    )


def node_features(nid, data: dict,
                  n_injected_into, n_connects_to, n_connects_from,
                  degree_out, degree_in, n_persistence, n_cred_access, n_priv_esc,
                  n_svchost_anom, n_service_mismatch, n_c2_pattern) -> list:
    ntype = data.get("node_type", "kernel")
    oh = [0.0] * len(NODE_TYPES)
    oh[NODE_TYPE_IDX.get(ntype, len(NODE_TYPES) - 1)] = 1.0

    pname = str(data.get("name", data.get("label", ""))).lower()
    is_svchost = float(pname == "svchost.exe")
    is_powershell = float("powershell" in pname)
    is_noisy_trusted = float(pname in {"svchost.exe", "explorer.exe", "chrome.exe", "lsass.exe"})
    hub_benign = float(int(data.get("benign_high_volume_hub", 0) or 0))
    zone = node_triage_zone(data)
    is_benign_zone = float(zone == "benign")
    is_suspect_zone = float(zone == "suspect")
    session_id = str(data.get("session_id", ""))
    boundary_cross_risk = float(is_svchost > 0 and session_id not in {"", "0"})
    net_base = 20.0 if is_svchost > 0 else (4.0 if is_powershell > 0 else 8.0)
    normalized_net_pressure = _log1p(n_connects_to.get(nid, 0) / net_base)

    nums = [
        float(data.get("is_suspicious",  0) or 0),
        float(data.get("is_rwx",         0) or 0),
        float(data.get("has_mz_header",  0) or 0),
        float(data.get("is_external",    0) or 0),
        _log1p(data.get("private_memory", 0)),
        _log1p(data.get("commit_charge",  0)),
        _log1p(data.get("load_count",     0)),
        is_svchost,
        is_powershell,
        normalized_net_pressure + boundary_cross_risk + (0.25 * is_noisy_trusted),
        hub_benign,
        is_benign_zone,
        is_suspect_zone,
    ]

    roles = [
        _log1p(n_injected_into.get(nid,  0)),
        _log1p(n_connects_to.get(nid,    0)),
        _log1p(n_connects_from.get(nid,  0)),
        0.5 * _log1p(degree_out.get(nid,       0)),
        0.5 * _log1p(degree_in.get(nid,        0)),
        _log1p(n_persistence.get(nid,    0)),
        _log1p(n_cred_access.get(nid,    0)),
        _log1p(n_priv_esc.get(nid,       0)),
        _log1p(n_svchost_anom.get(nid,   0)),
        _log1p(n_service_mismatch.get(nid, 0)),
        _log1p(n_c2_pattern.get(nid, 0)),
    ]

    return oh + nums + roles


def count_benign_high_volume_hubs(G) -> int:
    """Processes tagged in build_graph as benign_high_volume_hub (expected-parent browsers/IDEs)."""
    return sum(
        1
        for _, d in G.nodes(data=True)
        if str(d.get("node_type")) == "process" and int(d.get("benign_high_volume_hub", 0) or 0) == 1
    )


def count_rwx_thread_context(G) -> int:
    """Threads belonging to a process that has an RWX malfind injected_into edge (semantic bridge)."""
    procs = set()
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "injected_into":
            continue
        if str(G.nodes[u].get("node_type", "")) != "memory_region":
            continue
        if int(G.nodes[u].get("is_rwx", 0) or 0) != 1:
            continue
        procs.add(v)
    if not procs:
        return 0
    n = 0
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "belongs_to":
            continue
        if str(G.nodes[u].get("node_type", "")) != "thread":
            continue
        if v in procs:
            n += 1
    return n


def merge_manifest_csv_files(primary_csv: str, extra_csvs: list[str]) -> str:
    """Concatenate manifest CSVs; on duplicate folder, keep the primary manifest row."""
    import tempfile

    frames = [pd.read_csv(os.path.abspath(primary_csv))]
    for p in extra_csvs:
        ap = os.path.abspath(str(p).strip())
        if ap and os.path.isfile(ap):
            frames.append(pd.read_csv(ap))
    merged = pd.concat(frames, ignore_index=True)
    if "folder" in merged.columns:
        merged = merged.drop_duplicates(subset=["folder"], keep="first")
    out_dir = os.path.dirname(os.path.abspath(primary_csv)) or "."
    fd, path = tempfile.mkstemp(prefix="merged_manifest_", suffix=".csv", dir=out_dir)
    os.close(fd)
    merged.to_csv(path, index=False)
    return path


def _edge_type_distribution(G) -> list:
    counts = [0] * N_EDGE_TYPES
    for _, _, edata in G.edges(data=True):
        etype = edata.get("edge_type", "spawned_by")
        idx   = EDGE_TYPE_IDX.get(etype, 0)
        counts[idx] += 1
    return [math.log1p(c) for c in counts]


def _safe_float(value, default: float = 0.0) -> float:
    try:
        if value is None:
            return default
        if isinstance(value, str) and not value.strip():
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_int_from_text(text: str, key: str, default: int = 0) -> int:
    if not text:
        return default
    match = re.search(rf"{re.escape(key)}\s*=\s*(-?\d+)", str(text))
    if not match:
        return default
    try:
        return int(match.group(1))
    except ValueError:
        return default


def _compact_node_metadata(nid, data: dict) -> dict:
    """Small JSON-safe node context for model evidence (avoid bulky blobs)."""
    keys = (
        "node_type",
        "label",
        "name",
        "pid",
        "tid",
        "path",
        "owner",
        "image",
        "start_vpn",
        "end_vpn",
        "protection",
        "is_suspicious",
        "heuristic_score",
    )
    out = {"graph_node_id": str(nid)}
    for k in keys:
        v = data.get(k)
        if v is None or v == "":
            continue
        if isinstance(v, (int, float, bool)):
            out[k] = v
        else:
            out[k] = str(v)[:240]
    return out


def _compact_edge_metadata(edge_idx: int, u, v, edata: dict, node_idx: dict) -> dict:
    keys = (
        "edge_type",
        "time_delta_seconds",
        "parent_name",
        "child_name",
        "has_shellcode",
        "has_mz_header",
        "is_rwx",
        "user_writable_path",
        "persistence_hint",
    )
    out = {
        "edge_index": int(edge_idx),
        "src": int(node_idx[u]),
        "dst": int(node_idx[v]),
        "src_graph_node_id": str(u),
        "dst_graph_node_id": str(v),
    }
    for k in keys:
        v0 = edata.get(k)
        if v0 is None or v0 == "":
            continue
        if isinstance(v0, (int, float, bool)):
            out[k] = v0
        else:
            out[k] = str(v0)[:160]
    return out


def nx_to_pyg(G, label: int) -> Data:
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()

    if n_nodes < MIN_NODES:
        raise ValueError(
            f"Degenerate graph: {n_nodes} node(s) (min {MIN_NODES}). Skipping."
        )
    if n_edges == 0:
        raise ValueError(
            f"Degenerate graph: 0 edges ({n_nodes} nodes). Skipping."
        )

    n_inj, n_cto, n_cfr, d_out, d_in, n_persist, n_cred, n_priv, n_sv_anom, n_svc_mis, n_c2_pat = _build_per_node_edge_roles(G)

    nodes     = list(G.nodes(data=True))
    node_idx  = {nid: i for i, (nid, _) in enumerate(nodes)}

    x = torch.tensor(
        [node_features(
            nid, data, n_inj, n_cto, n_cfr, d_out, d_in, n_persist, n_cred, n_priv, n_sv_anom, n_svc_mis, n_c2_pat
        )
         for nid, data in nodes],
        dtype=torch.float,
    )

    node_metadata = [_compact_node_metadata(nid, data) for nid, data in nodes]
    edge_metadata = []
    src_list, dst_list, edge_attr_list = [], [], []
    for u, v, edata in G.edges(data=True):
        if u in node_idx and v in node_idx:
            edge_metadata.append(_compact_edge_metadata(len(edge_metadata), u, v, edata, node_idx))
            src_list.append(node_idx[u])
            dst_list.append(node_idx[v])
            etype = edata.get("edge_type", "spawned_by")
            edge_attr_list.append(EDGE_TYPE_IDX.get(etype, 0))

    if src_list:
        edge_index = torch.tensor([src_list, dst_list], dtype=torch.long)
        edge_attr  = torch.tensor(edge_attr_list,        dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr  = torch.zeros(0,      dtype=torch.long)

    data = Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=x.size(0),
    )
    data.node_metadata = node_metadata
    data.edge_metadata = edge_metadata
    data.suspect_node_mask = torch.tensor(
        [node_triage_zone(data) != "benign" for _, data in nodes],
        dtype=torch.bool,
    )
    return data


# ── Manifest governance (shared by trainers / analyzers / evaluate) ─────────────

DEFAULT_ALLOWED_BENIGN_SUBTYPES = (
    "clean_benign,hard_benign_admin_tooling,ambiguous_novirus_control"
)


def parse_allowed_benign_subtypes(csv_value: str) -> tuple[str, ...]:
    return tuple(x.strip() for x in str(csv_value or "").split(",") if x.strip())


def manifest_coerce_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value or "").strip().lower()
    if not text:
        return default
    return text in {"1", "true", "yes", "y"}


def governance_load_options(
    *,
    require_governance_manifest: bool = False,
    allowed_benign_subtypes: str = DEFAULT_ALLOWED_BENIGN_SUBTYPES,
    require_train_eligible: bool = False,
    include_uncertain: bool = True,
) -> dict:
    """Keyword args for MalwareGraphDataset governance-aware loading."""
    allowed = None
    if require_governance_manifest:
        allowed = parse_allowed_benign_subtypes(allowed_benign_subtypes)
    return {
        "include_uncertain": include_uncertain,
        "require_train_eligible": require_train_eligible,
        "require_governance_columns": require_governance_manifest,
        "allowed_benign_subtypes": allowed,
    }


def manifest_row_governance(row: dict) -> dict:
    """Governance fields copied into analysis JSON per sample."""
    try:
        label = int(row.get("label", -1))
    except (TypeError, ValueError):
        label = -1
    return {
        "label_from_manifest": label,
        "benign_subtype": str(row.get("benign_subtype", "") or ""),
        "train_eligible": manifest_coerce_bool(row.get("train_eligible", True), True),
        "uncertain": manifest_coerce_bool(row.get("uncertain", False), False),
        "uncertain_reason": str(row.get("uncertain_reason", "") or ""),
        "label_quality_flag": manifest_coerce_bool(row.get("label_quality_flag", False), False),
        "label_quality_reason": str(row.get("label_quality_reason", "") or ""),
    }


def evaluation_subset_predicates() -> dict:
    """Named manifest slices for evaluate.py subset metrics."""

    def _subtype(row: dict, name: str) -> bool:
        return str(row.get("benign_subtype", "")).strip().lower() == name

    def _label(row: dict, value: int) -> bool:
        return str(row.get("label", "")).strip() == str(value)

    def _uncertain(row: dict) -> bool:
        return manifest_coerce_bool(row.get("uncertain", False), False)

    def _train_eligible(row: dict) -> bool:
        return manifest_coerce_bool(row.get("train_eligible", True), True)

    def _suspect_disagreement(row: dict) -> bool:
        reason = str(row.get("uncertain_reason", "") or "")
        return (
            "benign_label_critical_verdict" in reason
            or "benign_label_high_suspect_zone" in reason
        )

    return {
        "all_rows": lambda row: True,
        "manifest_uncertain": _uncertain,
        "train_eligible": _train_eligible,
        "train_ineligible": lambda row: not _train_eligible(row),
        "uncertain_benign": lambda row: _label(row, 0) and _uncertain(row),
        "train_eligible_benign": lambda row: _label(row, 0) and _train_eligible(row),
        "suspect_disagreement_benign": lambda row: _label(row, 0) and _suspect_disagreement(row),
        "clean_benign": lambda row: _label(row, 0) and _subtype(row, "clean_benign"),
        "hard_benign_admin_tooling": lambda row: _label(row, 0) and _subtype(row, "hard_benign_admin_tooling"),
        "ambiguous_novirus_control": lambda row: _label(row, 0) and _subtype(row, "ambiguous_novirus_control"),
        "malware_labelled": lambda row: _label(row, 1),
    }


# ── Dataset class ─────────────────────────────────────────────────────────────────

class MalwareGraphDataset(Dataset):
    """
    graph_attr shape: [1, GRAPH_ATTR_DIM] per sample.
      PyG DataLoader cats along dim-0 → [B, GRAPH_ATTR_DIM] in a batch.

    graph_attr layout:
      [0]    max_score      (manifest)
      [1]    attack_steps   (manifest)
      [2]    injections     (manifest)
      [3]    c2_conns       (manifest)
      [4]    log1p(nodes)
      [5]    log1p(edges)
      [6]    graph_density
      [7]    behavioural_suspects_found
      [8]    lolbin_c2_found
      [9]    ransom_note_found
      [10]   log1p(rwx_injections)
      [11]   triage_confidence
      [12]   benign_clean_software_flag
      [13]   benign_admin_or_security_tool_flag
      [14]   signal_temporal_chain_count
      [15]   signal_api_semantic_count
      [16]   signal_persistence_count
      [17]   signal_credential_access_count_manifest
      [18]   signal_privilege_escalation_count
      [19]   signal_svchost_lineage_anomaly_count
      [20]   signal_svchost_cmdline_anomaly_count
      [21]   signal_dll_trust_anomaly_count
      [22]   signal_service_orphan_count
      [23]   signal_lolbin_chain_count
      [24]   signal_c2_relation_pattern_count
      [25]   log1p(benign_high_volume_hub process count)
      [26]   log1p(RWX malfind process ↔ thread context count)
      [27:54]  log1p edge-type counts (N_EDGE_TYPES)
      [54:61]  motif tail (see utils/graph_motif_signals.graph_differentiation_signals)
    """

    RISK_LEVEL_MAP = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3,
    }

    def __init__(
        self,
        manifest_csv: str,
        base_dir: str = None,
        include_uncertain: bool = True,
        include_unknown: bool = False,
        require_train_eligible: bool = False,
        require_governance_columns: bool = False,
        allowed_benign_subtypes: tuple[str, ...] | None = None,
        target: str = "label",
        graph_attr_profile: str = "full",
        graph_view: str = "full",
    ):
        super().__init__()
        self.manifest  = pd.read_csv(manifest_csv)
        self.base_dir  = base_dir or os.path.dirname(manifest_csv)
        self.graph_attr_profile = str(graph_attr_profile or "full").strip().lower()
        self.graph_view = str(graph_view or "full").strip().lower()
        self.include_uncertain = include_uncertain
        self.include_unknown = include_unknown
        self.require_train_eligible = require_train_eligible
        self.require_governance_columns = require_governance_columns
        self.allowed_benign_subtypes = (
            {self._normalize_benign_subtype(x) for x in allowed_benign_subtypes}
            if allowed_benign_subtypes is not None
            else None
        )
        self.target = str(target).strip().lower()
        if self.target not in {"label", "risk", "curated_label"}:
            raise ValueError(
                f"Invalid target '{target}'. Expected one of: label, risk, curated_label."
            )
        if self.require_governance_columns:
            required = {"benign_subtype", "label_quality_flag", "label_quality_reason", "train_eligible"}
            missing = [c for c in sorted(required) if c not in self.manifest.columns]
            if missing:
                raise ValueError(
                    "Manifest is missing required governance column(s): "
                    + ", ".join(missing)
                    + ". Rebuild the manifest with build_dataset.py before training."
                )
        self._data_list: list[Data] = []
        self._load_all()

    @staticmethod
    def _as_bool(value) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value).strip().lower() in {"1", "true", "yes", "y"}

    @staticmethod
    def _normalize_benign_subtype(value: str) -> str:
        text = str(value or "").strip().lower().replace("-", "_")
        aliases = {
            "clean": "clean_benign",
            "clean_software": "clean_benign",
            "clean_benign": "clean_benign",
            "admin_tool": "hard_benign_admin_tooling",
            "admin_security_tool": "hard_benign_admin_tooling",
            "admin_or_security_tool": "hard_benign_admin_tooling",
            "security_tool": "hard_benign_admin_tooling",
            "hard_benign": "hard_benign_admin_tooling",
            "hard_benign_admin_tooling": "hard_benign_admin_tooling",
            "ambiguous_novirus_control": "ambiguous_novirus_control",
        }
        return aliases.get(text, text)

    def _load_all(self) -> None:
        ok = fail = skipped_uncertain = 0
        skip_reasons: Counter[str] = Counter()
        subtype_counts: Counter[str] = Counter()

        for _, row in self.manifest.iterrows():
            name   = str(row["folder"])
            label  = int(row["label"])
            family = row.get("family", "unknown")
            uncertain = self._as_bool(row.get("uncertain", False))
            train_eligible = self._as_bool(row.get("train_eligible", True))
            benign_subtype = self._normalize_benign_subtype(row.get("benign_subtype", ""))
            if label == 0:
                subtype_counts[benign_subtype or "unspecified"] += 1
            if uncertain and not self.include_uncertain:
                print(f"  [SKIP] {name} — marked uncertain in manifest")
                skipped_uncertain += 1
                skip_reasons["uncertain"] += 1
                continue
            if self.require_train_eligible and not train_eligible:
                print(f"  [SKIP] {name} — train_eligible=false (strict training filter)")
                skipped_uncertain += 1
                skip_reasons["train_eligible_false"] += 1
                continue
            if label < 0 and not self.include_unknown:
                print(f"  [SKIP] {name} — unknown label={label}")
                skipped_uncertain += 1
                skip_reasons["unknown_label"] += 1
                continue
            if (
                self.allowed_benign_subtypes is not None
                and label == 0
            ):
                # Manifest train_eligible is authoritative when strict training filter is on.
                subtype_ok = (
                    self.require_train_eligible
                    and train_eligible
                ) or benign_subtype in self.allowed_benign_subtypes
                if not benign_subtype and not subtype_ok:
                    print(f"  [SKIP] {name} — missing benign_subtype in governance-aware load")
                    skipped_uncertain += 1
                    skip_reasons["missing_benign_subtype"] += 1
                    continue
                if not subtype_ok:
                    print(f"  [SKIP] {name} — benign_subtype={benign_subtype} excluded")
                    skipped_uncertain += 1
                    skip_reasons[f"benign_subtype:{benign_subtype}"] += 1
                    continue
            pkl    = os.path.join(self.base_dir, name, "graph.pkl")
            sub_pkl = os.path.join(self.base_dir, name, "graph_subgraph.pkl")

            if not os.path.exists(pkl):
                print(f"  [SKIP] {name} — graph.pkl not found")
                fail += 1
                continue

            try:
                if self.graph_view == "attack_subgraph" and os.path.exists(sub_pkl):
                    with open(sub_pkl, "rb") as f:
                        G = pickle.load(f)
                else:
                    with open(pkl, "rb") as f:
                        G = pickle.load(f)
                    if self.graph_view == "attack_subgraph":
                        G = extract_attack_subgraph(G)
            except Exception as exc:
                print(f"  [SKIP] {name} — failed to load pkl: {exc}")
                fail += 1
                continue

            try:
                target_label = self._row_target(row, default_label=label)
                pyg = nx_to_pyg(G, target_label)
            except ValueError as exc:
                print(f"  [SKIP] {name} — {exc}")
                fail += 1
                continue

            nodes = _safe_float(row.get("nodes", 0), default=0.0)
            edges = _safe_float(row.get("edges", 0), default=0.0)
            max_edges = max(nodes * (nodes - 1.0), 1.0)
            density = min(max(edges / max_edges, 0.0), 1.0)

            label_signals = {}
            raw_label_signals_json = row.get("label_signals_json", "")
            if isinstance(raw_label_signals_json, str) and raw_label_signals_json.strip():
                try:
                    label_signals = json.loads(raw_label_signals_json)
                except json.JSONDecodeError:
                    label_signals = {}
            label_signals_top = str(row.get("label_signals_top", ""))

            behavioural_suspects_found = (
                _safe_float(row.get("signal_behavioural_suspects_found", 0), default=0.0)
                if "signal_behavioural_suspects_found" in row
                else float("behavioural_suspects_found=True" in label_signals_top)
            )
            lolbin_c2_found = (
                _safe_float(row.get("signal_lolbin_c2_found", 0), default=0.0)
                if "signal_lolbin_c2_found" in row
                else float("lolbin_c2_found=True" in label_signals_top)
            )
            ransom_note_found = (
                _safe_float(row.get("signal_ransom_note_found", 0), default=0.0)
                if "signal_ransom_note_found" in row
                else float("ransom_note_found=True" in label_signals_top)
            )
            rwx_injections = (
                _safe_float(row.get("signal_rwx_injections", 0), default=0.0)
                if "signal_rwx_injections" in row
                else float(_extract_int_from_text(label_signals_top, "rwx_injections", 0))
            )
            triage_conf = (
                _safe_float(row.get("signal_triage_confidence", 0), default=0.0)
                if "signal_triage_confidence" in row
                else _safe_float(label_signals.get("triage_confidence", 0), default=0.0)
            )
            signal_temporal_chain_count = _safe_float(row.get("signal_temporal_chain_count", 0), default=0.0)
            signal_api_semantic_count = _safe_float(row.get("signal_api_semantic_count", 0), default=0.0)
            signal_persistence_count = _safe_float(row.get("signal_persistence_count", 0), default=0.0)
            signal_credential_access_count_manifest = _safe_float(row.get("signal_credential_access_count", 0), default=0.0)
            signal_privilege_escalation_count = _safe_float(row.get("signal_privilege_escalation_count", 0), default=0.0)
            signal_svchost_lineage_anomaly_count = _safe_float(row.get("signal_svchost_lineage_anomaly_count", 0), default=0.0)
            signal_svchost_cmdline_anomaly_count = _safe_float(row.get("signal_svchost_cmdline_anomaly_count", 0), default=0.0)
            signal_dll_trust_anomaly_count = _safe_float(row.get("signal_dll_trust_anomaly_count", 0), default=0.0)
            signal_service_orphan_count = _safe_float(row.get("signal_service_orphan_count", 0), default=0.0)
            signal_lolbin_chain_count = _safe_float(row.get("signal_lolbin_chain_count", 0), default=0.0)
            signal_c2_relation_pattern_count = _safe_float(row.get("signal_c2_relation_pattern_count", 0), default=0.0)
            benign_hub_n = count_benign_high_volume_hubs(G)
            rwx_thread_n = count_rwx_thread_context(G)
            benign_subtype = self._normalize_benign_subtype(row.get("benign_subtype", ""))
            benign_clean_software_flag = float(
                benign_subtype in {"clean_benign"}
            )
            benign_admin_or_security_tool_flag = float(
                benign_subtype == "hard_benign_admin_tooling"
            )

            # Soft downweight weak shared structural/noisy injection channels.
            density_weighted = 0.35 * density
            benign_injection_damp = 0.5 if benign_clean_software_flag > 0.5 else 1.0
            rwx_injections_weighted = _log1p(rwx_injections * benign_injection_damp)
            manifest_feats = [
                _safe_float(row.get("max_score", 0), default=0.0),
                _safe_float(row.get("attack_steps", 0), default=0.0),
                _safe_float(row.get("injections", 0), default=0.0),
                _safe_float(row.get("c2_conns", 0), default=0.0),
                _log1p(nodes),
                _log1p(edges),
                density_weighted,
                float(behavioural_suspects_found),
                float(lolbin_c2_found),
                float(ransom_note_found),
                rwx_injections_weighted,
                max(0.0, min(1.0, triage_conf)),
                benign_clean_software_flag,
                benign_admin_or_security_tool_flag,
                _log1p(signal_temporal_chain_count),
                _log1p(signal_api_semantic_count),
                _log1p(signal_persistence_count),
                _log1p(signal_credential_access_count_manifest),
                _log1p(signal_privilege_escalation_count),
                _log1p(signal_svchost_lineage_anomaly_count),
                _log1p(signal_svchost_cmdline_anomaly_count),
                _log1p(signal_dll_trust_anomaly_count),
                _log1p(signal_service_orphan_count),
                _log1p(signal_lolbin_chain_count),
                _log1p(signal_c2_relation_pattern_count),
                _log1p(benign_hub_n),
                _log1p(rwx_thread_n),
            ]
            edge_dist_feats = _edge_type_distribution(G)
            motif_tail = graph_differentiation_signals(G)
            merged_graph_attr = manifest_feats + edge_dist_feats + motif_tail
            if len(merged_graph_attr) != EXPECTED_GRAPH_ATTR_DIM:
                raise ValueError(
                    f"Invalid graph_attr length for {name}: "
                    f"{len(merged_graph_attr)} != {EXPECTED_GRAPH_ATTR_DIM}"
                )

            # Shape [1, GRAPH_ATTR_DIM] so DataLoader stacks to [B, GRAPH_ATTR_DIM]
            ga = torch.tensor([merged_graph_attr], dtype=torch.float)
            pyg.graph_attr = apply_graph_attr_profile(ga, self.graph_attr_profile)
            pyg.name   = name
            pyg.family = family
            pyg.benign_subtype = benign_subtype
            pyg.train_eligible = bool(train_eligible)
            pyg.uncertain = bool(uncertain)
            pyg.label_quality_flag = self._as_bool(row.get("label_quality_flag", False))
            pyg.label_quality_reason = str(row.get("label_quality_reason", "") or "")
            self._data_list.append(pyg)
            ok += 1

        print(
            f"[Dataset] Loaded {ok}/{ok + fail} graphs  "
            f"(target={self.target})"
        )
        if self._data_list:
            values, counts = np.unique([d.y.item() for d in self._data_list], return_counts=True)
            dist = ", ".join(f"class={int(v)}: {int(c)}" for v, c in zip(values, counts))
            print(f"[Dataset] Class distribution: {dist}")
        if skipped_uncertain:
            print(f"[Dataset] {skipped_uncertain} uncertain/unknown sample(s) excluded.")
        if fail:
            print(f"[Dataset] {fail} sample(s) skipped.")
        if subtype_counts:
            details = ", ".join(f"{k}={v}" for k, v in sorted(subtype_counts.items()))
            print(f"[Dataset] Benign subtype counts: {details}")
        if skip_reasons:
            details = ", ".join(f"{k}={v}" for k, v in sorted(skip_reasons.items()))
            print(f"[Dataset] Governance exclusions: {details}")

    def _row_target(self, row, default_label: int) -> int:
        if self.target == "label":
            return int(default_label)
        if self.target == "curated_label":
            curated = row.get("curated_label", "")
            feedback_state = str(row.get("feedback_state", "")).strip().lower()
            try:
                if str(curated).strip() != "" and feedback_state in {"approved", "validated"}:
                    return int(curated)
            except (TypeError, ValueError):
                pass
            return int(default_label)

        verdict = str(row.get("verdict", "")).strip().upper()
        if not verdict:
            raise ValueError("Missing verdict for risk target")

        prefix = verdict.split("—", 1)[0].strip()
        if prefix not in self.RISK_LEVEL_MAP:
            raise ValueError(f"Unsupported verdict '{verdict}' for risk target")
        return self.RISK_LEVEL_MAP[prefix]

    def len(self) -> int:
        return len(self._data_list)

    def get(self, idx: int) -> Data:
        return self._data_list[idx]

    def labels(self) -> list[int]:
        return [d.y.item() for d in self._data_list]

    def get_labels(self) -> list[int]:
        return self.labels()

    def summary(self) -> None:
        if not self._data_list:
            print("Dataset is empty.")
            return
        print(f"\nDataset summary ({len(self)} graphs):")
        print(f"  Node feature dim  : {self._data_list[0].x.size(1)}   (expect {NODE_FEAT_DIM})")
        print(f"  Graph attr dim    : {self._data_list[0].graph_attr.shape}  (expect [1, {GRAPH_ATTR_DIM}])")
        for d in self._data_list:
            print(
                f"  {d.name:<45} "
                f"nodes={d.num_nodes:<6} "
                f"edges={d.edge_index.size(1):<6} "
                f"label={d.y.item()}  "
                f"graph_attr={d.graph_attr.squeeze().tolist()}"
            )


if __name__ == "__main__":
    import sys
    manifest = (
        sys.argv[1] if len(sys.argv) > 1
        else "extracted_data/dataset_manifest.csv"
    )
    ds = MalwareGraphDataset(manifest)
    ds.summary()
