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

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data, Dataset
from utils.schema import EXPECTED_GRAPH_ATTR_DIM

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
]
EDGE_TYPE_IDX  = {t: i for i, t in enumerate(EDGE_TYPES)}
N_EDGE_TYPES   = len(EDGE_TYPES)

# ── Feature layout ───────────────────────────────────────────────────────────
#  [0:9]   one-hot node type          (9 dims)
#  [9:16]  semantic numeric attrs     (7 dims)
#  [16:21] per-node edge-role counts  (5 dims)
NODE_FEAT_DIM = 9 + 7 + 5   # = 21

# Graph-level attrs:
#   4  base manifest counts
#   8  additional manifest/derived risk signals
#   10 edge-type log-counts
# = 22 dims total
GRAPH_ATTR_DIM = 12 + N_EDGE_TYPES   # = 22

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

    return n_injected_into, n_connects_to, n_connects_from, degree_out, degree_in


def node_features(nid, data: dict,
                  n_injected_into, n_connects_to, n_connects_from,
                  degree_out, degree_in) -> list:
    ntype = data.get("node_type", "kernel")
    oh = [0.0] * len(NODE_TYPES)
    oh[NODE_TYPE_IDX.get(ntype, len(NODE_TYPES) - 1)] = 1.0

    nums = [
        float(data.get("is_suspicious",  0) or 0),
        float(data.get("is_rwx",         0) or 0),
        float(data.get("has_mz_header",  0) or 0),
        float(data.get("is_external",    0) or 0),
        _log1p(data.get("private_memory", 0)),
        _log1p(data.get("commit_charge",  0)),
        _log1p(data.get("load_count",     0)),
    ]

    roles = [
        _log1p(n_injected_into.get(nid,  0)),
        _log1p(n_connects_to.get(nid,    0)),
        _log1p(n_connects_from.get(nid,  0)),
        _log1p(degree_out.get(nid,       0)),
        _log1p(degree_in.get(nid,        0)),
    ]

    return oh + nums + roles


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

    n_inj, n_cto, n_cfr, d_out, d_in = _build_per_node_edge_roles(G)

    nodes     = list(G.nodes(data=True))
    node_idx  = {nid: i for i, (nid, _) in enumerate(nodes)}

    x = torch.tensor(
        [node_features(nid, data, n_inj, n_cto, n_cfr, d_out, d_in)
         for nid, data in nodes],
        dtype=torch.float,
    )

    src_list, dst_list, edge_attr_list = [], [], []
    for u, v, edata in G.edges(data=True):
        if u in node_idx and v in node_idx:
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

    return Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=x.size(0),
    )


# ── Dataset class ─────────────────────────────────────────────────────────────────

class MalwareGraphDataset(Dataset):
    """
    graph_attr shape: [1, 22] per sample.
      PyG DataLoader cats along dim-0 → [B, 22] in a batch.

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
      [12:22] log1p edge-type counts (10 dims)
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
        target: str = "label",
    ):
        super().__init__()
        self.manifest  = pd.read_csv(manifest_csv)
        self.base_dir  = base_dir or os.path.dirname(manifest_csv)
        self.include_uncertain = include_uncertain
        self.include_unknown = include_unknown
        self.target = str(target).strip().lower()
        if self.target not in {"label", "risk"}:
            raise ValueError(
                f"Invalid target '{target}'. Expected one of: label, risk."
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

    def _load_all(self) -> None:
        ok = fail = skipped_uncertain = 0

        for _, row in self.manifest.iterrows():
            name   = str(row["folder"])
            label  = int(row["label"])
            family = row.get("family", "unknown")
            uncertain = self._as_bool(row.get("uncertain", False))
            if uncertain and not self.include_uncertain:
                print(f"  [SKIP] {name} — marked uncertain in manifest")
                skipped_uncertain += 1
                continue
            if label < 0 and not self.include_unknown:
                print(f"  [SKIP] {name} — unknown label={label}")
                skipped_uncertain += 1
                continue
            pkl    = os.path.join(self.base_dir, name, "graph.pkl")

            if not os.path.exists(pkl):
                print(f"  [SKIP] {name} — graph.pkl not found")
                fail += 1
                continue

            try:
                with open(pkl, "rb") as f:
                    G = pickle.load(f)
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
            manifest_feats = [
                _safe_float(row.get("max_score", 0), default=0.0),
                _safe_float(row.get("attack_steps", 0), default=0.0),
                _safe_float(row.get("injections", 0), default=0.0),
                _safe_float(row.get("c2_conns", 0), default=0.0),
                _log1p(nodes),
                _log1p(edges),
                density,
                float(behavioural_suspects_found),
                float(lolbin_c2_found),
                float(ransom_note_found),
                _log1p(rwx_injections),
                max(0.0, min(1.0, triage_conf)),
            ]
            edge_dist_feats = _edge_type_distribution(G)  # 10 dims
            merged_graph_attr = manifest_feats + edge_dist_feats
            if len(merged_graph_attr) != EXPECTED_GRAPH_ATTR_DIM:
                raise ValueError(
                    f"Invalid graph_attr length for {name}: "
                    f"{len(merged_graph_attr)} != {EXPECTED_GRAPH_ATTR_DIM}"
                )

            # Shape [1, 22] so DataLoader stacks to [B, 22] — not [B*22]
            pyg.graph_attr = torch.tensor(
                [merged_graph_attr], dtype=torch.float
            )  # [1, 22]
            pyg.name   = name
            pyg.family = family
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

    def _row_target(self, row, default_label: int) -> int:
        if self.target == "label":
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
