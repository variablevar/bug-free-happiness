#!/usr/bin/env python3
"""
dataset.py
Loads graph.pkl files from a dataset manifest and converts each
NetworkX graph into a PyTorch Geometric Data object.

Usage:
    from dataset import MalwareGraphDataset
    dataset = MalwareGraphDataset("extracted_data/dataset_manifest.csv")
    data = dataset[0]   # PyG Data object
"""

import os
import pickle

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data, Dataset

# ── Node type vocabulary ──────────────────────────────────────────────────────
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
EDGE_TYPE_IDX = {t: i for i, t in enumerate(EDGE_TYPES)}

# ── Numeric node attributes (fixed order → feature vector) ───────────────────
NUMERIC_ATTRS = [
    "pid", "ppid", "threads", "handles",
    "is_suspicious", "is_rwx", "has_mz_header",
    "private_memory", "commit_charge",
    "local_port", "foreign_port", "is_external",
    "size", "start",
    "load_count",
    "tid",
]

# Minimum viable graph size — must match augment_dataset.py
MIN_NODES = 10


def node_features(data: dict) -> list:
    """
    Build a fixed-length float feature vector for one node:
      [one-hot node_type (9 dims)] + [numeric attrs (16 dims)] = 25 dims
    """
    ntype = data.get("node_type", "kernel")
    oh = [0.0] * len(NODE_TYPES)
    oh[NODE_TYPE_IDX.get(ntype, len(NODE_TYPES) - 1)] = 1.0

    nums = []
    for attr in NUMERIC_ATTRS:
        v = data.get(attr, 0)
        try:
            nums.append(float(v))
        except (TypeError, ValueError):
            nums.append(0.0)

    return oh + nums


def nx_to_pyg(G, label: int) -> Data:
    """
    Convert a NetworkX DiGraph to a PyTorch Geometric Data object.

    Raises
    ------
    ValueError
        If the graph has fewer than MIN_NODES nodes or zero edges.
        This catches degenerate graphs that survived disk writes but
        would produce constant GNN embeddings and corrupt training.
    """
    n_nodes = G.number_of_nodes()
    n_edges = G.number_of_edges()

    if n_nodes < MIN_NODES:
        raise ValueError(
            f"Degenerate graph: {n_nodes} node(s) "
            f"(minimum {MIN_NODES}). Skipping."
        )
    if n_edges == 0:
        raise ValueError(
            f"Degenerate graph: 0 edges ({n_nodes} nodes present). Skipping."
        )

    nodes = list(G.nodes(data=True))
    node_idx = {nid: i for i, (nid, _) in enumerate(nodes)}

    x = torch.tensor(
        [node_features(data) for _, data in nodes],
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
        edge_attr  = torch.tensor(edge_attr_list, dtype=torch.long)
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        edge_attr  = torch.zeros(0, dtype=torch.long)

    return Data(
        x=x,
        edge_index=edge_index,
        edge_attr=edge_attr,
        y=torch.tensor([label], dtype=torch.long),
        num_nodes=x.size(0),
    )


class MalwareGraphDataset(Dataset):
    """
    Reads a manifest CSV, loads each graph.pkl, and returns PyG Data objects.

    Skips any sample whose .pkl is missing, cannot be unpickled, or whose
    resulting graph is degenerate (< MIN_NODES nodes or 0 edges).
    """

    def __init__(self, manifest_csv: str, base_dir: str = None):
        super().__init__()
        self.manifest = pd.read_csv(manifest_csv)
        self.base_dir = base_dir or os.path.dirname(manifest_csv)
        self._data_list: list[Data] = []
        self._load_all()

    # ------------------------------------------------------------------
    def _load_all(self) -> None:
        ok = fail = 0

        for _, row in self.manifest.iterrows():
            name   = str(row["folder"])
            label  = int(row["label"])
            family = row.get("family", "unknown")
            pkl    = os.path.join(self.base_dir, name, "graph.pkl")

            # ── 1. File-exists guard ──────────────────────────────────
            if not os.path.exists(pkl):
                print(f"  [SKIP] {name} — graph.pkl not found")
                fail += 1
                continue

            # ── 2. Unpickle guard ────────────────────────────────────
            try:
                with open(pkl, "rb") as f:
                    G = pickle.load(f)
            except Exception as exc:
                print(f"  [SKIP] {name} — failed to load pkl: {exc}")
                fail += 1
                continue

            # ── 3. Degenerate-graph guard ────────────────────────────
            try:
                pyg = nx_to_pyg(G, label)
            except ValueError as exc:
                print(f"  [SKIP] {name} — {exc}")
                fail += 1
                continue

            # ── 4. Attach graph-level metadata ───────────────────────
            graph_feat = torch.tensor([
                float(row.get("max_score",    0) or 0),
                float(row.get("attack_steps", 0) or 0),
                float(row.get("injections",   0) or 0),
                float(row.get("c2_conns",     0) or 0),
            ], dtype=torch.float)

            pyg.name       = name
            pyg.family     = family
            pyg.graph_attr = graph_feat
            self._data_list.append(pyg)
            ok += 1

        print(
            f"[Dataset] Loaded {ok}/{ok + fail} graphs  "
            f"(label=1: {sum(d.y.item() == 1 for d in self._data_list)}  "
            f"label=0: {sum(d.y.item() == 0 for d in self._data_list)})"
        )
        if fail:
            print(f"[Dataset] {fail} sample(s) skipped — "
                  f"check [SKIP] lines above for details.")

    # ------------------------------------------------------------------
    def len(self) -> int:
        return len(self._data_list)

    def get(self, idx: int) -> Data:
        return self._data_list[idx]

    def labels(self) -> list[int]:
        """Return integer label for every loaded graph."""
        return [d.y.item() for d in self._data_list]

    def get_labels(self) -> list[int]:
        """Alias for labels() — for compatibility with train.py."""
        return self.labels()

    def summary(self) -> None:
        if not self._data_list:
            print("Dataset is empty — no graphs were loaded.")
            return
        print(f"\nDataset summary ({len(self)} graphs):")
        print(f"  Node feature dim : {self._data_list[0].x.size(1)}")
        print(f"  Edge types       : {len(EDGE_TYPES)}")
        for d in self._data_list:
            print(
                f"  {d.name:<45} "
                f"nodes={d.num_nodes:<6} "
                f"edges={d.edge_index.size(1):<6} "
                f"label={d.y.item()}"
            )


if __name__ == "__main__":
    import sys
    manifest = (
        sys.argv[1]
        if len(sys.argv) > 1
        else "extracted_data/dataset_manifest.csv"
    )
    ds = MalwareGraphDataset(manifest)
    ds.summary()
