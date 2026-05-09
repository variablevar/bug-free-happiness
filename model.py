#!/usr/bin/env python3
"""
Graph neural networks for memory-forensics / EDR-style **process graphs**.

Each training sample is one graph built from a memory snapshot (CSVs under a
sample folder → `graph.pkl`): nodes are processes, threads, DLLs, memory
regions, network objects, etc.; edges encode relationships (spawn, load,
injection, C2, …). The GNN scores the **whole graph** (structural anomaly /
malware vs benign), not isolated strings.

Typical deployment story
------------------------
1. **Snapshot** — capture memory when the endpoint looks suspicious.
2. **Graph mapping** — build a directed graph of entities and typed relations.
3. **GNN inference** — this module: message passing over neighborhoods, then a
   graph-level readout fused with manifest-level `graph_attr` (density, edge
   counts, risk hints).
4. **Alerting** — logits or calibrated probabilities drive SOC / EDR alerts.

Tensor contract (matches `MalwareGraphDataset` in `dataset.py`)
-----------------------------------------------------------------
- `x`: node features, last dim **31** (type one-hot + numeric flags + role counts).
- `edge_index`: `[2, E]` PyG COO.
- `batch`: batch vector for `global_*_pool`.
- `graph_attr`: `[B, D]` (or omitted → zeros); see `EXPECTED_GRAPH_ATTR_DIM` in `utils/schema.py`.
- `edge_attr`: optional `[E]` long indices of edge type; **required** for
  `GINEMalwareClassifier` (typed relations).

Exports: `GINMalwareClassifier`, `SAGEMalwareClassifier`, `GATMalwareClassifier`,
`GINEMalwareClassifier` — same constructor kwargs expected by `train.py` /
`evaluate.py`.
"""

from __future__ import annotations

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (
    GATConv,
    GINConv,
    GINEConv,
    SAGEConv,
    global_add_pool,
    global_max_pool,
    global_mean_pool,
)

from dataset import N_EDGE_TYPES
from utils.schema import EXPECTED_GRAPH_ATTR_DIM


def _graph_readout(x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
    """Per-graph vector: concat(mean, max, sum) over nodes → dim `3 * F`."""
    return torch.cat(
        [
            global_mean_pool(x, batch),
            global_max_pool(x, batch),
            global_add_pool(x, batch),
        ],
        dim=-1,
    )


def _zeros_graph_attr(batch_size: int, device: torch.device) -> torch.Tensor:
    return torch.zeros(batch_size, EXPECTED_GRAPH_ATTR_DIM, device=device)


class GINMalwareClassifier(nn.Module):
    """Jumping-knowledge style GIN: readout after each layer, concat, then head."""

    def __init__(
        self,
        in_channels: int,
        hidden: int = 16,
        layers: int = 2,
        dropout: float = 0.5,
        num_classes: int = 2,
    ):
        super().__init__()
        self.hidden = hidden
        self.n_layers = layers
        self.dropout = dropout
        self.num_classes = num_classes

        self.convs = nn.ModuleList()
        self.bns = nn.ModuleList()
        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            mlp = nn.Sequential(
                nn.Linear(in_ch, hidden),
                nn.BatchNorm1d(hidden),
                nn.ReLU(),
                nn.Linear(hidden, hidden),
            )
            self.convs.append(GINConv(mlp, train_eps=True))
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head: nn.Module | None = None

    def _build_head(self, clf_in: int, device: torch.device) -> None:
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, self.num_classes),
        ).to(device)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None = None,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        del edge_attr

        chunks = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            chunks.append(_graph_readout(x, batch))

        gnn_vec = torch.cat(chunks, dim=1)
        if graph_attr is None:
            graph_attr = _zeros_graph_attr(gnn_vec.size(0), gnn_vec.device)

        if self._head is None:
            self._build_head(gnn_vec.size(1) + graph_attr.size(1), gnn_vec.device)

        return self._head(torch.cat([gnn_vec, graph_attr], dim=1))


class SAGEMalwareClassifier(nn.Module):
    """GraphSAGE stack + single readout + `graph_attr` fusion."""

    def __init__(
        self,
        in_channels: int,
        hidden: int = 16,
        layers: int = 2,
        dropout: float = 0.5,
        num_classes: int = 2,
    ):
        super().__init__()
        self.hidden = hidden
        self.dropout = dropout
        self.num_classes = num_classes

        self.convs = nn.ModuleList()
        self.bns = nn.ModuleList()
        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head: nn.Module | None = None

    def _build_head(self, clf_in: int, device: torch.device) -> None:
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, self.num_classes),
        ).to(device)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None = None,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        del edge_attr

        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        gnn_vec = _graph_readout(x, batch)
        if graph_attr is None:
            graph_attr = _zeros_graph_attr(gnn_vec.size(0), gnn_vec.device)

        if self._head is None:
            self._build_head(gnn_vec.size(1) + graph_attr.size(1), gnn_vec.device)

        return self._head(torch.cat([gnn_vec, graph_attr], dim=1))


class GATMalwareClassifier(nn.Module):
    """
    Multi-head GAT: intermediate layers concat heads to width `hidden`;
    last layer averages heads. `hidden` must be divisible by `heads`.
    """

    def __init__(
        self,
        in_channels: int,
        hidden: int = 16,
        layers: int = 2,
        heads: int = 4,
        dropout: float = 0.5,
        num_classes: int = 2,
    ):
        super().__init__()
        if hidden % heads != 0:
            raise ValueError(f"hidden ({hidden}) must be divisible by heads ({heads})")

        self.hidden = hidden
        self.dropout = dropout
        self.heads = heads
        self.num_classes = num_classes

        head_dim = hidden // heads
        self.convs = nn.ModuleList()
        self.bns = nn.ModuleList()
        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            last = i == layers - 1
            if last:
                self.convs.append(
                    GATConv(in_ch, hidden, heads=heads, concat=False, dropout=dropout)
                )
            else:
                self.convs.append(
                    GATConv(in_ch, head_dim, heads=heads, concat=True, dropout=dropout)
                )
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head: nn.Module | None = None

    def _build_head(self, clf_in: int, device: torch.device) -> None:
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, self.num_classes),
        ).to(device)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None = None,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        del edge_attr

        for conv, bn in zip(self.convs, self.bns):
            x = F.elu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        gnn_vec = _graph_readout(x, batch)
        if graph_attr is None:
            graph_attr = _zeros_graph_attr(gnn_vec.size(0), gnn_vec.device)

        if self._head is None:
            self._build_head(gnn_vec.size(1) + graph_attr.size(1), gnn_vec.device)

        return self._head(torch.cat([gnn_vec, graph_attr], dim=1))


class GINEMalwareClassifier(nn.Module):
    """
    GINE: same jumping readout as GIN, but each message uses **learned edge-type
    vectors** (integer `edge_attr` from the dataset).
    """

    def __init__(
        self,
        in_channels: int,
        hidden: int = 16,
        layers: int = 2,
        dropout: float = 0.5,
        num_classes: int = 2,
        num_edge_types: int = N_EDGE_TYPES,
        edge_emb_dim: int = 8,
    ):
        super().__init__()
        self.hidden = hidden
        self.n_layers = layers
        self.dropout = dropout
        self.num_classes = num_classes
        self.edge_emb = nn.Embedding(num_edge_types, edge_emb_dim)

        self.convs = nn.ModuleList()
        self.bns = nn.ModuleList()
        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            mlp = nn.Sequential(
                nn.Linear(in_ch, hidden),
                nn.BatchNorm1d(hidden),
                nn.ReLU(),
                nn.Linear(hidden, hidden),
            )
            self.convs.append(GINEConv(mlp, train_eps=True, edge_dim=edge_emb_dim))
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head: nn.Module | None = None

    def _build_head(self, clf_in: int, device: torch.device) -> None:
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, self.num_classes),
        ).to(device)

    def encode_graph(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None = None,
        edge_attr: torch.Tensor | None = None,
    ) -> torch.Tensor:
        if edge_attr is None:
            raise ValueError("GINEMalwareClassifier requires edge_attr (edge-type indices).")

        idx = edge_attr.view(-1).long().clamp(
            min=0, max=self.edge_emb.num_embeddings - 1
        )
        edge_feat = self.edge_emb(idx)

        chunks = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index, edge_attr=edge_feat)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            chunks.append(_graph_readout(x, batch))

        gnn_vec = torch.cat(chunks, dim=1)
        if graph_attr is None:
            graph_attr = _zeros_graph_attr(gnn_vec.size(0), gnn_vec.device)

        return torch.cat([gnn_vec, graph_attr], dim=1)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None = None,
        edge_attr: torch.Tensor | None = None,
        *,
        return_embedding: bool = False,
    ) -> torch.Tensor | tuple[torch.Tensor, torch.Tensor]:
        emb = self.encode_graph(x, edge_index, batch, graph_attr=graph_attr, edge_attr=edge_attr)
        if self._head is None:
            self._build_head(emb.size(1), emb.device)
        logits = self._head(emb)
        if return_embedding:
            return logits, emb
        return logits
