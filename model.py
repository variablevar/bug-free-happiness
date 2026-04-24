#!/usr/bin/env python3
"""
model.py v5
Changes vs v4:
- Added GATMalwareClassifier (Graph Attention Network)
  * Multi-head attention, concat(mean+max+sum) readout
  * Same lazy-head pattern as GIN/SAGE — graph_attr dim resolved on first forward
  * Defaults: hidden=32, layers=2, heads=4, dropout=0.5
- GINMalwareClassifier, SAGEMalwareClassifier unchanged from v4
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (
    GINConv, SAGEConv, GATConv,
    global_mean_pool,
    global_max_pool,
    global_add_pool,
)
from utils.schema import EXPECTED_GRAPH_ATTR_DIM

READOUT_MULT = 3  # mean + max + sum


def readout(x, batch):
    return torch.cat([
        global_mean_pool(x, batch),
        global_max_pool(x, batch),
        global_add_pool(x, batch),
    ], dim=-1)  # [B, hidden*3]


# ── GIN Classifier ─────────────────────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs    = nn.ModuleList()
        self.bns      = nn.ModuleList()
        self.hidden   = hidden
        self.n_layers = layers
        self.dropout  = dropout

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

        self._head = None  # lazy — built on first forward

    def _build_head(self, graph_attr_dim: int, device):
        gnn_dim = self.hidden * READOUT_MULT * self.n_layers
        clf_in  = gnn_dim + graph_attr_dim
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, 2),
        ).to(device)

    def forward(self, x, edge_index, batch, graph_attr=None):
        layer_outs = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(readout(x, batch))

        graph_emb = torch.cat(layer_outs, dim=1)  # [B, hidden*3*layers]

        if graph_attr is None:
            graph_attr = torch.zeros(
                graph_emb.size(0), EXPECTED_GRAPH_ATTR_DIM, device=graph_emb.device
            )

        if self._head is None:
            self._build_head(graph_attr.size(1), graph_emb.device)

        graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        return self._head(graph_emb)


# ── GraphSAGE Classifier ───────────────────────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs   = nn.ModuleList()
        self.bns     = nn.ModuleList()
        self.hidden  = hidden
        self.dropout = dropout

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head = None

    def _build_head(self, graph_attr_dim: int, device):
        clf_in = self.hidden * READOUT_MULT + graph_attr_dim
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, 2),
        ).to(device)

    def forward(self, x, edge_index, batch, graph_attr=None):
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        graph_emb = readout(x, batch)  # [B, hidden*3]

        if graph_attr is None:
            graph_attr = torch.zeros(
                graph_emb.size(0), EXPECTED_GRAPH_ATTR_DIM, device=graph_emb.device
            )

        if self._head is None:
            self._build_head(graph_attr.size(1), graph_emb.device)

        graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        return self._head(graph_emb)


# ── GAT Classifier ─────────────────────────────────────────────────────────────
class GATMalwareClassifier(nn.Module):
    """
    Graph Attention Network classifier with multi-head attention.

    Architecture:
        - `layers` GAT conv layers, each with `heads` attention heads
        - Intermediate layers: concat heads  → output dim = hidden
        - Final layer: average heads         → output dim = hidden
        - Readout: concat(mean + max + sum)
        - Lazy classification head: built on first forward pass so
          graph_attr dim is resolved automatically (same pattern as GIN/SAGE)

    Args:
        in_channels:  Node feature dimension (= 31 for this dataset)
        hidden:       Hidden units per layer (must be divisible by heads)
        layers:       Number of GAT conv layers (default 2)
        heads:        Attention heads per intermediate layer (default 4)
        dropout:      Dropout on features and attention weights (default 0.5)
    """

    def __init__(self, in_channels: int, hidden: int = 32,
                 layers: int = 2, heads: int = 4, dropout: float = 0.5):
        super().__init__()
        assert hidden % heads == 0, (
            f"hidden ({hidden}) must be divisible by heads ({heads})"
        )

        self.convs   = nn.ModuleList()
        self.bns     = nn.ModuleList()
        self.hidden  = hidden
        self.dropout = dropout
        self.heads   = heads

        head_dim = hidden // heads  # per-head output size

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            is_last = (i == layers - 1)

            if is_last:
                # Last layer: average heads → output dim = hidden
                self.convs.append(
                    GATConv(in_ch, hidden, heads=heads,
                            concat=False, dropout=dropout)
                )
            else:
                # Intermediate layers: concat heads → output dim = head_dim*heads = hidden
                self.convs.append(
                    GATConv(in_ch, head_dim, heads=heads,
                            concat=True, dropout=dropout)
                )
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head = None  # lazy

    def _build_head(self, graph_attr_dim: int, device):
        clf_in = self.hidden * READOUT_MULT + graph_attr_dim
        self._head = nn.Sequential(
            nn.Linear(clf_in, self.hidden),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(self.hidden, 2),
        ).to(device)

    def forward(self, x, edge_index, batch, graph_attr=None):
        for conv, bn in zip(self.convs, self.bns):
            x = F.elu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        graph_emb = readout(x, batch)  # [B, hidden*3]

        if graph_attr is None:
            graph_attr = torch.zeros(
                graph_emb.size(0), EXPECTED_GRAPH_ATTR_DIM, device=graph_emb.device
            )

        if self._head is None:
            self._build_head(graph_attr.size(1), graph_emb.device)

        graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        return self._head(graph_emb)