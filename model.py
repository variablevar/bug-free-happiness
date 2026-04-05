#!/usr/bin/env python3
"""
model.py  v4
Changes vs v3:
  - GRAPH_ATTR_DIM 4 → 14 to match dataset.py v2
    (4 manifest cols + 10 log1p edge-type counts)
  - clf_in now reads graph_attr size DYNAMICALLY from the first forward pass
    so if dataset.py changes again the model self-adjusts without code edits.
    Achieved via a lazy Linear that is built on first call.
  - Readout: concat(mean + max + sum)  — unchanged from v3
  - Default hidden=16, layers=2, dropout=0.5  — unchanged
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (GINConv, SAGEConv,
                                 global_mean_pool,
                                 global_max_pool,
                                 global_add_pool)

READOUT_MULT   = 3   # mean + max + sum


def readout(x, batch):
    return torch.cat([
        global_mean_pool(x, batch),
        global_max_pool(x, batch),
        global_add_pool(x, batch),
    ], dim=-1)  # [B, hidden*3]


# ── GIN Classifier ──────────────────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()
        self.hidden  = hidden
        self.n_layers = layers
        self.dropout = dropout

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

        # Lazy head: built on first forward when we know graph_attr dim
        self._head = None

    def _build_head(self, graph_attr_dim: int, device):
        gnn_dim  = self.hidden * READOUT_MULT * self.n_layers
        clf_in   = gnn_dim + graph_attr_dim
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

        graph_emb = torch.cat(layer_outs, dim=1)   # [B, hidden*3*layers]

        if graph_attr is None:
            graph_attr = torch.zeros(graph_emb.size(0), 14,
                                     device=graph_emb.device)

        if self._head is None:
            self._build_head(graph_attr.size(1), graph_emb.device)

        graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        return self._head(graph_emb)


# ── GraphSAGE Classifier ──────────────────────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()
        self.hidden   = hidden
        self.dropout  = dropout

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self._head = None

    def _build_head(self, graph_attr_dim: int, device):
        clf_in   = self.hidden * READOUT_MULT + graph_attr_dim
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

        graph_emb = readout(x, batch)              # [B, hidden*3]

        if graph_attr is None:
            graph_attr = torch.zeros(graph_emb.size(0), 14,
                                     device=graph_emb.device)

        if self._head is None:
            self._build_head(graph_attr.size(1), graph_emb.device)

        graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        return self._head(graph_emb)
