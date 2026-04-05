#!/usr/bin/env python3
"""
model.py  v3
Changes vs v2:
  - GIN readout: global_mean_pool → concat(mean + max + sum) for richer
    graph-level embedding on small graphs (3× the signal per layer)
  - SAGE readout: same concat(mean + max + sum)
  - Classifier head input dims updated accordingly
  - hidden=16, layers=2 are now the recommended defaults for 30-graph datasets
    (pass via train.py CLI: --hidden 16 --layers 2)
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (GINConv, SAGEConv,
                                 global_mean_pool,
                                 global_max_pool,
                                 global_add_pool)

GRAPH_ATTR_DIM = 4   # max_score, attack_steps, injections, c2_conns
READOUT_MULT   = 3   # mean + max + sum concatenated


def readout(x, batch):
    """Concatenated mean+max+sum pooling — richer than mean alone."""
    return torch.cat([
        global_mean_pool(x, batch),
        global_max_pool(x, batch),
        global_add_pool(x, batch),
    ], dim=-1)  # [B, hidden * 3]


# ── GIN Classifier ────────────────────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

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

        self.dropout = dropout

        # JK-concat across layers, each layer produces hidden*3 via readout
        clf_in = hidden * READOUT_MULT * layers + GRAPH_ATTR_DIM
        self.classifier = nn.Sequential(
            nn.Linear(clf_in, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

    def forward(self, x, edge_index, batch, graph_attr=None):
        layer_outs = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(readout(x, batch))   # [B, hidden*3] per layer

        graph_emb = torch.cat(layer_outs, dim=1)   # [B, hidden*3*layers]

        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)


# ── GraphSAGE Classifier ──────────────────────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 16,
                 layers: int = 2, dropout: float = 0.5):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self.dropout = dropout

        # Last layer readout only (no JK for SAGE) + graph attrs
        clf_in = hidden * READOUT_MULT + GRAPH_ATTR_DIM
        self.classifier = nn.Sequential(
            nn.Linear(clf_in, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

    def forward(self, x, edge_index, batch, graph_attr=None):
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        graph_emb = readout(x, batch)              # [B, hidden*3]

        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)
