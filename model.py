#!/usr/bin/env python3
"""
model.py  v2
Changes vs v1:
  - graph_attr (4-dim graph-level features) concatenated to graph embedding
    before classifier head — free signal from max_score, attack_steps,
    injections, c2_conns already computed in dataset.py
  - GINConv: global_add_pool → global_mean_pool (stable for variable-size graphs)
  - SAGE classifier head input adjusted for graph_attr
  - GRAPH_ATTR_DIM = 4 constant shared by both models
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (GINConv, SAGEConv,
                                 global_mean_pool, global_add_pool)

GRAPH_ATTR_DIM = 4   # max_score, attack_steps, injections, c2_conns


# ── GIN Classifier ────────────────────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 64,
                 layers: int = 3, dropout: float = 0.3):
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

        # Input: (hidden * layers) from JK-concat  +  4 graph-level attrs
        clf_in = hidden * layers + GRAPH_ATTR_DIM
        self.classifier = nn.Sequential(
            nn.Linear(clf_in, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

    def forward(self, x, edge_index, batch, graph_attr=None):
        layer_outs = []
        for conv, bn in zip(self.convs, self.bns):
            # FIX: global_mean_pool — stable for variable-size graphs
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(global_mean_pool(x, batch))

        graph_emb = torch.cat(layer_outs, dim=1)          # [B, hidden*layers]

        # Concatenate graph-level features if provided
        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)  # [B, hidden*layers+4]
        else:
            # Fallback: pad with zeros so classifier shape is always valid
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)


# ── GraphSAGE Classifier ──────────────────────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):

    def __init__(self, in_channels: int, hidden: int = 64,
                 layers: int = 3, dropout: float = 0.3):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self.dropout = dropout

        # Input: hidden from mean_pool  +  4 graph-level attrs
        clf_in = hidden + GRAPH_ATTR_DIM
        self.classifier = nn.Sequential(
            nn.Linear(clf_in, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, 2),
        )

    def forward(self, x, edge_index, batch, graph_attr=None):
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)

        graph_emb = global_mean_pool(x, batch)             # [B, hidden]

        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)
