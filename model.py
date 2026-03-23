#!/usr/bin/env python3
"""
model.py
GIN-based binary classifier for malware graph detection.
Also provides a GraphSAGE variant for comparison.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GINConv, SAGEConv, global_mean_pool, global_add_pool


# ── GIN Classifier (recommended) ─────────────────────────────────────────────
class GINMalwareClassifier(nn.Module):
    """
    Graph Isomorphism Network for binary malware classification.
    Strongest at distinguishing structurally different graphs.
    """

    def __init__(self, in_channels: int, hidden: int = 64, layers: int = 3, dropout: float = 0.3):
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
        self.classifier = nn.Sequential(
            nn.Linear(hidden * layers, hidden),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden, 2),
        )

    def forward(self, x, edge_index, batch):
        # Collect embeddings from every layer (jumping knowledge)
        layer_outs = []
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(global_add_pool(x, batch))

        # Concatenate all layer readouts → graph embedding
        graph_emb = torch.cat(layer_outs, dim=1)
        return self.classifier(graph_emb)


# ── GraphSAGE Classifier (alternative) ───────────────────────────────────────
class SAGEMalwareClassifier(nn.Module):
    """GraphSAGE variant — good for large heterogeneous graphs."""

    def __init__(self, in_channels: int, hidden: int = 64, layers: int = 3, dropout: float = 0.3):
        super().__init__()
        self.convs = nn.ModuleList()
        self.bns   = nn.ModuleList()

        for i in range(layers):
            in_ch = in_channels if i == 0 else hidden
            self.convs.append(SAGEConv(in_ch, hidden))
            self.bns.append(nn.BatchNorm1d(hidden))

        self.dropout = dropout
        self.classifier = nn.Sequential(
            nn.Linear(hidden, hidden // 2),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden // 2, 2),
        )

    def forward(self, x, edge_index, batch):
        for conv, bn in zip(self.convs, self.bns):
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
        graph_emb = global_mean_pool(x, batch)
        return self.classifier(graph_emb)
