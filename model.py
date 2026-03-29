#!/usr/bin/env python3
"""
model.py  v3
Changes vs v2:
  - Added GATMalwareClassifier with:
    * Multi-head Graph Attention (GATConv)
    * Residual connections per layer
    * BatchNorm between layers
    * ELU activation (smoother gradient flow for attention)
    * JK-concat pooling across all layers (same as GIN)
  - GIN and SAGE classifiers unchanged for baseline comparison
  - GRAPH_ATTR_DIM = 4 constant shared by all three models
"""

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import (GINConv, SAGEConv, GATConv,
                                 global_mean_pool, global_add_pool,
                                 BatchNorm)

GRAPH_ATTR_DIM = 4   # max_score, attack_steps, injections, c2_conns


# ── GAT Classifier ────────────────────────────────────────────────────────────
class GATMalwareClassifier(nn.Module):
    """
    Graph Attention Network with:
      - Multi-head attention per layer
      - Residual (skip) connections
      - BatchNorm after each GAT layer
      - JK-concat pooling
      - graph_attr concatenated before classifier head
    """

    def __init__(self, in_channels: int, hidden: int = 32,
                 layers: int = 3, heads: int = 4,
                 dropout: float = 0.3):
        super().__init__()
        self.convs     = nn.ModuleList()
        self.bns       = nn.ModuleList()
        self.res_projs = nn.ModuleList()   # project input dim → conv output dim

        for i in range(layers):
            in_ch  = in_channels if i == 0 else hidden * heads
            # All layers use concat=True so output dim = hidden * heads
            self.convs.append(
                GATConv(in_ch, hidden, heads=heads, concat=True,
                        dropout=dropout)
            )
            self.bns.append(BatchNorm(hidden * heads))
            # Linear projection for residual: in_ch → hidden * heads
            self.res_projs.append(nn.Linear(in_ch, hidden * heads, bias=False))

        self.dropout = dropout

        # JK-concat: pool from every layer  →  layers * hidden * heads
        # + graph-level attrs
        clf_in = layers * hidden * heads + GRAPH_ATTR_DIM
        self.classifier = nn.Sequential(
            nn.Linear(clf_in, hidden * heads),
            nn.ELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden * heads, 2),
        )

    def forward(self, x, edge_index, batch, graph_attr=None):
        layer_outs = []
        for conv, bn, res_proj in zip(self.convs, self.bns, self.res_projs):
            residual = res_proj(x)                         # skip connection
            x        = conv(x, edge_index)                 # GAT conv
            x        = bn(x)                               # batch norm
            x        = F.elu(x)                            # ELU activation
            x        = x + residual                        # add residual
            x        = F.dropout(x, p=self.dropout,
                                  training=self.training)
            layer_outs.append(global_mean_pool(x, batch))  # pool this layer

        graph_emb = torch.cat(layer_outs, dim=1)           # JK-concat [B, layers*hidden*heads]

        # Concatenate graph-level features
        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)


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
            x = F.relu(bn(conv(x, edge_index)))
            x = F.dropout(x, p=self.dropout, training=self.training)
            layer_outs.append(global_mean_pool(x, batch))

        graph_emb = torch.cat(layer_outs, dim=1)

        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
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

        graph_emb = global_mean_pool(x, batch)

        if graph_attr is not None:
            graph_emb = torch.cat([graph_emb, graph_attr], dim=1)
        else:
            pad = torch.zeros(graph_emb.size(0), GRAPH_ATTR_DIM,
                              device=graph_emb.device)
            graph_emb = torch.cat([graph_emb, pad], dim=1)

        return self.classifier(graph_emb)
