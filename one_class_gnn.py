#!/usr/bin/env python3
"""Shared one-class GNN utilities for malware/benign conformity models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Data
from torch_geometric.loader import DataLoader
from torch_geometric.nn import GINEConv, global_add_pool, global_max_pool, global_mean_pool

from dataset import N_EDGE_TYPES
from utils.evidence_metadata import enrich_edge, enrich_node
from utils.inference_align import align_pyg_data_to_oneclass_model
from utils.schema import EXPECTED_GRAPH_ATTR_DIM


def _graph_readout(x: torch.Tensor, batch: torch.Tensor) -> torch.Tensor:
    return torch.cat(
        [global_mean_pool(x, batch), global_max_pool(x, batch), global_add_pool(x, batch)],
        dim=-1,
    )


class OneClassGINE(nn.Module):
    def __init__(
        self,
        in_channels: int,
        hidden: int = 32,
        layers: int = 2,
        dropout: float = 0.4,
        edge_emb_dim: int = 16,
        out_dim: int = 64,
        graph_attr_dim: int = EXPECTED_GRAPH_ATTR_DIM,
    ):
        super().__init__()
        self.hidden = hidden
        self.layers = layers
        self.dropout = dropout
        self.edge_emb = nn.Embedding(N_EDGE_TYPES, edge_emb_dim)
        self.graph_attr_dim = graph_attr_dim
        self.expected_node_in = int(in_channels)

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

        self.proj: nn.Module | None = None
        self.out_dim = out_dim

    def _build_proj(self, in_dim: int, device: torch.device) -> None:
        self.proj = nn.Sequential(
            nn.Linear(in_dim, max(self.out_dim, self.hidden)),
            nn.ReLU(),
            nn.Dropout(self.dropout),
            nn.Linear(max(self.out_dim, self.hidden), self.out_dim),
        ).to(device)

    def encode(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None,
        edge_attr: torch.Tensor | None,
    ) -> torch.Tensor:
        if edge_attr is None:
            raise ValueError("OneClassGINE requires edge_attr edge type ids")
        idx = edge_attr.view(-1).long().clamp(min=0, max=self.edge_emb.num_embeddings - 1)
        edge_feat = self.edge_emb(idx)

        chunks = []
        h = x
        for conv, bn in zip(self.convs, self.bns):
            h = F.relu(bn(conv(h, edge_index, edge_attr=edge_feat)))
            h = F.dropout(h, p=self.dropout, training=self.training)
            chunks.append(_graph_readout(h, batch))
        gnn_vec = torch.cat(chunks, dim=1)

        if graph_attr is None:
            graph_attr = torch.zeros((gnn_vec.size(0), self.graph_attr_dim), device=gnn_vec.device)

        feat = torch.cat([gnn_vec, graph_attr], dim=1)
        if self.proj is None:
            self._build_proj(feat.size(1), feat.device)
        z = self.proj(feat)
        return F.normalize(z, p=2, dim=1)

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        graph_attr: torch.Tensor | None,
        edge_attr: torch.Tensor | None,
    ) -> torch.Tensor:
        return self.encode(x, edge_index, batch, graph_attr, edge_attr)


@dataclass
class OneClassArtifacts:
    state_dict: dict[str, Any]
    center: np.ndarray
    radius: float
    in_channels: int
    graph_attr_dim: int
    hidden: int
    layers: int
    dropout: float
    edge_emb_dim: int
    out_dim: int


def _batch_embeddings(model: OneClassGINE, loader: DataLoader, device: torch.device) -> torch.Tensor:
    model.eval()
    emb = []
    with torch.no_grad():
        for batch in loader:
            batch = batch.to(device)
            z = model(
                batch.x,
                batch.edge_index,
                batch.batch,
                getattr(batch, "graph_attr", None),
                getattr(batch, "edge_attr", None),
            )
            emb.append(z.detach().cpu())
    if not emb:
        return torch.zeros((0, model.out_dim))
    return torch.cat(emb, dim=0)


def _intra_class_spread_loss(z: torch.Tensor) -> torch.Tensor:
    if z.size(0) < 2:
        return z.new_tensor(0.0)
    z = F.normalize(z, p=2, dim=1)
    sim = torch.matmul(z, z.t())
    mask = ~torch.eye(sim.size(0), device=sim.device, dtype=torch.bool)
    if not torch.any(mask):
        return z.new_tensor(0.0)
    return (1.0 - sim[mask]).mean()


def train_one_class(
    ds_list: list[Data],
    device: torch.device,
    *,
    hidden: int = 32,
    layers: int = 2,
    dropout: float = 0.4,
    edge_emb_dim: int = 16,
    out_dim: int = 64,
    epochs: int = 120,
    batch_size: int = 4,
    lr: float = 3e-4,
    weight_decay: float = 1e-4,
    radius_quantile: float = 0.9,
    seed: int = 42,
    contrastive_weight: float = 0.10,
    radius_min: float = 1e-3,
    radius_max: float = 25.0,
) -> OneClassArtifacts:
    if len(ds_list) == 0:
        raise ValueError("Empty training dataset")
    torch.manual_seed(seed)
    np.random.seed(seed)

    in_channels = int(ds_list[0].x.size(1))
    graph_attr_dim = (
        int(ds_list[0].graph_attr.size(1))
        if getattr(ds_list[0], "graph_attr", None) is not None
        else EXPECTED_GRAPH_ATTR_DIM
    )
    model = OneClassGINE(
        in_channels=in_channels,
        hidden=hidden,
        layers=layers,
        dropout=dropout,
        edge_emb_dim=edge_emb_dim,
        out_dim=out_dim,
        graph_attr_dim=graph_attr_dim,
    ).to(device)
    loader = DataLoader(ds_list, batch_size=batch_size, shuffle=True)

    # Initialize center from random features
    init_emb = _batch_embeddings(model, loader, device)
    if init_emb.numel() == 0:
        raise ValueError("Could not initialize embeddings")
    center = init_emb.mean(dim=0).to(device)

    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=weight_decay)
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=max(epochs, 1), eta_min=1e-5)

    for epoch in range(1, epochs + 1):
        model.train()
        running = 0.0
        for batch in loader:
            batch = batch.to(device)
            z = model(
                batch.x,
                batch.edge_index,
                batch.batch,
                getattr(batch, "graph_attr", None),
                getattr(batch, "edge_attr", None),
            )
            dist = torch.sum((z - center.unsqueeze(0)) ** 2, dim=1)
            loss = dist.mean() + (max(0.0, contrastive_weight) * _intra_class_spread_loss(z))
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
            opt.step()
            running += float(loss.item())
        scheduler.step()
        if epoch % 10 == 0 or epoch == epochs:
            print(f"  Epoch {epoch:>3} loss={running / max(len(loader), 1):.5f}")

    final_emb = _batch_embeddings(model, loader, device)
    center_np = final_emb.mean(dim=0).numpy()
    d2 = ((final_emb.numpy() - center_np) ** 2).sum(axis=1)
    radius = float(np.quantile(d2, min(max(radius_quantile, 0.5), 0.999)))
    radius = max(float(radius_min), min(float(radius_max), radius))

    return OneClassArtifacts(
        state_dict={k: v.detach().cpu() for k, v in model.state_dict().items()},
        center=center_np.astype(np.float32),
        radius=radius,
        in_channels=in_channels,
        graph_attr_dim=graph_attr_dim,
        hidden=hidden,
        layers=layers,
        dropout=dropout,
        edge_emb_dim=edge_emb_dim,
        out_dim=out_dim,
    )


def build_model_from_payload(payload: dict, device: torch.device) -> tuple[OneClassGINE, torch.Tensor, float]:
    model = OneClassGINE(
        in_channels=int(payload["in_channels"]),
        hidden=int(payload["hidden"]),
        layers=int(payload["layers"]),
        dropout=float(payload["dropout"]),
        edge_emb_dim=int(payload["edge_emb_dim"]),
        out_dim=int(payload["out_dim"]),
        graph_attr_dim=int(payload.get("graph_attr_dim", EXPECTED_GRAPH_ATTR_DIM)),
    ).to(device)
    proj_in = (3 * int(payload["hidden"]) * int(payload["layers"])) + int(
        payload.get("graph_attr_dim", EXPECTED_GRAPH_ATTR_DIM)
    )
    model._build_proj(proj_in, device)
    model.load_state_dict(payload["state_dict"], strict=True)
    model.eval()
    center = torch.tensor(payload["center"], dtype=torch.float32, device=device)
    radius = float(payload["radius"])
    return model, center, radius


def score_graph(
    model: OneClassGINE,
    center: torch.Tensor,
    radius: float,
    data: Data,
    device: torch.device,
    *,
    force_eval: bool = True,
) -> tuple[float, float]:
    if force_eval:
        model.eval()
    with torch.no_grad():
        d = align_pyg_data_to_oneclass_model(data, model).to(device)
        batch = torch.zeros(d.x.size(0), dtype=torch.long, device=device)
        z = model(d.x, d.edge_index, batch, getattr(d, "graph_attr", None), getattr(d, "edge_attr", None))
        d2 = float(torch.sum((z[0] - center) ** 2).item())
    score = 1.0 / (1.0 + np.exp((d2 - radius) / max(radius, 1e-6)))
    return float(score), d2


def explain_graph(
    model: OneClassGINE,
    center: torch.Tensor,
    data: Data,
    device: torch.device,
    *,
    top_k_nodes: int = 5,
    top_k_graph_attrs: int = 5,
) -> dict:
    model.eval()
    d = align_pyg_data_to_oneclass_model(data, model).clone().to(device)
    d.x = d.x.detach().requires_grad_(True)
    graph_attr = getattr(d, "graph_attr", None)
    if graph_attr is not None:
        graph_attr = graph_attr.detach().requires_grad_(True)
    batch = torch.zeros(d.x.size(0), dtype=torch.long, device=device)

    z = model(d.x, d.edge_index, batch, graph_attr, getattr(d, "edge_attr", None))
    dist = torch.sum((z[0] - center) ** 2)
    dist.backward()

    node_sal = (d.x.grad * d.x).abs().sum(dim=1).detach().cpu().numpy()
    node_order = np.argsort(-node_sal)
    top_nodes = [enrich_node(d, int(i), float(node_sal[i])) for i in node_order[: max(1, top_k_nodes)]]

    graph_attr_top = []
    if graph_attr is not None and graph_attr.grad is not None:
        ga_sal = (graph_attr.grad * graph_attr).abs().detach().cpu().numpy().reshape(-1)
        ga_order = np.argsort(-ga_sal)
        graph_attr_top = [
            {"feature_index": int(i), "importance": float(ga_sal[i])}
            for i in ga_order[: max(1, top_k_graph_attrs)]
        ]

    edge_pairs = []
    if d.edge_index is not None and d.edge_index.size(1) > 0:
        src = d.edge_index[0].detach().cpu().numpy()
        dst = d.edge_index[1].detach().cpu().numpy()
        scores = []
        for edge_i, (u, v) in enumerate(zip(src.tolist(), dst.tolist())):
            score = float(node_sal[int(u)]) + float(node_sal[int(v)])
            scores.append((score, int(edge_i), int(u), int(v)))
        scores.sort(reverse=True)
        edge_pairs = [
            enrich_edge(d, edge_i, u, v, s)
            for s, edge_i, u, v in scores[: max(1, top_k_nodes)]
        ]

    return {
        "distance": float(dist.detach().cpu().item()),
        "top_nodes": top_nodes,
        "top_graph_attrs": graph_attr_top,
        "edge_pairs": edge_pairs,
    }

