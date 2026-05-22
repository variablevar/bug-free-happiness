"""Align PyG Data tensors to checkpoint training shapes (node x, graph_attr)."""

from __future__ import annotations

import torch
from torch_geometric.data import Data

from utils.schema import EXPECTED_GRAPH_ATTR_DIM


def align_x(x: torch.Tensor, expected_dim: int) -> torch.Tensor:
    """Truncate or zero-pad node feature matrix along feature dim."""
    if x.size(1) == expected_dim:
        return x
    if x.size(1) > expected_dim:
        return x[:, :expected_dim].contiguous()
    pad = torch.zeros(x.size(0), expected_dim - x.size(1), device=x.device, dtype=x.dtype)
    return torch.cat([x, pad], dim=1)


def align_graph_attr(ga: torch.Tensor, expected_dim: int) -> torch.Tensor:
    """Truncate or zero-pad graph_attr (supports [1, D] or [D])."""
    if ga is None:
        return ga
    if ga.dim() == 1:
        ga = ga.unsqueeze(0)
    cur = ga.size(-1)
    if cur == expected_dim:
        return ga
    if cur > expected_dim:
        return ga[..., :expected_dim].contiguous()
    pad = torch.zeros(*ga.shape[:-1], expected_dim - cur, device=ga.device, dtype=ga.dtype)
    return torch.cat([ga, pad], dim=-1)


def align_pyg_data_to_binary_checkpoint(data: Data, ckpt: dict) -> Data:
    """Match supervised GINE checkpoint in_channels and graph_attr_dim."""
    d = data.clone()
    exp_x = int(ckpt["in_channels"])
    exp_ga = int(ckpt.get("graph_attr_dim", EXPECTED_GRAPH_ATTR_DIM))
    d.x = align_x(d.x, exp_x)
    ga = getattr(d, "graph_attr", None)
    if ga is not None:
        d.graph_attr = align_graph_attr(ga, exp_ga)
    return d


def align_pyg_data_to_oneclass_model(data: Data, model) -> Data:
    """Use OneClassGINE.expected_node_in and graph_attr_dim."""
    d = data.clone()
    exp_x = int(getattr(model, "expected_node_in", d.x.size(1)))
    exp_ga = int(getattr(model, "graph_attr_dim", EXPECTED_GRAPH_ATTR_DIM))
    d.x = align_x(d.x, exp_x)
    ga = getattr(d, "graph_attr", None)
    if ga is not None:
        d.graph_attr = align_graph_attr(ga, exp_ga)
    return d
