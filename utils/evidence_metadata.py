"""Helpers for adding graph/node context to model explanation evidence."""

from __future__ import annotations

from typing import Any


def _as_dict(value: Any) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def node_context(data: Any, node_idx: int) -> dict:
    nodes = getattr(data, "node_metadata", []) or []
    if 0 <= int(node_idx) < len(nodes):
        return _as_dict(nodes[int(node_idx)])
    return {}


def edge_context(data: Any, edge_idx: int) -> dict:
    edges = getattr(data, "edge_metadata", []) or []
    if 0 <= int(edge_idx) < len(edges):
        return _as_dict(edges[int(edge_idx)])
    return {}


def enrich_node(data: Any, node_idx: int, importance: float) -> dict:
    meta = node_context(data, node_idx)
    return {
        "node_id": int(node_idx),
        "importance": float(importance),
        **meta,
    }


def enrich_edge(data: Any, edge_idx: int, src_idx: int, dst_idx: int, importance: float) -> dict:
    edge_meta = edge_context(data, edge_idx)
    src_meta = node_context(data, src_idx)
    dst_meta = node_context(data, dst_idx)
    return {
        "src": int(src_idx),
        "dst": int(dst_idx),
        "importance": float(importance),
        "edge_index": int(edge_idx),
        "edge_type": str(edge_meta.get("edge_type", "")),
        "src_node": src_meta,
        "dst_node": dst_meta,
        **{k: v for k, v in edge_meta.items() if k not in {"src", "dst", "edge_index", "edge_type"}},
    }
