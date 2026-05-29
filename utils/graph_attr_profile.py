"""Graph-level attribute profiles (leakage control for training/inference)."""

from __future__ import annotations

import torch

# Indices in merged graph_attr (see dataset.MalwareGraphDataset docstring).
MANIFEST_LEAKAGE_IDXS = [0, 1, 2, 3, 7, 8, 9, 10, 11, 12, 13]
STRUCTURE_ONLY_KEEP = list(range(4, 7))  # log_nodes, log_edges, density

GRAPH_ATTR_PROFILES = ("full", "no_manifest_leakage", "structure_only")


def apply_graph_attr_profile(
    graph_attr: torch.Tensor | None,
    profile: str = "full",
) -> torch.Tensor | None:
    """Return a copy of graph_attr with profile masking applied."""
    if graph_attr is None:
        return None
    p = str(profile or "full").strip().lower()
    if p == "full":
        return graph_attr
    ga = graph_attr.clone()
    if ga.dim() == 1:
        ga = ga.unsqueeze(0)
    width = int(ga.size(-1))
    if p == "no_manifest_leakage":
        for idx in MANIFEST_LEAKAGE_IDXS:
            if 0 <= idx < width:
                ga[..., idx] = 0.0
        return ga
    if p == "structure_only":
        mask = torch.zeros(width, dtype=ga.dtype, device=ga.device)
        for idx in STRUCTURE_ONLY_KEEP:
            if 0 <= idx < width:
                mask[idx] = 1.0
        # edge histogram starts at 27; motifs at tail — keep from index 27 onward
        if width > 27:
            mask[27:] = 1.0
        return ga * mask.unsqueeze(0)
    raise ValueError(f"Unknown graph_attr_profile: {profile!r}")
