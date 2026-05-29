"""Attack-centric subgraph extraction from behavioural graphs."""

from __future__ import annotations

import networkx as nx

SEED_EDGE_TYPES = frozenset(
    {
        "injected_into",
        "intent_injection",
        "intent_credential_access",
        "intent_c2",
        "lolbin_execution_chain",
        "parent_child_anomaly",
        "c2_relation_pattern",
        "persistence_behavior",
        "privilege_escalation_indicator",
    }
)

PROCESS_LIKE = frozenset({"process", "thread", "dll", "network_conn", "ip_address", "handle"})

TRAVERSE_EDGE_TYPES = frozenset(
    {
        "spawned_by",
        "belongs_to",
        "loaded_into",
        "injected_into",
        "connects_from",
        "connects_to",
        "parent_child_anomaly",
        "lolbin_execution_chain",
        "temporal_execution_chain",
        "intent_c2",
        "intent_injection",
        "intent_credential_access",
        "c2_relation_pattern",
        "persistence_behavior",
        "privilege_escalation_indicator",
    }
)


def _is_suspicious_memory(G: nx.DiGraph, nid: str) -> bool:
    d = G.nodes[nid]
    if str(d.get("node_type")) != "memory_region":
        return False
    if int(d.get("is_rwx", 0) or 0) == 1:
        return True
    if int(d.get("has_mz_header", 0) or 0) == 1:
        return True
    return int(d.get("is_suspicious", 0) or 0) == 1


def seed_nodes(G: nx.DiGraph) -> set[str]:
    seeds: set[str] = set()
    for u, v, ed in G.edges(data=True):
        et = ed.get("edge_type", "")
        if et in SEED_EDGE_TYPES:
            seeds.add(u)
            seeds.add(v)
    for nid, d in G.nodes(data=True):
        if str(d.get("node_type")) == "process" and int(d.get("is_suspicious", 0) or 0) == 1:
            seeds.add(nid)
    return seeds


def k_hop_neighborhood(G: nx.DiGraph, seeds: set[str], k: int = 2) -> set[str]:
    if not seeds:
        return set()
    frontier = set(seeds)
    visited = set(seeds)
    for _ in range(max(1, k)):
        nxt: set[str] = set()
        for nid in frontier:
            for _, v, ed in G.out_edges(nid, data=True):
                if ed.get("edge_type", "") in TRAVERSE_EDGE_TYPES and v not in visited:
                    nxt.add(v)
                    visited.add(v)
            for u, _, ed in G.in_edges(nid, data=True):
                if ed.get("edge_type", "") in TRAVERSE_EDGE_TYPES and u not in visited:
                    nxt.add(u)
                    visited.add(u)
        frontier = nxt
    return visited


def extract_attack_subgraph(
    G: nx.DiGraph,
    *,
    k_hops: int = 2,
    max_nodes: int = 500,
    max_edges: int = 2000,
) -> nx.DiGraph:
    """Return a causal-ish subgraph around attack seeds; drop bulk benign memory regions."""
    seeds = seed_nodes(G)
    if not seeds:
        # fallback: top suspicious processes by out-degree on semantic edges
        proc_scores: list[tuple[str, int]] = []
        for nid, d in G.nodes(data=True):
            if str(d.get("node_type")) != "process":
                continue
            score = int(d.get("is_suspicious", 0) or 0)
            proc_scores.append((nid, score))
        proc_scores.sort(key=lambda x: -x[1])
        seeds = {nid for nid, _ in proc_scores[:3]}
    nodes = k_hop_neighborhood(G, seeds, k=k_hops)
    # Always include seed-adjacent memory only when suspicious
    for nid in list(nodes):
        if str(G.nodes[nid].get("node_type")) == "memory_region" and not _is_suspicious_memory(G, nid):
            nodes.discard(nid)
    if len(nodes) > max_nodes:
        # prioritize seeds then process-like nodes
        ranked = sorted(
            nodes,
            key=lambda n: (
                0 if n in seeds else 1,
                0 if str(G.nodes[n].get("node_type")) in PROCESS_LIKE else 2,
                -G.degree(n),
            ),
        )
        nodes = set(ranked[:max_nodes])
    sub = G.subgraph(nodes).copy()
    if sub.number_of_edges() > max_edges:
        keep_edges = list(sub.edges(data=True))[:max_edges]
        sub = nx.DiGraph()
        sub.add_nodes_from(nodes)
        for u, v, d in keep_edges:
            sub.add_edge(u, v, **d)
    return sub
