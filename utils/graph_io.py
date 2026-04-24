import os
import pickle

import networkx as nx


def load_graph_from_path(path: str):
    """Accept a graph.pkl path or sample folder; return (graph, output_dir)."""
    if os.path.isdir(path):
        candidate = os.path.join(path, "graph.pkl")
        if not os.path.exists(candidate):
            raise FileNotFoundError(f"graph.pkl not found in {path}")
        path = candidate
    if not os.path.exists(path):
        raise FileNotFoundError(f"Not found: {path}")
    with open(path, "rb") as handle:
        graph = pickle.load(handle)
    if not isinstance(graph, nx.Graph):
        raise TypeError("Pickle does not contain a NetworkX graph.")
    return graph, os.path.dirname(os.path.abspath(path))

