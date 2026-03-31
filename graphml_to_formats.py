#!/usr/bin/env python3
"""
graphml_to_formats.py
=====================
Reconstruct graph.json and graph.pkl from graph.graphml for every
sub-directory inside a given root directory.

Useful when the JSON/pickle files are missing or corrupted but the
GraphML files are intact.

Usage
-----
    python graphml_to_formats.py <root_dir>
    python graphml_to_formats.py extracted_data_augmented/
    python graphml_to_formats.py extracted_data/

For each sub-directory that contains a graph.graphml file the script:
  1. Reads graph.graphml  → NetworkX DiGraph
  2. Writes graph.json    (node-link format, overwrites if present)
  3. Writes graph.pkl     (pickle, overwrites if present)

Files that already exist are silently overwritten (use --dry-run to
preview without writing anything).
"""

import argparse
import json
import pickle
import sys
from pathlib import Path

import networkx as nx


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def graphml_to_nx(graphml_path: Path) -> nx.DiGraph:
    """Read a GraphML file and return a NetworkX DiGraph."""
    G = nx.read_graphml(str(graphml_path))
    # Ensure we always work with a DiGraph (GraphML may load as Graph)
    if not isinstance(G, nx.DiGraph):
        G = nx.DiGraph(G)
    return G


def nx_to_json(G: nx.DiGraph) -> dict:
    """
    Serialise a NetworkX DiGraph to the node-link JSON dict used
    everywhere else in this project (edges stored under key 'links').
    """
    return nx.node_link_data(G, edges="links")


def process_dir(sample_dir: Path, dry_run: bool = False) -> str:
    """
    Process one sample directory.
    Returns a status string: 'ok', 'skipped' (no graphml), or 'error:<msg>'.
    """
    graphml_path = sample_dir / "graph.graphml"
    if not graphml_path.exists():
        return "skipped"

    try:
        G = graphml_to_nx(graphml_path)
    except Exception as exc:
        return f"error:read:{exc}"

    json_path = sample_dir / "graph.json"
    pkl_path  = sample_dir / "graph.pkl"

    if dry_run:
        json_status = "(would overwrite)" if json_path.exists() else "(would create)"
        pkl_status  = "(would overwrite)" if pkl_path.exists()  else "(would create)"
        print(f"  [dry-run] {sample_dir.name}")
        print(f"            graph.json {json_status}")
        print(f"            graph.pkl  {pkl_status}")
        return "ok"

    try:
        graph_data = nx_to_json(G)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)
    except Exception as exc:
        return f"error:json:{exc}"

    try:
        with open(pkl_path, "wb") as f:
            pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as exc:
        return f"error:pkl:{exc}"

    return "ok"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(root: Path, dry_run: bool = False) -> None:
    if not root.is_dir():
        print(f"[ERROR] Not a directory: {root}")
        sys.exit(1)

    sub_dirs = sorted([d for d in root.iterdir() if d.is_dir()])

    if not sub_dirs:
        print(f"[!] No sub-directories found in {root}")
        return

    mode = "DRY RUN — no files will be written" if dry_run else "overwrite mode"
    print(f"[+] {len(sub_dirs)} sub-director{'y' if len(sub_dirs)==1 else 'ies'} "
          f"found in {root}  [{mode}]\n")

    ok = skipped = errors = 0

    for sub_dir in sub_dirs:
        status = process_dir(sub_dir, dry_run=dry_run)

        if status == "ok":
            ok += 1
            if not dry_run:
                print(f"  [✓] {sub_dir.name}")
        elif status == "skipped":
            skipped += 1
            print(f"  [–] {sub_dir.name}  (no graph.graphml — skipped)")
        else:
            errors += 1
            print(f"  [!] {sub_dir.name}  {status}")

    print(f"\n[+] Done — {ok} converted, {skipped} skipped, {errors} errors")
    if errors:
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rebuild graph.json and graph.pkl from graph.graphml "
                    "for every sub-directory in a root directory."
    )
    parser.add_argument(
        "root_dir",
        help="Root directory whose sub-directories contain graph.graphml files"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be written without touching any files"
    )
    args = parser.parse_args()
    run(Path(args.root_dir), dry_run=args.dry_run)
