#!/usr/bin/env python3
"""
rebuild_pkl.py  (formerly graphml_to_formats.py)
================================================
Reconstruct graph.pkl (and optionally re-validate graph.json) from the
existing graph.json written by build_graph.py for every sub-directory
inside a given root directory.

Why graph.json, not graph.graphml?
  build_graph.py writes graph.json and graph.pkl only.
  graph.graphml is never produced by the pipeline, so reading it yields
  an empty graph.  The authoritative serialised graph is graph.json
  (node-link format, edges under key "links").

Usage
-----
    python rebuild_pkl.py <root_dir>
    python rebuild_pkl.py extracted_data_augmented/ --workers 8
    python rebuild_pkl.py extracted_data/ --dry-run

For each sub-directory that contains a graph.json file the script:
  1. Reads  graph.json  → NetworkX DiGraph (via node_link_graph)
  2. Sanity-checks: warns if the loaded graph has 0 nodes
  3. Writes graph.pkl   (overwrites if present)

The --workers flag controls parallel threads (default: CPU count).
"""

import argparse
import json
import os
import pickle
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import networkx as nx
from networkx.readwrite import json_graph

# Thread-safe print
_print_lock = threading.Lock()


def tprint(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Core per-directory logic
# ---------------------------------------------------------------------------

def json_to_nx(json_path: Path) -> nx.DiGraph:
    """Load a node-link graph.json and return a NetworkX DiGraph."""
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    # node_link_graph accepts both 'edges' and 'links' as the edge key
    G = json_graph.node_link_graph(data, directed=True, multigraph=False, edges="links")
    if not isinstance(G, nx.DiGraph):
        G = nx.DiGraph(G)
    return G


def process_dir(sample_dir: Path, dry_run: bool = False) -> tuple[str, str]:
    """
    Process one sample directory.
    Returns (name, status) where status is:
      'ok'           — graph.pkl written successfully
      'ok:empty'     — written but graph had 0 nodes (warns)
      'skipped'      — no graph.json found
      'error:<msg>'  — something went wrong
    """
    name      = sample_dir.name
    json_path = sample_dir / "graph.json"
    pkl_path  = sample_dir / "graph.pkl"

    if not json_path.exists():
        return name, "skipped"

    try:
        G = json_to_nx(json_path)
    except Exception as exc:
        return name, f"error:read:{exc}"

    empty = G.number_of_nodes() == 0

    if dry_run:
        pkl_tag = "(would overwrite)" if pkl_path.exists() else "(would create)"
        node_info = f"{G.number_of_nodes()} nodes, {G.number_of_edges()} edges"
        tprint(f"  [dry-run] {name}")
        tprint(f"            graph.pkl {pkl_tag}  [{node_info}]{'  ⚠ EMPTY' if empty else ''}")
        return name, "ok:empty" if empty else "ok"

    try:
        with open(pkl_path, "wb") as f:
            pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as exc:
        return name, f"error:pkl:{exc}"

    return name, "ok:empty" if empty else "ok"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def run(root: Path, workers: int, dry_run: bool = False) -> None:
    if not root.is_dir():
        print(f"[ERROR] Not a directory: {root}")
        sys.exit(1)

    sub_dirs = sorted([d for d in root.iterdir() if d.is_dir()])

    if not sub_dirs:
        print(f"[!] No sub-directories found in {root}")
        return

    mode = "DRY RUN — no files will be written" if dry_run else "overwrite mode"
    print(
        f"[+] {len(sub_dirs)} sub-director{'y' if len(sub_dirs)==1 else 'ies'} "
        f"found in {root}  — using {workers} worker thread(s)  [{mode}]\n"
    )

    ok = skipped = errors = empty_warns = 0
    counter = 0
    total = len(sub_dirs)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(process_dir, d, dry_run): d for d in sub_dirs}

        for future in as_completed(futures):
            name, status = future.result()
            counter += 1

            if status == "ok":
                ok += 1
                if not dry_run:
                    tprint(f"  [✓] {name}  ({counter}/{total})")
            elif status == "ok:empty":
                ok += 1
                empty_warns += 1
                tprint(f"  [⚠] {name}  graph has 0 nodes — graph.json may be corrupt  ({counter}/{total})")
            elif status == "skipped":
                skipped += 1
                tprint(f"  [–] {name}  (no graph.json — skipped)  ({counter}/{total})")
            else:
                errors += 1
                tprint(f"  [!] {name}  {status}  ({counter}/{total})")

    print(f"\n[+] Done — {ok} rebuilt, {skipped} skipped, {errors} errors"
          + (f", {empty_warns} empty-graph warning(s)" if empty_warns else ""))
    if errors:
        sys.exit(1)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Rebuild graph.pkl from graph.json for every sub-directory "
                    "in a root directory."
    )
    parser.add_argument(
        "root_dir",
        help="Root directory whose sub-directories contain graph.json files"
    )
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=os.cpu_count() or 4,
        help="Number of parallel worker threads (default: CPU count)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview what would be written without touching any files"
    )
    args = parser.parse_args()
    run(Path(args.root_dir), workers=args.workers, dry_run=args.dry_run)
