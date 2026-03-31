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
    python graphml_to_formats.py extracted_data_augmented/ --workers 8
    python graphml_to_formats.py extracted_data/ --dry-run

For each sub-directory that contains a graph.graphml file the script:
  1. Reads graph.graphml  → NetworkX DiGraph
  2. Writes graph.json    (node-link format, overwrites if present)
  3. Writes graph.pkl     (pickle, overwrites if present)

Files that already exist are silently overwritten.
The --workers flag controls how many threads run in parallel
(default: number of CPUs on the machine).
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

# Thread-safe print lock
_print_lock = threading.Lock()


def tprint(*args, **kwargs):
    """Thread-safe print."""
    with _print_lock:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# Core per-directory logic
# ---------------------------------------------------------------------------

def graphml_to_nx(graphml_path: Path) -> nx.DiGraph:
    """Read a GraphML file and return a NetworkX DiGraph."""
    G = nx.read_graphml(str(graphml_path))
    if not isinstance(G, nx.DiGraph):
        G = nx.DiGraph(G)
    return G


def nx_to_json(G: nx.DiGraph) -> dict:
    """Serialise to node-link JSON dict (edges stored under key 'links')."""
    return nx.node_link_data(G, edges="links")


def process_dir(sample_dir: Path, dry_run: bool = False) -> tuple[str, str]:
    """
    Process one sample directory.
    Returns (name, status) where status is 'ok', 'skipped', or 'error:<msg>'.
    """
    name = sample_dir.name
    graphml_path = sample_dir / "graph.graphml"

    if not graphml_path.exists():
        return name, "skipped"

    try:
        G = graphml_to_nx(graphml_path)
    except Exception as exc:
        return name, f"error:read:{exc}"

    json_path = sample_dir / "graph.json"
    pkl_path  = sample_dir / "graph.pkl"

    if dry_run:
        json_tag = "(would overwrite)" if json_path.exists() else "(would create)"
        pkl_tag  = "(would overwrite)" if pkl_path.exists()  else "(would create)"
        tprint(f"  [dry-run] {name}")
        tprint(f"            graph.json {json_tag}")
        tprint(f"            graph.pkl  {pkl_tag}")
        return name, "ok"

    try:
        graph_data = nx_to_json(G)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)
    except Exception as exc:
        return name, f"error:json:{exc}"

    try:
        with open(pkl_path, "wb") as f:
            pickle.dump(G, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception as exc:
        return name, f"error:pkl:{exc}"

    return name, "ok"


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

    ok = skipped = errors = 0
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
            elif status == "skipped":
                skipped += 1
                tprint(f"  [–] {name}  (no graph.graphml — skipped)  ({counter}/{total})")
            else:
                errors += 1
                tprint(f"  [!] {name}  {status}  ({counter}/{total})")

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
