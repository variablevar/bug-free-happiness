#!/usr/bin/env python3
"""
Lightweight parity checks for refactor safety.

Checks a sample folder for core pipeline contract consistency:
- required artifacts exist
- graph node/edge counts match graph.json
- graph_attr shape sanity
- manifest columns available (when dataset_manifest.csv exists)
"""

import argparse
import csv
import json
import os
import pickle
import sys

from utils.schema import EXPECTED_GRAPH_ATTR_BASE_DIM


REQUIRED_FILES = (
    "filtered_malicious.json",
    "graph.json",
    "graph.pkl",
    "graph_attr.json",
    "analysis_report.json",
)

MANIFEST_REQUIRED_COLUMNS = (
    "sample_id",
    "folder",
    "label",
    "family",
    "nodes",
    "edges",
    "max_score",
    "attack_steps",
    "injections",
    "c2_conns",
    "verdict",
    "graph_attr",
    "label_signals_top",
    "filter_ok",
    "graph_ok",
    "analyze_ok",
    "error",
)


def fail(message):
    print(f"[FAIL] {message}")
    return 1


def check_sample(sample_dir):
    for name in REQUIRED_FILES:
        path = os.path.join(sample_dir, name)
        if not os.path.exists(path):
            return fail(f"missing required file: {path}")

    graph_pkl_path = os.path.join(sample_dir, "graph.pkl")
    graph_json_path = os.path.join(sample_dir, "graph.json")
    graph_attr_path = os.path.join(sample_dir, "graph_attr.json")

    with open(graph_json_path, "r", encoding="utf-8") as handle:
        graph_json = json.load(handle)
    json_nodes = len(graph_json.get("nodes", []))
    json_edges = len(graph_json.get("links", []))

    pkl_nodes = pkl_edges = None
    try:
        with open(graph_pkl_path, "rb") as handle:
            graph = pickle.load(handle)
        pkl_nodes = graph.number_of_nodes()
        pkl_edges = graph.number_of_edges()
    except ModuleNotFoundError as exc:
        print(f"[WARN] skipped graph.pkl count check (missing dependency: {exc})")
    except Exception as exc:
        return fail(f"unable to read graph.pkl for parity check: {exc}")

    if pkl_nodes is not None and pkl_edges is not None:
        if (pkl_nodes, pkl_edges) != (json_nodes, json_edges):
            return fail(
                "graph count mismatch: "
                f"pkl=({pkl_nodes}, {pkl_edges}) json=({json_nodes}, {json_edges})"
            )

    with open(graph_attr_path, "r", encoding="utf-8") as handle:
        graph_attr = json.load(handle).get("graph_attr", [])
    if len(graph_attr) != EXPECTED_GRAPH_ATTR_BASE_DIM:
        return fail(
            f"graph_attr length {len(graph_attr)} != {EXPECTED_GRAPH_ATTR_BASE_DIM}"
        )

    print(
        "[OK] sample parity: "
        f"json_nodes={json_nodes} json_edges={json_edges} "
        f"pkl_nodes={pkl_nodes} pkl_edges={pkl_edges} "
        f"graph_attr_len={len(graph_attr)}"
    )
    return 0


def check_manifest(base_dir):
    manifest_path = os.path.join(base_dir, "dataset_manifest.csv")
    if not os.path.exists(manifest_path):
        print(f"[INFO] manifest not found: {manifest_path} (skipping)")
        return 0

    with open(manifest_path, "r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        missing = [c for c in MANIFEST_REQUIRED_COLUMNS if c not in reader.fieldnames]
    if missing:
        return fail(f"manifest missing columns: {missing}")

    print("[OK] manifest columns verified")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Run refactor parity checks.")
    parser.add_argument(
        "sample_dir",
        help="Path to a sample folder containing graph/analysis artifacts",
    )
    parser.add_argument(
        "--base-dir",
        default=None,
        help="Base extracted_data directory to validate dataset_manifest.csv",
    )
    args = parser.parse_args()

    code = check_sample(os.path.abspath(args.sample_dir))
    if code != 0:
        sys.exit(code)

    if args.base_dir:
        code = check_manifest(os.path.abspath(args.base_dir))
        if code != 0:
            sys.exit(code)

    print("[DONE] parity checks passed")


if __name__ == "__main__":
    main()

