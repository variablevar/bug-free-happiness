#!/usr/bin/env python3
"""
Corpus-level profiling for MalVol graphs: manifest + optional two-model JSON,
per-folder graph stats (graph.pkl or graph.json), paired family deltas, and
optional ego-subgraph export for deep dives.

NoVirus / WithVirus labels follow name_inference (control vs infected snapshot);
they do not mean the NoVirus graph is structurally clean — see manifest verdicts.
"""

from __future__ import annotations

import argparse
import json
import os
import pickle
import re
from pathlib import Path
from typing import Any

import networkx as nx
import pandas as pd
from networkx.readwrite import json_graph

# Columns to carry from manifest into the wide profile table
MANIFEST_KEEP = [
    "sample_id",
    "folder",
    "label",
    "family",
    "benign_subtype",
    "label_source",
    "nodes",
    "edges",
    "max_score",
    "attack_steps",
    "injections",
    "c2_conns",
    "verdict",
    "label_signals_top",
    "uncertain",
    "train_eligible",
    "filter_ok",
    "graph_ok",
    "analyze_ok",
]
SIGNAL_PREFIX = "signal_"


def _signal_columns(df: pd.DataFrame) -> list[str]:
    return [c for c in df.columns if c.startswith(SIGNAL_PREFIX)]


def load_graph(sample_dir: Path) -> tuple[nx.DiGraph | None, str]:
    pkl = sample_dir / "graph.pkl"
    js = sample_dir / "graph.json"
    if pkl.is_file():
        with open(pkl, "rb") as f:
            G = pickle.load(f)
        if not isinstance(G, nx.DiGraph):
            G = nx.DiGraph(G) if isinstance(G, nx.Graph) else None
        return G, "pkl"
    if js.is_file():
        with open(js, encoding="utf-8") as f:
            data = json.load(f)
        G = json_graph.node_link_graph(data, edges="links", directed=True)
        return G, "json"
    return None, "missing"


def _as_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except (TypeError, ValueError):
        return default


def _as_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def graph_stats(G: nx.DiGraph, top_k: int = 5) -> dict[str, Any]:
    node_types: dict[str, int] = {}
    edge_types: dict[str, int] = {}
    suspicious = 0
    proc_deg: list[tuple[str, int, str, int, float]] = []

    for nid, data in G.nodes(data=True):
        nt = str(data.get("node_type", "unknown"))
        node_types[nt] = node_types.get(nt, 0) + 1
        if nt == "process":
            sus = _as_int(data.get("is_suspicious", 0))
            if sus:
                suspicious += 1
            deg = G.out_degree(nid) + G.in_degree(nid)
            name = str(data.get("name", data.get("label", "")))[:80]
            pid = _as_int(data.get("pid", -1))
            heur = _as_float(data.get("heuristic_score", 0.0))
            proc_deg.append((nid, deg, name, pid, heur))

    for _, _, data in G.edges(data=True):
        et = str(data.get("edge_type", "unknown"))
        edge_types[et] = edge_types.get(et, 0) + 1

    proc_deg.sort(key=lambda t: (t[1], t[4]), reverse=True)
    top = proc_deg[:top_k]
    top_summary = " | ".join(f"{t[2]}(pid={t[3]},deg={t[1]})" for t in top)

    return {
        "graph_n_nodes": G.number_of_nodes(),
        "graph_n_edges": G.number_of_edges(),
        "graph_n_suspicious_processes": suspicious,
        "graph_node_types_json": json.dumps(dict(sorted(node_types.items()))),
        "graph_edge_types_json": json.dumps(dict(sorted(edge_types.items()))),
        "graph_top_processes_by_degree": top_summary,
    }


def load_two_model_map(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    out: dict[str, dict[str, Any]] = {}
    for s in payload.get("samples", []):
        folder = s.get("folder")
        if not folder:
            continue
        fusion = s.get("fusion") or {}
        out[str(folder)] = {
            "tm_triage_state": s.get("triage_state"),
            "tm_label_from_manifest": s.get("label_from_manifest"),
            "tm_malware_pattern_score": s.get("malware_pattern_score"),
            "tm_benign_conformity_score": s.get("benign_conformity_score"),
            "tm_delta_score": s.get("delta_score"),
            "tm_fusion_ensemble_score": fusion.get("ensemble_score"),
            "tm_fusion_final_triage_state": fusion.get("final_triage_state"),
            "tm_fusion_dual_triage_state": fusion.get("dual_triage_state"),
            "tm_fusion_binary_calibrated": fusion.get("binary_malware_probability_calibrated"),
            "tm_fusion_binary_effective": fusion.get("binary_probability_effective"),
            "tm_fusion_heuristic_risk": fusion.get("heuristic_risk_score"),
        }
    return out


def run_tier1_manifest_plus(
    manifest_path: Path,
    two_model_path: Path | None,
    out_csv: Path,
) -> pd.DataFrame:
    df = pd.read_csv(manifest_path)
    sig_cols = _signal_columns(df)
    keep = [c for c in MANIFEST_KEEP if c in df.columns] + sig_cols
    wide = df[keep].copy()
    wide["family_sort"] = wide["family"].astype(str).str.lower()
    wide["label_sort"] = wide["label"].astype(int)

    tm = load_two_model_map(two_model_path)
    if tm:
        tm_rows = wide["folder"].map(lambda f: tm.get(str(f), {}))
        tm_df = pd.DataFrame(list(tm_rows))
        wide = pd.concat([wide.reset_index(drop=True), tm_df], axis=1)

    wide = wide.sort_values(["family_sort", "label_sort", "folder"]).drop(
        columns=["family_sort", "label_sort"], errors="ignore"
    )
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    wide.to_csv(out_csv, index=False)
    return wide


def run_tier2_graph_stats(base_dir: Path, manifest_folders: list[str], out_csv: Path) -> pd.DataFrame:
    rows = []
    for folder in manifest_folders:
        sample_dir = base_dir / folder
        G, src = load_graph(sample_dir)
        if G is None:
            rows.append({"folder": folder, "graph_source": src})
            continue
        st = graph_stats(G)
        st["folder"] = folder
        st["graph_source"] = src
        rows.append(st)
    out = pd.DataFrame(rows)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv, index=False)
    return out


def _numeric_delta_columns(df: pd.DataFrame) -> list[str]:
    skip = {"folder", "sample_id", "label", "family", "graph_node_types_json", "graph_edge_types_json"}
    cols = []
    for c in df.columns:
        if c in skip or c.startswith("tm_") and c in ("tm_triage_state", "tm_fusion_final_triage_state"):
            continue
        if pd.api.types.is_numeric_dtype(df[c]):
            cols.append(c)
    return cols


def run_tier3_pair_deltas(merged: pd.DataFrame, out_csv: Path) -> pd.DataFrame:
    """Within each family: compare single NoVirus (label 0) row to each WithVirus (label 1)."""
    merged = merged.copy()
    merged["_fam"] = merged["family"].astype(str).str.lower()
    delta_rows = []
    num_cols = _numeric_delta_columns(merged)

    for fam, g in merged.groupby("_fam", sort=False):
        nv = g[g["label"] == 0]
        wv = g[g["label"] == 1]
        if nv.empty or wv.empty:
            continue
        base = nv.iloc[0]
        base_folder = str(base["folder"])
        for _, wr in wv.iterrows():
            w_folder = str(wr["folder"])
            rec: dict[str, Any] = {
                "family": fam,
                "no_virus_folder": base_folder,
                "with_virus_folder": w_folder,
            }
            for c in num_cols:
                if c in base.index and c in wr.index:
                    bv = base[c]
                    wvv = wr[c]
                    if pd.isna(bv) and pd.isna(wvv):
                        rec[f"d_{c}"] = 0.0
                    elif pd.isna(bv):
                        rec[f"d_{c}"] = float(wvv) if not pd.isna(wvv) else 0.0
                    elif pd.isna(wvv):
                        rec[f"d_{c}"] = -float(bv)
                    else:
                        rec[f"d_{c}"] = float(wvv) - float(bv)
            delta_rows.append(rec)

    ddf = pd.DataFrame(delta_rows)
    if not ddf.empty:
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        ddf.to_csv(out_csv, index=False)
    return ddf


def run_tier4_dump_ego(base_dir: Path, folder: str, radius: int, out_path: Path) -> None:
    sample_dir = base_dir / folder
    G, src = load_graph(sample_dir)
    if G is None:
        raise SystemExit(f"No graph.pkl or graph.json in {sample_dir}")
    # Pick ego center: process with max total degree
    best = None
    best_deg = -1
    for nid, data in G.nodes(data=True):
        if str(data.get("node_type")) != "process":
            continue
        deg = G.out_degree(nid) + G.in_degree(nid)
        if deg > best_deg:
            best_deg = deg
            best = nid
    if best is None:
        best = next(iter(G.nodes()))
    und = G.to_undirected()
    sub_u = nx.ego_graph(und, best, radius=radius)
    sub = G.subgraph(sub_u.nodes()).copy()
    data = json_graph.node_link_data(sub, edges="links")
    meta = {"folder": folder, "graph_source": src, "ego_center": str(best), "ego_radius": radius}
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"meta": meta, "graph": data}, indent=2), encoding="utf-8")
    print(f"[corpus_profile] wrote ego subgraph ({len(sub)} nodes) to {out_path}")


def main() -> None:
    p = argparse.ArgumentParser(description="Profile extracted_csvs corpus (manifest + graphs + deltas)")
    p.add_argument("--manifest", default="extracted_csvs/dataset_manifest.csv")
    p.add_argument("--base-dir", default="extracted_csvs", dest="base_dir")
    p.add_argument("--two-model", default=None, dest="two_model", help="Optional outputs/two_model_analysis.json")
    p.add_argument("--out-dir", default="outputs", dest="out_dir")
    p.add_argument("--skip-graph", action="store_true", dest="skip_graph", help="Only manifest (+two-model) table")
    p.add_argument(
        "--dump-ego",
        default=None,
        dest="dump_ego",
        help="Folder name under base-dir to export ego subgraph JSON",
    )
    p.add_argument("--ego-radius", type=int, default=1, dest="ego_radius")
    p.add_argument(
        "--dump-ego-out",
        default=None,
        dest="dump_ego_out",
        help="Output path for ego JSON (default: out-dir/ego_<folder>.json)",
    )
    args = p.parse_args()

    base = Path(args.base_dir)
    manifest_path = Path(args.manifest)
    out_dir = Path(args.out_dir)
    two_path = Path(args.two_model) if args.two_model else None

    if args.dump_ego:
        folder = args.dump_ego
        out_ego = Path(args.dump_ego_out) if args.dump_ego_out else out_dir / f"ego_{re.sub(r'[^a-zA-Z0-9_.-]+', '_', folder)}.json"
        run_tier4_dump_ego(base, folder, args.ego_radius, out_ego)
        return

    tm_default = out_dir / "two_model_analysis.json"
    if two_path is None and tm_default.is_file():
        two_path = tm_default

    wide = run_tier1_manifest_plus(manifest_path, two_path, out_dir / "corpus_manifest_plus_models.csv")
    print(f"[corpus_profile] wrote {out_dir / 'corpus_manifest_plus_models.csv'} ({len(wide)} rows)")

    if args.skip_graph:
        return

    folders = wide["folder"].astype(str).tolist()
    stats = run_tier2_graph_stats(base, folders, out_dir / "corpus_graph_stats.csv")
    print(f"[corpus_profile] wrote {out_dir / 'corpus_graph_stats.csv'} ({len(stats)} rows)")

    merged = wide.merge(stats, on="folder", how="left")
    merged.to_csv(out_dir / "corpus_merged_manifest_graph.csv", index=False)
    print(f"[corpus_profile] wrote {out_dir / 'corpus_merged_manifest_graph.csv'}")

    deltas = run_tier3_pair_deltas(merged, out_dir / "corpus_pair_deltas.csv")
    if deltas.empty:
        print("[corpus_profile] no family pairs for corpus_pair_deltas.csv (need both label 0 and 1 in same family)")
    else:
        print(f"[corpus_profile] wrote {out_dir / 'corpus_pair_deltas.csv'} ({len(deltas)} pair rows)")


if __name__ == "__main__":
    main()
