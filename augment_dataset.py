"""
augment_dataset.py
==================
Graph Augmentation — Strategy 1 for the ransomware GNN dissertation.

Reads every sample folder under `extracted_data/` that contains a
`graph.json` file, applies four augmentation strategies, and writes each
augmented variant as a new sub-directory under `extracted_data_augmented/`
mirroring the exact file layout of the originals:

    extracted_data_augmented/
        <SampleName>__aug_noise_00/
            graph.json
            graph.graphml
            graph.gexf
            graph.pkl
            graph_attr.json
        <SampleName>__aug_dropnodes_00/
            ...
        <SampleName>__aug_dropedges_00/
            ...
        <SampleName>__aug_benign_00/   ← label = 0, regardless of original
            ...

An `augmented_manifest.csv` is also written next to the script recording
every generated sample with its label, source, and strategy — ready to be
consumed by build_dataset.py / dataset.py without any changes to those files.

Strategies
----------
A  feature_noise   — Gaussian noise on threads/handles/heuristic_score
B  drop_nodes      — Remove a fraction of benign non-system process/thread nodes
C  drop_edges      — Remove a fraction of non-critical edges
D  benign_variant  — Strip all malware indicators → label 0

Usage
-----
    python augment_dataset.py [--variants N] [--noise FLOAT] [--drop FLOAT]
                              [--workers N] [--skip-existing]

Defaults: 10 variants per strategy, noise=0.10, drop=0.10,
          workers=os.cpu_count(), skip-existing=False
"""

import argparse
import copy
import json
import os
import pickle
import random
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import networkx as nx

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

EXTRACTED_DATA_DIR  = Path("extracted_data")
AUGMENTED_DATA_DIR  = Path("extracted_data_augmented")
MANIFEST_PATH       = Path("augmented_manifest.csv")

VIRUS_KEYWORD       = "WithVirus"
BENIGN_KEYWORD      = "NoVirus"

# Files that must all be present for a folder to be considered complete
EXPECTED_FILES = {"graph.json", "graph.graphml", "graph.gexf",
                  "graph.pkl", "graph_attr.json"}

PROTECTED_PROCESS_NAMES = {
    "System", "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "lsass.exe", "lsm.exe",
}

MALWARE_PROCESS_NAMES = {
    "cerber.exe", "mshta.exe", "wannacry.exe", "locky.exe",
    "gandcrab.exe", "dharma.exe", "spora.exe",
}

# XML 1.0 legal character range — https://www.w3.org/TR/xml/#charsets
_XML_LEGAL = re.compile(
    r"[^\x09\x0A\x0D\x20-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]"
)

# Thread-safe print lock
_print_lock = threading.Lock()


def tprint(*args, **kwargs) -> None:
    """Thread-safe print."""
    with _print_lock:
        print(*args, **kwargs)


# ---------------------------------------------------------------------------
# XML sanitisation
# ---------------------------------------------------------------------------

def _sanitise_str(value: str) -> str:
    """Strip null bytes and XML 1.0 illegal control characters."""
    return _XML_LEGAL.sub("", value)


def sanitise_graph_for_xml(G: nx.DiGraph) -> nx.DiGraph:
    """Return a copy of G with string attributes safe for lxml serialisation."""
    G2 = G.copy()
    for _, data in G2.nodes(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                data[k] = _sanitise_str(v)
    for _, _, data in G2.edges(data=True):
        for k, v in list(data.items()):
            if isinstance(v, str):
                data[k] = _sanitise_str(v)
    return G2


# ---------------------------------------------------------------------------
# Skip-existing helper
# ---------------------------------------------------------------------------

def is_complete(out_dir: Path) -> bool:
    """Return True if out_dir already contains all 5 expected output files."""
    if not out_dir.is_dir():
        return False
    existing = {f.name for f in out_dir.iterdir() if f.is_file()}
    return EXPECTED_FILES.issubset(existing)


# ---------------------------------------------------------------------------
# Augmentation functions
# ---------------------------------------------------------------------------

def augment_feature_noise(G_data: dict, noise_level: float = 0.10,
                          seed: int = 0) -> dict:
    """Strategy A — Gaussian noise on threads / handles / heuristic_score."""
    rng = random.Random(seed)
    G2  = copy.deepcopy(G_data)
    for node in G2["nodes"]:
        ntype = node.get("node_type")
        if ntype == "process":
            if node.get("threads", 0) > 0:
                delta = int(node["threads"] * noise_level * rng.gauss(0, 1))
                node["threads"] = max(1, node["threads"] + delta)
            if node.get("handles", 0) > 0:
                delta = int(node["handles"] * noise_level * rng.gauss(0, 1))
                node["handles"] = max(0, node["handles"] + delta)
            if node.get("heuristic_score", 0) > 0:
                node["heuristic_score"] = max(
                    0, node["heuristic_score"] + rng.choice([-1, 0, 1])
                )
        elif ntype == "thread":
            if node.get("heuristic_score", 0) == 0 and rng.random() < 0.05:
                node["heuristic_score"] = 1
    return G2


def augment_drop_nodes(G_data: dict, drop_frac: float = 0.10,
                       seed: int = 0) -> dict:
    """Strategy B — drop a fraction of non-critical benign nodes."""
    rng = random.Random(seed)
    G2  = copy.deepcopy(G_data)
    removable_ids = set()
    for node in G2["nodes"]:
        ntype = node.get("node_type")
        if ntype == "process":
            if (node.get("is_suspicious", 0) == 0
                    and node.get("pid", 4) not in {0, 4}
                    and node.get("name", "") not in PROTECTED_PROCESS_NAMES
                    and node.get("name", "") not in MALWARE_PROCESS_NAMES):
                removable_ids.add(node["id"])
        elif ntype == "thread":
            if node.get("is_suspicious", 0) == 0:
                removable_ids.add(node["id"])
    k = max(1, int(len(removable_ids) * drop_frac))
    to_remove = set(rng.sample(sorted(removable_ids), k))
    G2["nodes"] = [n for n in G2["nodes"] if n["id"] not in to_remove]
    G2["links"] = [l for l in G2.get("links", [])
                   if l["source"] not in to_remove
                   and l["target"] not in to_remove]
    return G2


def augment_drop_edges(G_data: dict, drop_frac: float = 0.10,
                       seed: int = 0) -> dict:
    """Strategy C — drop a fraction of non-critical edges."""
    rng = random.Random(seed)
    G2  = copy.deepcopy(G_data)
    critical_ids = set()
    for node in G2["nodes"]:
        if (node.get("is_suspicious", 0) == 1
                or node.get("node_type") == "kernel"
                or node.get("name", "") in MALWARE_PROCESS_NAMES):
            critical_ids.add(node["id"])
    safe_indices = [
        i for i, l in enumerate(G2.get("links", []))
        if l["source"] not in critical_ids
        and l["target"] not in critical_ids
    ]
    k = max(1, int(len(safe_indices) * drop_frac))
    to_drop = set(rng.sample(safe_indices, min(k, len(safe_indices))))
    G2["links"] = [l for i, l in enumerate(G2.get("links", []))
                   if i not in to_drop]
    return G2


def make_benign_variant(G_data: dict, seed: int = 0) -> dict:
    """Strategy D — strip malware indicators → label 0."""
    rng = random.Random(seed)
    G2  = copy.deepcopy(G_data)
    malware_ids = {
        node["id"] for node in G2["nodes"]
        if node.get("name", "").lower() in {n.lower() for n in MALWARE_PROCESS_NAMES}
        or node.get("suspicion_reasons", "[]") not in ("[]", "", None)
           and node.get("heuristic_score", 0) >= 6
    }
    G2["nodes"] = [n for n in G2["nodes"] if n["id"] not in malware_ids]
    G2["links"] = [l for l in G2.get("links", [])
                   if l["source"] not in malware_ids
                   and l["target"] not in malware_ids]
    for node in G2["nodes"]:
        node["is_suspicious"]     = 0
        node["heuristic_score"]   = 0
        node["suspicion_reasons"] = "[]"
        if "threads" in node:
            node["threads"] = max(1, node["threads"] + rng.randint(-1, 2))
        if "handles" in node:
            node["handles"] = max(0, node["handles"] + rng.randint(-15, 15))
    return G2


# ---------------------------------------------------------------------------
# Format conversion & writing
# ---------------------------------------------------------------------------

def json_data_to_nx(G_data: dict) -> nx.DiGraph:
    """Node-link JSON dict → NetworkX DiGraph (edges='links' silences FutureWarning)."""
    return nx.node_link_graph(G_data, directed=True, multigraph=False,
                              edges="links")


def write_all_formats(G_data: dict, out_dir: Path, graph_attr: dict) -> None:
    """Write graph.json / .graphml / .gexf / .pkl / graph_attr.json."""
    out_dir.mkdir(parents=True, exist_ok=True)

    with open(out_dir / "graph.json", "w", encoding="utf-8") as f:
        json.dump(G_data, f, indent=2)

    with open(out_dir / "graph_attr.json", "w", encoding="utf-8") as f:
        json.dump(graph_attr, f, indent=2)

    G_nx = json_data_to_nx(G_data)

    with open(out_dir / "graph.pkl", "wb") as f:
        pickle.dump(G_nx, f, protocol=pickle.HIGHEST_PROTOCOL)

    G_xml = sanitise_graph_for_xml(G_nx)
    nx.write_graphml(G_xml, str(out_dir / "graph.graphml"))
    nx.write_gexf(G_xml, str(out_dir / "graph.gexf"))


# ---------------------------------------------------------------------------
# Label helper
# ---------------------------------------------------------------------------

def label_from_folder(folder_name: str) -> int:
    if VIRUS_KEYWORD in folder_name:
        return 1
    if BENIGN_KEYWORD in folder_name:
        return 0
    return 1


# ---------------------------------------------------------------------------
# Per-sample worker  (called inside each thread)
# ---------------------------------------------------------------------------

def process_sample(
    sample_dir: Path,
    strategies: list,
    variants: int,
    noise: float,
    skip_existing: bool,
) -> tuple[list[str], int, int]:
    """
    Generate all augmented variants for a single source sample.

    Returns (manifest_rows, generated_count, skipped_count).
    """
    sample_name = sample_dir.name
    base_label  = label_from_folder(sample_name)

    with open(sample_dir / "graph.json", encoding="utf-8") as f:
        base_graph = json.load(f)

    graph_attr: dict = {}
    graph_attr_path = sample_dir / "graph_attr.json"
    if graph_attr_path.exists():
        with open(graph_attr_path, encoding="utf-8") as f:
            graph_attr = json.load(f)

    manifest_rows: list[str] = []
    generated = 0
    skipped   = 0

    for strategy_tag, strategy_fn, extra_kwargs in strategies:
        is_benign_strategy = strategy_tag == "aug_benign"

        for seed in range(variants):
            aug_name = f"{sample_name}__{strategy_tag}_{seed:02d}"
            out_dir  = AUGMENTED_DATA_DIR / aug_name

            if skip_existing and is_complete(out_dir):
                skipped += 1
                aug_label = 0 if is_benign_strategy else base_label
                manifest_rows.append(
                    f"{aug_name},{sample_name},{strategy_tag},{aug_label},{seed},{out_dir}"
                )
                continue

            kwargs = {"seed": seed, **extra_kwargs}
            if strategy_tag == "aug_noise" and "noise_level" not in kwargs:
                kwargs["noise_level"] = noise

            aug_graph = strategy_fn(base_graph, **kwargs)
            aug_label = 0 if is_benign_strategy else base_label

            aug_attr = copy.deepcopy(graph_attr)
            aug_attr["label"]    = aug_label
            aug_attr["strategy"] = strategy_tag
            aug_attr["source"]   = sample_name
            aug_attr["seed"]     = seed

            write_all_formats(aug_graph, out_dir, aug_attr)

            manifest_rows.append(
                f"{aug_name},{sample_name},{strategy_tag},{aug_label},{seed},{out_dir}"
            )
            generated += 1

    status = f"  [✓] {sample_name}  "\
             f"({generated} generated, {skipped} skipped)"
    tprint(status)
    return manifest_rows, generated, skipped


# ---------------------------------------------------------------------------
# Main runner
# ---------------------------------------------------------------------------

def run(
    variants: int      = 10,
    noise: float       = 0.10,
    drop: float        = 0.10,
    workers: int       = None,
    skip_existing: bool = False,
) -> None:
    AUGMENTED_DATA_DIR.mkdir(exist_ok=True)

    sample_dirs = sorted([
        d for d in EXTRACTED_DATA_DIR.iterdir()
        if d.is_dir() and (d / "graph.json").exists()
    ])

    if not sample_dirs:
        print(f"[!] No sample directories with graph.json found under "
              f"{EXTRACTED_DATA_DIR}/")
        return

    n_workers = workers or os.cpu_count() or 4
    print(f"[+] Found {len(sample_dirs)} sample(s) — "
          f"using {n_workers} worker thread(s) "
          f"({'skip existing' if skip_existing else 'overwrite existing'})")

    strategies = [
        ("aug_noise",     augment_feature_noise, {}),
        ("aug_dropnodes", augment_drop_nodes,    {"drop_frac": drop}),
        ("aug_dropedges", augment_drop_edges,    {"drop_frac": drop}),
        ("aug_benign",    make_benign_variant,   {}),
    ]

    all_manifest_rows: list[str] = [
        "aug_sample_name,source_sample,strategy,label,aug_index,out_path"
    ]
    total_generated = 0
    total_skipped   = 0

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {
            pool.submit(
                process_sample,
                sample_dir, strategies, variants, noise, skip_existing
            ): sample_dir.name
            for sample_dir in sample_dirs
        }

        for future in as_completed(futures):
            sample_name = futures[future]
            try:
                rows, generated, skipped = future.result()
                all_manifest_rows.extend(rows)
                total_generated += generated
                total_skipped   += skipped
            except Exception as exc:
                tprint(f"  [!] {sample_name} failed: {exc}")

    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        f.write("\n".join(all_manifest_rows))

    print(f"\n[+] Done — {total_generated} generated, "
          f"{total_skipped} skipped — "
          f"{total_generated + total_skipped} total variants")
    print(f"[+] Manifest saved → {MANIFEST_PATH}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Graph augmentation for ransomware GNN dataset."
    )
    parser.add_argument(
        "--variants", type=int, default=10,
        help="Number of variants per strategy per sample (default: 10)"
    )
    parser.add_argument(
        "--noise", type=float, default=0.10,
        help="Noise level for feature_noise strategy (default: 0.10)"
    )
    parser.add_argument(
        "--drop", type=float, default=0.10,
        help="Drop fraction for drop_nodes / drop_edges strategies (default: 0.10)"
    )
    parser.add_argument(
        "--workers", type=int, default=None,
        help="Number of parallel worker threads (default: os.cpu_count())"
    )
    parser.add_argument(
        "--skip-existing", action="store_true",
        help="Skip any output folder that already contains all 5 expected files"
    )
    args = parser.parse_args()
    run(
        variants      = args.variants,
        noise         = args.noise,
        drop          = args.drop,
        workers       = args.workers,
        skip_existing = args.skip_existing,
    )
