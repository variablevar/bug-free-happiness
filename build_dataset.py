#!/usr/bin/env python3
"""
build_dataset.py
Loops over all 24 sample folders inside extracted_data/,
runs filter_malicious.py → build_graph.py → graph_summary.py
on each one, and saves ALL outputs into that sample's folder.

Also produces:
  extracted_data/dataset_manifest.csv   ← label table for GNN training

Usage:
  python build_dataset.py
  python build_dataset.py ./extracted_data        # custom base folder
  python build_dataset.py ./extracted_data --dry-run  # preview only

Expects filter_malicious.py, build_graph.py, graph_summary.py
to be in the SAME folder as this script.
"""

import os
import sys
import subprocess
import json
import csv
import time
import argparse

# ── Label inference from folder name ─────────────────────────────────────────
def infer_label(folder_name):
    """
    Returns (label_int, family_str) from folder naming convention:
      FamilyName-WithVirus  → label=1
      FamilyName-NoVirus    → label=0
    """
    name = os.path.basename(folder_name)
    if name.endswith("-WithVirus"):
        family = name.replace("-WithVirus", "").lower()
        return 1, family
    elif name.endswith("-NoVirus"):
        family = name.replace("-NoVirus", "").lower()
        return 0, family
    else:
        # Unknown — ask user to label manually in manifest
        return -1, name.lower()

# ── Run a script against a folder, capturing output ──────────────────────────
def run_script(script_path, target_folder, timeout=300):
    """
    Runs: python <script_path> <target_folder>
    Returns (success, stdout, stderr, elapsed_seconds)
    """
    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, script_path, target_folder],
            capture_output=True, text=True, timeout=timeout
        )
        elapsed = time.time() - start
        success = result.returncode == 0
        return success, result.stdout, result.stderr, round(elapsed, 1)
    except subprocess.TimeoutExpired:
        return False, "", f"TIMEOUT after {timeout}s", timeout
    except Exception as e:
        return False, "", str(e), time.time() - start

# ── Check what outputs already exist ─────────────────────────────────────────
def check_outputs(folder):
    expected = {
        "filtered_malicious.json": os.path.join(folder, "filtered_malicious.json"),
        "graph.json":              os.path.join(folder, "graph.json"),
        "graph.pkl":               os.path.join(folder, "graph.pkl"),
        "graph.graphml":           os.path.join(folder, "graph.graphml"),
        "graph.gexf":              os.path.join(folder, "graph.gexf"),
        "analysis_report.json":    os.path.join(folder, "analysis_report.json"),
    }
    return {k: os.path.exists(v) for k, v in expected.items()}

# ── Log writer ────────────────────────────────────────────────────────────────
def write_run_log(folder, log_entries):
    log_path = os.path.join(folder, "pipeline_run.log")
    with open(log_path, "w") as f:
        for entry in log_entries:
            f.write(entry + "\n")

# ── Main pipeline ─────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Build dataset: run pipeline on all samples")
    parser.add_argument("base_dir", nargs="?", default="./extracted_data",
                        help="Path to extracted_data folder (default: ./extracted_data)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview folders + labels without running anything")
    parser.add_argument("--skip-existing", action="store_true", default=False,
                        help="Skip steps where output already exists (default: False)")
    parser.add_argument("--force", action="store_true",
                        help="Re-run all steps even if outputs exist")
    args = parser.parse_args()

    base_dir    = os.path.abspath(args.base_dir)
    script_dir  = os.path.dirname(os.path.abspath(__file__))
    skip        = args.skip_existing and not args.force

    # Locate the three scripts
    filter_script  = os.path.join(script_dir, "filter_malicious.py")
    graph_script   = os.path.join(script_dir, "build_graph.py")
    summary_script = os.path.join(script_dir, "graph_summary.py")

    # Validate scripts exist
    for s in [filter_script, graph_script, summary_script]:
        if not os.path.exists(s):
            print(f"[ERROR] Script not found: {s}")
            print("        Make sure filter_malicious.py, build_graph.py, graph_summary.py")
            print("        are in the same folder as build_dataset.py")
            sys.exit(1)

    # Discover all sample folders
    if not os.path.isdir(base_dir):
        print(f"[ERROR] Base folder not found: {base_dir}")
        sys.exit(1)

    sample_dirs = sorted([
        os.path.join(base_dir, d)
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ])

    if not sample_dirs:
        print(f"[ERROR] No subdirectories found in: {base_dir}")
        sys.exit(1)

    # Build job list with labels
    jobs = []
    for folder in sample_dirs:
        label, family = infer_label(folder)
        jobs.append({"folder": folder, "name": os.path.basename(folder),
                     "label": label, "family": family})

    # ── Dry run preview ───────────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{'='*65}")
        print(f"  DRY RUN — {len(jobs)} samples found in: {base_dir}")
        print(f"{'='*65}")
        print(f"  {'Folder':<35} {'Label':<7} {'Family'}")
        print(f"  {'-'*60}")
        for j in jobs:
            lbl = "MALWARE" if j['label'] == 1 else "CLEAN" if j['label'] == 0 else "UNKNOWN"
            print(f"  {j['name']:<35} {lbl:<7} {j['family']}")
        print(f"\n  Scripts that will run per folder:")
        print(f"    1. filter_malicious.py  → filtered_malicious.json")
        print(f"    2. build_graph.py       → graph.json / .pkl / .graphml / .gexf")
        print(f"    3. graph_summary.py     → analysis_report.json")
        print(f"  Output manifest: {base_dir}/dataset_manifest.csv")
        return

    # ── Run pipeline ──────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  BUILD DATASET — {len(jobs)} samples")
    print(f"  Base: {base_dir}")
    print(f"  Skip existing: {skip}")
    print(f"{'='*65}\n")

    manifest_rows = []
    total_start   = time.time()

    for idx, job in enumerate(jobs, 1):
        folder  = job["folder"]
        name    = job["name"]
        label   = job["label"]
        family  = job["family"]
        log     = []

        print(f"[{idx:02d}/{len(jobs)}] {name}  (label={label}, family={family})")
        log.append(f"Sample: {name} | label={label} | family={family}")

        existing = check_outputs(folder)
        row = {"sample_id": f"{idx:02d}", "folder": name,
               "label": label, "family": family,
               "filter_ok": False, "graph_ok": False,
               "summary_ok": False, "error": ""}

        # ── Step 1: filter_malicious.py ───────────────────────────────────────
        if skip and existing["filtered_malicious.json"]:
            print(f"  [SKIP] filter_malicious.py — filtered_malicious.json exists")
            log.append("SKIP filter_malicious.py (already exists)")
            row["filter_ok"] = True
        else:
            print(f"  [RUN]  filter_malicious.py ...", end="", flush=True)
            ok, out, err, t = run_script(filter_script, folder)
            print(f" {'✅' if ok else '❌'} ({t}s)")
            log.append(f"filter_malicious.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if err and not ok:
                log.append(f"  STDERR: {err[:300]}")
                row["error"] += f"filter:{err[:80]} "
            row["filter_ok"] = ok

        # ── Step 2: build_graph.py ────────────────────────────────────────────
        if skip and existing["graph.json"] and existing["graph.pkl"]:
            print(f"  [SKIP] build_graph.py — graph files exist")
            log.append("SKIP build_graph.py (already exists)")
            row["graph_ok"] = True
        else:
            print(f"  [RUN]  build_graph.py ...", end="", flush=True)
            ok, out, err, t = run_script(graph_script, folder)
            print(f" {'✅' if ok else '❌'} ({t}s)")
            log.append(f"build_graph.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if err and not ok:
                log.append(f"  STDERR: {err[:300]}")
                row["error"] += f"graph:{err[:80]} "
            row["graph_ok"] = ok

        # ── Step 3: graph_summary.py ──────────────────────────────────────────
        if skip and existing["analysis_report.json"]:
            print(f"  [SKIP] graph_summary.py — analysis_report.json exists")
            log.append("SKIP graph_summary.py (already exists)")
            row["summary_ok"] = True
        else:
            print(f"  [RUN]  graph_summary.py ...", end="", flush=True)
            ok, out, err, t = run_script(summary_script, folder)
            print(f" {'✅' if ok else '❌'} ({t}s)")
            log.append(f"graph_summary.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if err and not ok:
                log.append(f"  STDERR: {err[:300]}")
                row["error"] += f"summary:{err[:80]} "
            row["summary_ok"] = ok

        # ── Collect graph stats for manifest ──────────────────────────────────
        graph_json = os.path.join(folder, "graph.json")
        if os.path.exists(graph_json):
            try:
                with open(graph_json) as f:
                    gdata = json.load(f)
                row["nodes"] = len(gdata.get("nodes", []))
                row["edges"] = len(gdata.get("links", []))
            except:
                row["nodes"] = -1; row["edges"] = -1
        else:
            row["nodes"] = -1; row["edges"] = -1

        # ── Collect heuristic score from analysis_report ──────────────────────
        report_json = os.path.join(folder, "analysis_report.json")
        if os.path.exists(report_json):
            try:
                with open(report_json) as f:
                    report = json.load(f)
                row["max_score"]     = report.get("attack_chain", {}).get("max_process_score", -1)
                row["attack_steps"]  = len(report.get("attack_chain", {}).get("steps", []))
                row["injections"]    = len([x for x in report.get("injections", [])
                                            if x.get("source") == "malfind"])
                row["c2_conns"]      = len([x for x in report.get("network", [])
                                            if x.get("is_external") and
                                            x.get("state") == "ESTABLISHED"])
                row["verdict"]       = report.get("attack_chain", {}).get("overall_verdict", "")[:50]
            except:
                row["max_score"] = row["attack_steps"] = row["injections"] = row["c2_conns"] = -1
                row["verdict"] = "parse_error"
        else:
            row["max_score"] = row["attack_steps"] = row["injections"] = row["c2_conns"] = -1
            row["verdict"] = "no_report"

        write_run_log(folder, log)
        manifest_rows.append(row)

        status = "✅" if row["filter_ok"] and row["graph_ok"] and row["summary_ok"] else "⚠️ "
        print(f"  {status} nodes={row['nodes']} edges={row['edges']} "
              f"max_score={row['max_score']} c2={row['c2_conns']}\n")

    # ── Write manifest CSV ────────────────────────────────────────────────────
    manifest_path = os.path.join(base_dir, "dataset_manifest.csv")
    fieldnames = ["sample_id","folder","label","family","nodes","edges",
                  "max_score","attack_steps","injections","c2_conns",
                  "verdict","filter_ok","graph_ok","summary_ok","error"]

    with open(manifest_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(manifest_rows)

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed = round(time.time() - total_start, 1)
    ok_count = sum(1 for r in manifest_rows
                   if r["filter_ok"] and r["graph_ok"] and r["summary_ok"])
    malware  = [r for r in manifest_rows if r["label"] == 1]
    clean    = [r for r in manifest_rows if r["label"] == 0]

    print(f"\n{'='*65}")
    print(f"  DATASET BUILD COMPLETE  ({elapsed}s total)")
    print(f"{'='*65}")
    print(f"  Samples processed : {len(manifest_rows)}")
    print(f"  Fully successful  : {ok_count}/{len(manifest_rows)}")
    print(f"  Malware (label=1) : {len(malware)}")
    print(f"  Clean   (label=0) : {len(clean)}")
    print(f"  Manifest saved    : {manifest_path}")
    print(f"\n  Per-sample outputs saved inside each folder:")
    print(f"    filtered_malicious.json")
    print(f"    graph.json / graph.pkl / graph.graphml / graph.gexf")
    print(f"    analysis_report.json")
    print(f"    pipeline_run.log")
    print(f"{'='*65}\n")

    # Show any failures
    failed = [r for r in manifest_rows
              if not (r["filter_ok"] and r["graph_ok"] and r["summary_ok"])]
    if failed:
        print(f"  ⚠️  FAILURES ({len(failed)}):")
        for r in failed:
            print(f"    {r['folder']:<35} error: {r['error'][:60]}")
        print()

if __name__ == "__main__":
    main()
