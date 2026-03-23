#!/usr/bin/env python3
"""
build_dataset.py  v2  (MalVol-25 aware)

Loops over all sample folders inside extracted_data/,
runs the full pipeline on each:
  1. filter_malicious.py  → filtered_malicious.json
  2. build_graph.py       → graph.json / graph.pkl / graph_attr.json
  3. analyze_graph.py     → analysis_report.json   ← was graph_summary.py

Also produces:
  extracted_data/dataset_manifest.csv   ← label table for GNN training

Changes vs v1:
  - Step 3 now calls analyze_graph.py (was graph_summary.py)
  - check_outputs updated: graph_attr.json added, .graphml/.gexf removed
    (build_graph v2 no longer writes those by default)
  - manifest collects graph_attr tensor + label_signals from graph_attr.json
  - is_external / state checks use safe_int (graph nodes store ints not bools)
  - c2_conns count fixed: checks int 1 not bool True
  - verdict slicing raised from 50 → 80 chars
  - --only flag: run only specific step(s)  e.g. --only filter graph
  - progress bar per sample with ETA estimate

Usage:
  python build_dataset.py
  python build_dataset.py ./extracted_data
  python build_dataset.py ./extracted_data --dry-run
  python build_dataset.py ./extracted_data --skip-existing
  python build_dataset.py ./extracted_data --only filter
  python build_dataset.py ./extracted_data --only graph analyze
"""

import os, sys, subprocess, json, csv, time, argparse


# ── Label inference ───────────────────────────────────────────────────────────
def infer_label(folder_name):
    name = os.path.basename(folder_name)
    if name.endswith("-WithVirus"):
        return 1, name.replace("-WithVirus","").lower()
    if name.endswith("-NoVirus"):
        return 0, name.replace("-NoVirus","").lower()
    return -1, name.lower()


# ── Run a script ──────────────────────────────────────────────────────────────
def run_script(script_path, target_folder, timeout=300):
    start = time.time()
    try:
        r = subprocess.run(
            [sys.executable, script_path, target_folder],
            capture_output=True, text=True, timeout=timeout,
        )
        elapsed = round(time.time() - start, 1)
        return r.returncode == 0, r.stdout, r.stderr, elapsed
    except subprocess.TimeoutExpired:
        return False, "", f"TIMEOUT after {timeout}s", timeout
    except Exception as e:
        return False, "", str(e), round(time.time() - start, 1)


# ── Check existing outputs ────────────────────────────────────────────────────
def check_outputs(folder):
    files = {
        "filtered_malicious.json": "filtered_malicious.json",
        "graph.json":              "graph.json",
        "graph.pkl":               "graph.pkl",
        "graph_attr.json":         "graph_attr.json",   # new in build_graph v2
        "analysis_report.json":    "analysis_report.json",
    }
    return {k: os.path.exists(os.path.join(folder, v)) for k, v in files.items()}


# ── Write per-sample run log ──────────────────────────────────────────────────
def write_run_log(folder, log_entries):
    with open(os.path.join(folder, "pipeline_run.log"), "w") as f:
        f.write("\n".join(log_entries) + "\n")


# ── Collect stats from outputs ────────────────────────────────────────────────
def collect_stats(folder):
    stats = {
        "nodes": -1, "edges": -1,
        "max_score": -1, "attack_steps": -1,
        "injections": -1, "c2_conns": -1,
        "verdict": "no_report",
        "graph_attr": "",
        "label_signals_top": "",
    }

    # graph.json → node/edge count
    gp = os.path.join(folder, "graph.json")
    if os.path.exists(gp):
        try:
            with open(gp) as f:
                gdata = json.load(f)
            stats["nodes"] = len(gdata.get("nodes", []))
            stats["edges"] = len(gdata.get("links", []))
        except Exception:
            pass

    # graph_attr.json → 5-element tensor + label_signals
    ap = os.path.join(folder, "graph_attr.json")
    if os.path.exists(ap):
        try:
            with open(ap) as f:
                ga = json.load(f)
            stats["graph_attr"] = str(ga.get("graph_attr", []))
            # Summarise label_signals as key=val pairs for manifest
            ls = ga.get("label_signals", {})
            stats["label_signals_top"] = " ".join(
                f"{k}={v}" for k, v in list(ls.items())[:4]
            )
        except Exception:
            pass

    # analysis_report.json → heuristic scores, chain, C2
    rp = os.path.join(folder, "analysis_report.json")
    if os.path.exists(rp):
        try:
            with open(rp) as f:
                report = json.load(f)
            chain = report.get("attack_chain", {})
            stats["max_score"]    = chain.get("max_process_score", -1)
            stats["attack_steps"] = len(chain.get("steps", []))
            stats["injections"]   = len([
                x for x in report.get("injections", [])
                if x.get("source") == "malfind"
            ])
            # FIX: is_external stored as int 1, not bool True
            stats["c2_conns"] = len([
                x for x in report.get("network", [])
                if int(x.get("is_external", 0)) == 1
                and x.get("state") == "ESTABLISHED"
            ])
            stats["verdict"] = chain.get("overall_verdict", "")[:80]
        except Exception:
            stats["verdict"] = "parse_error"

    return stats


# ── Progress bar ──────────────────────────────────────────────────────────────
def progress_bar(done, total, elapsed, bar_width=28):
    pct   = done / total if total else 0
    filled= int(bar_width * pct)
    bar   = "█" * filled + "░" * (bar_width - filled)
    eta   = ""
    if done > 0 and elapsed > 0:
        secs_per = elapsed / done
        remaining = secs_per * (total - done)
        eta = f"  ETA {int(remaining)}s"
    return f"[{bar}] {done}/{total} ({pct*100:.0f}%){eta}"


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Build MalVol-25 dataset: run full pipeline on all sample folders"
    )
    parser.add_argument("base_dir", nargs="?", default="./extracted_data",
                        help="Path to extracted_data/ (default: ./extracted_data)")
    parser.add_argument("--dry-run",       action="store_true",
                        help="Preview folders + labels without running")
    parser.add_argument("--skip-existing", action="store_true",
                        help="Skip steps where output already exists")
    parser.add_argument("--force",         action="store_true",
                        help="Re-run all steps even if outputs exist")
    parser.add_argument("--only", nargs="+",
                        choices=["filter","graph","analyze"],
                        help="Run only specific step(s): filter graph analyze")
    args = parser.parse_args()

    base_dir   = os.path.abspath(args.base_dir)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    skip       = args.skip_existing and not args.force
    run_steps  = set(args.only) if args.only else {"filter","graph","analyze"}

    # Script paths — step 3 is now analyze_graph.py (was graph_summary.py)
    scripts = {
        "filter":  os.path.join(script_dir, "filter_malicious.py"),
        "graph":   os.path.join(script_dir, "build_graph.py"),
        "analyze": os.path.join(script_dir, "analyze_graph.py"),
    }

    # Validate scripts exist
    missing = [s for s in scripts.values() if not os.path.exists(s)]
    if missing:
        print("[ERROR] Missing scripts:")
        for m in missing: print(f"  {m}")
        print("  Ensure filter_malicious.py, build_graph.py, analyze_graph.py")
        print("  are in the same folder as build_dataset.py")
        sys.exit(1)

    # Discover sample folders
    if not os.path.isdir(base_dir):
        print(f"[ERROR] Not found: {base_dir}"); sys.exit(1)

    sample_dirs = sorted([
        os.path.join(base_dir, d)
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ])
    if not sample_dirs:
        print(f"[ERROR] No subfolders in: {base_dir}"); sys.exit(1)

    jobs = [{"folder": f, "name": os.path.basename(f), **dict(zip(["label","family"], infer_label(f)))}
            for f in sample_dirs]

    # ── Dry run ───────────────────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{'='*65}")
        print(f"  DRY RUN — {len(jobs)} samples in: {base_dir}")
        print(f"  Steps that will run: {sorted(run_steps)}")
        print(f"{'='*65}")
        print(f"  {'Folder':<38} {'Label':<9} Family")
        print(f"  {'-'*62}")
        for j in jobs:
            lbl = "MALWARE" if j['label']==1 else "CLEAN" if j['label']==0 else "UNKNOWN"
            print(f"  {j['name']:<38} {lbl:<9} {j['family']}")
        print(f"\n  Step outputs:")
        print(f"    filter  → filtered_malicious.json")
        print(f"    graph   → graph.json / graph.pkl / graph_attr.json")
        print(f"    analyze → analysis_report.json")
        print(f"  Manifest → {base_dir}/dataset_manifest.csv")
        return

    # ── Pipeline ──────────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  BUILD DATASET v2 — {len(jobs)} samples")
    print(f"  Base        : {base_dir}")
    print(f"  Steps       : {sorted(run_steps)}")
    print(f"  Skip exist  : {skip}")
    print(f"{'='*65}\n")

    manifest_rows = []
    total_start   = time.time()

    for idx, job in enumerate(jobs, 1):
        folder = job["folder"]
        name   = job["name"]
        label  = job["label"]
        family = job["family"]
        log    = [f"Sample: {name} | label={label} | family={family}"]

        print(f"[{idx:02d}/{len(jobs)}] {name}  label={label}  family={family}")

        existing = check_outputs(folder)
        row = {
            "sample_id": f"{idx:02d}", "folder": name,
            "label": label, "family": family,
            "filter_ok": False, "graph_ok": False,
            "analyze_ok": False, "error": "",
        }

        # ── Step 1: filter_malicious.py ───────────────────────────────────────
        if "filter" in run_steps:
            if skip and existing["filtered_malicious.json"]:
                print(f"  [SKIP] filter_malicious.py")
                log.append("SKIP filter_malicious.py")
                row["filter_ok"] = True
            else:
                print(f"  [RUN]  filter_malicious.py ...", end="", flush=True)
                ok, out, err, t = run_script(scripts["filter"], folder)
                print(f" {'✅' if ok else '❌'} ({t}s)")
                log.append(f"filter_malicious.py: {'OK' if ok else 'FAIL'} ({t}s)")
                if not ok and err:
                    log.append(f"  STDERR: {err[:400]}")
                    row["error"] += f"filter:{err[:80]} "
                row["filter_ok"] = ok
        else:
            row["filter_ok"] = existing["filtered_malicious.json"]

        # ── Step 2: build_graph.py ────────────────────────────────────────────
        if "graph" in run_steps:
            if skip and existing["graph.json"] and existing["graph.pkl"]:
                print(f"  [SKIP] build_graph.py")
                log.append("SKIP build_graph.py")
                row["graph_ok"] = True
            else:
                print(f"  [RUN]  build_graph.py ...", end="", flush=True)
                ok, out, err, t = run_script(scripts["graph"], folder)
                print(f" {'✅' if ok else '❌'} ({t}s)")
                log.append(f"build_graph.py: {'OK' if ok else 'FAIL'} ({t}s)")
                if not ok and err:
                    log.append(f"  STDERR: {err[:400]}")
                    row["error"] += f"graph:{err[:80]} "
                row["graph_ok"] = ok
        else:
            row["graph_ok"] = existing["graph.json"] and existing["graph.pkl"]

        # ── Step 3: analyze_graph.py  (was graph_summary.py) ─────────────────
        if "analyze" in run_steps:
            if skip and existing["analysis_report.json"]:
                print(f"  [SKIP] analyze_graph.py")
                log.append("SKIP analyze_graph.py")
                row["analyze_ok"] = True
            else:
                print(f"  [RUN]  analyze_graph.py ...", end="", flush=True)
                ok, out, err, t = run_script(scripts["analyze"], folder)
                print(f" {'✅' if ok else '❌'} ({t}s)")
                log.append(f"analyze_graph.py: {'OK' if ok else 'FAIL'} ({t}s)")
                if not ok and err:
                    log.append(f"  STDERR: {err[:400]}")
                    row["error"] += f"analyze:{err[:80]} "
                row["analyze_ok"] = ok
        else:
            row["analyze_ok"] = existing["analysis_report.json"]

        # ── Collect stats ─────────────────────────────────────────────────────
        stats = collect_stats(folder)
        row.update(stats)

        write_run_log(folder, log)
        manifest_rows.append(row)

        elapsed = round(time.time() - total_start, 1)
        bar     = progress_bar(idx, len(jobs), elapsed)
        ok_all  = row["filter_ok"] and row["graph_ok"] and row["analyze_ok"]
        print(f"  {'✅' if ok_all else '⚠️ '} "
              f"nodes={stats['nodes']} edges={stats['edges']} "
              f"max_score={stats['max_score']} c2={stats['c2_conns']}")
        if stats["graph_attr"]:
            print(f"     graph_attr: {stats['graph_attr']}")
        print(f"  {bar}\n")

    # ── Write manifest CSV ────────────────────────────────────────────────────
    manifest_path = os.path.join(base_dir, "dataset_manifest.csv")
    fieldnames = [
        "sample_id","folder","label","family",
        "nodes","edges",
        "max_score","attack_steps","injections","c2_conns",
        "verdict",
        "graph_attr","label_signals_top",
        "filter_ok","graph_ok","analyze_ok","error",
    ]
    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(manifest_rows)

    # ── Final summary ─────────────────────────────────────────────────────────
    elapsed  = round(time.time() - total_start, 1)
    ok_count = sum(1 for r in manifest_rows
                   if r["filter_ok"] and r["graph_ok"] and r["analyze_ok"])
    malware  = [r for r in manifest_rows if r["label"] == 1]
    clean    = [r for r in manifest_rows if r["label"] == 0]
    unknown  = [r for r in manifest_rows if r["label"] == -1]
    failed   = [r for r in manifest_rows
                if not (r["filter_ok"] and r["graph_ok"] and r["analyze_ok"])]

    print(f"{'='*65}")
    print(f"  DATASET BUILD COMPLETE  ({elapsed}s total)")
    print(f"{'='*65}")
    print(f"  Samples total     : {len(manifest_rows)}")
    print(f"  Fully successful  : {ok_count}/{len(manifest_rows)}")
    print(f"  Malware (label=1) : {len(malware)}")
    print(f"  Clean   (label=0) : {len(clean)}")
    if unknown:
        print(f"  Unknown (label=-1): {len(unknown)}  ← manually label in manifest")
    print(f"  Manifest          : {manifest_path}")
    print(f"\n  Per-sample outputs (inside each folder):")
    print(f"    filtered_malicious.json")
    print(f"    graph.json / graph.pkl / graph_attr.json")
    print(f"    analysis_report.json")
    print(f"    pipeline_run.log")
    print(f"{'='*65}\n")

    if failed:
        print(f"  ⚠️  FAILURES ({len(failed)}):")
        for r in failed:
            step = ("filter" if not r["filter_ok"] else
                    "graph"  if not r["graph_ok"]  else "analyze")
            print(f"    {r['folder']:<38} failed-at={step}  {r['error'][:60]}")
        print()


if __name__ == "__main__":
    main()