#!/usr/bin/env python3
"""
build_dataset.py  v3  (MalVol-25 aware — threaded)

Loops over all sample folders inside extracted_data/,
runs the full pipeline on each sample in parallel:
  1. filter_malicious.py  → filtered_malicious.json
  2. build_graph.py       → graph.json / graph.pkl / graph_attr.json
  3. analyze_graph.py     → analysis_report.json

Also produces:
  extracted_data/dataset_manifest.csv   ← label table for GNN training

Changes vs v2:
  - ThreadPoolExecutor: all samples processed in parallel
  - --workers N flag (default: 4)
  - Thread-safe progress bar + manifest collection via Lock
  - Steps within a sample stay sequential (filter → graph → analyze)
  - Per-sample output flushed to terminal as soon as it finishes
  - --skip-existing still works (skips individual steps per sample)
  - Dry-run unchanged
  - collect_stats reads graph.pkl (nx.DiGraph) for node/edge counts
    instead of parsing graph.json — faster and always in sync with the
    actual graph object used by the ML pipeline

Usage:
  python build_dataset.py
  python build_dataset.py ./extracted_data
  python build_dataset.py ./extracted_data --workers 8
  python build_dataset.py ./extracted_data --skip-existing --workers 12
  python build_dataset.py ./extracted_data --dry-run
  python build_dataset.py ./extracted_data --only filter graph --workers 6
"""

import os, sys, subprocess, json, csv, time, argparse, threading, pickle
from concurrent.futures import ThreadPoolExecutor, as_completed


# ── Label inference ──────────────────────────────────────────────────────
def infer_label(folder_name):
    name = os.path.basename(folder_name)
    if "-WithVirus"in name:
        return 1, name.replace("-WithVirus", "").lower()
    if "-NoVirus"in name:
        return 0, name.replace("-NoVirus", "").lower()
    return -1, name.lower()


# ── Run a script ────────────────────────────────────────────────────────────
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


# ── Check existing outputs ─────────────────────────────────────────────────
def check_outputs(folder):
    files = {
        "filtered_malicious.json": "filtered_malicious.json",
        "graph.json":              "graph.json",
        "graph.pkl":               "graph.pkl",
        "graph_attr.json":         "graph_attr.json",
        "analysis_report.json":    "analysis_report.json",
    }
    return {k: os.path.exists(os.path.join(folder, v)) for k, v in files.items()}


# ── Write per-sample run log ──────────────────────────────────────────────
def write_run_log(folder, log_entries):
    with open(os.path.join(folder, "pipeline_run.log"), "w") as f:
        f.write("\n".join(log_entries) + "\n")


# ── Collect stats from outputs ─────────────────────────────────────────────
def collect_stats(folder):
    stats = {
        "nodes": -1, "edges": -1,
        "max_score": -1, "attack_steps": -1,
        "injections": -1, "c2_conns": -1,
        "verdict": "no_report",
        "graph_attr": "",
        "label_signals_top": "",
    }

    # graph.pkl → node/edge count  (load the nx.DiGraph directly)
    pp = os.path.join(folder, "graph.pkl")
    if os.path.exists(pp):
        try:
            with open(pp, "rb") as f:
                G = pickle.load(f)
            stats["nodes"] = G.number_of_nodes()
            stats["edges"] = G.number_of_edges()
        except Exception:
            pass

    # graph_attr.json → 5-element tensor + label_signals
    ap = os.path.join(folder, "graph_attr.json")
    if os.path.exists(ap):
        try:
            with open(ap) as f:
                ga = json.load(f)
            stats["graph_attr"] = str(ga.get("graph_attr", []))
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
            stats["c2_conns"] = len([
                x for x in report.get("network", [])
                if int(x.get("is_external", 0)) == 1
                and x.get("state") == "ESTABLISHED"
            ])
            stats["verdict"] = chain.get("overall_verdict", "")[:80]
        except Exception:
            stats["verdict"] = "parse_error"

    return stats


# ── Progress bar (call inside print_lock) ─────────────────────────────────
def progress_bar(done, total, elapsed, bar_width=28):
    pct    = done / total if total else 0
    filled = int(bar_width * pct)
    bar    = "█" * filled + "░" * (bar_width - filled)
    eta    = ""
    if done > 0 and elapsed > 0:
        secs_per  = elapsed / done
        remaining = secs_per * (total - done)
        eta = f"  ETA {int(remaining)}s"
    return f"[{bar}] {done}/{total} ({pct*100:.0f}%){eta}"


# ── Per-sample worker ────────────────────────────────────────────────────────
def process_sample(job, scripts, skip, run_steps):
    """
    Runs the full pipeline for one sample folder.
    Returns (row_dict, stats_dict, log_lines, lines_to_print).
    All filesystem I/O is contained here — no shared mutable state.
    """
    folder = job["folder"]
    name   = job["name"]
    label  = job["label"]
    family = job["family"]
    idx    = job["idx"]
    total  = job["total"]

    log    = [f"Sample: {name} | label={label} | family={family}"]
    lines  = []
    lines.append(f"[{idx:02d}/{total}] {name}  label={label}  family={family}")

    existing = check_outputs(folder)
    row = {
        "sample_id":  f"{idx:02d}",
        "folder":     name,
        "label":      label,
        "family":     family,
        "filter_ok":  False,
        "graph_ok":   False,
        "analyze_ok": False,
        "error":      "",
    }

    # ─ Step 1: filter_malicious.py ──────────────────────────────────────────
    if "filter" in run_steps:
        if skip and existing["filtered_malicious.json"]:
            lines.append("  [SKIP] filter_malicious.py")
            log.append("SKIP filter_malicious.py")
            row["filter_ok"] = True
        else:
            ok, _, err, t = run_script(scripts["filter"], folder)
            mark = "✅" if ok else "❌"
            lines.append(f"  [RUN]  filter_malicious.py ... {mark} ({t}s)")
            log.append(f"filter_malicious.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if not ok and err:
                log.append(f"  STDERR: {err[:400]}")
                row["error"] += f"filter:{err[:80]} "
            row["filter_ok"] = ok
    else:
        row["filter_ok"] = existing["filtered_malicious.json"]

    # ─ Step 2: build_graph.py ──────────────────────────────────────────────
    if "graph" in run_steps:
        if skip and existing["graph.json"] and existing["graph.pkl"]:
            lines.append("  [SKIP] build_graph.py")
            log.append("SKIP build_graph.py")
            row["graph_ok"] = True
        else:
            ok, _, err, t = run_script(scripts["graph"], folder)
            mark = "✅" if ok else "❌"
            lines.append(f"  [RUN]  build_graph.py ... {mark} ({t}s)")
            log.append(f"build_graph.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if not ok and err:
                log.append(f"  STDERR: {err[:400]}")
                row["error"] += f"graph:{err[:80]} "
            row["graph_ok"] = ok
    else:
        row["graph_ok"] = existing["graph.json"] and existing["graph.pkl"]

    # ─ Step 3: analyze_graph.py ─────────────────────────────────────────
    if "analyze" in run_steps:
        if skip and existing["analysis_report.json"]:
            lines.append("  [SKIP] analyze_graph.py")
            log.append("SKIP analyze_graph.py")
            row["analyze_ok"] = True
        else:
            ok, _, err, t = run_script(scripts["analyze"], folder)
            mark = "✅" if ok else "❌"
            lines.append(f"  [RUN]  analyze_graph.py ... {mark} ({t}s)")
            log.append(f"analyze_graph.py: {'OK' if ok else 'FAIL'} ({t}s)")
            if not ok and err:
                log.append(f"  STDERR: {err[:400]}")
                row["error"] += f"analyze:{err[:80]} "
            row["analyze_ok"] = ok
    else:
        row["analyze_ok"] = existing["analysis_report.json"]

    stats = collect_stats(folder)
    row.update(stats)
    write_run_log(folder, log)

    ok_all = row["filter_ok"] and row["graph_ok"] and row["analyze_ok"]
    lines.append(
        f"  {('✅' if ok_all else '⚠️')} "
        f"nodes={stats['nodes']} edges={stats['edges']} "
        f"max_score={stats['max_score']} c2={stats['c2_conns']}"
    )
    if stats["graph_attr"]:
        lines.append(f"     graph_attr: {stats['graph_attr']}")

    return row, stats, log, lines


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
                        choices=["filter", "graph", "analyze"],
                        help="Run only specific step(s): filter graph analyze")
    parser.add_argument("--workers", type=int, default=4,
                        help="Number of parallel worker threads (default: 4)")
    args = parser.parse_args()

    base_dir   = os.path.abspath(args.base_dir)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    skip       = args.skip_existing and not args.force
    run_steps  = set(args.only) if args.only else {"filter", "graph", "analyze"}
    n_workers  = max(1, args.workers)

    scripts = {
        "filter":  os.path.join(script_dir, "filter_malicious.py"),
        "graph":   os.path.join(script_dir, "build_graph.py"),
        "analyze": os.path.join(script_dir, "analyze_graph.py"),
    }

    missing = [s for s in scripts.values() if not os.path.exists(s)]
    if missing:
        print("[ERROR] Missing scripts:")
        for m in missing: print(f"  {m}")
        sys.exit(1)

    if not os.path.isdir(base_dir):
        print(f"[ERROR] Not found: {base_dir}"); sys.exit(1)

    sample_dirs = sorted([
        os.path.join(base_dir, d)
        for d in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, d))
    ])
    if not sample_dirs:
        print(f"[ERROR] No subfolders in: {base_dir}"); sys.exit(1)

    jobs = [
        {
            "folder": f,
            "name":   os.path.basename(f),
            "label":  infer_label(f)[0],
            "family": infer_label(f)[1],
            "idx":    i,
            "total":  len(sample_dirs),
        }
        for i, f in enumerate(sample_dirs, 1)
    ]

    # ─ Dry run ────────────────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{'='*65}")
        print(f"  DRY RUN — {len(jobs)} samples in: {base_dir}")
        print(f"  Steps   : {sorted(run_steps)}")
        print(f"  Workers : {n_workers}")
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

    # ─ Pipeline ──────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print(f"  BUILD DATASET v3 — {len(jobs)} samples  [{n_workers} workers]")
    print(f"  Base       : {base_dir}")
    print(f"  Steps      : {sorted(run_steps)}")
    print(f"  Skip exist : {skip}")
    print(f"{'='*65}\n")

    manifest_rows = [None] * len(jobs)
    print_lock    = threading.Lock()
    done_counter  = [0]
    total_start   = time.time()

    def submit(job):
        row, stats, _log, lines = process_sample(job, scripts, skip, run_steps)
        elapsed = round(time.time() - total_start, 1)
        with print_lock:
            done_counter[0] += 1
            done = done_counter[0]
            for line in lines:
                print(line)
            bar = progress_bar(done, len(jobs), elapsed)
            print(f"  {bar}\n")
        return job["idx"] - 1, row

    with ThreadPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(submit, job): job for job in jobs}
        for fut in as_completed(futures):
            try:
                slot, row = fut.result()
                manifest_rows[slot] = row
            except Exception as exc:
                job = futures[fut]
                with print_lock:
                    print(f"  [❌ EXCEPTION] {job['name']}: {exc}")
                manifest_rows[job["idx"] - 1] = {
                    "sample_id":  f"{job['idx']:02d}",
                    "folder":     job["name"],
                    "label":      job["label"],
                    "family":     job["family"],
                    "filter_ok":  False,
                    "graph_ok":   False,
                    "analyze_ok": False,
                    "error":      str(exc)[:120],
                    "nodes": -1, "edges": -1, "max_score": -1,
                    "attack_steps": -1, "injections": -1, "c2_conns": -1,
                    "verdict": "exception",
                    "graph_attr": "", "label_signals_top": "",
                }

    # ─ Write manifest CSV ────────────────────────────────────────────────
    manifest_path = os.path.join(base_dir, "dataset_manifest.csv")
    fieldnames = [
        "sample_id", "folder", "label", "family",
        "nodes", "edges",
        "max_score", "attack_steps", "injections", "c2_conns",
        "verdict",
        "graph_attr", "label_signals_top",
        "filter_ok", "graph_ok", "analyze_ok", "error",
    ]
    with open(manifest_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(r for r in manifest_rows if r is not None)

    # ─ Final summary ────────────────────────────────────────────────────
    elapsed  = round(time.time() - total_start, 1)
    rows     = [r for r in manifest_rows if r is not None]
    ok_count = sum(1 for r in rows if r["filter_ok"] and r["graph_ok"] and r["analyze_ok"])
    malware  = [r for r in rows if r["label"] == 1]
    clean    = [r for r in rows if r["label"] == 0]
    unknown  = [r for r in rows if r["label"] == -1]
    failed   = [r for r in rows if not (r["filter_ok"] and r["graph_ok"] and r["analyze_ok"])]

    print(f"{'='*65}")
    print(f"  DATASET BUILD COMPLETE  ({elapsed}s total, {n_workers} workers)")
    print(f"{'='*65}")
    print(f"  Samples total     : {len(rows)}")
    print(f"  Fully successful  : {ok_count}/{len(rows)}")
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
