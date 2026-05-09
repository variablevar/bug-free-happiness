#!/usr/bin/env python3
"""
build_dataset.py  v3  (MalVol-25 aware — threaded)

Loops over all sample folders inside extracted_data/,
runs the full pipeline on each sample in parallel:
  1. ensure graph.pkl exists (bootstrap build_graph.py if needed)
  2. filter_malicious.py  → filtered_malicious.json
  3. build_graph.py       → graph.json / graph.pkl / graph_attr.json
  4. analyze_graph.py     → analysis_report.json

Also produces:
  extracted_data/dataset_manifest.csv   ← label table for GNN training

Changes vs v2:
  - ThreadPoolExecutor: all samples processed in parallel
  - --workers N flag (default: 4)
  - Thread-safe progress bar + manifest collection via Lock
  - Steps within a sample stay sequential with dependency safety:
    ensure-graph → filter → graph → analyze
  - Per-sample output flushed to terminal as soon as it finishes
  - --skip-existing still works (skips individual steps per sample)
  - Dry-run unchanged
  - collect_stats reads graph.pkl (nx.DiGraph) for node/edge counts
    instead of parsing graph.json — faster and always in sync with the
    actual graph object used by the ML pipeline

Usage:
  python build_dataset.py
  python build_dataset.py ./extracted_data
  python build_dataset.py ./extracted_csvs --labels-csv ./0/labels.csv --workers 8
  python build_dataset.py ./extracted_data --workers 8
  python build_dataset.py ./extracted_data --skip-existing --workers 12
  python build_dataset.py ./extracted_data --dry-run
  python build_dataset.py ./extracted_data --only filter graph --workers 6

  Benign BCCC-style folders (no -WithVirus/-NoVirus in name) default to label 0:
  python build_dataset.py ./extracted_csvs --default-label-for-unmatched 0 --skip-existing --workers 8

  Labels only from CSV (no suffix inference on folder names):
  python build_dataset.py ./extracted_csvs --labels-csv ./labels.csv

  Same-directory samples all one class (suffix inference off); requires default or use --labels-csv:
  python build_dataset.py ./all_benign --no-malvol-suffix-inference --default-label-for-unmatched 0
"""

import os, sys, subprocess, json, csv, time, argparse, threading, pickle, re

from utils.graph_motif_signals import graph_differentiation_signals
from concurrent.futures import ThreadPoolExecutor, as_completed


def _count_benign_hubs_graph(G):
    return sum(
        1
        for _, d in G.nodes(data=True)
        if str(d.get("node_type")) == "process" and int(d.get("benign_high_volume_hub", 0) or 0) == 1
    )


def _count_rwx_thread_context_graph(G):
    procs = set()
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "injected_into":
            continue
        if str(G.nodes[u].get("node_type", "")) != "memory_region":
            continue
        if int(G.nodes[u].get("is_rwx", 0) or 0) != 1:
            continue
        procs.add(v)
    if not procs:
        return 0
    n = 0
    for u, v, ed in G.edges(data=True):
        if ed.get("edge_type") != "belongs_to":
            continue
        if str(G.nodes[u].get("node_type", "")) != "thread":
            continue
        if v in procs:
            n += 1
    return n


# ── Label inference ──────────────────────────────────────────────────────
def infer_label(folder_name):
    name = os.path.basename(folder_name)
    if "-WithVirus"in name:
        return 1, name.replace("-WithVirus", "").lower()
    if "-NoVirus"in name:
        return 0, name.replace("-NoVirus", "").lower()
    return -1, name.lower()


def resolve_label_family(
    folder_path,
    *,
    use_suffix_inference,
    default_label_unmatched,
    default_unmatched_family,
):
    """
    Returns (label, family). Suffix inference uses -WithVirus/-NoVirus on basename.
    If label is still -1 and default_label_unmatched is set, apply that label;
    family becomes default_unmatched_family if set, else basename lower.
    """
    base = os.path.basename(folder_path)
    base_l = base.lower()
    if use_suffix_inference:
        lab, fam = infer_label(folder_path)
    else:
        lab, fam = -1, base_l
    if lab == -1 and default_label_unmatched is not None:
        lab = default_label_unmatched
        if default_unmatched_family:
            fam = default_unmatched_family.strip() or base_l
    return lab, fam


def _infer_benign_subtype(folder_name: str, label: int) -> str:
    if int(label) != 0:
        return ""
    n = str(folder_name).lower()
    if any(k in n for k in ("admin", "security", "sysinternals", "defender", "monitor", "av", "edr")):
        return "admin_security_tool"
    return "clean_software"


def _is_hash_like_name(name: str) -> bool:
    token = re.sub(r"[^A-Fa-f0-9]", "", str(name))
    return len(token) >= 32 and bool(re.fullmatch(r"[A-Fa-f0-9]+", token))


def _label_quality_flags(job: dict) -> tuple[bool, list[str]]:
    name_l = str(job.get("name", "")).lower()
    family_l = str(job.get("family", "")).lower()
    source = str(job.get("label_source", "")).lower()
    reasons: list[str] = []
    if source == "name_inference":
        if "timeout" in name_l or "timeout" in family_l:
            reasons.append("timeout_derived_label")
        if _is_hash_like_name(name_l) or _is_hash_like_name(family_l):
            reasons.append("hash_derived_label")
    return bool(reasons), reasons


def load_explicit_label_rows(labels_csv_path, base_dir):
    """
    CSV columns: folder (basename under base_dir), label (0/1), optional family,
    optional benign_subtype.
    Duplicate folder values abort. Rows missing on disk are skipped with a warning.
    Returns sorted list of (abs_folder_path, label:int, family:str, benign_subtype:str).
    """
    base_dir = os.path.abspath(base_dir)
    if not os.path.isfile(labels_csv_path):
        print(f"[ERROR] --labels-csv not found: {labels_csv_path}")
        sys.exit(1)

    seen = {}
    rows_raw = []
    with open(labels_csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if not reader.fieldnames:
            print("[ERROR] --labels-csv has no header row")
            sys.exit(1)
        fields = {h.strip().lower(): h for h in reader.fieldnames if h}
        if "folder" not in fields or "label" not in fields:
            print("[ERROR] --labels-csv must include columns: folder, label")
            sys.exit(1)
        fk_folder = fields["folder"]
        fk_label = fields["label"]
        fk_family = fields.get("family")
        fk_benign_subtype = fields.get("benign_subtype")
        for lineno, row in enumerate(reader, start=2):
            if not row:
                continue
            folder = str(row.get(fk_folder, "") or "").strip()
            if not folder:
                continue
            if folder in seen:
                print(
                    f"[ERROR] Duplicate folder in --labels-csv: {folder!r} "
                    f"(lines {seen[folder]} and {lineno}); remove duplicates."
                )
                sys.exit(1)
            seen[folder] = lineno
            try:
                label = int(row.get(fk_label, ""))
            except (TypeError, ValueError):
                print(f"[WARN]  line {lineno}: bad label for {folder!r}, skipped")
                continue
            fam = "unknown"
            if fk_family:
                fam = str(row.get(fk_family, "") or "").strip() or "unknown"
            benign_subtype = ""
            if fk_benign_subtype:
                benign_subtype = str(row.get(fk_benign_subtype, "") or "").strip()
            if not benign_subtype:
                benign_subtype = _infer_benign_subtype(folder, label)
            rows_raw.append((folder, label, fam, benign_subtype, lineno))

    resolved = []
    for folder, label, fam, benign_subtype, lineno in rows_raw:
        abs_path = os.path.join(base_dir, folder)
        if not os.path.isdir(abs_path):
            print(
                f"[WARN]  --labels-csv line {lineno}: folder {folder!r} "
                f"not found under {base_dir}, skipped"
            )
            continue
        resolved.append((abs_path, label, fam, benign_subtype))

    resolved.sort(key=lambda x: os.path.basename(x[0]).lower())
    return resolved


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
        "label_signals_json": "",
        "signal_behavioural_suspects_found": 0,
        "signal_lolbin_c2_found": 0,
        "signal_ransom_note_found": 0,
        "signal_rwx_injections": 0,
        "signal_hidden_processes": 0,
        "signal_top_suspect_score": 0,
        "signal_triage_confidence": 0.0,
        "signal_stage_coverage_score": 0.0,
        "signal_lineage_depth_p95": 0,
        "signal_nonrwx_exec_count": 0,
        "signal_credential_access_count": 0,
        "signal_num_attack_motifs": 0,
        "signal_temporal_chain_count": 0,
        "signal_api_semantic_count": 0,
        "signal_persistence_count": 0,
        "signal_privilege_escalation_count": 0,
        "signal_parent_child_anomaly_count": 0,
        "signal_svchost_lineage_anomaly_count": 0,
        "signal_svchost_cmdline_anomaly_count": 0,
        "signal_dll_trust_anomaly_count": 0,
        "signal_service_orphan_count": 0,
        "signal_lolbin_chain_count": 0,
        "signal_c2_relation_pattern_count": 0,
        "signal_motif_ransom_decryptor_log": 0.0,
        "signal_motif_tor_tasksvc_log": 0.0,
        "signal_motif_hex_image_name_log": 0.0,
        "signal_motif_memory_per_process_log": 0.0,
        "signal_motif_lolbin_path_log": 0.0,
        "signal_motif_injection_path_log": 0.0,
        "signal_motif_persistence_path_log": 0.0,
        "signal_benign_high_volume_hub_count": 0,
        "signal_rwx_thread_context_count": 0,
    }

    # graph.pkl → node/edge count  (load the nx.DiGraph directly)
    pp = os.path.join(folder, "graph.pkl")
    if os.path.exists(pp):
        try:
            with open(pp, "rb") as f:
                G = pickle.load(f)
            stats["nodes"] = G.number_of_nodes()
            stats["edges"] = G.number_of_edges()
            edge_counts = {}
            for _, _, ed in G.edges(data=True):
                et = str(ed.get("edge_type", ""))
                edge_counts[et] = edge_counts.get(et, 0) + 1
            stats["signal_temporal_chain_count"] = int(edge_counts.get("temporal_execution_chain", 0))
            stats["signal_api_semantic_count"] = int(edge_counts.get("api_semantic_activity", 0))
            stats["signal_persistence_count"] = int(edge_counts.get("persistence_behavior", 0))
            stats["signal_privilege_escalation_count"] = int(edge_counts.get("privilege_escalation_indicator", 0))
            stats["signal_parent_child_anomaly_count"] = int(edge_counts.get("parent_child_anomaly", 0))
            stats["signal_svchost_lineage_anomaly_count"] = int(edge_counts.get("svchost_lineage_anomaly", 0))
            stats["signal_svchost_cmdline_anomaly_count"] = int(edge_counts.get("svchost_cmdline_anomaly", 0))
            stats["signal_dll_trust_anomaly_count"] = int(edge_counts.get("dll_trust_anomaly", 0))
            stats["signal_service_orphan_count"] = int(edge_counts.get("service_orphan", 0))
            stats["signal_lolbin_chain_count"] = int(edge_counts.get("lolbin_execution_chain", 0))
            stats["signal_c2_relation_pattern_count"] = int(edge_counts.get("c2_relation_pattern", 0))
            m = graph_differentiation_signals(G)
            stats["signal_motif_ransom_decryptor_log"] = float(m[0])
            stats["signal_motif_tor_tasksvc_log"] = float(m[1])
            stats["signal_motif_hex_image_name_log"] = float(m[2])
            stats["signal_motif_memory_per_process_log"] = float(m[3])
            stats["signal_motif_lolbin_path_log"] = float(m[4])
            stats["signal_motif_injection_path_log"] = float(m[5])
            stats["signal_motif_persistence_path_log"] = float(m[6])
            stats["signal_benign_high_volume_hub_count"] = int(_count_benign_hubs_graph(G))
            stats["signal_rwx_thread_context_count"] = int(_count_rwx_thread_context_graph(G))
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
            stats["label_signals_json"] = json.dumps(ls, sort_keys=True)
            stats["label_signals_top"] = " ".join(
                f"{k}={v}" for k, v in list(ls.items())[:4]
            )
            stats["signal_behavioural_suspects_found"] = int(ls.get("behavioural_suspects_found", 0))
            stats["signal_lolbin_c2_found"] = int(ls.get("lolbin_c2_found", 0))
            stats["signal_ransom_note_found"] = int(ls.get("ransom_note_found", 0))
            stats["signal_rwx_injections"] = int(ls.get("rwx_injections", 0))
            stats["signal_hidden_processes"] = int(ls.get("hidden_processes", 0))
            stats["signal_top_suspect_score"] = int(ls.get("top_suspect_score", 0))
            stats["signal_triage_confidence"] = float(ls.get("triage_confidence", 0.0))
            stats["signal_stage_coverage_score"] = float(ls.get("stage_coverage_score", 0.0))
            stats["signal_lineage_depth_p95"] = int(ls.get("lineage_depth_p95", 0))
            stats["signal_nonrwx_exec_count"] = int(ls.get("nonrwx_exec_count", 0))
            stats["signal_credential_access_count"] = int(ls.get("credential_access_count", 0))
            stats["signal_num_attack_motifs"] = int(ls.get("num_attack_motifs", 0))
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


def uncertainty_flags(row):
    """
    Mark manifest uncertainty for label-quality or pipeline integrity reasons.
    """
    reasons = []
    if not bool(row.get("filter_ok", False)):
        reasons.append("filter_failed")
    if not bool(row.get("graph_ok", False)):
        reasons.append("graph_failed")
    if not bool(row.get("analyze_ok", False)):
        reasons.append("analyze_failed")

    quality_reasons = str(row.get("label_quality_reason", "")).strip()
    if quality_reasons:
        reasons.append(quality_reasons)
    return bool(reasons), "|".join([r for r in reasons if r])


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
    benign_subtype = job.get("benign_subtype", "")
    idx    = job["idx"]
    total  = job["total"]

    log    = [f"Sample: {name} | label={label} | family={family} | benign_subtype={benign_subtype}"]
    lines  = []
    lines.append(
        f"[{idx:02d}/{total}] {name}  label={label}  family={family}  "
        f"benign_subtype={benign_subtype or '-'}"
    )

    existing = check_outputs(folder)
    row = {
        "sample_id":  f"{idx:02d}",
        "folder":     name,
        "label":      label,
        "family":     family,
        "benign_subtype": benign_subtype,
        "label_source": job.get("label_source", "inferred"),
        "label_version": job.get("label_version", "v1"),
        "reviewer_id": job.get("reviewer_id", ""),
        "reviewed_at": job.get("reviewed_at", ""),
        "feedback_state": job.get("feedback_state", "unreviewed"),
        "curated_label": job.get("curated_label", ""),
        "label_quality_flag": bool(job.get("label_quality_flag", False)),
        "label_quality_reason": str(job.get("label_quality_reason", "")),
        "train_eligible": bool(job.get("train_eligible", True)),
        "filter_ok":  False,
        "graph_ok":   False,
        "analyze_ok": False,
        "error":      "",
    }

    # Ensure graph.pkl exists before filtering. filter_malicious.py requires it.
    graph_missing = not existing["graph.pkl"]
    if "filter" in run_steps and graph_missing:
        ok, _, err, t = run_script(scripts["graph"], folder)
        mark = "✅" if ok else "❌"
        lines.append(f"  [RUN]  build_graph.py (bootstrap) ... {mark} ({t}s)")
        log.append(f"build_graph.py (bootstrap): {'OK' if ok else 'FAIL'} ({t}s)")
        if not ok and err:
            log.append(f"  STDERR: {err[:400]}")
            row["error"] += f"graph_bootstrap:{err[:80]} "
        existing = check_outputs(folder)

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
    uncertain, uncertain_reason = uncertainty_flags(row)
    row["uncertain"] = uncertain
    row["uncertain_reason"] = uncertain_reason
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
    parser.add_argument(
        "--labels-csv",
        default=None,
        dest="labels_csv",
        help=(
            "Optional CSV with columns folder,label[,family]. "
            "Only those basenames under base_dir are processed; label/family come "
            "from the file (not infer_label). Duplicate folder values abort. "
            "CSV rows pointing at missing folders are skipped with a warning."
        ),
    )
    parser.add_argument(
        "--default-label-for-unmatched",
        type=int,
        default=None,
        metavar="N",
        help=(
            "When scanning subfolders (no --labels-csv), if a folder name does not "
            "match -WithVirus/-NoVirus (or suffix inference is off), use label N "
            "instead of -1. N must be -1, 0, or 1. Typical: 0 for known-benign BCCC dumps."
        ),
    )
    parser.add_argument(
        "--default-unmatched-family",
        default=None,
        metavar="NAME",
        help=(
            "Used with --default-label-for-unmatched when the inferred label was -1: "
            "set family column to this string; default is the folder basename (lower)."
        ),
    )
    parser.add_argument(
        "--no-malvol-suffix-inference",
        action="store_true",
        help=(
            "Do not infer label/family from -WithVirus/-NoVirus in folder names. "
            "Without --labels-csv you must pass --default-label-for-unmatched "
            "(all scanned folders get that label). Do not use on mixed MalVol+BCCC "
            "trees unless every sample is listed in --labels-csv."
        ),
    )
    parser.add_argument(
        "--allow-timeout-hash-labels",
        action="store_true",
        help=(
            "Allow timeout/hash-derived labels from name-inference into training eligibility. "
            "Default: excluded from training via train_eligible=false."
        ),
    )
    args = parser.parse_args()

    if args.default_label_for_unmatched is not None and args.default_label_for_unmatched not in (
        -1,
        0,
        1,
    ):
        print("[ERROR] --default-label-for-unmatched must be -1, 0, or 1")
        sys.exit(1)
    if args.default_unmatched_family and args.default_label_for_unmatched is None:
        print("[ERROR] --default-unmatched-family requires --default-label-for-unmatched")
        sys.exit(1)
    if args.no_malvol_suffix_inference and not args.labels_csv:
        if args.default_label_for_unmatched is None:
            print(
                "[ERROR] --no-malvol-suffix-inference without --labels-csv requires "
                "--default-label-for-unmatched (every folder would otherwise be label -1)."
            )
            sys.exit(1)

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

    use_suffix = not args.no_malvol_suffix_inference
    def_lab = args.default_label_for_unmatched
    def_fam = args.default_unmatched_family

    if args.labels_csv:
        labels_csv = os.path.abspath(args.labels_csv)
        explicit = load_explicit_label_rows(labels_csv, base_dir)
        if not explicit:
            print("[ERROR] --labels-csv produced no valid sample folders"); sys.exit(1)
        sample_dirs = [p for p, _, _ in explicit]
        jobs = [
            {
                "folder": f,
                "name":   os.path.basename(f),
                "label":  lab,
                "family": fam,
                "benign_subtype": benign_subtype,
                "label_source": "labels_csv",
                "label_version": "v1",
                "reviewer_id": "",
                "reviewed_at": "",
                "feedback_state": "unreviewed",
                "curated_label": "",
                "idx":    i,
                "total":  len(sample_dirs),
            }
            for i, (f, lab, fam, benign_subtype) in enumerate(explicit, 1)
        ]
    else:
        sample_dirs = sorted([
            os.path.join(base_dir, d)
            for d in os.listdir(base_dir)
            if os.path.isdir(os.path.join(base_dir, d))
        ])
        if not sample_dirs:
            print(f"[ERROR] No subfolders in: {base_dir}"); sys.exit(1)

        jobs = []
        for i, f in enumerate(sample_dirs, 1):
            lab, fam = resolve_label_family(
                f,
                use_suffix_inference=use_suffix,
                default_label_unmatched=def_lab,
                default_unmatched_family=def_fam,
            )
            jobs.append(
                {
                    "folder": f,
                    "name":   os.path.basename(f),
                    "label":  lab,
                    "family": fam,
                    "benign_subtype": _infer_benign_subtype(os.path.basename(f), lab),
                    "label_source": "name_inference",
                    "label_version": "v1",
                    "reviewer_id": "",
                    "reviewed_at": "",
                    "feedback_state": "unreviewed",
                    "curated_label": "",
                    "idx":    i,
                    "total":  len(sample_dirs),
                }
            )

    for job in jobs:
        flagged, reasons = _label_quality_flags(job)
        job["label_quality_flag"] = flagged
        job["label_quality_reason"] = "|".join(reasons)
        job["train_eligible"] = not (flagged and not args.allow_timeout_hash_labels)

    # ─ Dry run ────────────────────────────────────────────────────────────
    if args.dry_run:
        print(f"\n{'='*65}")
        print(f"  DRY RUN — {len(jobs)} samples in: {base_dir}")
        if args.labels_csv:
            print(f"  Labels  : explicit {os.path.abspath(args.labels_csv)}")
        else:
            print(
                f"  Suffix inference (-WithVirus/-NoVirus): "
                f"{'on' if use_suffix else 'off (--no-malvol-suffix-inference)'}"
            )
            if def_lab is not None:
                print(f"  Default label for unmatched names : {def_lab}")
                if def_fam:
                    print(f"  Default family for those          : {def_fam!r}")
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
    if args.labels_csv:
        print(f"  Labels CSV : {os.path.abspath(args.labels_csv)}")
    else:
        print(
            f"  Suffix inference : "
            f"{'on (-WithVirus/-NoVirus)' if use_suffix else 'off'}"
        )
        if def_lab is not None:
            print(f"  Default label (unmatched names): {def_lab}")
            if def_fam:
                print(f"  Default family (unmatched)     : {def_fam}")
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
                    "benign_subtype": job.get("benign_subtype", ""),
                    "label_source": job.get("label_source", "inferred"),
                    "label_version": job.get("label_version", "v1"),
                    "reviewer_id": job.get("reviewer_id", ""),
                    "reviewed_at": job.get("reviewed_at", ""),
                    "feedback_state": job.get("feedback_state", "unreviewed"),
                    "curated_label": job.get("curated_label", ""),
                    "label_quality_flag": bool(job.get("label_quality_flag", False)),
                    "label_quality_reason": str(job.get("label_quality_reason", "")),
                    "train_eligible": bool(job.get("train_eligible", True)),
                    "filter_ok":  False,
                    "graph_ok":   False,
                    "analyze_ok": False,
                    "error":      str(exc)[:120],
                    "nodes": -1, "edges": -1, "max_score": -1,
                    "attack_steps": -1, "injections": -1, "c2_conns": -1,
                    "verdict": "exception",
                    "graph_attr": "", "label_signals_top": "", "label_signals_json": "",
                    "signal_behavioural_suspects_found": 0,
                    "signal_lolbin_c2_found": 0,
                    "signal_ransom_note_found": 0,
                    "signal_rwx_injections": 0,
                    "signal_hidden_processes": 0,
                    "signal_top_suspect_score": 0,
                    "signal_triage_confidence": 0.0,
                    "signal_stage_coverage_score": 0.0,
                    "signal_lineage_depth_p95": 0,
                    "signal_nonrwx_exec_count": 0,
                    "signal_credential_access_count": 0,
                    "signal_num_attack_motifs": 0,
                    "signal_temporal_chain_count": 0,
                    "signal_api_semantic_count": 0,
                    "signal_persistence_count": 0,
                    "signal_privilege_escalation_count": 0,
                    "signal_parent_child_anomaly_count": 0,
                    "signal_svchost_lineage_anomaly_count": 0,
                    "signal_svchost_cmdline_anomaly_count": 0,
                    "signal_dll_trust_anomaly_count": 0,
                    "signal_service_orphan_count": 0,
                    "signal_lolbin_chain_count": 0,
                    "signal_c2_relation_pattern_count": 0,
                    "signal_motif_ransom_decryptor_log": 0.0,
                    "signal_motif_tor_tasksvc_log": 0.0,
                    "signal_motif_hex_image_name_log": 0.0,
                    "signal_motif_memory_per_process_log": 0.0,
                    "signal_motif_lolbin_path_log": 0.0,
                    "signal_motif_injection_path_log": 0.0,
                    "signal_motif_persistence_path_log": 0.0,
                    "signal_benign_high_volume_hub_count": 0,
                    "signal_rwx_thread_context_count": 0,
                    "uncertain": True,
                    "uncertain_reason": "pipeline_exception",
                }

    # ─ Write manifest CSV ────────────────────────────────────────────────
    manifest_path = os.path.join(base_dir, "dataset_manifest.csv")
    fieldnames = [
        "sample_id", "folder", "label", "family",
        "benign_subtype", "label_source", "label_version", "reviewer_id", "reviewed_at", "feedback_state", "curated_label",
        "label_quality_flag", "label_quality_reason", "train_eligible",
        "nodes", "edges",
        "max_score", "attack_steps", "injections", "c2_conns",
        "verdict",
        "graph_attr", "label_signals_top", "label_signals_json",
        "signal_behavioural_suspects_found",
        "signal_lolbin_c2_found",
        "signal_ransom_note_found",
        "signal_rwx_injections",
        "signal_hidden_processes",
        "signal_top_suspect_score",
        "signal_triage_confidence",
        "signal_stage_coverage_score",
        "signal_lineage_depth_p95",
        "signal_nonrwx_exec_count",
        "signal_credential_access_count",
        "signal_num_attack_motifs",
        "signal_temporal_chain_count",
        "signal_api_semantic_count",
        "signal_persistence_count",
        "signal_privilege_escalation_count",
        "signal_parent_child_anomaly_count",
        "signal_svchost_lineage_anomaly_count",
        "signal_svchost_cmdline_anomaly_count",
        "signal_dll_trust_anomaly_count",
        "signal_service_orphan_count",
        "signal_lolbin_chain_count",
        "signal_c2_relation_pattern_count",
        "signal_motif_ransom_decryptor_log",
        "signal_motif_tor_tasksvc_log",
        "signal_motif_hex_image_name_log",
        "signal_motif_memory_per_process_log",
        "signal_motif_lolbin_path_log",
        "signal_motif_injection_path_log",
        "signal_motif_persistence_path_log",
        "signal_benign_high_volume_hub_count",
        "signal_rwx_thread_context_count",
        "uncertain", "uncertain_reason",
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
    uncertain_rows = [r for r in rows if r.get("uncertain")]

    print(f"{'='*65}")
    print(f"  DATASET BUILD COMPLETE  ({elapsed}s total, {n_workers} workers)")
    print(f"{'='*65}")
    print(f"  Samples total     : {len(rows)}")
    print(f"  Fully successful  : {ok_count}/{len(rows)}")
    print(f"  Uncertain samples : {len(uncertain_rows)}")
    print(f"  Malware (label=1) : {len(malware)}")
    print(f"  Clean   (label=0) : {len(clean)}")
    if unknown:
        print(f"  Unknown (label=-1): {len(unknown)}  ← manually label in manifest")
    elif def_lab is not None and not args.labels_csv:
        print(f"  Unknown (label=-1): 0  (unmatched names used --default-label-for-unmatched={def_lab})")
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
