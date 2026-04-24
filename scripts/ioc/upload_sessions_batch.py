#!/usr/bin/env python3
"""
Run IOC-style analyses against upload_sessions/ (Vol3 dashboard dumps).

Usage:
  python scripts/ioc/upload_sessions_batch.py --script-id code_injection
  python scripts/ioc/upload_sessions_batch.py --script-id network --dump-id <uuid>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd

BASE_DIR = Path(__file__).resolve().parents[2]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from ioc_analysis.common import ensure_outputs_dir
from ioc_analysis.session_ioc import (
    detect_hidden_processes,
    iter_upload_session_dirs,
    load_filescan_suspicious_metrics,
    load_netscan_metrics,
    malfind_row_count,
    master_ioc_row_for_dir,
)

SESSIONS = BASE_DIR / "upload_sessions"
OUTPUTS = BASE_DIR / "outputs"

SCRIPT_CHOICES = (
    "code_injection",
    "hidden_proc",
    "network",
    "filescan",
    "analysis_corpus",
)

OUT_FILES = {
    "code_injection": "ioc_uploads_malfind.csv",
    "hidden_proc": "ioc_uploads_hidden_proc.csv",
    "network": "ioc_uploads_netscan.csv",
    "filescan": "ioc_uploads_filescan.csv",
    "analysis_corpus": "ioc_uploads_master_iocs.csv",
}


def run_code_injection(dirs: list[Path]) -> pd.DataFrame:
    rows = []
    for d in dirs:
        rows.append({"dump_id": d.name, "malfind_rows": malfind_row_count(d)})
    return pd.DataFrame(rows)


def run_hidden_proc(dirs: list[Path]) -> pd.DataFrame:
    rows = []
    for d in dirs:
        h = detect_hidden_processes(d)
        rows.append(
            {
                "dump_id": d.name,
                "hidden_count": h["hidden_count"],
                "total_psscan": h["total_psscan"],
                "total_pslist": h["total_pslist"],
                "hidden_names": h["hidden_names"],
            }
        )
    return pd.DataFrame(rows)


def run_network(dirs: list[Path]) -> pd.DataFrame:
    rows = []
    for d in dirs:
        m = load_netscan_metrics(d)
        rows.append(
            {
                "dump_id": d.name,
                "connections": m["connections"],
                "suspicious_ports": m["susp_ports"],
                "c2_hits": m["c2_hits"],
            }
        )
    return pd.DataFrame(rows)


def run_filescan(dirs: list[Path]) -> pd.DataFrame:
    rows = []
    for d in dirs:
        a = load_filescan_suspicious_metrics(d)
        rows.append(
            {
                "dump_id": d.name,
                "suspicious_files": a["suspicious_count"],
                "deleted_files": a["deleted_count"],
                "suspicious_names": a["susp_names"],
            }
        )
    return pd.DataFrame(rows)


def run_analysis_corpus(dirs: list[Path]) -> pd.DataFrame:
    rows = [master_ioc_row_for_dir(d) for d in dirs]
    return pd.DataFrame(rows)


def main() -> int:
    ap = argparse.ArgumentParser(description="IOC metrics over upload_sessions/")
    ap.add_argument(
        "--script-id",
        required=True,
        choices=SCRIPT_CHOICES,
        help="Which analysis to run",
    )
    ap.add_argument(
        "--dump-id",
        default="",
        help="If set, only analyze this upload session folder name (UUID)",
    )
    args = ap.parse_args()

    dirs = iter_upload_session_dirs(SESSIONS, args.dump_id or None)
    if not dirs:
        print("[!] No matching upload session directories (need folders under upload_sessions/ with windows_*.csv).")
        if args.dump_id:
            print(f"    dump_id={args.dump_id!r} not found or invalid.")
        return 1

    ensure_outputs_dir(str(OUTPUTS))
    out_name = OUT_FILES[args.script_id]
    out_path = OUTPUTS / out_name

    if args.script_id == "code_injection":
        df = run_code_injection(dirs)
        title = "## Code injection signal (Malfind row counts, upload_sessions)"
    elif args.script_id == "hidden_proc":
        df = run_hidden_proc(dirs)
        title = "## Hidden processes (PSScan vs PSList, upload_sessions)"
    elif args.script_id == "network":
        df = run_network(dirs)
        title = "## Network / netscan heuristics (upload_sessions)"
    elif args.script_id == "filescan":
        df = run_filescan(dirs)
        title = "## Filescan suspicious paths (upload_sessions)"
    else:
        df = run_analysis_corpus(dirs)
        title = "## Master IOC-style summary per dump (upload_sessions)"

    print(title)
    print(f"\nSessions analyzed: {len(dirs)}")
    try:
        print("\n" + df.to_markdown(index=False))
    except Exception:
        print(df.to_string(index=False))
    df.to_csv(out_path, index=False)
    print(f"\n✅ Wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
