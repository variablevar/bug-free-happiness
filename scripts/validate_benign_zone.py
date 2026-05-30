#!/usr/bin/env python3
"""Print benign-zone vs suspect-zone triage stats per sample folder."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def load_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def summarize(folder: Path) -> dict:
    fm = load_json(folder / "filtered_malicious.json")
    ar = load_json(folder / "analysis_report.json")
    meta = fm.get("_meta", {})
    chain = ar.get("attack_chain", {})
    bz = ar.get("benign_zone_summary", {})
    return {
        "folder": folder.name,
        "suspect_pids": len(meta.get("suspect_zone_pids", meta.get("suspicious_pids", []))),
        "benign_pids": len(meta.get("benign_zone_pids", [])),
        "behavioural_suspects": len(fm.get("behavioural_suspects", [])),
        "benign_context": len(fm.get("benign_context_processes", [])),
        "verdict": chain.get("overall_verdict", "")[:60],
        "attack_steps": len(chain.get("steps", [])),
        "benign_zone_procs": bz.get("process_count", 0),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Validate benign-zone pipeline outputs.")
    ap.add_argument("root", nargs="?", default="experiment/data", help="Root with sample folders")
    ap.add_argument("--suffix", default="", help="Only folders ending with this (e.g. -NoVirus)")
    args = ap.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"[ERROR] Not a directory: {root}", file=sys.stderr)
        return 1

    rows = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        if args.suffix and not d.name.endswith(args.suffix):
            continue
        if not (d / "filtered_malicious.json").is_file():
            continue
        rows.append(summarize(d))

    print(f"{'folder':32s}  sus  ben  beh  bctx  steps  verdict")
    for r in rows:
        print(
            f"{r['folder']:32s}  {r['suspect_pids']:3d}  {r['benign_pids']:3d}  "
            f"{r['behavioural_suspects']:3d}  {r['benign_context']:4d}  "
            f"{r['attack_steps']:5d}  {r['verdict']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
