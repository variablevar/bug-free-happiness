#!/usr/bin/env python3
"""Rank process names contributing to benign-labelled false positives."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def main() -> None:
    p = argparse.ArgumentParser(description="Per-process FP hints from two-model analysis")
    p.add_argument(
        "input_json",
        nargs="?",
        default="outputs/two_model_analysis.json",
    )
    p.add_argument("--output", default="outputs/per_process_fp_report.json")
    p.add_argument("--top", type=int, default=25)
    args = p.parse_args()

    data = json.loads(Path(args.input_json).read_text(encoding="utf-8"))
    counts: Counter[str] = Counter()
    hub_counts: Counter[str] = Counter()
    for s in data.get("samples", []):
        if int(s.get("label_from_manifest", -1)) != 0:
            continue
        if s.get("triage_state") not in {"likely_malicious", "needs_analyst_review"}:
            continue
        for ev in (s.get("malware_model_evidence") or {}).get("top_nodes", [])[:8]:
            name = str(ev.get("name") or ev.get("label") or "").strip().lower()
            if name:
                counts[name] += 1
                if ev.get("benign_high_volume_hub") or "searchhost" in name or "svchost" in name:
                    hub_counts[name] += 1

    ranked = [{"process": k, "fp_hint_count": v} for k, v in counts.most_common(args.top)]
    report = {
        "source": args.input_json,
        "benign_labelled_fp_processes": ranked,
        "hub_like_fp_processes": [
            {"process": k, "count": v} for k, v in hub_counts.most_common(args.top)
        ],
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[per_process_fp_report] wrote {out}")


if __name__ == "__main__":
    main()
