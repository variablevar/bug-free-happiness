#!/usr/bin/env python3
"""Evaluation orchestration wrapper (two-model + binary + merged fusion)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str]) -> int:
    return subprocess.call(cmd)


def main():
    args = sys.argv[1:]
    # Backward-compatible path: if explicit passthrough requested, keep old behavior.
    if "--passthrough-two-model" in args:
        args = [a for a in args if a != "--passthrough-two-model"]
        raise SystemExit(_run([sys.executable, "analyze_two_model.py", *args]))

    manifest = args[0] if args else "extracted_data/dataset_manifest.csv"
    base_dir = None
    if "--base-dir" in args:
        i = args.index("--base-dir")
        if i + 1 < len(args):
            base_dir = args[i + 1]

    two_out = "outputs/two_model_analysis.json"
    bin_out = "outputs/binary_analysis.json"

    rc_two = _run([sys.executable, "analyze_two_model.py", manifest, "--output-json", two_out] + (["--base-dir", base_dir] if base_dir else []))
    rc_bin = _run([sys.executable, "analyze_binary_model.py", manifest, "--output-json", bin_out] + (["--base-dir", base_dir] if base_dir else []))
    if rc_two != 0 and rc_bin != 0:
        raise SystemExit(max(rc_two, rc_bin))

    merge_out = Path("outputs/evaluate_merged_analysis.json")
    payload = {"summary": {"sources": {}}, "samples": []}
    two = {}
    binary = {}
    if Path(two_out).exists():
        two_data = json.loads(Path(two_out).read_text(encoding="utf-8"))
        two = {s.get("folder"): s for s in two_data.get("samples", [])}
        payload["summary"]["sources"]["two_model"] = two_data.get("summary", {})
    if Path(bin_out).exists():
        bin_data = json.loads(Path(bin_out).read_text(encoding="utf-8"))
        binary = {s.get("folder"): s for s in bin_data.get("samples", [])}
        payload["summary"]["sources"]["binary_model"] = bin_data.get("summary", {})

    folders = sorted(set(two.keys()) | set(binary.keys()))
    for folder in folders:
        payload["samples"].append(
            {
                "folder": folder,
                "two_model": two.get(folder, {}),
                "binary_model": binary.get(folder, {}),
            }
        )
    payload["summary"]["samples_analyzed"] = len(payload["samples"])
    merge_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[Evaluate] wrote merged output: {merge_out}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()

