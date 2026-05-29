#!/usr/bin/env python3
"""Evaluation orchestration wrapper (two-model + binary + merged fusion)."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path


def _run(cmd: list[str]) -> int:
    return subprocess.call(cmd)


def _model_triage_metrics(states: list[str], *, source: str) -> dict:
    decisive_states = {"likely_malicious", "likely_benign"}
    if source == "two_model":
        abstain_states = {"needs_analyst_review", "anomalous_unknown"}
        review_states = {"needs_analyst_review"}
    else:
        abstain_states = {"high_risk_ambiguous", "low_risk_ambiguous"}
        review_states = set()
    total = len(states)
    if total == 0:
        return {
            "samples": 0,
            "decisive_coverage": 0.0,
            "abstention_coverage": 0.0,
            "review_routing_rate": 0.0,
            "state_counts": {},
        }
    counts: dict[str, int] = {}
    for state in states:
        counts[state] = counts.get(state, 0) + 1
    return {
        "samples": total,
        "decisive_coverage": round(sum(counts.get(s, 0) for s in decisive_states) / total, 6),
        "abstention_coverage": round(sum(counts.get(s, 0) for s in abstain_states) / total, 6),
        "review_routing_rate": round(sum(counts.get(s, 0) for s in review_states) / total, 6),
        "state_counts": counts,
    }


def _load_manifest_rows(path: str) -> dict[str, dict]:
    manifest_by_folder: dict[str, dict] = {}
    manifest_path = Path(path)
    if not manifest_path.exists():
        return manifest_by_folder
    with manifest_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            folder = str(row.get("folder", "") or "").strip()
            if folder:
                manifest_by_folder[folder] = row
    return manifest_by_folder


GATE_ABLATION_PRESETS = {
    "disabled": [
        "--abstention-mode",
        "disabled",
    ],
    "legacy_or": [
        "--abstention-mode",
        "legacy_or",
        "--uncertainty-disagreement-threshold",
        "0.35",
        "--uncertainty-dual-margin-threshold",
        "0.10",
    ],
    "calibrated": [
        "--abstention-mode",
        "calibrated",
        "--uncertainty-disagreement-threshold",
        "0.55",
        "--uncertainty-dual-margin-threshold",
        "0.05",
        "--uncertainty-mc-variance-threshold",
        "0.08",
    ],
}


def _run_gate_ablation(manifest: str, base_dir: str | None) -> None:
    import csv

    out_csv = Path("outputs/gate_ablation.csv")
    rows: list[dict] = []
    for preset, extra in GATE_ABLATION_PRESETS.items():
        two_out = f"outputs/two_model_analysis_{preset}.json"
        cmd = [
            sys.executable,
            "analyze_two_model.py",
            manifest,
            "--output-json",
            two_out,
            *extra,
        ]
        if base_dir:
            cmd.extend(["--base-dir", base_dir])
        thresholds = Path("outputs/uncertainty_thresholds.json")
        if preset == "calibrated" and thresholds.exists():
            cmd.extend(["--uncertainty-thresholds-json", str(thresholds)])
        rc = _run(cmd)
        metrics = {"preset": preset, "rc": rc}
        if Path(two_out).exists():
            data = json.loads(Path(two_out).read_text(encoding="utf-8"))
            summary = data.get("summary", {})
            metrics.update(
                {
                    "samples": summary.get("samples_analyzed", 0),
                    "review_routing_rate": summary.get("review_routing_rate"),
                    "decisive_coverage": summary.get("decisive_coverage"),
                    "uncertainty_gated": summary.get("uncertainty_gated"),
                }
            )
        rows.append(metrics)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    if rows:
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        print(f"[Evaluate] gate ablation -> {out_csv}")


def main():
    args = sys.argv[1:]
    # Backward-compatible path: if explicit passthrough requested, keep old behavior.
    if "--passthrough-two-model" in args:
        args = [a for a in args if a != "--passthrough-two-model"]
        raise SystemExit(_run([sys.executable, "analyze_two_model.py", *args]))

    if "--gate-ablation" in args:
        args = [a for a in args if a != "--gate-ablation"]
        manifest = args[0] if args else "extracted_data/dataset_manifest.csv"
        base_dir = None
        if "--base-dir" in args:
            i = args.index("--base-dir")
            if i + 1 < len(args):
                base_dir = args[i + 1]
        _run_gate_ablation(manifest, base_dir)
        raise SystemExit(0)

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
    manifest_rows = _load_manifest_rows(manifest)
    if two:
        payload["summary"]["sources"]["two_model_metrics"] = _model_triage_metrics(
            [s.get("triage_state", "") for s in two.values()],
            source="two_model",
        )
    if binary:
        payload["summary"]["sources"]["binary_model_metrics"] = _model_triage_metrics(
            [s.get("triage_state", "") for s in binary.values()],
            source="binary_model",
        )
    if manifest_rows:
        def _subtype(row: dict, name: str) -> bool:
            return str(row.get("benign_subtype", "")).strip().lower() == name

        subsets = {
            "uncertain_benign": lambda row: str(row.get("label", "")).strip() == "0"
            and str(row.get("uncertain", "")).strip().lower() == "true",
            "clean_benign": lambda row: str(row.get("label", "")).strip() == "0"
            and _subtype(row, "clean_benign"),
            "hard_benign_admin_tooling": lambda row: str(row.get("label", "")).strip() == "0"
            and _subtype(row, "hard_benign_admin_tooling"),
            "ambiguous_novirus_control": lambda row: str(row.get("label", "")).strip() == "0"
            and _subtype(row, "ambiguous_novirus_control"),
            "malware_labelled": lambda row: str(row.get("label", "")).strip() == "1",
            "other_rows": lambda row: not (
                str(row.get("label", "")).strip() == "0"
                and str(row.get("uncertain", "")).strip().lower() == "true"
            ),
        }
        subset_metrics: dict[str, dict] = {}
        for subset_name, pred in subsets.items():
            rows = [folder for folder, row in manifest_rows.items() if pred(row)]
            if rows:
                subset_metrics[subset_name] = {
                    "two_model": _model_triage_metrics(
                        [two.get(folder, {}).get("triage_state", "") for folder in rows if folder in two],
                        source="two_model",
                    ),
                    "binary_model": _model_triage_metrics(
                        [binary.get(folder, {}).get("triage_state", "") for folder in rows if folder in binary],
                        source="binary_model",
                    ),
                }
        if subset_metrics:
            payload["summary"]["subset_metrics"] = subset_metrics
    merge_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"[Evaluate] wrote merged output: {merge_out}")
    raise SystemExit(0)


if __name__ == "__main__":
    main()

