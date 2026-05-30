#!/usr/bin/env python3
"""Generate per-sample REPORT.md from analysis_report.json and optional manifest/ML outputs."""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _load_manifest(path: Path | None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if path is None or not path.is_file():
        return out
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            folder = str(row.get("folder", "") or "").strip()
            if folder:
                out[folder] = row
    return out


def _load_analysis_json(path: Path | None) -> dict[str, dict]:
    out: dict[str, dict] = {}
    if path is None or not path.is_file():
        return out
    data = json.loads(path.read_text(encoding="utf-8"))
    for sample in data.get("samples", []):
        folder = str(sample.get("folder", "") or "").strip()
        if folder:
            out[folder] = sample
    return out


def _truncate(text: str, max_len: int = 120) -> str:
    text = " ".join(str(text or "").split())
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _count_list(section) -> int:
    if isinstance(section, list):
        return len(section)
    if isinstance(section, dict):
        return len(section)
    return 0


def _artifact_check(sample_dir: Path, name: str) -> str:
    return "yes" if (sample_dir / name).is_file() else "no"


def render_report(
    folder: str,
    report: dict,
    manifest_row: dict | None,
    ml_row: dict | None,
    sample_dir: Path,
) -> str:
    summary = report.get("summary", {}) or {}
    attack = report.get("attack_chain", {}) or {}
    steps = attack.get("steps", []) or []
    entry_points = report.get("entry_points", []) or []

    label = (manifest_row or {}).get("label", "—")
    family = (manifest_row or {}).get("family", "—")
    sample_id = (manifest_row or {}).get("sample_id", folder)
    uncertain = (manifest_row or {}).get("uncertain", "—")
    benign_subtype = (manifest_row or {}).get("benign_subtype", "—")

    lines: list[str] = [
        f"# Sample report: {folder}",
        "",
        "## Identity",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| sample_id | {sample_id} |",
        f"| folder | `{folder}` |",
        f"| label | {label} |",
        f"| family | {family} |",
        f"| uncertain | {uncertain} |",
        f"| benign_subtype | {benign_subtype} |",
        "",
        "## Graph scale",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| nodes | {summary.get('nodes_total', '—')} |",
        f"| edges | {summary.get('edges_total', '—')} |",
        f"| suspicious_total | {summary.get('suspicious_total', '—')} |",
        "",
        "## Attack chain",
        "",
        f"**Verdict:** {attack.get('overall_verdict', '—')}",
        "",
        f"**Max process score:** {attack.get('max_process_score', '—')}",
        "",
    ]

    if steps:
        lines.append("| Step | Tactic | MITRE | Detail |")
        lines.append("|------|--------|-------|--------|")
        for step in steps[:5]:
            lines.append(
                "| {step} | {tactic} | {mitre} | {detail} |".format(
                    step=step.get("step", "—"),
                    tactic=_truncate(str(step.get("tactic", "—")), 40),
                    mitre=step.get("mitre", "—"),
                    detail=_truncate(str(step.get("detail", "—")), 80),
                )
            )
        lines.append("")
    else:
        lines.append("_No attack-chain steps recorded._")
        lines.append("")

    lines.extend(["## Top entry points", ""])
    if entry_points:
        lines.append("| Process | PID | Score | Severity | Signals |")
        lines.append("|---------|-----|-------|----------|---------|")
        for ep in entry_points[:5]:
            signals = ", ".join(ep.get("signals", []) or [])
            lines.append(
                f"| {ep.get('name', '—')} | {ep.get('pid', '—')} | "
                f"{ep.get('entry_score', '—')} | {ep.get('severity', '—')} | "
                f"{_truncate(signals, 60)} |"
            )
        lines.append("")
    else:
        lines.append("_No entry points listed._")
        lines.append("")

    lines.extend(
        [
            "## IOC summary",
            "",
            f"| Category | Count |",
            f"|----------|-------|",
            f"| injections | {_count_list(report.get('injections'))} |",
            f"| network (suspicious) | {_count_list(report.get('network'))} |",
            f"| credentials | {_count_list(report.get('credentials'))} |",
            f"| hidden_processes | {_count_list(report.get('hidden_processes'))} |",
            "",
            "## Pipeline artifacts",
            "",
            "| File | Present |",
            "|------|---------|",
        ]
    )
    for name in (
        "graph.pkl",
        "graph.json",
        "graph_attr.json",
        "filtered_malicious.json",
        "analysis_report.json",
    ):
        lines.append(f"| `{name}` | {_artifact_check(sample_dir, name)} |")
    lines.append("")

    if ml_row:
        lines.extend(
            [
                "## ML triage (optional)",
                "",
                f"| Field | Value |",
                f"|-------|-------|",
                f"| triage_state | {ml_row.get('triage_state', '—')} |",
                f"| malware_pattern_score | {ml_row.get('malware_pattern_score', '—')} |",
                f"| benign_conformity_score | {ml_row.get('benign_conformity_score', '—')} |",
                f"| delta_score | {ml_row.get('delta_score', '—')} |",
                f"| routing_tier | {ml_row.get('routing_tier', '—')} |",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "",
            "_Generated by `scripts/generate_sample_reports.py` — re-run after pipeline refresh._",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate REPORT.md for each sample folder")
    parser.add_argument(
        "--base-dir",
        required=True,
        help="Root containing per-sample folders (e.g. extracted_csvs)",
    )
    parser.add_argument(
        "--manifest",
        default=None,
        help="dataset_manifest.csv (default: <base-dir>/dataset_manifest.csv if present)",
    )
    parser.add_argument(
        "--analysis-json",
        default=None,
        help="Optional two_model_analysis.json to attach ML triage rows",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print paths only, do not write files",
    )
    args = parser.parse_args()

    base = Path(args.base_dir).resolve()
    if not base.is_dir():
        raise SystemExit(f"[ERROR] base-dir not found: {base}")

    manifest_path = Path(args.manifest) if args.manifest else base / "dataset_manifest.csv"
    manifest = _load_manifest(manifest_path if manifest_path.is_file() else None)

    analysis_path = Path(args.analysis_json) if args.analysis_json else None
    ml_by_folder = _load_analysis_json(analysis_path)

    written = 0
    skipped = 0
    for child in sorted(base.iterdir()):
        if not child.is_dir():
            continue
        report_path = child / "analysis_report.json"
        if not report_path.is_file():
            skipped += 1
            continue
        folder = child.name
        report = json.loads(report_path.read_text(encoding="utf-8"))
        content = render_report(
            folder,
            report,
            manifest.get(folder),
            ml_by_folder.get(folder),
            child,
        )
        out_path = child / "REPORT.md"
        if args.dry_run:
            print(out_path)
        else:
            out_path.write_text(content, encoding="utf-8")
            written += 1

    print(f"[generate_sample_reports] base={base} written={written} skipped={skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
