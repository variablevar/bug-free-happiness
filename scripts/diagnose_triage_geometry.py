#!/usr/bin/env python3
"""Reproducible triage geometry report from two_model_analysis.json."""

from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path


def _percentiles(vals: list[float], ps: tuple[float, ...] = (0.0, 0.5, 1.0)) -> dict[str, float]:
    if not vals:
        return {f"p{int(p * 100)}": 0.0 for p in ps}
    s = sorted(float(v) for v in vals)
    n = len(s)
    out = {}
    for p in ps:
        if n == 1:
            out[f"p{int(p * 100)}"] = s[0]
            continue
        idx = min(n - 1, max(0, int(round(p * (n - 1)))))
        out[f"p{int(p * 100)}"] = round(s[idx], 6)
    return out


def _gate_reason_counts(samples: list[dict]) -> dict[str, int]:
    c: Counter[str] = Counter()
    for s in samples:
        reason = s.get("abstention_reason") or ""
        for part in reason.split("|"):
            if part:
                c[part] += 1
    return dict(c.most_common())


def _process_fp_hints(samples: list[dict], top_k: int = 15) -> list[dict]:
    counts: Counter[str] = Counter()
    for s in samples:
        if s.get("triage_state") not in {"likely_malicious", "needs_analyst_review"}:
            continue
        label = s.get("label_from_manifest")
        if label not in (0, "0"):
            continue
        for ev in (s.get("malware_model_evidence") or {}).get("top_nodes", [])[:5]:
            name = str(ev.get("name") or ev.get("label") or "").strip().lower()
            if name:
                counts[name] += 1
    return [{"process": k, "count": v} for k, v in counts.most_common(top_k)]


def build_report(data: dict) -> dict:
    samples = data.get("samples") or []
    summary = data.get("summary") or {}

    p_mal = [
        float(s.get("fusion", {}).get("binary_malware_probability_calibrated", 0))
        for s in samples
    ]
    margins = [
        abs(float(s.get("malware_pattern_score", 0)) - float(s.get("benign_conformity_score", 0)))
        for s in samples
    ]
    gaps = [float(s.get("fusion", {}).get("binary_dual_gap", 0)) for s in samples]

    by_subtype: dict[str, dict] = defaultdict(lambda: {"n": 0})
    for s in samples:
        st = str(s.get("benign_subtype") or s.get("label_quality_reason") or "unknown")
        by_subtype[st]["n"] += 1
        by_subtype[st].setdefault("p_mal", []).append(
            float(s.get("fusion", {}).get("binary_malware_probability_calibrated", 0))
        )
        by_subtype[st].setdefault("dual_margin", []).append(
            abs(float(s.get("malware_pattern_score", 0)) - float(s.get("benign_conformity_score", 0)))
        )

    subtype_summary = {}
    for st, block in by_subtype.items():
        subtype_summary[st] = {
            "n": block["n"],
            "p_mal": _percentiles(block.get("p_mal", [])),
            "dual_margin": _percentiles(block.get("dual_margin", [])),
        }

    states = [s.get("triage_state", "") for s in samples]
    state_counts = dict(Counter(states))

    return {
        "source": "two_model_analysis",
        "schema_version": summary.get("schema_version"),
        "samples": len(samples),
        "review_routing_rate": summary.get("review_routing_rate"),
        "decisive_coverage": summary.get("decisive_coverage"),
        "uncertainty_gated": summary.get("uncertainty_gated"),
        "gate_reason_counts": _gate_reason_counts(samples),
        "binary_p_malware": _percentiles(p_mal, (0.0, 0.25, 0.5, 0.75, 1.0)),
        "dual_margin": _percentiles(margins, (0.0, 0.5, 1.0)),
        "binary_dual_gap": _percentiles(gaps, (0.0, 0.5, 1.0)),
        "triage_state_counts": state_counts,
        "by_benign_subtype": subtype_summary,
        "benign_label_fp_process_hints": _process_fp_hints(samples),
        "thresholds_from_summary": {
            k: summary.get(k)
            for k in (
                "uncertainty_disagreement_threshold",
                "uncertainty_dual_margin_threshold",
                "uncertainty_mc_variance_threshold",
                "abstention_mode",
            )
            if k in summary
        },
    }


def main() -> None:
    p = argparse.ArgumentParser(description="Diagnose triage score geometry from analysis JSON")
    p.add_argument(
        "input_json",
        nargs="?",
        default="outputs/two_model_analysis.json",
        help="Path to two_model_analysis.json",
    )
    p.add_argument(
        "--output",
        default="outputs/triage_geometry_report.json",
        help="Output report path",
    )
    args = p.parse_args()
    inp = Path(args.input_json)
    if not inp.exists():
        raise SystemExit(f"[ERROR] Input not found: {inp}")
    data = json.loads(inp.read_text(encoding="utf-8"))
    report = build_report(data)
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[diagnose_triage_geometry] wrote {out} ({report['samples']} samples)")


if __name__ == "__main__":
    main()
