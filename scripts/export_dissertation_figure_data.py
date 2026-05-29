#!/usr/bin/env python3
"""Export figure data for LaTeX/TikZ (no matplotlib PDF generation)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "extracted_data" / "dataset_manifest.csv"
DATA_DIR = ROOT / "latex_dissertation" / "figures" / "data"
EXTRACTED = ROOT / "extracted_data"
EVAL_DIR = ROOT / "latex_dissertation" / "eval"


def _first_existing(*paths: Path) -> Path | None:
    for p in paths:
        if p.exists():
            return p
    return None


BINARY_JSON = _first_existing(
    EVAL_DIR / "binary_analysis.json",
    ROOT / "outputs" / "binary_analysis.json",
) or (ROOT / "outputs" / "binary_analysis.json")
TWO_JSON = _first_existing(
    EVAL_DIR / "two_model_analysis.json",
    ROOT / "outputs" / "two_model_analysis.json",
) or (ROOT / "outputs" / "two_model_analysis.json")


def load_manifest() -> pd.DataFrame:
    df = pd.read_csv(MANIFEST)
    df["uncertain"] = df["uncertain"].astype(str).str.lower().eq("true")
    return df


def write_dat(path: Path, header: str, rows: list[tuple]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [header]
    for row in rows:
        lines.append(" ".join(str(x) for x in row))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, df: pd.DataFrame) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


def write_values_tex(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "\n".join(["% auto-generated — do not edit by hand"] + lines) + "\n"
    path.write_text(body, encoding="utf-8")


def _tex_escape(label: str) -> str:
    return (
        label.replace("\\", r"\textbackslash{}")
        .replace("_", r"\_")
        .replace("&", r"\&")
        .replace("%", r"\%")
    )


def _fmt_int(n: int) -> str:
    return f"{n:,}".replace(",", "{,}")


def export_corpus_summary_tex(stats: dict) -> None:
    table_dir = ROOT / "latex_dissertation" / "tables"
    table_dir.mkdir(parents=True, exist_ok=True)
    uncertain_benign = int(stats["n_uncertain_benign"])
    body = f"""% auto-generated — do not edit by hand
\\begin{{tabular}}{{lrrrr}}
\\toprule
\\textbf{{Statistic}} & \\textbf{{Min}} & \\textbf{{Median}} & \\textbf{{Max}} & \\textbf{{Notes}} \\\\
\\midrule
Nodes (all) & {stats['nodes_min']} & {_fmt_int(int(round(stats['nodes_median'])))} & {_fmt_int(stats['nodes_max'])} & MyDoom pair smallest \\\\
Edges (all) & {stats['edges_min']} & {_fmt_int(int(round(stats['edges_median'])))} & {_fmt_int(stats['edges_max'])} & \\\\
Malware-labelled & {stats['n_malware']} & --- & --- & No uncertain flags \\\\
Benign-labelled & {stats['n_benign']} & --- & --- & {uncertain_benign} uncertain \\\\
\\bottomrule
\\end{{tabular}}
"""
    (table_dir / "corpus_summary.tex").write_text(body, encoding="utf-8")


def _box_stats(vals: list[float]) -> tuple[float, float, float, float, float]:
    arr = np.asarray(vals, dtype=float)
    q1, med, q3 = np.percentile(arr, [25, 50, 75])
    return float(arr.min()), float(q1), float(med), float(q3), float(arr.max())


def _bar_rows_macro(rows: list[tuple[str, int]]) -> str:
    parts = []
    for label, count in rows:
        safe = _tex_escape(label).replace(" ", "~")
        parts.append(f"{{{safe}}}/{int(count)}")  # group label/count for \foreach \a/\b
    return "\\def\\BarRows{" + ", ".join(parts) + "}"


def _display_label(label: str) -> str:
    return (
        label.replace("_", " ")
        .replace(".az", ".AZ")
        .title()
        .replace("W32.Mydoom.A.", "W32.MyDoom.A.")
        .replace("Dllhijacking", "DLL hijacking")
    )


def _points_macro(name: str, values: list[float]) -> str:
    pts = ", ".join(f"{float(max(v, 1)):.1f}" for v in sorted(values))
    return f"\\def\\{name}{{{pts}}}"


def _ycoords_macro(name: str, values: list[float], log_min: float, log_max: float, plot_h: float = 5.6) -> str:
    span = max(log_max - log_min, 1e-9)
    ys = [
        round((float(np.log10(max(v, 1.0))) - log_min) / span * plot_h, 3)
        for v in sorted(values)
    ]
    return f"\\def\\{name}{{{', '.join(str(y) for y in ys)}}}"


def export_tikz_values(df: pd.DataFrame) -> None:
    benign_n = int((df["label"] == 0).sum())
    malware_n = int((df["label"] == 1).sum())
    benign = df[df["label"] == 0]
    uncertain_n = int(benign["uncertain"].sum())
    certain_n = len(benign) - uncertain_n

    write_values_tex(
        DATA_DIR / "values_uncertainty.tex",
        [
            f"\\def\\UncertainN{{{uncertain_n}}}",
            f"\\def\\CertainN{{{certain_n}}}",
        ],
    )
    write_values_tex(
        DATA_DIR / "values_label_balance.tex",
        [
            f"\\def\\BenignN{{{benign_n}}}",
            f"\\def\\MalwareN{{{malware_n}}}",
            f"\\def\\UncertainN{{{uncertain_n}}}",
            f"\\def\\CertainN{{{certain_n}}}",
        ],
    )

    metrics = ["injections", "c2_conns", "max_score"]
    metric_labels = ["Injections", "C2 connections", "Max score"]
    b_means = [float(df[df["label"] == 0][m].mean()) for m in metrics]
    m_means = [float(df[df["label"] == 1][m].mean()) for m in metrics]
    ymax = max(b_means + m_means) * 1.15
    suffixes = ("One", "Two", "Three")
    write_values_tex(
        DATA_DIR / "values_forensic.tex",
        [
            f"\\def\\ForensicYmax{{{ymax:.2f}}}",
            *[
                f"\\def\\BenignMean{s}{{{v:.3f}}}"
                for s, v in zip(suffixes, b_means)
            ],
            *[
                f"\\def\\MalwareMean{s}{{{v:.3f}}}"
                for s, v in zip(suffixes, m_means)
            ],
        ],
    )

    verdicts = df["verdict"].str.extract(r"^(\w+)")[0].fillna("OTHER")
    vc = verdicts.value_counts()
    write_values_tex(
        DATA_DIR / "values_verdict.tex",
        [_bar_rows_macro([(v, int(c)) for v, c in vc.items()])],
    )

    fam = df.groupby("family").size().sort_values()
    fam_names = [_display_label(str(f)) for f in fam.index]
    grid_lines: list[str] = []
    for i in range(0, len(fam_names), 3):
        row = fam_names[i : i + 3]
        while len(row) < 3:
            row.append("")
        grid_lines.append(" & ".join(row) + r" \\")
    (DATA_DIR / "family_grid.tex").write_text("\n".join(grid_lines) + "\n", encoding="utf-8")
    write_values_tex(
        DATA_DIR / "values_family.tex",
        [
            f"\\def\\FamilyCount{{{int(fam.iloc[0]) if len(fam) else 2}}}",
            f"\\def\\FamilyN{{{len(fam_names)}}}",
        ],
    )

    all_counts = pd.concat(
        [df["nodes"].astype(float), df["edges"].astype(float)], ignore_index=True
    )
    log_min = float(np.log10(max(all_counts.min(), 1)))
    log_max = float(np.log10(all_counts.max()))
    plot_h = 5.6
    grid_parts: list[str] = []
    for tick, lbl in ((100, "100"), (1000, "1k"), (10000, "10k")):
        if tick >= all_counts.min() and tick <= all_counts.max():
            y = (float(np.log10(tick)) - log_min) / max(log_max - log_min, 1e-9) * plot_h
            grid_parts.append(f"{y:.3f}/{lbl}")
    graph_lines: list[str] = [
        f"\\def\\GraphCountMin{{{int(all_counts.min())}}}",
        f"\\def\\GraphCountMax{{{int(all_counts.max())}}}",
        f"\\def\\GraphLogMin{{{log_min:.6f}}}",
        f"\\def\\GraphLogMax{{{log_max:.6f}}}",
        f"\\def\\GraphPlotH{{{plot_h}}}",
        "\\def\\GraphGrid{" + ", ".join(grid_parts) + "}",
    ]
    for col, prefix in (("nodes", "Nodes"), ("edges", "Edges")):
        for label, name in ((0, "Benign"), (1, "Malware")):
            vals = df.loc[df["label"] == label, col].astype(float).tolist()
            lo, q1, med, q3, hi = _box_stats(vals)
            graph_lines.append(_ycoords_macro(f"{prefix}{name}Y", vals, log_min, log_max))
            for suffix, val in (
                ("Min", lo),
                ("LoQ", q1),
                ("Med", med),
                ("HiQ", q3),
                ("Max", hi),
            ):
                graph_lines.append(f"\\def\\{prefix}{name}{suffix}{{{int(round(val))}}}")
    write_values_tex(DATA_DIR / "values_graph_scale.tex", graph_lines)

    report_path = EXTRACTED / "WannaCry-WithVirus" / "analysis_report.json"
    if report_path.exists():
        data = json.loads(report_path.read_text(encoding="utf-8"))
        node_types = data.get("summary", {}).get("node_types", {})
        if node_types:
            total = sum(node_types.values())
            rows = [
                (k, round(100.0 * v / total, 1))
                for k, v in sorted(node_types.items(), key=lambda x: -x[1])
            ]
            write_values_tex(
                DATA_DIR / "values_wannacry.tex",
                [_bar_rows_macro(rows)],
            )


def export_manifest_figures(df: pd.DataFrame) -> None:
    # dataset_stats.json (tables + prose)
    stats = {
        "n_samples": int(len(df)),
        "n_malware": int((df["label"] == 1).sum()),
        "n_benign": int((df["label"] == 0).sum()),
        "n_uncertain_benign": int(df[df["label"] == 0]["uncertain"].sum()),
        "nodes_min": int(df["nodes"].min()),
        "nodes_max": int(df["nodes"].max()),
        "nodes_median": float(df["nodes"].median()),
        "edges_min": int(df["edges"].min()),
        "edges_max": int(df["edges"].max()),
        "edges_median": float(df["edges"].median()),
    }
    (DATA_DIR.parent / "dataset_stats.json").write_text(
        json.dumps(stats, indent=2), encoding="utf-8"
    )

    export_corpus_summary_tex(stats)

    # fig_dataset_overview
    write_dat(
        DATA_DIR / "label_balance.dat",
        "label count",
        [("Benign", int((df["label"] == 0).sum())), ("Malware", int((df["label"] == 1).sum()))],
    )
    benign = df[df["label"] == 0]
    u = int(benign["uncertain"].sum())
    write_dat(
        DATA_DIR / "uncertain_benign.dat",
        "category count",
        [("Uncertain", u), ("NotUncertain", len(benign) - u)],
    )

    # fig_graph_scale — per-sample points for pgfplots boxplot
    for col in ("nodes", "edges"):
        for label, name in ((0, "benign"), (1, "malware")):
            vals = df.loc[df["label"] == label, col].astype(float).tolist()
            write_dat(
                DATA_DIR / f"{col}_{name}.dat",
                "value",
                [(v,) for v in vals],
            )

    # fig_forensic_signals
    metrics = ["injections", "c2_conns", "max_score"]
    rows = []
    for m in metrics:
        rows.append(
            (
                m,
                float(df[df["label"] == 0][m].mean()),
                float(df[df["label"] == 1][m].mean()),
            )
        )
    write_dat(DATA_DIR / "forensic_signals.dat", "metric benign_mean malware_mean", rows)

    # fig_family_coverage
    fam = df.groupby("family").size().sort_values()
    write_dat(
        DATA_DIR / "family_coverage.dat",
        "family count",
        [(f, int(c)) for f, c in fam.items()],
    )

    # fig_verdict_distribution
    verdicts = df["verdict"].str.extract(r"^(\w+)")[0].fillna("OTHER")
    vc = verdicts.value_counts()
    write_dat(
        DATA_DIR / "verdict_distribution.dat",
        "verdict count",
        [(v, int(c)) for v, c in vc.items()],
    )

    # fig_wannacry_node_types
    report_path = EXTRACTED / "WannaCry-WithVirus" / "analysis_report.json"
    if report_path.exists():
        data = json.loads(report_path.read_text(encoding="utf-8"))
        node_types = data.get("summary", {}).get("node_types", {})
        if node_types:
            total = sum(node_types.values())
            rows = [
                (k.replace("_", r"\_"), int(v), round(100.0 * v / total, 1))
                for k, v in sorted(node_types.items(), key=lambda x: -x[1])
            ]
            write_dat(DATA_DIR / "wannacry_node_types.dat", "type count percent", rows)


def _export_confusion_values(cm: np.ndarray, path: Path) -> None:
    write_values_tex(
        path,
        [
            f"\\def\\CmTN{{{int(cm[0, 0])}}}",
            f"\\def\\CmFP{{{int(cm[0, 1])}}}",
            f"\\def\\CmFN{{{int(cm[1, 0])}}}",
            f"\\def\\CmTP{{{int(cm[1, 1])}}}",
        ],
    )


def _pred_binary(state: str) -> int | None:
    if state == "likely_malicious":
        return 1
    if state == "likely_benign":
        return 0
    return None


def _pred_two(state: str) -> int | None:
    if state == "likely_malicious":
        return 1
    if state == "likely_benign":
        return 0
    return None


def _triage_metrics(
    frame: pd.DataFrame,
    *,
    abstention_states: set[str],
    review_states: set[str],
) -> dict:
    total = int(len(frame))
    if total == 0:
        return {
            "samples": 0,
            "decisive_coverage": 0.0,
            "abstention_coverage": 0.0,
            "review_routing_rate": 0.0,
        }
    decisive = int(frame["triage_state"].isin({"likely_malicious", "likely_benign"}).sum())
    abstain = int(frame["triage_state"].isin(abstention_states).sum())
    review = int(frame["triage_state"].isin(review_states).sum())
    return {
        "samples": total,
        "decisive_coverage": round(decisive / total, 6),
        "abstention_coverage": round(abstain / total, 6),
        "review_routing_rate": round(review / total, 6),
    }


def export_analysis_figures(df: pd.DataFrame) -> None:
    if not BINARY_JSON.exists():
        print(f"Skip analysis export: missing {BINARY_JSON}")
        return

    bdf = pd.DataFrame(
        [
            {
                "folder": s["folder"],
                "triage_state": s["triage_state"],
                "prob": s.get("malware_probability_calibrated"),
            }
            for s in json.loads(BINARY_JSON.read_text(encoding="utf-8")).get("samples", [])
        ]
    )
    bdf = bdf.merge(df[["folder", "label", "uncertain"]], on="folder", how="inner")
    bdf["pred"] = bdf["triage_state"].map(_pred_binary)
    analysis_metrics: dict[str, dict] = {
        "binary_model": _triage_metrics(
            bdf,
            abstention_states={"high_risk_ambiguous", "low_risk_ambiguous"},
            review_states=set(),
        )
    }
    uncertain_benign = bdf[(bdf["label"] == 0) & (bdf["uncertain"])]
    analysis_metrics["binary_model"]["uncertain_benign_abstention_rate"] = round(
        float(uncertain_benign["triage_state"].isin({"high_risk_ambiguous", "low_risk_ambiguous"}).mean())
        if not uncertain_benign.empty
        else 0.0,
        6,
    )

    vc = bdf["triage_state"].value_counts()
    triage_labels = {
        "likely_malicious": "Likely malicious",
        "likely_benign": "Likely benign",
        "high_risk_ambiguous": "High-risk ambiguous",
        "low_risk_ambiguous": "Low-risk ambiguous",
        "needs_analyst_review": "Needs analyst review",
        "anomalous_unknown": "Anomalous / unknown",
    }
    write_csv(
        DATA_DIR / "binary_triage.csv",
        pd.DataFrame(
            [{"state": s.replace("_", r"\_"), "count": int(c)} for s, c in vc.items()]
        ),
    )

    sub = bdf[bdf["pred"].notna()]
    if not sub.empty:
        cm = _confusion_matrix(
            sub["label"].astype(int).values, sub["pred"].astype(int).values
        )
        write_dat(
            DATA_DIR / "binary_confusion.dat",
            "true pred count",
            [
                (0, 0, int(cm[0, 0])),
                (0, 1, int(cm[0, 1])),
                (1, 0, int(cm[1, 0])),
                (1, 1, int(cm[1, 1])),
            ],
        )
        _export_confusion_values(cm, DATA_DIR / "values_binary_confusion.tex")
        write_values_tex(
            DATA_DIR / "values_binary_triage.tex",
            [
                f"\\def\\BinaryTotal{{{len(bdf)}}}",
                _bar_rows_macro(
                    [
                        (triage_labels.get(s, _display_label(s)), int(c))
                        for s, c in vc.items()
                    ]
                ),
            ],
        )

    if TWO_JSON.exists():
        tdf = pd.DataFrame(
            [
                {
                    "folder": s["folder"],
                    "triage_state": s["triage_state"],
                }
                for s in json.loads(TWO_JSON.read_text(encoding="utf-8")).get("samples", [])
            ]
        )
        tdf = tdf.merge(df[["folder", "label", "uncertain"]], on="folder", how="inner")
        tdf["pred"] = tdf["triage_state"].map(_pred_two)
        analysis_metrics["two_model"] = _triage_metrics(
            tdf,
            abstention_states={"needs_analyst_review", "anomalous_unknown"},
            review_states={"needs_analyst_review"},
        )
        uncertain_benign_two = tdf[(tdf["label"] == 0) & (tdf["uncertain"])]
        analysis_metrics["two_model"]["uncertain_benign_review_rate"] = round(
            float((uncertain_benign_two["triage_state"] == "needs_analyst_review").mean())
            if not uncertain_benign_two.empty
            else 0.0,
            6,
        )
        vc2 = tdf["triage_state"].value_counts()
        write_csv(
            DATA_DIR / "two_model_triage.csv",
            pd.DataFrame(
                [{"state": s.replace("_", r"\_"), "count": int(c)} for s, c in vc2.items()]
            ),
        )
        sub2 = tdf[tdf["pred"].notna()]
        if not sub2.empty:
            cm2 = _confusion_matrix(
                sub2["label"].astype(int).values, sub2["pred"].astype(int).values
            )
            write_dat(
                DATA_DIR / "two_model_confusion.dat",
                "true pred count",
                [
                    (0, 0, int(cm2[0, 0])),
                    (0, 1, int(cm2[0, 1])),
                    (1, 0, int(cm2[1, 0])),
                    (1, 1, int(cm2[1, 1])),
                ],
            )
            _export_confusion_values(cm2, DATA_DIR / "values_two_model_confusion.tex")
            write_values_tex(
                DATA_DIR / "values_two_model_triage.tex",
                [_bar_rows_macro([(s, int(c)) for s, c in vc2.items()])],
            )
    (DATA_DIR / "analysis_metrics.json").write_text(
        json.dumps(analysis_metrics, indent=2),
        encoding="utf-8",
    )
    coverage_rows = []
    for model_name, metrics in analysis_metrics.items():
        for metric_name, value in metrics.items():
            coverage_rows.append(
                {
                    "model": model_name,
                    "metric": metric_name,
                    "value": value,
                }
            )
    write_csv(DATA_DIR / "triage_coverage.csv", pd.DataFrame(coverage_rows))


def _confusion_matrix(y_true: np.ndarray, y_pred: np.ndarray) -> np.ndarray:
    from sklearn.metrics import confusion_matrix

    return confusion_matrix(y_true, y_pred, labels=[0, 1])


def _export_ablation_tables() -> None:
    gate_path = ROOT / "outputs" / "gate_ablation.csv"
    if gate_path.exists():
        df_gate = pd.read_csv(gate_path)
        write_csv(DATA_DIR / "gate_ablation.csv", df_gate)
    geom_path = ROOT / "outputs" / "triage_geometry_report.json"
    if geom_path.exists():
        (DATA_DIR / "triage_geometry_report.json").write_text(
            geom_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )


def main() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    df = load_manifest()
    export_manifest_figures(df)
    export_tikz_values(df)
    export_analysis_figures(df)
    _export_ablation_tables()
    manifest = {
        "source_manifest": str(MANIFEST),
        "n_rows": len(df),
        "data_dir": str(DATA_DIR.relative_to(ROOT)),
    }
    (DATA_DIR / "export_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(f"Exported LaTeX figure data to {DATA_DIR}")


if __name__ == "__main__":
    main()
