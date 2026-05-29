#!/usr/bin/env python3
"""Generate LaTeX tables for Track 2/3 from analysis JSON (extracted_csvs corpus)."""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
TABLES_DIR = ROOT / "latex_dissertation" / "tables"
ML_MANIFEST = ROOT / "extracted_csvs" / "dataset_manifest.csv"
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
BINARY_META = _first_existing(
    ROOT / "outputs" / "binary_model_meta.json",
    EVAL_DIR / "binary_model_meta.json",
) or (ROOT / "outputs" / "binary_model_meta.json")
BINARY_META_BEFORE = _first_existing(
    ROOT / "outputs/binary_model_meta_before_phase1.json",
    EVAL_DIR / "binary_model_meta_before_phase1.json",
)
EVALUATE_JSON = _first_existing(
    ROOT / "outputs/evaluate.json",
    EVAL_DIR / "evaluate.json",
)
GATE_ABLATION = ROOT / "outputs/gate_ablation.csv"


def _tex(s: str) -> str:
    return str(s).replace("_", r"\_")


def _cell(v, fmt="{:.3f}"):
    if v is None or (isinstance(v, float) and np.isnan(v)):
        return "--"
    try:
        return fmt.format(float(v))
    except (TypeError, ValueError):
        return str(v)


def _pred_from_binary_state(state: str) -> int | None:
    if state == "likely_malicious":
        return 1
    if state == "likely_benign":
        return 0
    return None


def _pred_from_two_state(state: str) -> int | None:
    if state == "likely_malicious":
        return 1
    if state == "likely_benign":
        return 0
    return None


def _metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_score,
        recall_score,
    )

    return {
        "n": len(y_true),
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "cm": confusion_matrix(y_true, y_pred, labels=[0, 1]),
    }


def load_ml_manifest() -> pd.DataFrame:
    df = pd.read_csv(ML_MANIFEST)
    df["uncertain"] = df["uncertain"].astype(str).str.lower().eq("true")
    return df


def samples_to_df(path: Path, kind: str) -> pd.DataFrame:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for s in data.get("samples", []):
        row = {"folder": s["folder"], "triage_state": s["triage_state"]}
        if kind == "binary":
            row["prob_malware"] = s.get("malware_probability_calibrated")
        else:
            row["malware_score"] = s.get("malware_pattern_score")
            row["benign_score"] = s.get("benign_conformity_score")
            row["delta"] = s.get("delta_score")
        rows.append(row)
    return pd.DataFrame(rows)


def merge_manifest(df: pd.DataFrame, manifest: pd.DataFrame) -> pd.DataFrame:
    m = manifest[["folder", "label", "uncertain", "family", "verdict"]].copy()
    return df.merge(m, on="folder", how="inner")


def agreement_table(
    merged: pd.DataFrame, pred_col: str, caption: str, label: str
) -> list[str]:
    sub = merged[merged[pred_col].notna()].copy()
    if sub.empty:
        return [
            "\\begin{table}[htbp]",
            "\\centering",
            f"\\caption{{{caption} (no decisive predictions).}}",
            f"\\label{{{label}}}",
            "\\begin{tabular}{l}",
            "No decisive states in this run. \\\\",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]

    y_true = sub["label"].astype(int).values
    y_pred = sub[pred_col].astype(int).values
    m = _metrics(y_true, y_pred)
    cm = m["cm"]
    return [
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        "\\begin{tabular}{lcccc}",
        "\\toprule",
        "\\textbf{Metric} & \\textbf{Precision} & \\textbf{Recall} & "
        "\\textbf{F1} & \\textbf{Accuracy} \\\\",
        "\\midrule",
        f"Decisive predictions ($n$={m['n']}) & "
        f"{_cell(m['precision'])} & {_cell(m['recall'])} & "
        f"{_cell(m['f1'])} & {_cell(m['accuracy'])} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
        f"% Confusion [{label}]: TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}",
        "",
    ]


def _meta_table(meta: dict, caption: str, label: str) -> list[str]:
    rows = [
        ("Best validation F1", _cell(meta.get("best_val_f1"))),
        ("Validation AUROC", _cell(meta.get("val_auroc"))),
        ("Validation PR-AUC", _cell(meta.get("val_pr_auc"))),
        ("Val Brier (calibrated)", _cell(meta.get("val_brier_cal"))),
        ("Val ECE (calibrated)", _cell(meta.get("val_ece_cal"))),
        ("Temperature", _cell(meta.get("temperature"), "{:.2f}")),
        ("Threshold high", _cell(meta.get("threshold_high"))),
        ("Threshold low", _cell(meta.get("threshold_low"))),
        ("Strict train filter", str(meta.get("strict_train_filter", "--"))),
        ("Train / val size", f"{meta.get('n_train', '--')} / {meta.get('n_val', '--')}"),
    ]
    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{caption}}}",
        f"\\label{{{label}}}",
        "\\begin{tabular}{lc}",
        "\\toprule",
        "\\textbf{Metric} & \\textbf{Value} \\\\",
        "\\midrule",
    ]
    for k, v in rows:
        k_tex = k.replace("_", "\\_")
        lines.append(f"{k_tex} & {v} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]
    return lines


def _before_after_table(before: dict, after: dict) -> list[str]:
    return [
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Binary training metadata: earlier exploratory split vs current strict split.}",
        "\\label{tab:binary_meta_evolution}",
        "\\begin{tabular}{lcc}",
        "\\toprule",
        "\\textbf{Metric} & \\textbf{Earlier phase} & \\textbf{Current} \\\\",
        "\\midrule",
        f"Validation F1 & {_cell(before.get('best_val_f1'))} & {_cell(after.get('best_val_f1'))} \\\\",
        f"Validation AUROC & {_cell(before.get('val_auroc'))} & {_cell(after.get('val_auroc'))} \\\\",
        f"Temperature & {_cell(before.get('temperature'), '{:.2f}')} & "
        f"{_cell(after.get('temperature'), '{:.2f}')} \\\\",
        f"Train size & {before.get('n_train', '--')} & {after.get('n_train', '--')} \\\\",
        f"Val size & {before.get('n_val', '--')} & {after.get('n_val', '--')} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]


def _triage_counts_table(counts: dict, caption: str, label: str, n: int) -> list[str]:
    lines = [
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{caption} ($n={n}$).}}",
        f"\\label{{{label}}}",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "\\textbf{Triage state} & \\textbf{Count} \\\\",
        "\\midrule",
    ]
    for state, cnt in sorted(counts.items(), key=lambda x: -x[1]):
        state_tex = state.replace("_", r"\_")
        lines.append(f"{state_tex} & {cnt} \\\\")
    lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]
    return lines


def _compute_binary_strict_metrics(binary_df: pd.DataFrame) -> dict | None:
    sub = binary_df[binary_df["pred_decisive"].notna()].copy()
    if sub.empty:
        return None
    y_true = sub["label"].astype(int).values
    y_pred = sub["pred_decisive"].astype(int).values
    m = _metrics(y_true, y_pred)
    tn, fp, fn, tp = m["cm"].ravel()
    return {
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
        **{k: m[k] for k in ("precision", "recall", "accuracy")},
        "n_decisive": m["n"],
        "n_total": len(binary_df),
        "review_rate": 1.0 - m["n"] / len(binary_df),
    }


def write_analysis_tables() -> None:
    if not BINARY_JSON.exists():
        print(f"Missing {BINARY_JSON}")
        return

    manifest = load_ml_manifest()
    binary_raw = samples_to_df(BINARY_JSON, "binary")
    binary_df = merge_manifest(binary_raw, manifest)
    binary_df["pred_decisive"] = binary_df["triage_state"].map(_pred_from_binary_state)
    bin_summary = json.loads(BINARY_JSON.read_text(encoding="utf-8")).get("summary", {})
    binary_counts = binary_df["triage_state"].value_counts().to_dict()

    two_df = None
    two_summary: dict = {}
    two_counts: dict = {}
    review_on_uncertain = 0
    if TWO_JSON.exists():
        two_df = merge_manifest(samples_to_df(TWO_JSON, "two"), manifest)
        two_df["pred_decisive"] = two_df["triage_state"].map(_pred_from_two_state)
        two_counts = two_df["triage_state"].value_counts().to_dict()
        two_summary = json.loads(TWO_JSON.read_text(encoding="utf-8")).get("summary", {})
        review_on_uncertain = int(
            (
                (two_df["label"] == 0)
                & two_df["uncertain"]
                & (two_df["triage_state"] == "needs_analyst_review")
            ).sum()
        )

    uncertain_benign = manifest[(manifest["label"] == 0)]
    n_uncertain = int(uncertain_benign["uncertain"].sum())

    lines = [
        "% Auto-generated by scripts/generate_analysis_latex.py",
        f"% Corpus: {ML_MANIFEST.name} ($n={len(manifest)}$)",
        f"% Binary JSON: {BINARY_JSON.name}",
        "",
        "\\providecommand{\\analysistablesize}{\\footnotesize\\setlength{\\tabcolsep}{4pt}"
        "\\renewcommand{\\arraystretch}{1.15}}",
        "",
        "\\subsection{Evaluation corpus (Tracks 2 and 3)}",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\analysistablesize",
        "\\caption{Primary ML evaluation manifest (\\texttt{extracted\\_csvs}).}",
        "\\label{tab:ml_corpus}",
        "\\begin{tabular}{ll}",
        "\\toprule",
        "\\textbf{Field} & \\textbf{Value} \\\\",
        "\\midrule",
        "Manifest & \\texttt{extracted\\_csvs/dataset\\_manifest.csv} \\\\",
        f"Samples & {len(manifest)} \\\\",
        f"Benign-labelled & {int((manifest['label']==0).sum())} \\\\",
        f"Malware-labelled & {int((manifest['label']==1).sum())} \\\\",
        f"Uncertain benign & {n_uncertain} \\\\",
        "Binary schema & "
        + str(bin_summary.get("schema_version", "--")).replace("_", "\\_")
        + " \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\subsection{Track 2: binary GNN (\\texttt{analyze\\_binary\\_model.py})}",
    ]
    lines += _triage_counts_table(
        binary_counts,
        "Binary triage state counts",
        "tab:binary_triage_counts",
        len(binary_df),
    )
    lines += agreement_table(
        binary_df,
        "pred_decisive",
        "Binary model vs manifest labels (decisive states only)",
        "tab:binary_label_agreement",
    )

    strict = _compute_binary_strict_metrics(binary_df)
    if strict:
        lines += [
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Binary decisive-prediction breakdown (manifest labels).}",
            "\\label{tab:binary_strict}",
            "\\begin{tabular}{lc}",
            "\\toprule",
            "\\textbf{Metric} & \\textbf{Value} \\\\",
            "\\midrule",
            f"Decisive coverage & {_cell(strict['n_decisive'] / strict['n_total'])} \\\\",
            f"Precision & {_cell(strict['precision'])} \\\\",
            f"Recall & {_cell(strict['recall'])} \\\\",
            f"Accuracy (decisive) & {_cell(strict['accuracy'])} \\\\",
            f"TP / FP / TN / FN & {strict['tp']} / {strict['fp']} / {strict['tn']} / {strict['fn']} \\\\",
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]

    if BINARY_META.exists():
        meta = json.loads(BINARY_META.read_text(encoding="utf-8"))
        lines += _meta_table(
            meta,
            "Current binary training metadata (\\texttt{binary\\_model\\_meta.json})",
            "tab:binary_train_meta",
        )
    if BINARY_META_BEFORE and BINARY_META.exists():
        before = json.loads(BINARY_META_BEFORE.read_text(encoding="utf-8"))
        after = json.loads(BINARY_META.read_text(encoding="utf-8"))
        lines += _before_after_table(before, after)

    if two_df is not None:
        tc = two_summary.get("triage_counts") or two_counts
        lines += ["\\subsection{Track 3: two-model fusion (\\texttt{analyze\\_two\\_model.py})}"]
        lines += _triage_counts_table(
            tc,
            "Two-model triage state counts",
            "tab:two_triage_counts",
            len(two_df),
        )
        lines += [
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Two-model routing and abstention summary.}",
            "\\label{tab:two_routing}",
            "\\begin{tabular}{lc}",
            "\\toprule",
            "\\textbf{Metric} & \\textbf{Value} \\\\",
            "\\midrule",
            f"Abstention mode & {_tex(two_summary.get('abstention_mode', '--'))} \\\\",
            f"Review routing rate & {_cell(two_summary.get('review_routing_rate'))} \\\\",
            f"Decisive coverage & {_cell(two_summary.get('decisive_coverage'))} \\\\",
            f"Uncertainty gated & {two_summary.get('uncertainty_gated', '--')} \\\\",
            f"Uncertain benign $\\rightarrow$ review & {review_on_uncertain} / {n_uncertain} \\\\",
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]
        lines += agreement_table(
            two_df,
            "pred_decisive",
            "Two-model vs manifest labels (likely malicious/benign only)",
            "tab:two_label_agreement",
        )

    if GATE_ABLATION.exists():
        abl = pd.read_csv(GATE_ABLATION)
        lines += [
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Abstention gate presets (\\texttt{evaluate.py --gate-ablation}).}",
            "\\label{tab:gate_ablation}",
            "\\begin{tabular}{lrrr}",
            "\\toprule",
            "\\textbf{Preset} & \\textbf{Review rate} & "
            "\\textbf{Decisive cov.} & \\textbf{Gated} \\\\",
            "\\midrule",
        ]
        for _, row in abl.iterrows():
            lines.append(
                f"{_tex(row.get('preset', '--'))} & "
                f"{_cell(row.get('review_routing_rate'))} & "
                f"{_cell(row.get('decisive_coverage'))} & "
                f"{row.get('uncertainty_gated', '--')} \\\\"
            )
        lines += ["\\bottomrule", "\\end{tabular}", "\\end{table}", ""]

    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    out = TABLES_DIR / "analysis_results.tex"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out}")

    import importlib.util

    export_path = ROOT / "scripts" / "export_dissertation_figure_data.py"
    spec = importlib.util.spec_from_file_location("export_fig_data", export_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    mod.export_analysis_figures(manifest)
    print("Refreshed Track 2/3 figure data")


def main() -> None:
    write_analysis_tables()


if __name__ == "__main__":
    main()
