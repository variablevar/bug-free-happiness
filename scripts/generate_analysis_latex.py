#!/usr/bin/env python3
"""Generate LaTeX tables and figures from binary/two-model analysis JSON."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FIG_DIR = ROOT / "latex_dissertation" / "figures"
TABLES_DIR = ROOT / "latex_dissertation" / "tables"
MANIFEST = ROOT / "extracted_data" / "dataset_manifest.csv"
BINARY_JSON = ROOT / "outputs" / "binary_analysis.json"
TWO_JSON = ROOT / "outputs" / "two_model_analysis.json"
BINARY_META = ROOT / "outputs" / "binary_model_meta.json"


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
    return None  # ambiguous


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


def load_manifest() -> pd.DataFrame:
    df = pd.read_csv(MANIFEST)
    df["uncertain"] = df["uncertain"].astype(str).str.lower().eq("true")
    return df


def samples_to_df(path: Path, kind: str) -> pd.DataFrame:
    data = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for s in data.get("samples", []):
        row = {
            "folder": s["folder"],
            "triage_state": s["triage_state"],
        }
        if kind == "binary":
            row["prob_malware"] = s.get("malware_probability_calibrated")
            row["prob_raw"] = s.get("malware_probability_raw")
        else:
            row["malware_score"] = s.get("malware_pattern_score")
            row["benign_score"] = s.get("benign_conformity_score")
            row["delta"] = s.get("delta_score")
            row["label_from_manifest"] = s.get("label_from_manifest")
        rows.append(row)
    return pd.DataFrame(rows)


def merge_manifest(df: pd.DataFrame, manifest: pd.DataFrame) -> pd.DataFrame:
    m = manifest[["folder", "label", "uncertain", "family", "verdict"]].copy()
    return df.merge(m, on="folder", how="inner")


def plot_triage_bars(counts: dict[str, int], title: str, filename: str) -> None:
    labels = list(counts.keys())
    values = [counts[k] for k in labels]
    fig, ax = plt.subplots(figsize=(6, 3.2))
    ax.bar(labels, values, color="#4C78A8")
    ax.set_ylabel("Samples")
    ax.set_title(title)
    ax.tick_params(axis="x", rotation=25)
    for i, v in enumerate(values):
        ax.text(i, v + 0.3, str(v), ha="center", fontsize=9)
    fig.tight_layout()
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG_DIR / filename)
    plt.close(fig)


def plot_confusion(cm: np.ndarray, title: str, filename: str) -> None:
    fig, ax = plt.subplots(figsize=(4, 4))
    im = ax.imshow(cm, cmap="Blues")
    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Pred benign", "Pred malware"])
    ax.set_yticklabels(["True benign", "True malware"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, int(cm[i, j]), ha="center", va="center", color="black")
    ax.set_title(title)
    fig.colorbar(im, ax=ax, fraction=0.046)
    fig.tight_layout()
    fig.savefig(FIG_DIR / filename)
    plt.close(fig)


def agreement_table(
    merged: pd.DataFrame, pred_col: str, caption: str, label: str
) -> list[str]:
    sub = merged[merged[pred_col].notna()].copy()
    if sub.empty:
        return [
            f"\\begin{{table}}[htbp]",
            "\\centering",
            f"\\caption{{{caption} (no decisive predictions).}}",
            f"\\label{{{label}}}",
            "\\begin{tabular}{l}",
            "No data \\\\",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]

    y_true = sub["label"].astype(int).values
    y_pred = sub[pred_col].astype(int).values
    m = _metrics(y_true, y_pred)
    cm = m["cm"]
    lines = [
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
        f"% Confusion matrix [{label}]: TN={cm[0,0]} FP={cm[0,1]} FN={cm[1,0]} TP={cm[1,1]}",
        "",
    ]
    return lines


def write_analysis_tables() -> None:
    if not BINARY_JSON.exists() or not TWO_JSON.exists():
        print("Missing outputs/binary_analysis.json or outputs/two_model_analysis.json")
        return

    manifest = load_manifest()
    binary_df = merge_manifest(samples_to_df(BINARY_JSON, "binary"), manifest)
    two_df = merge_manifest(samples_to_df(TWO_JSON, "two"), manifest)

    binary_df["pred_decisive"] = binary_df["triage_state"].map(_pred_from_binary_state)
    two_df["pred_decisive"] = two_df["triage_state"].map(_pred_from_two_state)

    binary_counts = binary_df["triage_state"].value_counts().to_dict()
    two_counts = two_df["triage_state"].value_counts().to_dict()

    uncertain = manifest[manifest["label"] == 0]
    n_uncertain = int(uncertain["uncertain"].sum())
    review_on_uncertain = int(
        (
            (two_df["label"] == 0)
            & two_df["uncertain"]
            & (two_df["triage_state"] == "needs_analyst_review")
        ).sum()
    )

    meta_lines = []
    if BINARY_META.exists():
        meta = json.loads(BINARY_META.read_text(encoding="utf-8"))
        meta_lines = [
            "\\subsection{Binary model training metadata}",
            "\\begin{table}[htbp]",
            "\\centering",
            "\\caption{Hold-out validation metrics from \\texttt{binary\\_model\\_meta.json}.}",
            "\\label{tab:binary_train_meta}",
            "\\begin{tabular}{lc}",
            "\\toprule",
            "\\textbf{Metric} & \\textbf{Value} \\\\",
            "\\midrule",
            f"Best validation F1 & {_cell(meta.get('best_val_f1'))} \\\\",
            f"Validation AUROC & {_cell(meta.get('val_auroc'))} \\\\",
            f"Validation PR-AUC & {_cell(meta.get('val_pr_auc'))} \\\\",
            f"Temperature & {_cell(meta.get('temperature'), '{:.2f}')} \\\\",
            f"Threshold high & {_cell(meta.get('threshold_high'))} \\\\",
            f"Threshold low & {_cell(meta.get('threshold_low'))} \\\\",
            "\\bottomrule",
            "\\end{tabular}",
            "\\end{table}",
            "",
        ]

    lines = [
        "% Auto-generated by scripts/generate_analysis_latex.py",
        "% Sources: outputs/binary_analysis.json, outputs/two_model_analysis.json",
        "",
        "\\subsection{Binary GNN analysis (\\texttt{analyze\\_binary\\_model.py})}",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Triage state counts on dissertation manifest ($n="
        + str(len(binary_df))
        + "$).}",
        "\\label{tab:binary_triage_counts}",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "\\textbf{Triage state} & \\textbf{Count} \\\\",
        "\\midrule",
    ]
    for state, cnt in sorted(binary_counts.items(), key=lambda x: -x[1]):
        state_tex = state.replace("_", "\\_")
        lines.append(f"{state_tex} & {cnt} \\\\")
    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]
    lines += agreement_table(
        binary_df,
        "pred_decisive",
        "Binary model agreement with manifest labels (decisive states only).",
        "tab:binary_label_agreement",
    )
    lines += [
        "\\subsection{Two-model fused analysis (\\texttt{analyze\\_two\\_model.py})}",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Two-model triage state counts on dissertation manifest ($n="
        + str(len(two_df))
        + "$).}",
        "\\label{tab:two_triage_counts}",
        "\\begin{tabular}{lr}",
        "\\toprule",
        "\\textbf{Triage state} & \\textbf{Count} \\\\",
        "\\midrule",
    ]
    for state, cnt in sorted(two_counts.items(), key=lambda x: -x[1]):
        state_tex = state.replace("_", "\\_")
        lines.append(f"{state_tex} & {cnt} \\\\")
    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Two-model \\texttt{needs\\_analyst\\_review} vs manifest uncertainty.}",
        "\\label{tab:two_uncertain_overlap}",
        "\\begin{tabular}{lc}",
        "\\toprule",
        "\\textbf{Statistic} & \\textbf{Value} \\\\",
        "\\midrule",
        f"Benign-labelled rows & {len(uncertain)} \\\\",
        f"Marked uncertain in manifest & {n_uncertain} \\\\",
        f"Uncertain benign also needs analyst review (two-model) & {review_on_uncertain} \\\\",
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
        "",
    ]
    lines += agreement_table(
        two_df,
        "pred_decisive",
        "Two-model agreement with manifest labels (likely malicious/benign only).",
        "tab:two_label_agreement",
    )
    lines += meta_lines

    TABLES_DIR.mkdir(parents=True, exist_ok=True)
    out = TABLES_DIR / "analysis_results.tex"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out}")

    plot_triage_bars(
        binary_counts,
        f"Binary model triage ($n$={len(binary_df)})",
        "fig_binary_triage.pdf",
    )
    plot_triage_bars(
        two_counts,
        f"Two-model triage ($n$={len(two_df)})",
        "fig_two_model_triage.pdf",
    )

    b_sub = binary_df[binary_df["pred_decisive"].notna()]
    if not b_sub.empty:
        cm = _metrics(
            b_sub["label"].astype(int).values,
            b_sub["pred_decisive"].astype(int).values,
        )["cm"]
        plot_confusion(
            cm,
            "Binary model vs manifest label",
            "fig_binary_confusion.pdf",
        )

    t_sub = two_df[two_df["pred_decisive"].notna()]
    if not t_sub.empty:
        cm = _metrics(
            t_sub["label"].astype(int).values,
            t_sub["pred_decisive"].astype(int).values,
        )["cm"]
        plot_confusion(
            cm,
            "Two-model vs manifest label",
            "fig_two_model_confusion.pdf",
        )
    print("Wrote analysis figures to latex_dissertation/figures/")


def main() -> None:
    write_analysis_tables()


if __name__ == "__main__":
    main()
